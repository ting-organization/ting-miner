//! Mining for pay (ting-miner, see MINER.md): a selector that claims the block
//! rewards of the coins it is told of, then orders pending transactions by what
//! they pay this miner's payout account per share of the block, and in a full
//! pool lets the transaction that pays least give way. Everything it knows comes
//! from the program conventions (wiki: programs/conventions): the payout account
//! in the block's producer data, and the producer payment event every paying
//! program emits. A coin it mines needs no code here, only an entry in
//! `miner.json`.
use crate::{
    Result,
    daemon::Mining,
    discovery,
    mining::{FirstIn, Pending, Selector, fair_share},
    search::{self, Choice},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::OpenOptions,
    io::{ErrorKind, Write},
    net::IpAddr,
    path::Path,
};
use ting_core::{
    hash::{Hash, hash, hex},
    meter::Resources,
    protocol::{Payload, Receipt, Status, Transaction},
    vm::Candidate,
};

/// The policy file in the data directory.
pub const POLICY_FILE: &str = "miner.json";
/// A coin's reward claim: operation `03`, no authorization (wiki: programs/coin,
/// mining rewards). It costs about 1.42 million C and 9 S; a block counts what a
/// transaction uses, not its budget, so the budget leaves room.
const OP_CLAIM: u8 = 0x03;
const CLAIM_BUDGET: Resources = Resources([2_000_000, 16, 4_096, 4_096]);

/// `miner.json`: what this miner is paid in and what it claims.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The value of one unit of each asset this miner accepts, by the ContractId
    /// of the program that pays it, in hex. Payments in other assets count as
    /// nothing.
    #[serde(default)]
    pub assets: BTreeMap<String, f64>,
    /// Coins whose block reward this miner claims in each block it builds.
    #[serde(default)]
    pub claims: Vec<String>,
    /// Whether transactions that pay nothing still fill the rest of the block,
    /// first in, first served. On unless set to false.
    #[serde(default = "yes")]
    pub unpaid: bool,
    /// How the miner finds nonces (`search.rs`): `auto`, the default, times
    /// the CPU and any GPU on this machine and mines with the fastest.
    #[serde(default)]
    pub search: Choice,
}
fn yes() -> bool {
    true
}
/// No assets, no claims, every transaction first in, first served: the
/// reference node's selection, with the fastest search this machine has.
impl Default for Policy {
    fn default() -> Self {
        Self {
            assets: BTreeMap::new(),
            claims: Vec::new(),
            unpaid: true,
            search: Choice::Auto,
        }
    }
}
impl Policy {
    /// The policy in `dir`, or the default when there is none: no assets, no
    /// claims, every transaction first in, first served, as the reference node.
    pub fn load(dir: &Path) -> Result<Self> {
        match std::fs::read(dir.join(POLICY_FILE)) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("invalid {POLICY_FILE}: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read {POLICY_FILE}: {e}")),
        }
    }
}
/// `miner.production.json`, the policy of a miner on the production network:
/// it claims and values Daler.
pub const PRODUCTION_POLICY: &str = include_str!("../../miner.production.json");
/// Gives `dir`, a new data directory of the production network, the production
/// policy as its `miner.json`, unless it has one (`ting init`), and says
/// whether it wrote it. A ContractId belongs to one chain, so a node of another
/// network starts without one.
pub fn initialize(dir: &Path) -> Result<bool> {
    let path = dir.join(POLICY_FILE);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(PRODUCTION_POLICY.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| format!("cannot write {POLICY_FILE}: {e}"))?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(format!("cannot write {POLICY_FILE}: {e}")),
    }
}
/// The lines `ting init` adds once it wrote the production policy; `ting` is
/// the command as the person typed it.
pub fn initialized(ting: &str) -> String {
    format!(
        "\nIts {POLICY_FILE} mines Daler (DLR). Name the account the blocks pay with:\n  \
         {ting} miner payout <account>\n"
    )
}

/// The selector of a paid miner.
pub struct Payout {
    assets: BTreeMap<Hash, f64>,
    claims: Vec<Hash>,
    unpaid: bool,
    /// What each transaction pays per share of the block, tried alone on a
    /// block on the tip, by id: learned once and kept while it is pooled, or
    /// learned from what it paid when a block kept it. One ranked as paying
    /// that a block takes back out ranks as paying nothing.
    ranks: HashMap<Hash, f64>,
    /// Templates selected so far; each address range's place in the queue in
    /// which the ranges take turns, as Ting's `FirstIn` keeps it: the template
    /// in which one of its transactions last ran, or the one before the
    /// template that first found it in the pool; and the template in which
    /// each pooled transaction last ran, to keep or take back out.
    turn: u64,
    sources: BTreeMap<Option<IpAddr>, u64>,
    runs: HashMap<Hash, u64>,
    /// The reference selection, for a block that pays nobody.
    reference: FirstIn,
}
/// What became of a transaction [`Payout::keep`] tried.
enum Tried {
    /// The block holds it, and it pays this much per share of the block.
    Kept(f64),
    /// It ran and was taken back out: it failed, or paid nothing where that
    /// would not do.
    TakenBack,
    /// It ran and the block had no room for it.
    Unfit,
    /// It did not run: the block's allowance for discarded work was spent.
    Untried,
}
/// The address range a pooled transaction came from, by which the ranges take
/// turns and hold shares of the pool: an IPv4 address or an IPv6 /64, as Ting
/// counts them (`discovery::range`); none for the node's own.
fn range(pending: &Pending<'_>) -> Option<IpAddr> {
    pending.source.map(discovery::range)
}
impl Payout {
    pub fn new(policy: &Policy) -> Result<Self> {
        let id = |s: &str| -> Result<Hash> {
            crate::unhex(s, 32)?
                .try_into()
                .map_err(|_| format!("invalid ContractId {s} in {POLICY_FILE}"))
        };
        let mut assets = BTreeMap::new();
        for (contract, value) in &policy.assets {
            if !value.is_finite() || *value < 0.0 {
                return Err(format!(
                    "invalid value {value} for {contract} in {POLICY_FILE}"
                ));
            }
            assets.insert(id(contract)?, *value);
        }
        Ok(Self {
            assets,
            claims: policy.claims.iter().map(|c| id(c)).collect::<Result<_>>()?,
            unpaid: policy.unpaid,
            ranks: HashMap::new(),
            turn: 0,
            sources: BTreeMap::new(),
            runs: HashMap::new(),
            reference: FirstIn::default(),
        })
    }
    /// What a receipt pays `payee`, valued by the policy.
    fn value(&self, receipt: &Receipt, payee: &Hash) -> f64 {
        let topic = payment_topic();
        receipt
            .events
            .iter()
            .filter_map(|event| {
                let weight = self.assets.get(&event.contract)?;
                let p = &event.payload;
                (p.len() == 80 && p[..32] == topic && p[32..64] == payee[..]).then(|| {
                    let amount = u128::from_le_bytes(p[64..80].try_into().unwrap());
                    amount as f64 * weight
                })
            })
            .sum()
    }
    /// What `tx` pays `payee` per share of `block`, run on it and taken back
    /// out, with whether it succeeded: nothing when it fails or does not fit.
    fn trial(&self, tx: &Transaction, payee: &Hash, block: &mut Candidate<'_>) -> f64 {
        let limits = block.limits();
        let Ok(Some(receipt)) = block.add(tx) else {
            return 0.0;
        };
        let paid = if receipt.status == Status::Success {
            self.value(receipt, payee) / share(&receipt.used, &limits)
        } else {
            0.0
        };
        block.undo();
        paid
    }
    /// A pooled transaction's rank: what it pays per share of the block, tried
    /// once on `block` and remembered by its id. Unknown once the block's
    /// allowance for discarded work is spent: a later block tries it.
    fn rank(
        &mut self,
        pending: &Pending<'_>,
        payee: &Hash,
        block: &mut Candidate<'_>,
    ) -> Option<f64> {
        if let Some(rank) = self.ranks.get(&pending.id) {
            return Some(*rank);
        }
        if block.spent() {
            return None;
        }
        let rank = self.trial(pending.tx, payee, block);
        self.ranks.insert(pending.id, rank);
        Some(rank)
    }
    /// Adds `tx` to `block` and keeps it if it succeeds and, unless `unpaid`
    /// will do, pays.
    fn keep(
        &self,
        tx: &Transaction,
        payee: &Hash,
        unpaid: bool,
        block: &mut Candidate<'_>,
    ) -> Tried {
        if block.spent() {
            return Tried::Untried;
        }
        let limits = block.limits();
        let Ok(Some(receipt)) = block.add(tx) else {
            return Tried::Unfit;
        };
        let success = receipt.status == Status::Success;
        let paid = if success {
            self.value(receipt, payee) / share(&receipt.used, &limits)
        } else {
            0.0
        };
        if success && (paid > 0.0 || unpaid) {
            Tried::Kept(paid)
        } else {
            block.undo();
            Tried::TakenBack
        }
    }
    /// Notes that this template ran `pending` to keep it: its range goes to
    /// the back of the queue, and it behind the others of its range.
    fn ran(&mut self, pending: &Pending<'_>) {
        self.sources.insert(range(pending), self.turn);
        self.runs.insert(pending.id, self.turn);
    }
    /// The order in which the passes take the pool, as Ting's `FirstIn` takes
    /// it (`mining::turns`): the first transaction of each address range
    /// before the second of any, the ranges in queue order, and arrival order
    /// among equals. Within a range, the transaction that ran longest ago, or
    /// never, comes first, so that one which ran and was taken back out waits
    /// behind the others of its range, and a range's own failing transaction
    /// does not keep its later ones out.
    fn order(&self, pool: &[Pending<'_>]) -> Vec<usize> {
        let mut ranges: BTreeMap<Option<IpAddr>, Vec<usize>> = BTreeMap::new();
        for (i, pending) in pool.iter().enumerate() {
            ranges.entry(range(pending)).or_default().push(i);
        }
        let mut order = Vec::with_capacity(pool.len());
        for (key, arrivals) in &ranges {
            let place = self.sources.get(key).copied().unwrap_or(u64::MAX);
            let mut members = arrivals.clone();
            members.sort_by_key(|&i| (self.runs.get(&pool[i].id).copied().unwrap_or(0), i));
            // The k-th of a range ties with other ranges by the range's k-th
            // arrival, as in Ting's order.
            for (k, (&i, &arrival)) in members.iter().zip(arrivals).enumerate() {
                order.push((k, place, arrival, i));
            }
        }
        order.sort_unstable();
        order.into_iter().map(|(.., i)| i).collect()
    }
}
impl Selector for Payout {
    /// The claims; what the transactions not yet ranked pay; the paying ones,
    /// best paid first; then the others. A transaction that fails is never in
    /// the block, so it stays pooled and costs its sender nothing, while
    /// running it spends the template's allowance for discarded work. So no
    /// pass lets such transactions keep the others out:
    ///
    /// - Ranking takes at most half a block's compute, half the allowance Ting
    ///   gives a template, by the transactions' budgets: the passes that keep
    ///   transactions always have the other half.
    /// - Ranking and the last pass take the pool in turns by address range
    ///   (`order`), and a range goes to the back of the queue whenever a
    ///   template runs one of its transactions to keep it, whether the block
    ///   then holds it, takes it back out, or has no room for it. Only one the
    ///   allowance left untried keeps its place.
    /// - A paying transaction that fails or no longer pays is no longer ranked
    ///   as paying, and waits its range's turn with the others.
    fn select(&mut self, pool: &[Pending<'_>], block: &mut Candidate<'_>) {
        let Some(payee) = payout_account(block.producer()) else {
            // Nobody to pay: nothing to claim or rank by.
            if self.unpaid {
                self.reference.select(pool, block);
            }
            return;
        };
        // The rewards first, each kept only if the claim succeeds.
        for coin in &self.claims {
            if let Ok(Some(receipt)) = block.add(&claim(*coin))
                && receipt.status != Status::Success
            {
                block.undo();
            }
        }
        // The queue: ranges no longer in the pool leave it, new ones join its
        // back.
        self.turn = self.turn.saturating_add(1);
        let present: BTreeSet<Option<IpAddr>> = pool.iter().map(range).collect();
        self.sources.retain(|key, _| present.contains(key));
        let joined = self.turn - 1;
        for key in present {
            self.sources.entry(key).or_insert(joined);
        }
        // What left the pool is forgotten.
        let pooled: HashSet<Hash> = pool.iter().map(|p| p.id).collect();
        self.ranks.retain(|id, _| pooled.contains(id));
        self.runs.retain(|id, _| pooled.contains(id));
        let order = self.order(pool);
        // What each pending transaction pays per share of the block, tried
        // alone once, in turn, while its budget of compute fits in what is
        // left of half a block's. One that does not fit is ranked when a
        // later pass keeps it.
        let mut room = block.limits().0[0] / 2;
        let mut paying = Vec::new();
        for (place, &i) in order.iter().enumerate() {
            if !self.ranks.contains_key(&pool[i].id) {
                let compute = pool[i].tx.budget.0[0];
                if compute > room {
                    continue;
                }
                room -= compute;
            }
            if let Some(rank) = self.rank(&pool[i], &payee, block)
                && rank > 0.0
            {
                paying.push((rank, place, i));
            }
        }
        // Best paid first, ties in turn, each kept only if it still succeeds
        // and pays after what the block holds by then; one taken back is no
        // longer ranked as paying.
        paying.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut taken = vec![false; pool.len()];
        for (_, _, i) in paying {
            match self.keep(pool[i].tx, &payee, false, block) {
                Tried::Untried => continue,
                Tried::Kept(_) => taken[i] = true,
                Tried::TakenBack => {
                    self.ranks.insert(pool[i].id, 0.0);
                }
                Tried::Unfit => {}
            }
            self.ran(&pool[i]);
        }
        // Then the others, once each in turn: one that pays now, such as the
        // next payment of an account the block already holds one of, is kept
        // and ranked by what it paid; with `unpaid`, so is one that succeeds
        // and pays nothing.
        for &i in &order {
            if taken[i] {
                continue;
            }
            match self.keep(pool[i].tx, &payee, self.unpaid, block) {
                Tried::Untried => continue,
                Tried::Kept(paid) if paid > 0.0 => {
                    self.ranks.insert(pool[i].id, paid);
                }
                Tried::Kept(_) | Tried::TakenBack | Tried::Unfit => {}
            }
            self.ran(&pool[i]);
        }
    }
    /// In a full pool, the transaction that pays least per share of the block
    /// gives way, if it pays less than the newcomer, among those of address
    /// ranges holding at least as many as the newcomer's: so a range cannot
    /// push out others' transactions with ones of its own that will fail,
    /// beyond an equal share. A range is an IPv4 address or an IPv6 /64, as
    /// Ting's shares count (`discovery::range`), so the many addresses of one
    /// /64 hold one share between them. Among equals the most recent gives
    /// way. When none pays less, the reference rule decides, but never against
    /// a transaction that pays more than the newcomer. The node's own
    /// submissions never give way, and neither does one whose rank is unknown;
    /// a newcomer's unknown rank counts as paying nothing.
    fn give_way(
        &mut self,
        pool: &[Pending<'_>],
        incoming: &Pending<'_>,
        block: &mut Candidate<'_>,
    ) -> Option<usize> {
        let Some(payee) = payout_account(block.producer()) else {
            return fair_share(pool, incoming);
        };
        let offered = self.rank(incoming, &payee, block).unwrap_or(0.0);
        let mut held: HashMap<IpAddr, usize> = HashMap::new();
        for pending in pool {
            if let Some(source) = range(pending) {
                *held.entry(source).or_default() += 1;
            }
        }
        let own = range(incoming)
            .and_then(|source| held.get(&source).copied())
            .unwrap_or(0);
        let mut lowest: Option<(f64, usize)> = None;
        for (i, pending) in pool.iter().enumerate() {
            let Some(source) = range(pending) else {
                continue;
            };
            if held[&source] < own {
                continue;
            }
            let Some(rank) = self.rank(pending, &payee, block) else {
                continue;
            };
            if lowest.is_none_or(|(least, _)| rank <= least) {
                lowest = Some((rank, i));
            }
        }
        let gives = match lowest {
            Some((rank, i)) if rank < offered => Some(i),
            _ => fair_share(pool, incoming).filter(|&i| {
                self.ranks
                    .get(&pool[i].id)
                    .is_none_or(|rank| *rank <= offered)
            }),
        };
        match gives {
            Some(i) => {
                self.ranks.remove(&pool[i].id);
            }
            None => {
                self.ranks.remove(&incoming.id);
            }
        }
        gives
    }
    fn describe(&self) -> Value {
        json!({"kind":"payout",
            "assets":self.assets.iter().map(|(c, v)| (hex(c), json!(v))).collect::<serde_json::Map<_, _>>(),
            "claims":self.claims.iter().map(|c| hex(c)).collect::<Vec<_>>(),
            "unpaid":self.unpaid})
    }
}

/// The topic of every producer payment, `H("app/event/producer-payment-v1", "")`.
pub fn payment_topic() -> Hash {
    hash("app/event/producer-payment-v1", &[])
}
/// The payout account in producer data: after `"OCP1"`, the first entry of
/// type 1 whose value is 32 bytes (wiki: programs/conventions, producer data).
pub fn payout_account(producer: &[u8]) -> Option<Hash> {
    let mut rest = producer.strip_prefix(b"OCP1")?;
    while rest.len() >= 8 {
        let kind = u32::from_le_bytes(rest[..4].try_into().unwrap());
        let length = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
        let value = rest.get(8..8 + length)?;
        if kind == 1 && length == 32 {
            return value.try_into().ok();
        }
        rest = &rest[8 + length..];
    }
    None
}
/// Producer data naming `account` as the payout account, 44 bytes.
pub fn producer_data(account: &Hash) -> Vec<u8> {
    let mut data = b"OCP1".to_vec();
    data.extend(1u32.to_le_bytes());
    data.extend(32u32.to_le_bytes());
    data.extend(account);
    data
}
/// The producer data, in hex, paying `account`: 64 hex digits, as a wallet such
/// as Ting ID shows an account, in either case (`ting miner payout`).
pub fn payout_producer(account: &str) -> Result<String> {
    let account = crate::hash_arg(&account.to_ascii_lowercase()).map_err(|_| {
        format!("{account:?} is not an account: an account is 32 bytes, 64 hex digits")
    })?;
    Ok(hex(&producer_data(&account)))
}
/// `answer` with `payout`, the payout account its `producer_hex` names, or null
/// where it names none (`ting miner payout` and `ting miner status`).
pub fn with_payout(mut answer: Value) -> Value {
    let producer = answer["producer_hex"]
        .as_str()
        .and_then(|p| crate::unhex(p, crate::config::PRODUCER_MAX).ok())
        .unwrap_or_default();
    answer["payout"] = json!(payout_account(&producer).map(|account| hex(&account)));
    answer
}
/// The account an answer of [`with_payout`] names, as `ting miner status`
/// shows it.
pub fn account_text(payout: &Value) -> String {
    match payout.as_str() {
        Some(account) => account.to_owned(),
        None => "none: the blocks claim nothing and pay nobody".to_owned(),
    }
}
/// The text of `ting miner payout`: the account the blocks pay, and, after
/// setting it, whether the running node took it (`saved` false) or the node
/// was stopped and config.json holds it.
pub fn payout_text(answer: &Value, saved: Option<bool>, ting: &str) -> String {
    match (answer["payout"].as_str(), saved) {
        (Some(account), Some(true)) => {
            format!("Saved in config.json: the blocks this node builds pay {account}.\n")
        }
        (Some(account), Some(false)) => {
            format!("The blocks this node builds pay {account}, from its next template.\n")
        }
        (Some(account), None) => format!("The blocks this node builds pay {account}.\n"),
        (None, _) => format!(
            "The blocks this node builds pay no account, so they claim nothing.\n\
             Name one with: {ting} miner payout <account>\n"
        ),
    }
}
/// A transaction's share of the block: its largest fraction of any capacity.
fn share(used: &Resources, limits: &Resources) -> f64 {
    (0..4)
        .filter(|&i| limits.0[i] > 0)
        .map(|i| used.0[i] as f64 / limits.0[i] as f64)
        .fold(f64::MIN_POSITIVE, f64::max)
}
/// The reward claim of `coin`.
pub fn claim(coin: Hash) -> Transaction {
    Transaction {
        budget: CLAIM_BUDGET,
        payload: Payload::Call {
            target: coin,
            input: vec![OP_CLAIM],
        },
    }
}
/// The node's mining pieces for `dir`: the payout selector and the search its
/// policy asks for.
pub fn mining(dir: &Path) -> Result<Mining> {
    let policy = Policy::load(dir)?;
    Ok(Mining {
        selector: Box::new(Payout::new(&policy)?),
        search: search::factory(policy.search),
    })
}
