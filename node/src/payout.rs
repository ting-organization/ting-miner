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
    mining::{FirstIn, Pending, Selector, fair_share},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
}
fn yes() -> bool {
    true
}
/// No assets, no claims, every transaction first in, first served: the
/// reference node's selection.
impl Default for Policy {
    fn default() -> Self {
        Self {
            assets: BTreeMap::new(),
            claims: Vec::new(),
            unpaid: true,
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

/// The selector of a paid miner.
pub struct Payout {
    assets: BTreeMap<Hash, f64>,
    claims: Vec<Hash>,
    unpaid: bool,
    /// What each transaction pays per share of the block, tried alone on a
    /// block on the tip, by id: learned once, since what a transaction pays
    /// does not change with the tip, and kept while it is pooled.
    ranks: HashMap<Hash, f64>,
    /// The reference selection, for a block that pays nobody.
    reference: FirstIn,
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
    /// will do, pays: what it pays per share, or none when it was taken back.
    fn keep(
        &self,
        tx: &Transaction,
        payee: &Hash,
        unpaid: bool,
        block: &mut Candidate<'_>,
    ) -> Option<f64> {
        let limits = block.limits();
        let Ok(Some(receipt)) = block.add(tx) else {
            return None;
        };
        let success = receipt.status == Status::Success;
        let paid = if success {
            self.value(receipt, payee) / share(&receipt.used, &limits)
        } else {
            0.0
        };
        if success && (paid > 0.0 || unpaid) {
            Some(paid)
        } else {
            block.undo();
            None
        }
    }
}
impl Selector for Payout {
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
        // What each pending transaction pays per share of the block, tried
        // alone once; what left the pool is forgotten.
        let pooled: HashSet<Hash> = pool.iter().map(|p| p.id).collect();
        self.ranks.retain(|id, _| pooled.contains(id));
        let mut paying = Vec::new();
        for (i, pending) in pool.iter().enumerate() {
            if let Some(rank) = self.rank(pending, &payee, block)
                && rank > 0.0
            {
                paying.push((rank, i));
            }
        }
        // Best paid first, ties in arrival order, each kept only if it still
        // succeeds and pays after what the block holds by then.
        paying.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut taken = vec![false; pool.len()];
        for (_, i) in paying {
            taken[i] = self.keep(pool[i].tx, &payee, false, block).is_some();
        }
        // Then the others, once each in arrival order: one that pays now,
        // such as the next payment of an account the block already holds one
        // of, is kept and ranked by what it paid; with `unpaid`, so is one
        // that succeeds and pays nothing.
        for (i, pending) in pool.iter().enumerate() {
            if taken[i] {
                continue;
            }
            if let Some(paid) = self.keep(pending.tx, &payee, self.unpaid, block)
                && paid > 0.0
            {
                self.ranks.insert(pending.id, paid);
            }
        }
    }
    /// In a full pool, the transaction that pays least per share of the block
    /// gives way, if it pays less than the newcomer, among those of addresses
    /// holding at least as many as the newcomer's: so an address cannot push
    /// out others' transactions with ones of its own that will fail, beyond an
    /// equal share. Among equals the most recent gives way. When none pays
    /// less, the reference rule decides, but never against a transaction that
    /// pays more than the newcomer. The node's own submissions never give way,
    /// and neither does one whose rank is unknown; a newcomer's unknown rank
    /// counts as paying nothing.
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
            if let Some(source) = pending.source {
                *held.entry(source).or_default() += 1;
            }
        }
        let own = incoming
            .source
            .and_then(|source| held.get(&source).copied())
            .unwrap_or(0);
        let mut lowest: Option<(f64, usize)> = None;
        for (i, pending) in pool.iter().enumerate() {
            let Some(source) = pending.source else {
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
/// The node's mining pieces for `dir`: the payout selector from its policy, and
/// the reference search.
pub fn mining(dir: &Path) -> Result<Mining> {
    Ok(Mining {
        selector: Box::new(Payout::new(&Policy::load(dir)?)?),
        ..Mining::default()
    })
}
