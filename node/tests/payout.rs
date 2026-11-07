//! The paid miner's selector (MINER.md): reward claims, payments per share of the
//! block, and the policy in `miner.json`.
mod support;
use serde_json::json;
use std::sync::{Arc, atomic::AtomicBool};
use support::Directory;
use ting_core::{
    hash::{Hash, hash, hex},
    meter::Resources,
    protocol::{Encode, Header, Payload, Transaction},
};
use ting_node::{
    chain::Chain,
    config, mining,
    payout::{self, Payout, Policy},
};

fn open(dir: &Directory, policy: &Policy) -> Chain {
    Chain::open_with(
        &dir.0,
        Arc::new(AtomicBool::new(false)),
        Box::new(Payout::new(policy).unwrap()),
    )
    .unwrap()
}
/// A top-level deployment's ContractId: `H("contract", chain ‖ transaction ‖ 0)`.
fn contract_id(chain: &Hash, tx: &Transaction) -> Hash {
    let mut bytes = chain.to_vec();
    bytes.extend(tx.id(*chain));
    bytes.extend(0u64.to_le_bytes());
    hash("contract", &bytes)
}
fn deploy(code: Vec<u8>, input: Vec<u8>) -> Transaction {
    Transaction {
        budget: Resources([60_000_000, 64, 65_536, 131_072]),
        payload: Payload::Deploy { code, input },
    }
}
/// A program that pays the producer: its input is a payee and an amount, and it
/// emits the producer payment of the conventions for them. Written without
/// names, which the execution profile does not accept as a custom section.
fn payer() -> Vec<u8> {
    let topic: String = payout::payment_topic()
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect();
    wat::parse_str(format!(
        r#"(module
          (import "ting" "input" (func (param i32 i32) (result i32)))
          (import "ting" "emit" (func (param i32 i32)))
          (memory (export "memory") 1 1)
          (data (i32.const 0) "{topic}")
          (func (export "invoke")
            (if (i32.eq (call 0 (i32.const 32) (i32.const 48)) (i32.const 48))
              (then (call 1 (i32.const 0) (i32.const 80))))))"#
    ))
    .unwrap()
}
fn pay(payer: Hash, payee: &Hash, amount: u128) -> Transaction {
    let mut input = payee.to_vec();
    input.extend(amount.to_le_bytes());
    Transaction {
        budget: Resources([1_000_000, 16, 4_096, 4_096]),
        payload: Payload::Call {
            target: payer,
            input,
        },
    }
}
/// Mines one block holding exactly `ids`, through a template and a solution.
fn mine_exactly(chain: &mut Chain, ids: &[String]) {
    let template = chain
        .request("template", json!({"transactions":ids}))
        .unwrap();
    let header =
        Header::decode(&ting_node::unhex(template["header_hex"].as_str().unwrap(), 294).unwrap())
            .unwrap();
    let nonce = mining::search(
        &header,
        0,
        10_000,
        &AtomicBool::new(false),
        &Default::default(),
    )
    .unwrap();
    chain
        .request(
            "solution",
            json!({"template":template["id"],"nonce":nonce.to_string()}),
        )
        .unwrap();
}

#[test]
fn producer_data_names_the_payout_account_as_the_conventions_say() {
    assert_eq!(
        hex(&payout::payment_topic()),
        "29735265b80e981b9b7271e3de08bec1762823b25c977b2986b052879d0b6bcb"
    );
    let account = [7; 32];
    let data = payout::producer_data(&account);
    assert_eq!(data.len(), 44);
    assert_eq!(
        &data[..12],
        &[0x4f, 0x43, 0x50, 0x31, 1, 0, 0, 0, 32, 0, 0, 0]
    );
    assert_eq!(payout::payout_account(&data), Some(account));
    // Other entries are passed over; a short type-1 value does not count.
    let mut skipping = b"OCP1".to_vec();
    skipping.extend([2, 0, 0, 0, 3, 0, 0, 0, 1, 2, 3]);
    skipping.extend([1, 0, 0, 0, 2, 0, 0, 0, 9, 9]);
    skipping.extend(&data[4..]);
    assert_eq!(payout::payout_account(&skipping), Some(account));
    for none in [&b"miner"[..], &b"OCP1"[..], &data[..40], &[]] {
        assert_eq!(payout::payout_account(none), None);
    }
}

#[test]
fn the_best_paid_transactions_come_first_and_the_policy_decides_the_rest() {
    let me = [7; 32];
    let setup = |unpaid: bool| {
        let dir = Directory::new();
        dir.config(false, "miner");
        let chain_id = config::genesis(&dir.0).unwrap().chain_id();
        // Two paying programs: the miner values the first's asset only.
        let (valued, other) = (deploy(payer(), vec![]), deploy(payer(), vec![1]));
        let (valued_id, other_id) = (
            contract_id(&chain_id, &valued),
            contract_id(&chain_id, &other),
        );
        let policy = Policy {
            assets: [(hex(&valued_id), 1.0)].into(),
            unpaid,
            ..Default::default()
        };
        let mut chain = open(&dir, &policy);
        chain
            .request(
                "miner_config",
                json!({"enabled":false,"producer":hex(&payout::producer_data(&me))}),
            )
            .unwrap();
        for tx in [&valued, &other] {
            chain.submit(&tx.encode()).unwrap();
        }
        let ids = [&valued, &other].map(|tx| hex(&tx.id(chain_id))).to_vec();
        mine_exactly(&mut chain, &ids);
        // In arrival order: a payment to someone else, a small and a large
        // payment to this miner, and a large one in an asset it does not value.
        let txs = [
            pay(valued_id, &[9; 32], 10_000),
            pay(valued_id, &me, 10),
            pay(valued_id, &me, 1_000),
            pay(other_id, &me, 50_000),
        ];
        for tx in &txs {
            chain.submit(&tx.encode()).unwrap();
        }
        let ids: Vec<String> = txs.iter().map(|tx| hex(&tx.id(chain_id))).collect();
        (dir, chain, ids)
    };
    let (_dir, mut chain, ids) = setup(true);
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(
        template["transactions"],
        json!([ids[2], ids[1], ids[0], ids[3]]),
        "paid best first, then the rest as they came"
    );
    let (_dir, mut chain, ids) = setup(false);
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(template["transactions"], json!([ids[2], ids[1]]));
}

#[test]
fn the_miner_claims_each_reward_of_a_coin_into_its_payout_account() {
    let me = [7; 32];
    let dir = Directory::new();
    dir.config(false, "miner");
    let chain_id = config::genesis(&dir.0).unwrap().chain_id();
    // The reference coin, 5 coins of 10^8 units a block, halving every 1,000.
    let code = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../programs/coin.wasm"
    ))
    .unwrap();
    let mut input = vec![1];
    for text in [&b"Test coin"[..], b"TST"] {
        input.extend((text.len() as u32).to_le_bytes());
        input.extend(text);
    }
    input.push(8);
    input.extend(2_100_000_000_000_000u128.to_le_bytes());
    input.extend(500_000_000u128.to_le_bytes());
    input.extend(1_000u64.to_le_bytes());
    input.extend(0u128.to_le_bytes());
    input.extend([0; 32]);
    input.extend(0u64.to_le_bytes());
    let coin = deploy(code, input);
    let coin_id = contract_id(&chain_id, &coin);
    let policy = Policy {
        assets: [(hex(&coin_id), 1.0)].into(),
        claims: vec![hex(&coin_id)],
        ..Default::default()
    };
    let mut chain = open(&dir, &policy);
    // Without a payout account there is nothing to claim.
    chain.submit(&coin.encode()).unwrap();
    chain.mine(1, 10_000).unwrap();
    let first = chain.request("block", json!({"id":"1"})).unwrap();
    assert_eq!(first["transactions"], json!([hex(&coin.id(chain_id))]));
    assert_eq!(first["receipts"][0]["status_name"], "Success");
    chain
        .request(
            "miner_config",
            json!({"enabled":false,"producer":hex(&payout::producer_data(&me))}),
        )
        .unwrap();
    let claim = hex(&payout::claim(coin_id).id(chain_id));
    for height in ["2", "3"] {
        chain.mine(1, 10_000).unwrap();
        let block = chain.request("block", json!({"id":height})).unwrap();
        assert_eq!(block["transactions"][0], claim);
        let receipt = &block["receipts"][0];
        assert_eq!(receipt["status_name"], "Success", "{receipt}");
        // The reward is paid to this miner's payout account.
        let topic = hex(&payout::payment_topic());
        let payment = receipt["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["payload_hex"].as_str().unwrap())
            .find(|p| p.starts_with(&topic))
            .expect("a producer payment");
        assert_eq!(&payment[64..128], hex(&me));
        assert_eq!(&payment[128..], hex(&500_000_000u128.to_le_bytes()));
    }
}

/// A program that pays the producer only in sequence: its input is a payee, an
/// amount and a number, and it pays when the number is the next of its count,
/// and otherwise fails; without such input, as when deployed, it does nothing.
/// Imports by place: input, emit, storage_get, storage_set, revert.
fn sequenced() -> Vec<u8> {
    sequenced_failing_with("(call 4 (i32.const 0) (i32.const 0)) (unreachable)")
}
/// [`sequenced`], but out of sequence it spins until its compute runs out.
fn sequenced_or_spinning() -> Vec<u8> {
    sequenced_failing_with("(loop (br 0))")
}
fn sequenced_failing_with(fail: &str) -> Vec<u8> {
    let topic: String = payout::payment_topic()
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect();
    wat::parse_str(format!(
        r#"(module
          (import "ting" "input" (func (param i32 i32) (result i32)))
          (import "ting" "emit" (func (param i32 i32)))
          (import "ting" "storage_get" (func (param i32 i32 i32) (result i32)))
          (import "ting" "storage_set" (func (param i32 i32 i32)))
          (import "ting" "revert" (func (param i32 i32)))
          (memory (export "memory") 1 1)
          (data (i32.const 0) "{topic}")
          (func (export "invoke")
            (if (i32.ne (call 0 (i32.const 32) (i32.const 56)) (i32.const 56))
              (then (return)))
            (drop (call 2 (i32.const 128) (i32.const 160) (i32.const 8)))
            (if (i64.ne (i64.load (i32.const 80)) (i64.load (i32.const 160)))
              (then {fail}))
            (i64.store (i32.const 160) (i64.add (i64.load (i32.const 160)) (i64.const 1)))
            (call 3 (i32.const 128) (i32.const 160) (i32.const 8))
            (call 1 (i32.const 0) (i32.const 80))))"#
    ))
    .unwrap()
}
fn pay_next(program: Hash, payee: &Hash, amount: u128, number: u64) -> Transaction {
    let mut tx = pay(program, payee, amount);
    if let Payload::Call { input, .. } = &mut tx.payload {
        input.extend(number.to_le_bytes());
    }
    tx
}
/// A miner on the development chain with the paying program `code` deployed,
/// paid in it: the directory, the chain, the program and the chain's id.
fn paid_miner(code: Vec<u8>, unpaid: bool, pool: usize) -> (Directory, Chain, Hash, Hash) {
    let dir = Directory::new();
    dir.config(false, "miner");
    let mut c = config::Config::load(&dir.0).unwrap();
    c.mempool_transactions = pool;
    c.save(&dir.0).unwrap();
    let chain_id = config::genesis(&dir.0).unwrap().chain_id();
    let program = deploy(code, vec![]);
    let program_id = contract_id(&chain_id, &program);
    let policy = Policy {
        assets: [(hex(&program_id), 1.0)].into(),
        unpaid,
        ..Default::default()
    };
    let mut chain = open(&dir, &policy);
    chain
        .request(
            "miner_config",
            json!({"enabled":false,"producer":hex(&payout::producer_data(&[7; 32]))}),
        )
        .unwrap();
    chain.submit(&program.encode()).unwrap();
    mine_exactly(&mut chain, &[hex(&program.id(chain_id))]);
    (dir, chain, program_id, chain_id)
}

#[test]
fn a_payment_that_needs_another_first_is_taken_after_it() {
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(sequenced(), false, 1_024);
    // The second in sequence arrives first and pays more, and alone it fails.
    let (second, first) = (
        pay_next(program, &me, 5_000, 1),
        pay_next(program, &me, 10, 0),
    );
    for tx in [&second, &first] {
        chain.submit(&tx.encode()).unwrap();
    }
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(
        template["transactions"],
        json!([hex(&first.id(chain_id)), hex(&second.id(chain_id))]),
        "the first pays alone; the second pays once the first is in"
    );
}

/// Deploys a program whose calls spin until their compute runs out, and so
/// fail and pay nothing: running one spends its whole budget of C. It spins
/// only when given input, so its deployment returns at once.
fn spinner(chain: &mut Chain, chain_id: Hash) -> Hash {
    let spinner = deploy(
        wat::parse_str(
            r#"(module
              (import "ting" "input" (func (param i32 i32) (result i32)))
              (memory (export "memory") 1 1)
              (func (export "invoke")
                (if (i32.eqz (call 0 (i32.const 0) (i32.const 1)))
                  (then (return)))
                (loop (br 0))))"#,
        )
        .unwrap(),
        vec![],
    );
    chain.submit(&spinner.encode()).unwrap();
    mine_exactly(chain, &[hex(&spinner.id(chain_id))]);
    contract_id(&chain_id, &spinner)
}
/// A call of `spinner` that spins through `compute`, told apart by `n`.
fn spin(spinner: Hash, compute: u64, n: u8) -> Transaction {
    Transaction {
        budget: Resources([compute, 16, 4_096, 4_096]),
        payload: Payload::Call {
            target: spinner,
            input: vec![n],
        },
    }
}
/// The transactions of `count` templates in a row, each as the hex of its id.
fn templates(chain: &mut Chain, count: usize) -> Vec<Vec<String>> {
    (0..count)
        .map(|_| {
            let template = chain.request("template", json!({})).unwrap();
            serde_json::from_value(template["transactions"].clone()).unwrap()
        })
        .collect()
}

#[test]
fn a_payment_left_untried_by_the_allowance_is_ranked_by_a_later_template() {
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), false, 1_024);
    // Sixty calls that spin through a million C each, then a payment. Ranking
    // them takes the half of a template's allowance for discarded work that
    // ranking may, 50 million C on the development chain, and trying them again
    // in the last pass the other half.
    let spinner = spinner(&mut chain, chain_id);
    let spins: Vec<Transaction> = (0..60).map(|n| spin(spinner, 1_000_000, n)).collect();
    let paid = pay(program, &me, 1_000);
    for tx in spins.iter().chain([&paid]) {
        chain.submit(&tx.encode()).unwrap();
    }
    // The first template spends its allowance before it reaches the payment;
    // the next ranks it and takes it.
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(template["transactions"], json!([]));
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(template["transactions"], json!([hex(&paid.id(chain_id))]));
}

/// Transactions that fail are never in a block of a paid miner and stay in
/// the pool, costing their sender nothing, while trying them spends a
/// template's allowance for discarded work. Taken in turns by address range,
/// they keep no other range's transaction out.
#[test]
fn transactions_that_fail_leave_no_other_range_waiting() {
    use std::net::IpAddr;
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 1_024);
    let spinner = spinner(&mut chain, chain_id);
    let (attacker, other): (IpAddr, IpAddr) =
        ("10.0.0.66".parse().unwrap(), "10.0.0.1".parse().unwrap());
    // Two calls that fail, together more than the allowance, arrive first;
    // then a transfer that succeeds and pays the miner nothing.
    let spins = [0, 1].map(|n| spin(spinner, 60_000_000, n));
    for tx in &spins {
        chain.submit_from(&tx.encode(), Some(attacker)).unwrap();
    }
    let unpaid = pay(program, &[9; 32], 1);
    chain.submit_from(&unpaid.encode(), Some(other)).unwrap();
    let unpaid = hex(&unpaid.id(chain_id));
    for (n, transactions) in templates(&mut chain, 8).iter().enumerate() {
        assert_eq!(transactions, std::slice::from_ref(&unpaid), "template {n}");
    }
}

/// A stream of new transactions that fail, each costing its sender nothing,
/// takes at most half of each template's allowance to rank: the payments keep
/// the other half.
#[test]
fn a_stream_of_failing_transactions_keeps_no_payment_out() {
    use std::net::IpAddr;
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 1_024);
    let spinner = spinner(&mut chain, chain_id);
    let attacker: IpAddr = "10.0.0.66".parse().unwrap();
    let paid = pay(program, &me, 1_000);
    chain.submit(&paid.encode()).unwrap();
    let paid = hex(&paid.id(chain_id));
    // Before each template, eleven new calls that spin through 10 million C
    // each: more than the whole allowance to rank them all.
    for template in 0..3u8 {
        for n in 0..11 {
            let fresh = spin(spinner, 10_000_000, template * 11 + n);
            chain.submit_from(&fresh.encode(), Some(attacker)).unwrap();
        }
        let shown = &templates(&mut chain, 1)[0];
        assert_eq!(shown, std::slice::from_ref(&paid), "template {template}");
    }
}

/// A range's own transactions that fail keep none of its later ones out: the
/// one that ran longest ago, or never, goes first within the range.
#[test]
fn a_range_s_failing_transactions_keep_none_of_its_others_out() {
    use std::net::IpAddr;
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 1_024);
    let spinner = spinner(&mut chain, chain_id);
    let sender: IpAddr = "10.0.0.1".parse().unwrap();
    // From one address: two calls that fail, together more than the
    // allowance, then a transfer that succeeds and pays the miner nothing.
    let spins = [0, 1].map(|n| spin(spinner, 60_000_000, n));
    let unpaid = pay(program, &[9; 32], 1);
    for tx in spins.iter().chain([&unpaid]) {
        chain.submit_from(&tx.encode(), Some(sender)).unwrap();
    }
    let unpaid = hex(&unpaid.id(chain_id));
    let shown = templates(&mut chain, 8);
    assert!(shown[1].contains(&unpaid), "{shown:?}");
    for n in 2..shown.len() {
        assert!(
            shown[n].contains(&unpaid) || shown[n - 1].contains(&unpaid),
            "templates {} and {n} both leave the transfer out: {shown:?}",
            n - 1
        );
    }
}

/// A transaction ranked as paying that fails once the block holds another,
/// as a second payment in the same sequence, is no longer ranked as paying:
/// spending the allowance best paid first in every template, such payments
/// would keep every transaction of the last pass out.
#[test]
fn a_payment_that_fails_in_the_block_is_no_longer_ranked_as_paying() {
    use std::net::IpAddr;
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(sequenced_or_spinning(), true, 1_024);
    // One payment of number 0 pays most; nine more of number 0, each ranked
    // as paying alone, spin through 12 million C each once it is in. Then a
    // transfer of another range that pays the miner nothing.
    let first = pay_next(program, &me, 10_000, 0);
    let spinning: Vec<Transaction> = (0..9)
        .map(|n| Transaction {
            budget: Resources([12_000_000, 16, 4_096, 4_096]),
            ..pay_next(program, &me, 5_000 + n, 0)
        })
        .collect();
    for tx in [&first].into_iter().chain(&spinning) {
        chain.submit(&tx.encode()).unwrap();
    }
    let unpaid = pay_next(program, &[9; 32], 1, 1);
    let other: IpAddr = "10.0.0.1".parse().unwrap();
    chain.submit_from(&unpaid.encode(), Some(other)).unwrap();
    let (first, unpaid) = (hex(&first.id(chain_id)), hex(&unpaid.id(chain_id)));
    // Ranking takes three templates at most; the payment and the transfer are
    // in every template after.
    let shown = templates(&mut chain, 8);
    for (n, transactions) in shown.iter().enumerate().skip(2) {
        assert_eq!(
            transactions,
            &[first.clone(), unpaid.clone()],
            "template {n}"
        );
    }
}

/// Transactions too large for the room the block has left, as block fillers
/// behind a paid transaction, spend the allowance whenever they are tried,
/// each up to the room left: their ranges go to the back of the queue for it,
/// as for ones that fail, rather than keeping their places, and their claim on
/// every template's allowance, while an unpaid transaction of another range
/// waits behind them.
#[test]
fn transactions_the_block_cannot_fit_leave_no_other_range_waiting() {
    use std::net::IpAddr;
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 1_024);
    let spinner = spinner(&mut chain, chain_id);
    let address = |n: u8| -> IpAddr { format!("10.0.0.{n}").parse().unwrap() };
    // A payment; then from two ranges a call each that spins through a whole
    // block's compute, which fits only an empty block; then a transfer that
    // pays nothing.
    let paid = pay(program, &me, 1_000);
    chain.submit(&paid.encode()).unwrap();
    let fillers = [0, 1].map(|n| spin(spinner, 100_000_000, n));
    for (n, filler) in fillers.iter().enumerate() {
        chain
            .submit_from(&filler.encode(), Some(address(66 + n as u8)))
            .unwrap();
    }
    let unpaid = pay(program, &[9; 32], 1);
    chain
        .submit_from(&unpaid.encode(), Some(address(1)))
        .unwrap();
    let (paid, unpaid) = (hex(&paid.id(chain_id)), hex(&unpaid.id(chain_id)));
    let fillers = fillers.map(|filler| hex(&filler.id(chain_id)));
    // The first templates spend their allowance learning what each pays; from
    // the first that holds the payment on, the fillers are in none, and the
    // transfer is left out of no two in a row.
    let shown = templates(&mut chain, 12);
    let start = shown
        .iter()
        .position(|transactions| transactions.contains(&paid))
        .unwrap();
    assert!(start <= 2, "{shown:?}");
    for n in start..shown.len() {
        assert_eq!(shown[n].first(), Some(&paid), "template {n}");
        assert!(
            !fillers.iter().any(|f| shown[n].contains(f)),
            "template {n}"
        );
        assert!(
            n == start || shown[n].contains(&unpaid) || shown[n - 1].contains(&unpaid),
            "templates {} and {n} both leave the transfer out: {shown:?}",
            n - 1
        );
    }
}

#[test]
fn a_full_pool_lets_the_lowest_payment_give_way() {
    use std::net::IpAddr;
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 3);
    let address = |n: u8| -> IpAddr { format!("10.0.0.{n}").parse().unwrap() };
    let pooled = |chain: &mut Chain, tx: &Transaction| {
        chain
            .request("transaction", json!({"id":hex(&tx.id(chain_id))}))
            .is_ok()
    };
    // One address fills the pool with payments of 10, 20 and 30.
    let first: Vec<Transaction> = [10, 20, 30].map(|n| pay(program, &me, n)).to_vec();
    for tx in &first {
        chain.submit_from(&tx.encode(), Some(address(1))).unwrap();
    }
    // A payment of 15 takes the place of the 10.
    let fifteen = pay(program, &me, 15);
    chain
        .submit_from(&fifteen.encode(), Some(address(2)))
        .unwrap();
    assert!(!pooled(&mut chain, &first[0]));
    assert!(pooled(&mut chain, &fifteen));
    // One of 5 pays less than all of them, and one paying someone else pays
    // nothing: both are refused, and the address rule moves no payment for them.
    for (tx, from) in [
        (pay(program, &me, 5), 2),
        (pay(program, &[9; 32], 1_000), 3),
    ] {
        assert_eq!(
            chain
                .submit_from(&tx.encode(), Some(address(from)))
                .unwrap_err(),
            ting_node::chain::POOL_FULL
        );
    }
    for tx in [&first[1], &first[2], &fifteen] {
        assert!(pooled(&mut chain, tx));
    }
    // The block takes the best paid first.
    let template = chain.request("template", json!({})).unwrap();
    assert_eq!(
        template["transactions"],
        json!([&first[2], &first[1], &fifteen].map(|tx| hex(&tx.id(chain_id))))
    );
}

/// The addresses of one IPv6 /64 count as one range, as Ting's shares do: a
/// fresh address in it pushes out no other range's payment beyond the range's
/// equal share, while another /64 can.
#[test]
fn a_full_pool_counts_an_ipv6_64_as_one_range() {
    use std::net::IpAddr;
    let me = [7; 32];
    let (_dir, mut chain, program, chain_id) = paid_miner(payer(), true, 3);
    let address = |a: &str| -> IpAddr { a.parse().unwrap() };
    let pooled = |chain: &mut Chain, tx: &Transaction| {
        chain
            .request("transaction", json!({"id":hex(&tx.id(chain_id))}))
            .is_ok()
    };
    // Another range's payment of 10, then two of one /64, each from its own
    // address.
    let ten = pay(program, &me, 10);
    chain
        .submit_from(&ten.encode(), Some(address("10.0.0.1")))
        .unwrap();
    let range: Vec<Transaction> = [20, 30].map(|n| pay(program, &me, n)).to_vec();
    for (tx, from) in range.iter().zip(["2001:db8::1", "2001:db8::2"]) {
        chain
            .submit_from(&tx.encode(), Some(address(from)))
            .unwrap();
    }
    // A third address of the /64 pays 15, more than the 10: its range already
    // holds more than the 10's, so the 10 stays, and none of its own pays less.
    let fifteen = pay(program, &me, 15);
    assert_eq!(
        chain
            .submit_from(&fifteen.encode(), Some(address("2001:db8::3")))
            .unwrap_err(),
        ting_node::chain::POOL_FULL
    );
    for tx in [&ten, &range[0], &range[1]] {
        assert!(pooled(&mut chain, tx));
    }
    // The next /64 holds nothing yet: its 15 takes the place of the 10.
    chain
        .submit_from(&fifteen.encode(), Some(address("2001:db8:0:1::1")))
        .unwrap();
    assert!(!pooled(&mut chain, &ten));
    assert!(pooled(&mut chain, &fifteen));
}

#[test]
fn an_account_as_a_wallet_shows_it_becomes_producer_data_paying_it() {
    let account = "0123456789ABCDEF".repeat(4);
    let producer = payout::payout_producer(&account).unwrap();
    assert_eq!(
        producer,
        format!("4f4350310100000020000000{}", account.to_lowercase())
    );
    assert_eq!(
        payout::with_payout(json!({"producer_hex":producer}))["payout"],
        json!(account.to_lowercase())
    );
    // Only 32 bytes of hex: not part of one, more, or producer data itself.
    for wrong in [
        "",
        &account[..62],
        &format!("{account}00"),
        &account.replace('F', "g"),
        &producer,
    ] {
        let refused = payout::payout_producer(wrong).unwrap_err();
        assert!(refused.contains("64 hex digits"), "{wrong}: {refused}");
    }
    // A coin's two reserved keys are no account: the blocks would pay nobody.
    for reserved in ["0".repeat(64), format!("{}1", "0".repeat(63))] {
        let refused = payout::payout_producer(&reserved).unwrap_err();
        assert!(refused.contains("not an account"), "{reserved}: {refused}");
    }
    for none in ["", "4f435031", "6d696e6572"] {
        assert_eq!(
            payout::with_payout(json!({"producer_hex":none}))["payout"],
            json!(null)
        );
    }
}

fn ting(dir: &Directory, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ting"));
    command.arg("--data-dir").arg(&dir.0).args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.output().unwrap()
}
/// A command's result, printed as JSON.
fn answer(dir: &Directory, args: &[&str]) -> serde_json::Value {
    serde_json::from_str(&text(dir, &[&["--json"], args].concat())).unwrap()
}
/// A command's text, as a person reads it.
fn text(dir: &Directory, args: &[&str]) -> String {
    let output = ting(dir, args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
/// Stops the node of a test that started one, however the test ends.
struct Stop<'a>(&'a Directory);
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        let _ = ting(self.0, &["stop"]);
    }
}

/// `ting miner payout` sets the payout account with the node stopped or running,
/// and it and `ting miner status` show it; anything but an account is refused and
/// leaves the producer data as it was.
#[test]
fn the_payout_command_sets_the_account_the_blocks_pay_and_shows_it() {
    let dir = Directory::new();
    dir.config(false, "payout");
    let (first, second) = ("0123456789ABCDEF".repeat(4), "fe".repeat(32));
    let paying = |account: &str| format!("4f4350310100000020000000{account}");

    let set = answer(&dir, &["miner", "payout", &first]);
    assert_eq!(set["payout"], json!(first.to_lowercase()));
    let producer = config::Config::load(&dir.0).unwrap().producer();
    assert_eq!(hex(&producer), paying(&first.to_lowercase()));
    let refused = ting(&dir, &["miner", "payout", &first[..62]]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("64 hex digits"));
    assert_eq!(
        answer(&dir, &["miner", "payout"])["payout"],
        json!(first.to_lowercase())
    );
    // As text: the account, and where it went.
    let pays = |account: &str| format!("the blocks this node builds pay {account}");
    let saved = text(&dir, &["miner", "payout", &first]);
    assert!(saved.starts_with("Saved in config.json"), "{saved}");
    assert!(saved.contains(&pays(&first.to_lowercase())), "{saved}");
    let shown = text(&dir, &["miner", "payout"]);
    assert_eq!(
        shown,
        format!(
            "The blocks this node builds pay {}.\n",
            first.to_lowercase()
        )
    );

    answer(&dir, &["start"]);
    let _stop = Stop(&dir);
    assert_eq!(
        answer(&dir, &["miner", "payout", &second])["payout"],
        json!(second)
    );
    let status = answer(&dir, &["miner", "status"]);
    assert_eq!(status["payout"], json!(second));
    assert_eq!(status["producer_hex"], json!(paying(&second)));
    let set = text(&dir, &["miner", "payout", &second]);
    assert!(set.contains("from its next template"), "{set}");
    let status = text(&dir, &["miner", "status"]);
    assert!(
        status
            .lines()
            .any(|line| line.starts_with("Payout") && line.ends_with(&format!("  {second}"))),
        "{status}"
    );
    // Producer data naming no payout account pays nobody.
    answer(&dir, &["miner", "producer", "4f435031"]);
    assert_eq!(answer(&dir, &["miner", "status"])["payout"], json!(null));
    assert_eq!(answer(&dir, &["miner", "payout"])["payout"], json!(null));
    let none = text(&dir, &["miner", "payout"]);
    assert!(none.contains("pay no account"), "{none}");
    assert!(none.contains("miner payout <account>"), "{none}");
    let status = text(&dir, &["miner", "status"]);
    assert!(
        status.contains("none: the blocks claim nothing"),
        "{status}"
    );
}

/// `ting init` gives a production node the production policy, claiming and
/// valuing Daler, and a node of another network none; a policy already there is
/// kept.
#[test]
fn a_new_production_node_mines_daler_and_another_network_nothing() {
    let daler = "305378d17f6af84a563d0f8a8455084948aff7330b62b4f2f98a44b82ba113c4";
    let production = Directory::new();
    let created = text(&production, &["init"]);
    assert!(
        created.contains("miner.json mines Daler (DLR)"),
        "{created}"
    );
    assert!(created.contains("miner payout <account>"), "{created}");
    assert!(created.contains("wallet create"), "{created}");
    let written = std::fs::read_to_string(production.0.join("miner.json")).unwrap();
    assert_eq!(written, payout::PRODUCTION_POLICY);
    let policy = Policy::load(&production.0).unwrap();
    assert_eq!(policy.claims, [daler]);
    assert_eq!(policy.assets, [(daler.to_owned(), 1.0)].into());
    assert!(policy.unpaid);

    let development = Directory::new();
    let created = text(&development, &["init", "--dev"]);
    assert!(!created.contains("miner.json"), "{created}");
    assert!(!development.0.join("miner.json").exists());
    assert!(Policy::load(&development.0).unwrap().claims.is_empty());

    let own = r#"{"assets":{},"claims":[]}"#;
    std::fs::write(production.0.join("miner.json"), own).unwrap();
    assert!(!payout::initialize(&production.0).unwrap());
    let kept = std::fs::read_to_string(production.0.join("miner.json")).unwrap();
    assert_eq!(kept, own);
}
