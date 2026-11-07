//! The wallet (MINER.md): what it signs, the reference coin and the secp256k1
//! policy accept, on a chain where both are deployed as on any other.
mod support;
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicBool};
use support::Directory;
use ting_core::{
    hash::{Hash, hash, hex},
    meter::Resources,
    protocol::{Encode, Payload, Transaction},
};
use ting_node::{
    chain::Chain,
    config::{self, Running},
    payout, transport,
    wallet::{self, Command, Key, Transfer},
};
use zeroize::Zeroizing;

fn program(name: &str) -> Vec<u8> {
    ting_node::wiki::file(&format!("programs/{name}.wasm"))
        .unwrap()
        .1
        .to_vec()
}
/// A top-level deployment's ContractId: `H("contract", chain ‖ transaction ‖ 0)`.
fn contract_id(chain: &Hash, tx: &Transaction) -> Hash {
    let mut bytes = chain.to_vec();
    bytes.extend(tx.id(*chain));
    bytes.extend(0u64.to_le_bytes());
    hash("contract", &bytes)
}
/// The secp256k1 policy's canonical deployment (wiki: programs).
fn policy() -> Transaction {
    Transaction {
        budget: Resources([50_000_000, 64, 16_777_216, 16_777_216]),
        payload: Payload::Deploy {
            code: program("policy-secp256k1"),
            input: Vec::new(),
        },
    }
}
/// A coin of 8 decimals with no reward and no cap, crediting `allocations`.
fn coin(allocations: &[(Hash, u128)]) -> Transaction {
    let mut input = vec![1];
    for text in [&b"Test coin"[..], b"TST"] {
        input.extend((text.len() as u32).to_le_bytes());
        input.extend(text);
    }
    input.push(8);
    input.extend(u128::MAX.to_le_bytes());
    input.extend(0u128.to_le_bytes());
    input.extend(0u64.to_le_bytes());
    input.extend(0u128.to_le_bytes());
    input.extend([0; 32]);
    input.extend((allocations.len() as u64).to_le_bytes());
    for (account, amount) in allocations {
        input.extend(account);
        input.extend(amount.to_le_bytes());
    }
    Transaction {
        budget: Resources([60_000_000, 64, 65_536, 131_072]),
        payload: Payload::Deploy {
            code: program("coin"),
            input,
        },
    }
}
/// An account's balance and nonce in `coin`.
fn holding(chain: &mut Chain, coin: &Hash, account: &Hash) -> (u128, u64) {
    let answer = chain
        .request("storage", json!({"id":hex(coin),"key":hex(account)}))
        .unwrap();
    match answer["value_hex"].as_str() {
        None => (0, 0),
        Some(value) => {
            let record = ting_node::unhex(value, 40).unwrap();
            (
                u128::from_le_bytes(record[..16].try_into().unwrap()),
                u64::from_le_bytes(record[32..].try_into().unwrap()),
            )
        }
    }
}
/// Mines one block from the pool and returns it.
fn mine(chain: &mut Chain) -> Value {
    chain.mine(1, 10_000).unwrap();
    let height = chain.request("status", json!({})).unwrap()["height"].clone();
    chain
        .request("block", json!({"id":height.to_string()}))
        .unwrap()
}

#[test]
fn transfers_the_wallet_signs_move_coins_and_pay_the_block_s_producer() {
    let dir = Directory::new();
    dir.config(false, "wallet");
    let chain_id = config::genesis(&dir.0).unwrap().chain_id();
    let mut chain = Chain::open(&dir.0, Arc::new(AtomicBool::new(false))).unwrap();
    // The wallet derives the policy's ContractId as its canonical deployment
    // makes it.
    let policy_id = contract_id(&chain_id, &policy());
    assert_eq!(wallet::policy(chain_id), policy_id);
    let key = Key::generate().unwrap();
    let from = wallet::account(&policy_id, &key.public_key());
    let coin_tx = coin(&[(from, 100_000_000_000)]);
    let coin_id = contract_id(&chain_id, &coin_tx);
    for tx in [policy(), coin_tx] {
        chain.submit(&tx.encode()).unwrap();
    }
    let block = mine(&mut chain);
    for receipt in block["receipts"].as_array().unwrap() {
        assert_eq!(receipt["status_name"], "Success", "{receipt}");
    }
    let (miner, to) = ([7; 32], [9; 32]);
    chain
        .request(
            "miner_config",
            json!({"enabled":false,"producer":hex(&payout::producer_data(&miner))}),
        )
        .unwrap();
    // Two sends in a row, the second taking the nonce after the first.
    let valid_until = ting_node::now() + 3_600;
    let sends = [(25_000_000_000, 1_000, 0), (1, 1, 1)].map(|(amount, fee, nonce)| {
        wallet::transfer(
            &key,
            chain_id,
            &policy_id,
            &Transfer {
                coin: coin_id,
                to,
                amount,
                fee,
                nonce,
                valid_until,
            },
        )
        .unwrap()
    });
    for tx in &sends {
        chain.submit(&tx.encode()).unwrap();
    }
    let block = mine(&mut chain);
    let ids: Vec<String> = sends.iter().map(|tx| hex(&tx.id(chain_id))).collect();
    assert_eq!(block["transactions"], json!(ids));
    for receipt in block["receipts"].as_array().unwrap() {
        assert_eq!(receipt["status_name"], "Success", "{receipt}");
        // About 14.2 million C and 15 S, well within the transfer's budget.
        let used = &receipt["used"];
        assert!(used[0].as_u64().unwrap() < 16_000_000, "{used}");
        assert!(used[1].as_u64().unwrap() <= 16, "{used}");
    }
    assert_eq!(
        holding(&mut chain, &coin_id, &from),
        (100_000_000_000 - 25_000_000_000 - 1 - 1_001, 2)
    );
    assert_eq!(holding(&mut chain, &coin_id, &to), (25_000_000_001, 0));
    assert_eq!(holding(&mut chain, &coin_id, &miner), (1_001, 0));
    // A send signed again with a nonce the account has used is refused.
    let stale = wallet::transfer(
        &key,
        chain_id,
        &policy_id,
        &Transfer {
            coin: coin_id,
            to,
            amount: 1,
            fee: 1,
            nonce: 1,
            valid_until,
        },
    )
    .unwrap();
    chain.submit(&stale.encode()).unwrap();
    let block = mine(&mut chain);
    let refused = &block["receipts"][0];
    assert_eq!(refused["transaction"], json!(hex(&stale.id(chain_id))));
    assert_eq!(refused["result_hex"], json!(hex(b"bad nonce")), "{refused}");
    assert_eq!(holding(&mut chain, &coin_id, &to), (25_000_000_001, 0));
}

#[test]
fn a_transfer_signed_for_another_chain_or_coin_is_not_authorized() {
    let dir = Directory::new();
    dir.config(false, "wallet");
    let chain_id = config::genesis(&dir.0).unwrap().chain_id();
    let mut chain = Chain::open(&dir.0, Arc::new(AtomicBool::new(false))).unwrap();
    let policy_id = contract_id(&chain_id, &policy());
    let key = Key::generate().unwrap();
    let from = wallet::account(&policy_id, &key.public_key());
    let coin_tx = coin(&[(from, 1_000)]);
    let coin_id = contract_id(&chain_id, &coin_tx);
    for tx in [policy(), coin_tx] {
        chain.submit(&tx.encode()).unwrap();
    }
    mine(&mut chain);
    let transfer = |coin: Hash| Transfer {
        coin,
        to: [9; 32],
        amount: 10,
        fee: 0,
        nonce: 0,
        valid_until: 0,
    };
    // Signed for another chain: the policy finds the signature wrong. Signed
    // for another coin and sent to this one: the same.
    let mut other_chain = chain_id;
    other_chain[0] ^= 1;
    let elsewhere = wallet::transfer(&key, other_chain, &policy_id, &transfer(coin_id)).unwrap();
    let mut moved = wallet::transfer(&key, chain_id, &policy_id, &transfer([3; 32])).unwrap();
    if let Payload::Call { target, .. } = &mut moved.payload {
        *target = coin_id;
    }
    for tx in [&elsewhere, &moved] {
        chain.submit(&tx.encode()).unwrap();
        let block = mine(&mut chain);
        let receipt = &block["receipts"][0];
        assert_eq!(receipt["status_name"], "Revert", "{receipt}");
        assert_eq!(
            receipt["result_hex"],
            json!(hex(b"not authorized")),
            "{receipt}"
        );
    }
    assert_eq!(holding(&mut chain, &coin_id, &from), (1_000, 0));
}

#[test]
fn without_a_wallet_each_command_says_how_to_make_one() {
    let dir = Directory::new();
    dir.config(false, "wallet");
    for args in [
        &["account"][..],
        &["balance"],
        &["send", &"a".repeat(64), "1"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ting"))
            .arg("--data-dir")
            .arg(&dir.0)
            .arg("wallet")
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("no wallet in"), "{args:?}: {error}");
        assert!(error.contains("wallet create"), "{args:?}: {error}");
    }
    assert!(!dir.0.join(wallet::WALLET_FILE).exists());
}

/// `ting` in `dir`, which must succeed.
fn cli(dir: &Directory, args: &[&str]) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ting"));
    command.arg("--data-dir").arg(&dir.0).args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
/// A node of the test chain started as `ting start` starts it, and stopped
/// when the test ends, however it ends.
struct Started(Directory);
impl Started {
    fn new() -> Self {
        let dir = Directory::new();
        let genesis = dir.0.join("test.genesis");
        std::fs::write(&genesis, support::test_genesis().encode()).unwrap();
        cli(
            &dir,
            &[
                "init",
                "--genesis",
                genesis.to_str().unwrap(),
                "--control",
                "127.0.0.1:0",
                "--p2p",
                "127.0.0.1:0",
                "--api-bind",
                "127.0.0.1:0",
            ],
        );
        cli(&dir, &["start"]);
        Self(dir)
    }
    async fn call(&self, method: &str, params: Value) -> Value {
        let control = Running::load(&self.0.0).unwrap().control;
        transport::control_call(control, &config::token(&self.0.0).unwrap(), method, params)
            .await
            .unwrap()
    }
    async fn mine(&self) {
        self.call("mine", json!({"count":1,"attempts":1_000_000}))
            .await;
    }
}
impl Drop for Started {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_ting"))
            .arg("--data-dir")
            .arg(&self.0.0)
            .arg("stop")
            .output();
    }
}

/// The commands themselves, through a running node's control channel: its
/// reads, the coin, and what `wallet-sent.json` keeps of the sends.
#[tokio::test]
async fn sends_go_through_a_running_node_which_tells_what_became_of_them() {
    let node = Started::new();
    let dir = node.0.0.as_path();
    let chain_id = config::genesis(dir).unwrap().chain_id();
    let ask = |_: &str| Ok::<_, String>(Zeroizing::new("correct horse battery".to_owned()));
    let (created, _) = wallet::execute(dir, Command::Create, "ting", &ask)
        .await
        .unwrap();
    let account = ting_node::hash_arg(created["account"].as_str().unwrap()).unwrap();
    let coin_tx = coin(&[(account, 10_000_000_000)]);
    let coin_id = hex(&contract_id(&chain_id, &coin_tx));
    for tx in [policy(), coin_tx] {
        node.call("submit", json!({"hex":hex(&tx.encode())})).await;
    }
    node.mine().await;
    let balance = || {
        wallet::execute(
            dir,
            Command::Balance {
                coin: Some(coin_id.clone()),
            },
            "ting",
            &ask,
        )
    };
    let send = |amount: &str| {
        wallet::execute(
            dir,
            Command::Send {
                account: "aa".repeat(32),
                amount: amount.into(),
                fee: None,
                coin: Some(coin_id.clone()),
            },
            "ting",
            &ask,
        )
    };
    let (held, _) = balance().await.unwrap();
    assert_eq!(held["balance"], "10000000000");
    assert_eq!(held["sends"], json!([]));
    // Two sends in a row, the second taking the nonce after the first; what
    // they take is not there to send again.
    let (first, _) = send("1.5").await.unwrap();
    let (second, _) = send("2").await.unwrap();
    assert_eq!((&first["nonce"], &second["nonce"]), (&json!(0), &json!(1)));
    let refused = send("97").await.unwrap_err();
    assert!(refused.contains("left after"), "{refused}");
    let (held, _) = balance().await.unwrap();
    let states: Vec<&Value> = held["sends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| &s["state"])
        .collect();
    assert_eq!(states, [&json!("waiting"), &json!("waiting")], "{held}");
    // A block takes both. The node names no payout account, so the fees
    // stay with the account.
    node.mine().await;
    let (held, text) = balance().await.unwrap();
    assert_eq!(held["balance"], "9650000000", "{text}");
    assert_eq!(held["nonce"], 2);
    assert_eq!(held["sends"], json!([]), "{text}");
    // A send the node no longer holds, as after a restart, is told; the next
    // send takes its nonce again, and is the one a block takes.
    let (lost, _) = send("1").await.unwrap();
    cli(&node.0, &["stop"]);
    cli(&node.0, &["start"]);
    let (held, _) = balance().await.unwrap();
    assert_eq!(held["sends"][0]["id"], lost["id"], "{held}");
    assert_eq!(held["sends"][0]["state"], "not sent", "{held}");
    let (again, _) = send("1").await.unwrap();
    assert_eq!(again["nonce"], 2);
    node.mine().await;
    let (held, text) = balance().await.unwrap();
    assert_eq!(
        (&held["balance"], &held["nonce"]),
        (&json!("9550000000"), &json!(3)),
        "{text}"
    );
    assert_eq!(held["sends"], json!([]), "{text}");
}

/// The node's words for a transaction it neither stores nor holds, which the
/// wallet takes to mean the node let a send go.
#[test]
fn the_node_says_a_transaction_it_does_not_know_is_not_found() {
    let dir = Directory::new();
    dir.config(false, "wallet");
    let mut chain = Chain::open(&dir.0, Arc::new(AtomicBool::new(false))).unwrap();
    let error = chain
        .request("transaction", json!({"id":hex(&[5; 32])}))
        .unwrap_err();
    assert_eq!(error, wallet::NOT_FOUND);
}
