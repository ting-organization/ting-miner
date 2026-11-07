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
    config, payout,
    wallet::{self, Key, Transfer},
};

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
