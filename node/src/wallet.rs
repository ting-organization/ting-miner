//! The wallet (ting-miner, see MINER.md): a key whose account the blocks can
//! pay, and `ting wallet create`, `account`, `balance` and `send`, which use
//! it. The account is a key account as Ting ID makes one: a policy account of
//! the reference `policy-secp256k1` and the key's uncompressed public key
//! (wiki: programs/conventions, accounts). Sending is a coin transfer that the
//! key signs (wiki: programs/coin, authorized actions). The key is on disk
//! only in `wallet.json`, sealed under a password, and nothing shows it.
use crate::{Result, config, payout::Policy, transport, wiki};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload as Sealed},
};
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
};
use ting_core::{
    hash::{Hash, hash, hash_parts, hex},
    meter::Resources,
    protocol::{Encode, Payload, Transaction},
};
use zeroize::Zeroizing;

/// The sealed key, in the data directory.
pub const WALLET_FILE: &str = "wallet.json";
/// The wallet's last send, from which the next one takes its nonce while the
/// last one waits for a block.
const SENT_FILE: &str = "wallet-sent.json";
/// The budget of a canonical deployment (wiki: programs#canonical-deployment).
const CANONICAL: Resources = Resources([50_000_000, 64, 16_777_216, 16_777_216]);
/// A transfer signed with the secp256k1 policy and an uncompressed key costs
/// about 14.2 million C and 15 S (wiki: programs/coin, costs). Before calling
/// the policy the coin holds back the standard reserve, 500,000 C, 64 S and
/// 65,536 D and G (wiki: programs/conventions, the budget reserve), which the
/// budget covers too. A block counts what a transaction uses, not its budget.
const TRANSFER_BUDGET: Resources = Resources([20_000_000, 128, 131_072, 131_072]);
/// How long a send can wait for a block before it expires, in seconds.
const VALID_FOR: u64 = 3_600;
/// What sealing a new key costs a guesser for each password tried: Argon2id
/// over 64 MiB, three passes, one lane. The file records it, so that a file
/// sealed otherwise opens too.
const STRONG: Strength = Strength {
    memory_kib: 65_536,
    passes: 3,
    lanes: 1,
};
/// The most a `wallet.json` may ask of Argon2id.
const MOST: Strength = Strength {
    memory_kib: 1 << 20,
    passes: 16,
    lanes: 16,
};
const SHORTEST_PASSWORD: usize = 8;
/// Bound into the seal with the public key, so that a file whose public key
/// was changed does not open.
const SEAL_TAG: &[u8] = b"ting-miner/wallet-v1";
const DAMAGED: &str = "wallet.json is damaged: its key does not match its public key";

/// The commands of `ting wallet`.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Make a new key, sealed in wallet.json under a password, and show its
    /// account.
    Create,
    /// Show the wallet's account, the one to pay the blocks to.
    Account,
    /// Show what the account holds of a coin: by default the first coin
    /// miner.json claims, Daler (DLR) on the production network.
    Balance {
        /// The coin's ContractId, 64 hex digits.
        #[arg(long)]
        coin: Option<String>,
    },
    /// Send AMOUNT of a coin, such as 12 or 0.5, to ACCOUNT, 64 hex digits.
    Send {
        account: String,
        amount: String,
        /// What the block that includes it pays its producer, from the account
        /// (default: the coin's smallest unit).
        #[arg(long)]
        fee: Option<String>,
        /// The coin's ContractId, 64 hex digits (default: the first coin
        /// miner.json claims).
        #[arg(long)]
        coin: Option<String>,
    },
}

/// The wallet's key, open only while a command signs with it.
pub struct Key(SigningKey);
impl Key {
    /// A new key from the system's random source.
    pub fn generate() -> Result<Self> {
        loop {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::fill(secret.as_mut()).map_err(|e| e.to_string())?;
            // Zero or a number past the curve's order, about one draw in
            // 2^128, is drawn again.
            if let Ok(key) = SigningKey::from_slice(secret.as_ref()) {
                return Ok(Self(key));
            }
        }
    }
    /// The public key, uncompressed SEC1: `04 ‖ x ‖ y`, 65 bytes, which the
    /// secp256k1 policy takes as its params.
    pub fn public_key(&self) -> Vec<u8> {
        public_key(self.0.verifying_key())
    }
    /// A low-S signature `r ‖ s` of a 32-byte digest, signed as it is, the
    /// form the policy checks (wiki: programs/policies).
    fn sign(&self, digest: &Hash) -> Result<[u8; 64]> {
        let signature: Signature = self.0.sign_prehash(digest).map_err(|e| e.to_string())?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.0
            .verifying_key()
            .verify_prehash(digest, &signature)
            .map_err(|_| "the key's signature does not verify")?;
        let mut out = [0; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(out)
    }
}
fn public_key(key: &VerifyingKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// The ContractId of `policy-secp256k1` on `chain`: its canonical deployment,
/// empty input and the canonical budget, the same for everyone.
pub fn policy(chain: Hash) -> Hash {
    let (_, code) = wiki::file("programs/policy-secp256k1.wasm").expect("a bundled program");
    let deploy = Transaction {
        budget: CANONICAL,
        payload: Payload::Deploy {
            code: code.to_vec(),
            input: Vec::new(),
        },
    };
    hash_parts(
        "contract",
        &[&chain, &deploy.id(chain), &0u64.to_le_bytes()],
    )
}
/// The policy account of `policy` and `params`,
/// `H("app/account-v1/policy", policy ‖ Bytes(params))`.
pub fn account(policy: &Hash, params: &[u8]) -> Hash {
    hash_parts(
        "app/account-v1/policy",
        &[policy, &(params.len() as u32).to_le_bytes(), params],
    )
}
/// `Bytes(x)`: its length, then itself.
fn put_bytes(out: &mut Vec<u8>, x: &[u8]) {
    out.extend((x.len() as u32).to_le_bytes());
    out.extend(x);
}

/// A transfer, as the wallet's key signs it.
pub struct Transfer {
    pub coin: Hash,
    pub to: Hash,
    pub amount: u128,
    /// Paid now to the producer of the block that includes it.
    pub fee: u128,
    /// The account's nonce in the coin.
    pub nonce: u64,
    /// The last block timestamp that may include it.
    pub valid_until: u64,
}
/// The action, `01 ‖ to ‖ amount ‖ timing`, with no tip, at once, in any
/// context (wiki: programs/coin, actions).
fn action(t: &Transfer) -> Vec<u8> {
    let mut a = vec![0x01];
    a.extend(t.to);
    a.extend(t.amount.to_le_bytes());
    a.extend(t.fee.to_le_bytes());
    a.extend(0u128.to_le_bytes());
    a.extend(0u64.to_le_bytes());
    a.extend(t.valid_until.to_le_bytes());
    a.push(0x00);
    a
}
/// The transaction of `t` from the key's account on `chain`, `policy` being
/// `policy-secp256k1` there: the coin's `execute`, operation `10`, by the
/// policy account, with the key's signature over the message's signing
/// digest (wiki: programs/coin, authorization).
pub fn transfer(key: &Key, chain: Hash, policy: &Hash, t: &Transfer) -> Result<Transaction> {
    let params = key.public_key();
    let from = account(policy, &params);
    let action = action(t);
    let mut message = Vec::new();
    put_bytes(&mut message, b"app/coin-v1");
    for part in [&chain, &t.coin, &from] {
        message.extend(part);
    }
    message.push(0x10);
    message.extend(t.nonce.to_le_bytes());
    message.extend(&action);
    let witness = key.sign(&hash("app/sign-v1", &message))?;
    let mut input = vec![0x10, 0x00];
    input.extend(policy);
    put_bytes(&mut input, &params);
    input.extend(t.nonce.to_le_bytes());
    put_bytes(&mut input, &witness);
    input.extend(action);
    Ok(Transaction {
        budget: TRANSFER_BUDGET,
        payload: Payload::Call {
            target: t.coin,
            input,
        },
    })
}

/// What sealing costs: Argon2id's memory in KiB, passes and lanes.
#[derive(Clone, Copy)]
struct Strength {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}
/// `wallet.json`: the public key in the open, the secret sealed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    /// 1.
    version: u32,
    /// The public key, uncompressed SEC1, in hex.
    public_key: String,
    /// How the password becomes the sealing key: Argon2id's memory in KiB,
    /// passes and lanes, and its salt in hex.
    kdf: Kdf,
    /// XChaCha20-Poly1305's nonce, 24 bytes in hex.
    nonce: String,
    /// The 32-byte secret sealed with its tag, in hex.
    sealed: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    salt: String,
}
/// The 32-byte sealing key that `password` makes under `kdf`. A file that
/// asks for more than [`MOST`], or a salt of under 16 bytes, is refused: a
/// changed file could otherwise take all the memory, or all day, to open.
fn sealing_key(password: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let salt = crate::unhex(&kdf.salt, 64).map_err(|e| format!("invalid {WALLET_FILE}: {e}"))?;
    if kdf.memory_kib > MOST.memory_kib
        || kdf.passes > MOST.passes
        || kdf.lanes > MOST.lanes
        || salt.len() < 16
    {
        return Err(format!(
            "invalid {WALLET_FILE}: its key derivation asks for more than this ting gives"
        ));
    }
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|e| format!("invalid {WALLET_FILE}: {e}"))?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|e| format!("invalid {WALLET_FILE}: {e}"))?;
    Ok(key)
}
fn cipher(password: &str, kdf: &Kdf) -> Result<XChaCha20Poly1305> {
    let key = sealing_key(password, kdf)?;
    Ok(XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(
        key.as_ref(),
    )))
}
fn associated(public_key: &[u8]) -> Vec<u8> {
    [SEAL_TAG, public_key].concat()
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
impl WalletFile {
    /// `key` sealed under `password`, at `strength`.
    fn seal(key: &Key, password: &str, strength: Strength) -> Result<Self> {
        let kdf = Kdf {
            memory_kib: strength.memory_kib,
            passes: strength.passes,
            lanes: strength.lanes,
            salt: hex(&random::<16>()?),
        };
        let nonce = random::<24>()?;
        let public_key = key.public_key();
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&key.0.to_bytes());
        let sealed = cipher(password, &kdf)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Sealed {
                    msg: secret.as_ref(),
                    aad: &associated(&public_key),
                },
            )
            .map_err(|_| "sealing the key failed")?;
        Ok(Self {
            version: 1,
            public_key: hex(&public_key),
            kdf,
            nonce: hex(&nonce),
            sealed: hex(&sealed),
        })
    }
    fn public_key(&self) -> Result<Vec<u8>> {
        let key = crate::unhex(&self.public_key, 65)
            .ok()
            .filter(|k| k.len() == 65)
            .and_then(|k| VerifyingKey::from_sec1_bytes(&k).ok())
            .ok_or_else(|| {
                format!("invalid {WALLET_FILE}: no uncompressed secp256k1 public key")
            })?;
        Ok(public_key(&key))
    }
    /// The key, opened with `password`.
    fn open(&self, password: &str) -> Result<Key> {
        let public_key = self.public_key()?;
        let nonce = crate::unhex(&self.nonce, 24)
            .ok()
            .filter(|n| n.len() == 24)
            .ok_or_else(|| format!("invalid {WALLET_FILE}: its nonce is not 24 bytes"))?;
        let sealed = crate::unhex(&self.sealed, 48).map_err(|_| DAMAGED)?;
        let secret = Zeroizing::new(
            cipher(password, &self.kdf)?
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Sealed {
                        msg: &sealed,
                        aad: &associated(&public_key),
                    },
                )
                .map_err(|_| "wrong password, or wallet.json was changed")?,
        );
        let key = Key(SigningKey::from_slice(&secret).map_err(|_| DAMAGED)?);
        if key.public_key() != public_key {
            return Err(DAMAGED.into());
        }
        Ok(key)
    }
    fn load(dir: &Path, ting: &str) -> Result<Self> {
        let bytes = fs::read(dir.join(WALLET_FILE)).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                format!(
                    "no wallet in {}: make one with {ting} wallet create",
                    dir.display()
                )
            } else {
                format!("cannot read {WALLET_FILE}: {e}")
            }
        })?;
        let file: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid {WALLET_FILE}: {e}"))?;
        if file.version != 1 {
            return Err(format!(
                "{WALLET_FILE} is of version {}, which this ting does not know",
                file.version
            ));
        }
        file.public_key()?;
        Ok(file)
    }
}
/// Writes `bytes` to a new file at `path` that only its owner can read:
/// mode 0600 on Unix, an access list for the current user on Windows. An
/// existing file is never replaced, and a file that could not be made
/// private is taken away again. On Unix the directory reaches the disk too,
/// so that the file is there after a power cut once its account is shown.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    #[cfg(windows)]
    if let Err(e) = config::owner_only(path) {
        let _ = fs::remove_file(path);
        return Err(e);
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("cannot sync {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// A send of the wallet, as `wallet-sent.json` keeps it for a day after it
/// expires: its transaction, account, coin and nonce, what it takes from the
/// account, the amount and the fee, and the last block timestamp that may
/// include it.
#[derive(Serialize, Deserialize, Clone)]
struct Sent {
    id: String,
    account: String,
    coin: String,
    nonce: u64,
    debit: u128,
    valid_until: u64,
}
/// What became of a send, as the node knows it.
#[derive(Debug, PartialEq)]
enum Fate {
    /// The node holds it, or cannot say, and it has not expired: a later
    /// send takes a nonce after it, and what it takes is spoken for.
    Waiting,
    /// A block of the best chain took it, and it succeeded.
    Done,
    /// A block took it, and it failed for this reason.
    Failed(String),
    /// No block took it before it expired.
    Expired,
    /// The node no longer holds it and no block took it. Another node may
    /// still have it, until it expires.
    Dropped,
}
async fn fate(dir: &Path, sent: &Sent) -> Fate {
    let found = rpc(dir, "transaction", json!({"id":sent.id})).await;
    let expired = crate::now() > sent.valid_until;
    match found {
        Ok(found) => {
            if found["pending"] == true && !expired {
                return Fate::Waiting;
            }
            if let Some(receipt) = found["occurrences"]
                .as_array()
                .and_then(|o| o.first())
                .map(|o| &o["receipt"])
            {
                return if receipt["status_name"] == "Success" {
                    Fate::Done
                } else {
                    let reason = receipt["result_hex"]
                        .as_str()
                        .and_then(|r| crate::unhex(r, 256).ok())
                        .map(|r| visible(&String::from_utf8_lossy(&r)))
                        .filter(|r| !r.is_empty())
                        .unwrap_or_else(|| format!("{}", receipt["status_name"]));
                    Fate::Failed(reason)
                };
            }
            if expired {
                Fate::Expired
            } else {
                Fate::Dropped
            }
        }
        Err(_) if expired => Fate::Expired,
        Err(e) if e == "transaction not found" => Fate::Dropped,
        // A node that cannot answer may still hold it: a nonce is never
        // signed twice.
        Err(_) => Fate::Waiting,
    }
}
/// The sends `wallet-sent.json` keeps; none when it is absent or unreadable.
fn sends(dir: &Path) -> Vec<Sent> {
    fs::read(dir.join(SENT_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}
/// The sends of `account` in `coin`, oldest first, each with its fate.
async fn fates(dir: &Path, account: &Hash, coin: &Hash) -> Vec<(Sent, Fate)> {
    let mut out = Vec::new();
    for sent in sends(dir) {
        if sent.account == hex(account) && sent.coin == hex(coin) {
            let fate = fate(dir, &sent).await;
            out.push((sent, fate));
        }
    }
    out
}
/// The nonce of the next send and what the waiting sends take from the
/// account: after the last of them still ahead of the account's nonce.
fn next(nonce: u64, fates: &[(Sent, Fate)]) -> (u64, u128) {
    let waiting: Vec<&Sent> = fates
        .iter()
        .filter(|(sent, fate)| *fate == Fate::Waiting && sent.nonce >= nonce)
        .map(|(sent, _)| sent)
        .collect();
    let next = waiting.iter().map(|s| s.nonce + 1).fold(nonce, u64::max);
    let debit = waiting
        .iter()
        .fold(0u128, |sum, s| sum.saturating_add(s.debit));
    (next, debit)
}
/// Adds `sent` to `wallet-sent.json`, dropping sends that expired a day ago.
fn record_send(dir: &Path, sent: Sent) -> Result<()> {
    let mut kept: Vec<Sent> = sends(dir)
        .into_iter()
        .filter(|s| s.valid_until + 86_400 > crate::now())
        .collect();
    kept.push(sent);
    config::atomic_write(
        &dir.join(SENT_FILE),
        &serde_json::to_vec_pretty(&kept).map_err(|e| e.to_string())?,
    )
}

/// A password typed at the terminal, which it does not show.
fn password(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read a password from the terminal: {e}"))
}
async fn rpc(dir: &Path, method: &str, params: Value) -> Result<Value> {
    let info = config::Running::load(dir)?;
    transport::control_call(info.control, &config::token(dir)?, method, params).await
}
/// The record of `key` in the storage of `contract`, if it has one.
async fn record(dir: &Path, contract: &Hash, key: &Hash) -> Result<Option<Vec<u8>>> {
    let answer = rpc(dir, "storage", json!({"id":hex(contract),"key":hex(key)})).await?;
    answer["value_hex"]
        .as_str()
        .map(|v| crate::unhex(v, crate::FRAME_MAX))
        .transpose()
}

/// A coin's symbol and decimals, from its configuration record.
struct Coin {
    id: Hash,
    symbol: String,
    decimals: u8,
}
impl Coin {
    /// `coin` on the node's chain, by default the first coin `miner.json`
    /// claims; it must run the reference coin program.
    async fn find(dir: &Path, coin: Option<String>) -> Result<Self> {
        let id = match coin {
            Some(coin) => crate::hash_arg(&coin.to_ascii_lowercase())
                .map_err(|_| format!("{coin:?} is not a ContractId: 64 hex digits"))?,
            None => {
                let first = Policy::load(dir)?
                    .claims
                    .into_iter()
                    .next()
                    .ok_or("miner.json claims no coin: name one with --coin <ContractId>")?;
                crate::hash_arg(&first)
                    .map_err(|_| format!("miner.json names {first:?}, which is no ContractId"))?
            }
        };
        let (_, code) = wiki::file("programs/coin.wasm").expect("a bundled program");
        let contract = rpc(dir, "contract", json!({"id":hex(&id)}))
            .await
            .map_err(|e| format!("{}: {e}", hex(&id)))?;
        if contract["code_hash"] != json!(hex(&hash("code", code))) {
            return Err(format!(
                "{} is not a coin: it runs another program than the reference coin",
                hex(&id)
            ));
        }
        let config = record(dir, &id, &[0; 32])
            .await?
            .ok_or("the coin has no configuration record")?;
        let corrupt = || "the coin's configuration record does not decode".to_string();
        let mut at = 1;
        let mut text = || -> Option<String> {
            let length = u32::from_le_bytes(config.get(at..at + 4)?.try_into().ok()?) as usize;
            let bytes = config.get(at + 4..at + 4 + length)?;
            at += 4 + length;
            Some(String::from_utf8_lossy(bytes).into_owned())
        };
        text().ok_or_else(corrupt)?;
        let symbol = visible(&text().ok_or_else(corrupt)?);
        let decimals = *config.get(at).ok_or_else(corrupt)?;
        if config[0] != 1 || decimals > 38 {
            return Err(corrupt());
        }
        Ok(Self {
            id,
            symbol,
            decimals,
        })
    }
    fn show(&self, units: u128) -> String {
        format!("{} {}", format_amount(units, self.decimals), self.symbol)
    }
}
/// A coin's symbol as a terminal shows it: controls, direction overrides and
/// invisible characters each become `�`, so that one coin cannot pass for
/// another.
fn visible(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            c if c.is_control() => '\u{fffd}',
            '\u{ad}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' => '\u{fffd}',
            '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' => '\u{fffd}',
            c => c,
        })
        .collect()
}
/// An account's record in a coin: `balance ‖ locked ‖ nonce`, all zero when
/// it has none (wiki: programs/coin, records).
struct Holding {
    balance: u128,
    locked: u128,
    nonce: u64,
}
async fn holding(dir: &Path, coin: &Hash, account: &Hash) -> Result<Holding> {
    let Some(record) = record(dir, coin, account).await? else {
        return Ok(Holding {
            balance: 0,
            locked: 0,
            nonce: 0,
        });
    };
    if record.len() != 40 {
        return Err("the account's record in the coin does not decode".into());
    }
    Ok(Holding {
        balance: u128::from_le_bytes(record[..16].try_into().unwrap()),
        locked: u128::from_le_bytes(record[16..32].try_into().unwrap()),
        nonce: u64::from_le_bytes(record[32..].try_into().unwrap()),
    })
}

/// An amount as a person writes it, `12` or `0.5`, in base units of a coin
/// with `decimals` decimals.
pub fn parse_amount(text: &str, decimals: u8) -> Result<u128> {
    let bad = || {
        format!(
            "{text:?} is not an amount: write it as 12 or 0.5, with at most {decimals} decimals"
        )
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || !digits(whole)
        || !digits(fraction)
        || (text.contains('.') && fraction.is_empty())
        || fraction.len() > decimals as usize
    {
        return Err(bad());
    }
    let mut padded = fraction.to_owned();
    padded.extend(std::iter::repeat_n('0', decimals as usize - fraction.len()));
    format!("{whole}{padded}")
        .trim_start_matches('0')
        .parse::<u128>()
        .or_else(|e| match e.kind() {
            std::num::IntErrorKind::Empty => Ok(0),
            _ => Err(format!("{text} is more than any coin holds")),
        })
}
/// `units` of a coin with `decimals` decimals as a person reads it: the
/// whole part in groups of three, the fraction without trailing zeros.
pub fn format_amount(units: u128, decimals: u8) -> String {
    let digits = format!("{units:0>width$}", width = decimals as usize + 1);
    let (whole, fraction) = digits.split_at(digits.len() - decimals as usize);
    let mut text = String::new();
    for (k, digit) in whole.chars().enumerate() {
        if k > 0 && (whole.len() - k).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    let fraction = fraction.trim_end_matches('0');
    if !fraction.is_empty() {
        text.push('.');
        text.push_str(fraction);
    }
    text
}
/// An account as a wallet shows it: 64 hex digits, in either case, and not
/// one of a coin's reserved keys.
fn account_arg(text: &str) -> Result<Hash> {
    let account = crate::hash_arg(&text.to_ascii_lowercase())
        .map_err(|_| format!("{text:?} is not an account: an account is 64 hex digits"))?;
    let mut state = [0; 32];
    state[31] = 1;
    if account == [0; 32] || account == state {
        return Err(format!("{text} is a coin's own record, not an account"));
    }
    Ok(account)
}

/// Runs `command` on the node in `dir`; returns its result and its text.
/// `ting` is the command as the person typed it, for the hints.
pub async fn execute(dir: &Path, command: Command, ting: &str) -> Result<(Value, String)> {
    let chain = config::genesis(dir)?.chain_id();
    let policy = policy(chain);
    match command {
        Command::Create => {
            let path = dir.join(WALLET_FILE);
            if path.exists() {
                return Err(format!(
                    "{} holds a wallet already; this ting never replaces one",
                    path.display()
                ));
            }
            eprintln!(
                "The password seals the key in {WALLET_FILE}. Nothing can open it without the password."
            );
            let first = password("Password: ")?;
            if first.chars().count() < SHORTEST_PASSWORD {
                return Err(format!(
                    "a password of at least {SHORTEST_PASSWORD} characters, please"
                ));
            }
            if *password("The same password again: ")? != *first {
                return Err("the two passwords differ; nothing was written".into());
            }
            let key = Key::generate()?;
            let file = WalletFile::seal(&key, &first, STRONG)?;
            let bytes = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
            write_private(&path, &bytes)?;
            // What was written must open again, before anything is paid to it;
            // a file that does not is taken away again.
            let reopened = WalletFile::load(dir, ting).and_then(|file| file.open(&first));
            if !reopened.is_ok_and(|opened| opened.public_key() == key.public_key()) {
                let _ = fs::remove_file(&path);
                return Err("the wallet written does not open again; nothing was kept".into());
            }
            let account = hex(&account(&policy, &key.public_key()));
            let text = format!(
                "Created the wallet in {}. Its account:\n  {account}\n\
                 Pay the blocks this node builds to it:\n  {ting} miner payout {account}\n\
                 Keep a copy of {WALLET_FILE} somewhere safe, and the password apart from it:\n\
                 without both, nobody can spend what the account holds.\n",
                path.display()
            );
            Ok((json!({"file":path,"account":account}), text))
        }
        Command::Account => {
            let file = WalletFile::load(dir, ting)?;
            let account = hex(&account(&policy, &file.public_key()?));
            let text = format!("{account}\n");
            Ok((json!({"account":account}), text))
        }
        Command::Balance { coin } => {
            let file = WalletFile::load(dir, ting)?;
            let account = account(&policy, &file.public_key()?);
            let status = rpc(dir, "status", json!({})).await?;
            let coin = Coin::find(dir, coin).await?;
            let fates = fates(dir, &account, &coin.id).await;
            let h = holding(dir, &coin.id, &account).await?;
            let mut lines = vec![
                ("Account", hex(&account)),
                ("Balance", coin.show(h.balance)),
            ];
            if h.locked > 0 {
                lines.push(("Scheduled", coin.show(h.locked)));
            }
            for (sent, fate) in &fates {
                if *fate == Fate::Waiting {
                    lines.push(("Waiting", format!("send {}, not in a block yet", sent.id)));
                }
            }
            // The last send, if no block took it as it was meant to.
            let last = fates.last().and_then(|(sent, fate)| {
                let what = match fate {
                    Fate::Failed(reason) => format!("failed: {reason}"),
                    Fate::Expired => "expired with no block taking it".into(),
                    Fate::Dropped => "is no longer in this node's pool, nor in a block".into(),
                    Fate::Waiting | Fate::Done => return None,
                };
                Some(format!("{} {what}", sent.id))
            });
            if let Some(last) = &last {
                lines.push(("Last send", last.clone()));
            }
            let (height, best) = heights(&status);
            lines.push(("At block", crate::log::count(height)));
            let width = lines
                .iter()
                .map(|(label, _)| label.len())
                .max()
                .unwrap_or(0);
            let mut text: String = lines
                .iter()
                .map(|(label, value)| format!("{label:width$}  {value}\n"))
                .collect();
            if best > height + 2 {
                text += &format!(
                    "The node is still catching up with the network, at block {} of {}: the balance is as of then.\n",
                    crate::log::count(height),
                    crate::log::count(best)
                );
            }
            Ok((
                json!({"account":hex(&account),"coin":hex(&coin.id),"symbol":coin.symbol,
                    "decimals":coin.decimals,"balance":h.balance.to_string(),"locked":h.locked.to_string(),
                    "nonce":h.nonce,"height":height,
                    "waiting":fates.iter().filter(|(_, f)| *f == Fate::Waiting).map(|(s, _)| &s.id).collect::<Vec<_>>(),
                    "last_send":last}),
                text,
            ))
        }
        Command::Send {
            account: to,
            amount,
            fee,
            coin,
        } => {
            let file = WalletFile::load(dir, ting)?;
            let from = account(&policy, &file.public_key()?);
            let to = account_arg(&to)?;
            let named = coin
                .as_ref()
                .map(|coin| format!(" --coin {coin}"))
                .unwrap_or_default();
            let coin = Coin::find(dir, coin).await?;
            let amount = parse_amount(&amount, coin.decimals)?;
            if amount == 0 {
                return Err("an amount of more than 0, please".into());
            }
            let fee = match fee {
                Some(fee) => parse_amount(&fee, coin.decimals)?,
                None => 1,
            };
            let (height, best) = heights(&rpc(dir, "status", json!({})).await?);
            if best > height + 2 {
                return Err(format!(
                    "the node is still catching up with the network, at block {} of {}: send once it has, so that the balance and nonce are current",
                    crate::log::count(height),
                    crate::log::count(best)
                ));
            }
            rpc(dir, "contract", json!({"id":hex(&policy)}))
                .await
                .map_err(|_| "the secp256k1 signature policy is not deployed on this chain, so no key account can sign here")?;
            // What still waits is asked before the account's record, so that a
            // send a block takes in between counts in the record.
            let fates = fates(dir, &from, &coin.id).await;
            let h = holding(dir, &coin.id, &from).await?;
            // Sends still waiting go first: this one takes the nonce after
            // theirs, and what they take is not there to send.
            let (nonce, waiting) = next(h.nonce, &fates);
            let available = h.balance.saturating_sub(h.locked).saturating_sub(waiting);
            let needed = amount
                .checked_add(fee)
                .ok_or("the amount and the fee are more than any coin holds")?;
            if needed > available {
                let has = if waiting > 0 {
                    format!(
                        "{} left after {} in sends still waiting",
                        coin.show(available),
                        coin.show(waiting)
                    )
                } else {
                    format!("{} to send", coin.show(available))
                };
                return Err(format!(
                    "the account has {has}, and this takes {}: {} and a fee of {}",
                    coin.show(needed),
                    coin.show(amount),
                    coin.show(fee)
                ));
            }
            eprintln!(
                "Sending {} to {}, with a fee of {}.",
                coin.show(amount),
                hex(&to),
                coin.show(fee)
            );
            let key = file.open(&password("Password: ")?)?;
            let t = Transfer {
                coin: coin.id,
                to,
                amount,
                fee,
                nonce,
                valid_until: crate::now() + VALID_FOR,
            };
            let tx = transfer(&key, chain, &policy, &t)?;
            drop(key);
            let result = rpc(dir, "submit", json!({"hex":hex(&tx.encode())})).await?;
            let id = hex(&tx.id(chain));
            let sent = Sent {
                id: id.clone(),
                account: hex(&from),
                coin: hex(&coin.id),
                nonce,
                debit: needed,
                valid_until: t.valid_until,
            };
            let mut text = format!(
                "Sent {} to {}, with a fee of {}.\n\
                 Transaction {id}: it waits in this node's pool for a block, for up to an hour.\n\
                 See the balance with: {ting} wallet balance{named}\n",
                coin.show(amount),
                hex(&to),
                coin.show(fee)
            );
            // The send went out: a record that cannot be kept is told, not an
            // error. A send right after it would take the same nonce.
            if let Err(e) = record_send(dir, sent) {
                text += &format!(
                    "Could not note it in {SENT_FILE} ({e}): wait for a block to take it before the next send.\n"
                );
            }
            Ok((
                json!({"id":id,"known":result["known"],"from":hex(&from),"to":hex(&to),"coin":hex(&coin.id),
                    "amount":amount.to_string(),"fee":fee.to_string(),"nonce":nonce,"valid_until":t.valid_until}),
                text,
            ))
        }
    }
}
/// The node's height and the height of the best chain of headers it knows.
fn heights(status: &Value) -> (u64, u64) {
    let height = status["height"].as_u64().unwrap_or(0);
    (height, status["best_height"].as_u64().unwrap_or(height))
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap to seal, so that the tests run quickly in a debug build.
    const LIGHT: Strength = Strength {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn a_sealed_key_opens_with_its_password_only() {
        let key = Key::generate().unwrap();
        let file = WalletFile::seal(&key, "correct horse", LIGHT).unwrap();
        let text = serde_json::to_string(&file).unwrap();
        // The file holds the public key and nothing of the secret in the open.
        let mut secret = [0; 32];
        secret.copy_from_slice(&key.0.to_bytes());
        assert!(!text.contains(&hex(&secret)));
        assert!(text.contains(&hex(&key.public_key())));
        let file: WalletFile = serde_json::from_str(&text).unwrap();
        assert_eq!(
            file.open("correct horse").unwrap().public_key(),
            key.public_key()
        );
        assert!(file.open("correct horsf").is_err());
    }

    #[test]
    fn a_file_with_another_public_key_does_not_open() {
        let (key, other) = (Key::generate().unwrap(), Key::generate().unwrap());
        let mut file = WalletFile::seal(&key, "correct horse", LIGHT).unwrap();
        file.public_key = hex(&other.public_key());
        assert!(file.open("correct horse").is_err());
    }

    #[test]
    fn a_file_that_asks_too_much_of_the_key_derivation_is_refused() {
        let key = Key::generate().unwrap();
        let mut file = WalletFile::seal(&key, "correct horse", LIGHT).unwrap();
        file.kdf.memory_kib = MOST.memory_kib + 1;
        let error = file.open("correct horse").err().unwrap();
        assert!(error.contains("asks for more"), "{error}");
        file.kdf.memory_kib = LIGHT.memory_kib;
        file.kdf.salt = "00".repeat(8);
        assert!(file.open("correct horse").is_err());
    }

    fn sent(nonce: u64, debit: u128) -> Sent {
        Sent {
            id: format!("{nonce:064x}"),
            account: "a".repeat(64),
            coin: "c".repeat(64),
            nonce,
            debit,
            valid_until: 1,
        }
    }

    #[test]
    fn a_send_takes_the_nonce_after_those_still_waiting_and_counts_what_they_take() {
        assert_eq!(next(5, &[]), (5, 0));
        // Two waiting in a row: the next goes after both, and both debits
        // are spoken for.
        let waiting = [(sent(5, 100), Fate::Waiting), (sent(6, 20), Fate::Waiting)];
        assert_eq!(next(5, &waiting), (7, 120));
        // One a block took is in the account's record already.
        assert_eq!(next(6, &waiting), (7, 20));
        // Sends that will not go in hold up nothing.
        let gone = [
            (sent(5, 100), Fate::Expired),
            (sent(5, 100), Fate::Dropped),
            (sent(5, 100), Fate::Failed("insufficient funds".into())),
            (sent(4, 100), Fate::Done),
        ];
        assert_eq!(next(5, &gone), (5, 0));
        // A record of more than a u64 survives the file.
        let big = sent(1, u128::MAX - 1);
        let read: Vec<Sent> = serde_json::from_slice(&serde_json::to_vec(&[big]).unwrap()).unwrap();
        assert_eq!(read[0].debit, u128::MAX - 1);
    }

    #[test]
    fn signatures_are_low_s_and_verify_over_the_digest_itself() {
        let key = Key::generate().unwrap();
        let order_half = num_bigint::BigUint::parse_bytes(
            b"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            16,
        )
        .unwrap();
        for n in 0u8..32 {
            let digest = hash("test", &[n]);
            let signature = key.sign(&digest).unwrap();
            assert!(num_bigint::BigUint::from_bytes_be(&signature[32..]) <= order_half);
            let parsed = Signature::from_slice(&signature).unwrap();
            assert!(
                key.0
                    .verifying_key()
                    .verify_prehash(&digest, &parsed)
                    .is_ok()
            );
        }
    }

    #[test]
    fn amounts_read_and_show_as_a_person_writes_them() {
        assert_eq!(parse_amount("12", 8), Ok(1_200_000_000));
        assert_eq!(parse_amount("0.5", 8), Ok(50_000_000));
        assert_eq!(parse_amount("0.00000001", 8), Ok(1));
        assert_eq!(parse_amount("007", 0), Ok(7));
        assert_eq!(parse_amount("0", 8), Ok(0));
        for bad in [
            "",
            ".5",
            "5.",
            "1.000000001",
            "-1",
            "1e3",
            "1,000",
            " 1",
            "0x10",
        ] {
            assert!(parse_amount(bad, 8).is_err(), "{bad:?}");
        }
        assert!(parse_amount("340282366920938463463.374607431768211456", 18).is_err());
        assert_eq!(format_amount(19_520_816_479_998, 8), "195,208.16479998");
        assert_eq!(format_amount(10_000_000_000, 8), "100");
        assert_eq!(format_amount(1, 8), "0.00000001");
        assert_eq!(format_amount(0, 8), "0");
        assert_eq!(format_amount(1_234_567, 0), "1,234,567");
        assert_eq!(
            format_amount(u128::MAX, 38),
            "3.40282366920938463463374607431768211455"
        );
    }

    #[test]
    fn accounts_are_64_hex_digits_and_no_reserved_key() {
        let account = "31988B503C5177470AAECED6A04A68CAA536C9BB6B4BB22F4240DC1FAD41160B";
        assert_eq!(
            hex(&account_arg(account).unwrap()),
            account.to_ascii_lowercase()
        );
        assert!(account_arg(&account[1..]).is_err());
        assert!(account_arg(&format!("{account}0")).is_err());
        assert!(account_arg(&account.replace('B', "G")).is_err());
        assert!(account_arg(&"0".repeat(64)).is_err());
        assert!(account_arg(&format!("{}1", "0".repeat(63))).is_err());
    }

    #[test]
    fn symbols_show_no_hidden_characters() {
        assert_eq!(visible("DLR"), "DLR");
        assert_eq!(visible("D\u{202e}RL"), "D\u{fffd}RL");
        assert_eq!(visible("D\u{200b}LR\n"), "D\u{fffd}LR\u{fffd}");
    }
}
