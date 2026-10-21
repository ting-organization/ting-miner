//! The miner's searches (`search.rs`) find exactly what the plain `valid_pow`
//! loop finds, on the CPU, on every GPU the machine has and on several at once,
//! and `auto` mines with the fastest. GPU tests say so and pass on a machine
//! without a GPU.
use num_bigint::BigUint;
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use ting_core::{consensus, hash::hash, meter::Resources, protocol::Header};
use ting_node::{
    mining::Search,
    payout::Policy,
    search::{self, Auto, Choice, Cpu, Gpu, Split},
};

/// A header whose every field depends on `seed`, so the bytes before the
/// nonce differ from header to header.
fn header(seed: u8, target: BigUint) -> Header {
    let bytes = |field: u8| hash("search-test", &[seed, field]);
    Header {
        chain_id: bytes(0),
        height: u64::from(seed) * 1_000 + 7,
        parent: bytes(1),
        timestamp: 1_800_000_000 + u64::from(seed),
        target,
        transactions_root: bytes(2),
        receipts_root: bytes(3),
        state_root: bytes(4),
        used: Resources([1, u64::from(seed), u64::MAX - u64::from(seed), 4]),
        votes: [0, 1, 2, seed % 3],
        producer_hash: bytes(5),
        nonce: u128::from(seed) << 100,
    }
}
fn pow2(bits: u32) -> BigUint {
    BigUint::from(1u8) << bits
}
/// The plain method: the first nonce in `count` from `start` (wrapping) that
/// `valid_pow` accepts.
fn reference(header: &Header, start: u128, count: u64) -> Option<u128> {
    let mut candidate = header.clone();
    (0..count).find_map(|offset| {
        candidate.nonce = start.wrapping_add(u128::from(offset));
        consensus::valid_pow(&candidate).then_some(candidate.nonce)
    })
}
/// Starts at every carry the nonce's 16 bytes have: into its second, third
/// and fourth u32 and around 2^128.
const STARTS: [u128; 7] = [
    0,
    (1 << 16) - 7,
    (1 << 32) - 30,
    (1 << 64) - 30,
    (1 << 96) - 30,
    u128::MAX - 40,
    u128::MAX,
];

/// `scan` of a search, run with a fresh stop and counter: its nonce and the
/// attempts it counted.
fn run(scan: impl Fn(&AtomicBool, &AtomicU64) -> Option<u128>) -> (Option<u128>, u64) {
    let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
    let found = scan(&stop, &tried);
    (found, tried.load(Ordering::Relaxed))
}

#[test]
fn the_cpu_finds_the_nonce_the_plain_loop_accepts_first() {
    for threads in [1, 3, 8] {
        let cpu = Cpu::new(threads);
        for seed in 0..3u8 {
            // One nonce in 32 meets 2^251, so 300 attempts find one or more.
            let h = header(seed, pow2(251));
            for start in STARTS {
                let (found, tried) = run(|stop, tried| cpu.scan(&h, start, 300, stop, tried));
                let want = reference(&h, start, 300);
                assert!(want.is_some());
                assert_eq!(found, want, "{threads} threads, seed {seed}, start {start}");
                if threads == 1 {
                    let offset = want.unwrap().wrapping_sub(start) as u64;
                    assert_eq!(tried, offset + 1);
                }
            }
        }
    }
}

#[test]
fn the_cpu_counts_every_attempt_when_it_finds_nothing() {
    let cpu = Cpu::new(4);
    // 2^200 is met once in 2^56 nonces; no target at all, never.
    let h = header(1, pow2(200));
    assert_eq!(run(|s, t| cpu.scan(&h, 5, 1_001, s, t)), (None, 1_001));
    let none = header(1, BigUint::from(0u8));
    assert_eq!(run(|s, t| cpu.scan(&none, 5, 1_001, s, t)), (None, 1_001));
    // Raised before it starts, a search tries nothing.
    let (stop, tried) = (AtomicBool::new(true), AtomicU64::new(0));
    assert_eq!(cpu.scan(&h, 0, 1_000_000, &stop, &tried), None);
    assert_eq!(tried.load(Ordering::Relaxed), 0);
}

#[test]
fn a_call_covers_attempts_on_each_cpu_thread() {
    let h = header(2, BigUint::from(1u8));
    let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
    assert_eq!(Cpu::new(3).search(&h, 0, 1_000, &stop, &tried), None);
    assert_eq!(tried.load(Ordering::Relaxed), 3_000);
}

#[test]
fn the_gpu_finds_the_nonce_the_plain_loop_accepts_first() {
    let Some(gpu) = Gpu::open() else {
        eprintln!("no GPU on this machine: the GPU search is not tested here");
        return;
    };
    eprintln!("GPU: {}", gpu.describe());
    for seed in 0..3u8 {
        let h = header(seed, pow2(251));
        for start in STARTS {
            assert_eq!(
                run(|s, t| gpu.scan(&h, start, 300, s, t)).0,
                reference(&h, start, 300),
                "seed {seed}, start {start}"
            );
        }
    }
    // Rarer finds, spread over many invocations and several batches.
    let cpu = Cpu::new(8);
    for (seed, bits, count) in [(3u8, 244, 20_000), (4, 236, 1 << 22), (5, 226, 1 << 23)] {
        let h = header(seed, pow2(bits));
        for start in [0, (1 << 32) - 1_000_000, u128::MAX - 3_000_000] {
            let want = run(|s, t| cpu.scan(&h, start, count, s, t)).0;
            let (found, tried) = run(|s, t| gpu.scan(&h, start, count, s, t));
            assert_eq!(found, want, "seed {seed}, 2^{bits}, start {start}");
            match found {
                Some(nonce) => assert_eq!(tried, nonce.wrapping_sub(start) as u64 + 1),
                None => assert_eq!(tried, count),
            }
        }
    }
}

#[test]
fn the_gpu_stops_and_counts() {
    let Some(gpu) = Gpu::open() else {
        eprintln!("no GPU on this machine: the GPU search is not tested here");
        return;
    };
    let h = header(6, BigUint::from(1u8));
    let (stop, tried) = (AtomicBool::new(true), AtomicU64::new(0));
    assert_eq!(gpu.scan(&h, 0, 1 << 30, &stop, &tried), None);
    assert_eq!(tried.load(Ordering::Relaxed), 0);
    // A call covers 64 times its attempts.
    let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
    assert_eq!(gpu.search(&h, 0, 1_000, &stop, &tried), None);
    assert_eq!(tried.load(Ordering::Relaxed), 64_000);
}

/// `split` finds what the plain loop finds first, on short ranges, and what
/// one CPU search finds on long ones, whose finds fall in any of its parts.
fn finds_the_first_nonce(split: &Split) {
    let cpu = Cpu::new(8);
    for seed in 0..2u8 {
        let h = header(seed, pow2(251));
        for start in STARTS {
            let want = reference(&h, start, 300);
            assert_eq!(run(|s, t| split.scan(&h, start, 300, s, t)).0, want);
        }
    }
    for (seed, bits, count) in [(7u8, 240, 1 << 20), (8, 236, 1 << 22), (9, 226, 1 << 22)] {
        let h = header(seed, pow2(bits));
        for start in [0, (1 << 64) - 100_000, u128::MAX - 50] {
            let want = run(|s, t| cpu.scan(&h, start, count, s, t)).0;
            let (found, tried) = run(|s, t| split.scan(&h, start, count, s, t));
            assert_eq!(found, want, "seed {seed}, 2^{bits}, start {start}");
            if found.is_none() {
                assert_eq!(tried, count);
            }
        }
    }
}

/// Each part's share of a split's range.
fn shares(split: &Split) -> Vec<f64> {
    let status = split.describe();
    let parts = status["parts"].as_array().unwrap();
    parts.iter().map(|p| p["share"].as_f64().unwrap()).collect()
}

#[test]
fn a_split_finds_the_first_nonce_in_any_of_its_parts() {
    // Three CPU searches stand for three GPUs, everywhere.
    let cpus = [1, 2, 3].map(|threads| Arc::new(Cpu::new(threads)));
    let split = Split::new(Vec::new(), cpus.to_vec());
    finds_the_first_nonce(&split);
}

#[test]
fn a_split_shares_its_range_by_how_fast_each_part_is() {
    let split = Split::new(
        Vec::new(),
        vec![Arc::new(Cpu::new(1)), Arc::new(Cpu::new(4))],
    );
    assert_eq!(shares(&split), [0.5, 0.5]);
    let h = header(11, BigUint::from(1u8));
    for _ in 0..6 {
        run(|s, t| split.scan(&h, 0, 1 << 22, s, t));
    }
    // Four threads search more of the range than one.
    let [one, four] = shares(&split)[..] else {
        panic!("two parts")
    };
    assert!(
        four > 0.6 && (one + four - 1.0).abs() < 0.002,
        "{one} and {four}"
    );
}

#[test]
fn the_gpu_and_the_cpu_together_find_the_first_nonce() {
    let Some(gpu) = Gpu::open() else {
        eprintln!("no GPU on this machine: the GPU search is not tested here");
        return;
    };
    finds_the_first_nonce(&Split::new(vec![gpu.clone()], vec![Arc::new(Cpu::new(4))]));
    // One GPU twice stands for a machine with two.
    finds_the_first_nonce(&Split::new(
        vec![gpu.clone(), gpu],
        vec![Arc::new(Cpu::new(4))],
    ));
}

/// A search that gives up at once, as a lost GPU does.
struct Broken;
impl Search for Broken {
    fn search(&self, _: &Header, _: u128, _: u64, _: &AtomicBool, _: &AtomicU64) -> Option<u128> {
        None
    }
    fn describe(&self) -> Value {
        serde_json::json!({"kind":"broken"})
    }
}
/// A search that claims every attempt, as fast as it can be called.
struct Quick;
impl Search for Quick {
    fn search(
        &self,
        _: &Header,
        _: u128,
        attempts: u64,
        _: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        tried.fetch_add(attempts * 1_000, Ordering::Relaxed);
        None
    }
    fn describe(&self) -> Value {
        serde_json::json!({"kind":"quick"})
    }
}

#[test]
fn auto_mines_with_the_fastest_search() {
    let auto = Auto::new(search::candidates(4), Duration::from_millis(150));
    let stop = AtomicBool::new(false);
    let using = auto.time(&stop);
    let status = auto.describe();
    eprintln!("{status:#}");
    let rates = status["mhs"].as_object().unwrap();
    assert_eq!(rates.len(), status["candidates"].as_object().unwrap().len());
    let fastest = rates
        .iter()
        .max_by(|a, b| a.1.as_f64().unwrap().total_cmp(&b.1.as_f64().unwrap()))
        .unwrap()
        .0;
    assert_eq!(using, fastest);
    assert_eq!(status["using"], using);
    // What it finds is valid: one nonce in 32 meets 2^251.
    let h = header(9, pow2(251));
    let found = run(|s, t| auto.search(&h, 77, 64, s, t)).0.unwrap();
    let mut solved = h.clone();
    solved.nonce = found;
    assert!(consensus::valid_pow(&solved));
}

#[test]
fn auto_times_again_when_its_search_fails() {
    let auto = Auto::new(
        vec![("broken", Arc::new(Broken)), ("quick", Arc::new(Quick))],
        Duration::from_millis(20),
    );
    // Neither has a rate yet; the first call times both and takes the faster.
    let h = header(10, pow2(251));
    run(|s, t| auto.search(&h, 0, 100, s, t));
    assert_eq!(auto.using(), "quick");
    assert!(auto.describe()["timed_seconds_ago"].is_u64());
    let auto = Auto::new(
        vec![("broken", Arc::new(Broken))],
        Duration::from_millis(20),
    );
    run(|s, t| auto.search(&h, 0, 100, s, t));
    // Its only search tried nothing: the timing is dropped, to be done again.
    assert!(auto.describe()["timed_seconds_ago"].is_null());
}

#[test]
fn miner_json_chooses_the_search() {
    let policy = |json: &str| serde_json::from_str::<Policy>(json);
    assert_eq!(policy("{}").unwrap().search, Choice::Auto);
    for (name, choice) in [
        ("auto", Choice::Auto),
        ("reference", Choice::Reference),
        ("cpu", Choice::Cpu),
        ("gpu", Choice::Gpu),
        ("both", Choice::Both),
    ] {
        let json = format!(r#"{{"search":"{name}"}}"#);
        assert_eq!(policy(&json).unwrap().search, choice);
    }
    assert!(policy(r#"{"search":"fastest"}"#).is_err());
    // Each makes a search; without a GPU, `gpu` and `both` fall back to the CPU.
    for choice in [Choice::Reference, Choice::Cpu, Choice::Gpu, Choice::Both] {
        let search = search::factory(choice)(2);
        let kind = search.describe()["kind"].clone();
        match (choice, Gpu::open()) {
            (Choice::Reference, _) => assert_eq!(kind, "cpu"),
            (Choice::Gpu, Some(_)) if Gpu::all().len() == 1 => assert_eq!(kind, "gpu"),
            (Choice::Gpu, Some(_)) => assert_eq!(kind, "split"),
            (Choice::Both, Some(_)) => assert_eq!(kind, "split"),
            _ => assert_eq!(kind, "cpu"),
        }
    }
}

/// `cargo test -p ting-node --release --test search -- --ignored --nocapture`
#[test]
#[ignore = "benchmark"]
fn search_speed() {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u32;
    let auto = Auto::new(search::candidates(threads), Duration::from_secs(2));
    let using = auto.time(&AtomicBool::new(false));
    let status = auto.describe();
    for (name, rate) in status["mhs"].as_object().unwrap() {
        println!("{name:>10}: {rate:>8} MH/s");
    }
    println!("auto mines with {using} on {threads} threads");
    println!("{:#}", status["candidates"]);
}
