//! Finding nonces as fast as this machine can (ting-miner, see MINER.md): the
//! CPU on its own SHA-256 instructions, a GPU through wgpu (Metal, Vulkan or
//! DX12), or both at once, and an automatic search that times each of them on
//! this machine, mines with the fastest and times them again every few
//! minutes, so the choice follows a GPU that slows as it heats or a CPU that
//! other work takes.
//!
//! Every search hashes a header as `mining::search` does: SHA-256 over the
//! tagged header, whose blocks are all fixed but the last, which holds the
//! nonce, so an attempt compresses that one block.
use crate::{
    daemon::SearchFactory,
    mining::{self, Search},
};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use ting_core::{
    meter::Resources,
    protocol::{Encode, HEADER_LEN, Header, target_bytes},
};

/// The search `miner.json` asks for, `"search"`; `auto` unless set.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    /// Time every search this machine has and mine with the fastest.
    #[default]
    Auto,
    /// Ting's own CPU search, `mining::Cpu`.
    Reference,
    /// The CPU, on its SHA-256 instructions where it has them.
    Cpu,
    /// The GPU, or the CPU where there is none.
    Gpu,
    /// The GPU and the CPU together, or the CPU alone where there is no GPU.
    Both,
}

/// The node's search for `choice`, made with the miner's threads each time the
/// miner starts.
pub fn factory(choice: Choice) -> SearchFactory {
    Arc::new(move |threads| -> Arc<dyn Search> {
        let cpu = Arc::new(Cpu::new(threads));
        match choice {
            Choice::Auto => Arc::new(Auto::new(candidates(threads), BENCH)),
            Choice::Reference => Arc::new(mining::Cpu::new(threads)),
            Choice::Cpu => cpu,
            Choice::Gpu => match Gpu::open() {
                Some(gpu) => gpu,
                None => cpu,
            },
            Choice::Both => match Gpu::open() {
                Some(gpu) => Arc::new(Both::new(gpu, cpu)),
                None => cpu,
            },
        }
    })
}

/// The searches `auto` chooses from on this machine, by name: Ting's, the
/// CPU's, and the GPU's alone and with the CPU where there is a GPU.
pub fn candidates(threads: u32) -> Vec<(&'static str, Arc<dyn Search>)> {
    let cpu = Arc::new(Cpu::new(threads));
    let mut all: Vec<(&'static str, Arc<dyn Search>)> = vec![
        ("reference", Arc::new(mining::Cpu::new(threads))),
        ("cpu", cpu.clone()),
    ];
    if let Some(gpu) = Gpu::open() {
        all.push(("gpu", gpu.clone()));
        all.push(("both", Arc::new(Both::new(gpu, cpu))));
    }
    all
}

/// How far one call may search. The built-in miner moves its start on by 64
/// times `attempts` after each call (`mining::Miner`), so a call may cover that
/// many nonces without trying any twice. The CPU searches `attempts` on each
/// thread, as Ting's does; a GPU takes the whole span.
pub const SPAN: u64 = 64;

/// A stop condition shared by the threads of one search.
type Quit<'a> = &'a (dyn Fn() -> bool + Sync);

// ---- The header ------------------------------------------------------------------

/// The message a block id hashes (`ting_core::hash`): `"Ting/"`, the tag's
/// length as a little-endian u16, `"block"` and the header, padded the SHA-256
/// way to whole 64-byte blocks.
const PREFIX: [u8; 12] = *b"Ting/\x05\x00block";
const MESSAGE_LEN: usize = PREFIX.len() + HEADER_LEN;
const PADDED_LEN: usize = (MESSAGE_LEN + 9).div_ceil(64) * 64;
/// Where the nonce starts in the message, and the blocks wholly before it.
const NONCE_AT: usize = PREFIX.len() + mining::NONCE_OFFSET;
const FIXED_LEN: usize = NONCE_AT / 64 * 64;
// The nonce, the padding and the length all sit in the one last block, the
// nonce from its byte 34: two bytes in word 8, four in each of words 9 to 11
// and two in word 12. `Work::block` and the GPU's shader rely on it.
const _: () = assert!(PADDED_LEN - FIXED_LEN == 64);
const _: () = assert!(NONCE_AT - FIXED_LEN == 34 && mining::NONCE_BYTES == 16);

/// A header ready to search: the SHA-256 state after its fixed blocks, its
/// last block as big-endian words with the nonce's bytes zero, and the target
/// as big-endian words, which an id meets when its state words, compared in
/// order, are at or below them.
#[derive(Clone)]
struct Work {
    state: [u32; 8],
    tail: [u32; 16],
    target: [u32; 8],
}

impl Work {
    /// `None` when no id can meet the target: `valid_pow` refuses a zero
    /// target and one wider than 256 bits.
    fn new(header: &Header) -> Option<Self> {
        if !(1..=256).contains(&header.target.bits()) {
            return None;
        }
        let mut message = [0u8; PADDED_LEN];
        message[..PREFIX.len()].copy_from_slice(&PREFIX);
        message[PREFIX.len()..MESSAGE_LEN].copy_from_slice(&header.encode());
        message[MESSAGE_LEN] = 0x80;
        message[PADDED_LEN - 8..].copy_from_slice(&(MESSAGE_LEN as u64 * 8).to_be_bytes());
        message[NONCE_AT..NONCE_AT + mining::NONCE_BYTES].fill(0);
        let words = |bytes: &[u8]| -> Vec<u32> {
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|w| u32::from_be_bytes(*w))
                .collect()
        };
        let mut state = IV;
        for block in words(&message[..FIXED_LEN]).as_chunks::<16>().0 {
            state = soft_compress(&state, block);
        }
        Some(Self {
            state,
            tail: words(&message[FIXED_LEN..]).try_into().expect("one block"),
            target: words(&target_bytes(&header.target))
                .try_into()
                .expect("eight words"),
        })
    }

    /// The last block with `nonce` in it, its 16 little-endian bytes from
    /// byte 34.
    fn block(&self, nonce: u128) -> [u32; 16] {
        let b = nonce.to_le_bytes();
        let mut block = self.tail;
        block[8] |= u32::from_be_bytes([0, 0, b[0], b[1]]);
        block[9] = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
        block[10] = u32::from_be_bytes([b[6], b[7], b[8], b[9]]);
        block[11] = u32::from_be_bytes([b[10], b[11], b[12], b[13]]);
        block[12] |= u32::from_be_bytes([b[14], b[15], 0, 0]);
        block
    }
}

/// A header no nonce meets in practice, target 1, for timing searches: every
/// attempt is hashed and fails.
fn unmeetable() -> Header {
    Header {
        chain_id: [0; 32],
        height: 0,
        parent: [0; 32],
        timestamp: 0,
        target: BigUint::from(1u8),
        transactions_root: [0; 32],
        receipts_root: [0; 32],
        state_root: [0; 32],
        used: Resources([0; 4]),
        votes: [0; 4],
        producer_hash: [0; 32],
        nonce: 0,
    }
}

// ---- SHA-256 ---------------------------------------------------------------------

/// The SHA-256 initial state (FIPS 180-4, 5.3.3).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
/// The SHA-256 round constants (FIPS 180-4, 4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One compression of `block`, as big-endian words, through `sha2`: on SHA-NI
/// where an x86 CPU has it, in software elsewhere.
fn soft_compress(state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
    let mut bytes = [0u8; 64];
    for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(block) {
        *out = word.to_be_bytes();
    }
    let mut state = *state;
    sha2::compress256(
        &mut state,
        std::slice::from_ref(sha2::digest::generic_array::GenericArray::from_slice(
            &bytes,
        )),
    );
    state
}

/// Whether this CPU has SHA-256 instructions `sha2` does not use: ARMv8's SHA2
/// extension, which `sha2` 0.10 leaves to its `asm` feature.
fn hardware() -> bool {
    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("sha2");
    #[cfg(not(target_arch = "aarch64"))]
    false
}

/// One compression on the fastest instructions this CPU has.
#[allow(unsafe_code)]
fn compress(hardware: bool, state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
    #[cfg(target_arch = "aarch64")]
    if hardware {
        // SAFETY: `hardware` is true only where the CPU has the SHA2
        // extension, as `hardware()` detected.
        return unsafe { arm::compress(state, block) };
    }
    let _ = hardware;
    soft_compress(state, block)
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
mod arm {
    use super::K;
    use std::arch::aarch64::*;

    /// One compression on ARMv8's SHA2 instructions, four rounds each.
    ///
    /// # Safety
    /// The CPU must have the SHA2 extension.
    #[target_feature(enable = "sha2")]
    pub unsafe fn compress(state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
        // SAFETY: every load and store is of four u32s inside `state`,
        // `block`, `K` or `out`; the caller vouches for the extension.
        unsafe {
            let abcd0 = vld1q_u32(state.as_ptr());
            let efgh0 = vld1q_u32(state[4..].as_ptr());
            let mut w = [
                vld1q_u32(block.as_ptr()),
                vld1q_u32(block[4..].as_ptr()),
                vld1q_u32(block[8..].as_ptr()),
                vld1q_u32(block[12..].as_ptr()),
            ];
            let (mut abcd, mut efgh) = (abcd0, efgh0);
            for r in 0..16 {
                if r >= 4 {
                    let j = r % 4;
                    w[j] = vsha256su1q_u32(
                        vsha256su0q_u32(w[j], w[(j + 1) % 4]),
                        w[(j + 2) % 4],
                        w[(j + 3) % 4],
                    );
                }
                let wk = vaddq_u32(w[r % 4], vld1q_u32(K[4 * r..].as_ptr()));
                let before = abcd;
                abcd = vsha256hq_u32(before, efgh, wk);
                efgh = vsha256h2q_u32(efgh, before, wk);
            }
            let mut out = [0u32; 8];
            vst1q_u32(out.as_mut_ptr(), vaddq_u32(abcd, abcd0));
            vst1q_u32(out[4..].as_mut_ptr(), vaddq_u32(efgh, efgh0));
            out
        }
    }
}

// ---- The CPU ---------------------------------------------------------------------

/// The CPU search: `threads` threads, each on its own share of the range, on
/// the CPU's SHA-256 instructions where it has them.
pub struct Cpu {
    threads: usize,
    hardware: bool,
}

impl Cpu {
    pub fn new(threads: u32) -> Self {
        Self {
            threads: (threads as usize).clamp(1, 64),
            hardware: hardware(),
        }
    }

    /// The first nonce in `count` from `start` (wrapping) whose id meets the
    /// header's target, the one `mining::search` finds; `None` when there is
    /// none or `stop` is raised. Counts every attempt into `tried`.
    pub fn scan(
        &self,
        header: &Header,
        start: u128,
        count: u64,
        stop: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        let quit = || stop.load(Ordering::Relaxed);
        match Work::new(header) {
            Some(work) => self.scan_work(&work, start, count, &quit, tried),
            None => unreachable_target(count, &quit, tried),
        }
    }

    fn scan_work(
        &self,
        work: &Work,
        start: u128,
        count: u64,
        quit: Quit<'_>,
        tried: &AtomicU64,
    ) -> Option<u128> {
        let threads = (self.threads as u64).min(count.max(1));
        let share = count.div_ceil(threads);
        // The lowest share that has found a nonce: the shares above it stop,
        // the ones below go on, so the nonce returned is the first in range.
        let first = AtomicUsize::new(usize::MAX);
        let found = Mutex::new(vec![None; threads as usize]);
        std::thread::scope(|scope| {
            for i in 0..threads as usize {
                let (first, found) = (&first, &found);
                scope.spawn(move || {
                    let from = i as u64 * share;
                    let quit = || quit() || first.load(Ordering::Relaxed) < i;
                    if let Some(nonce) = scan_one(
                        work,
                        self.hardware,
                        start.wrapping_add(u128::from(from)),
                        share.min(count.saturating_sub(from)),
                        &quit,
                        tried,
                    ) {
                        found.lock().unwrap()[i] = Some(nonce);
                        first.fetch_min(i, Ordering::Relaxed);
                    }
                });
            }
        });
        found.into_inner().unwrap().into_iter().flatten().next()
    }
}

/// One thread's part: the first nonce in `count` from `start` that meets the
/// target.
fn scan_one(
    work: &Work,
    hardware: bool,
    start: u128,
    count: u64,
    quit: Quit<'_>,
    tried: &AtomicU64,
) -> Option<u128> {
    for offset in 0..count {
        if offset.is_multiple_of(1024) && quit() {
            tried.fetch_add(offset, Ordering::Relaxed);
            return None;
        }
        let nonce = start.wrapping_add(u128::from(offset));
        if compress(hardware, &work.state, &work.block(nonce)) <= work.target {
            tried.fetch_add(offset + 1, Ordering::Relaxed);
            return Some(nonce);
        }
    }
    tried.fetch_add(count, Ordering::Relaxed);
    None
}

/// A search under a target no id meets: every attempt fails, so none is
/// hashed, as in `mining`.
fn unreachable_target(count: u64, quit: Quit<'_>, tried: &AtomicU64) -> Option<u128> {
    if count > 0 && !quit() {
        tried.fetch_add(count, Ordering::Relaxed);
    }
    None
}

impl Search for Cpu {
    fn search(
        &self,
        header: &Header,
        start: u128,
        attempts: u64,
        stop: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        let count = attempts.saturating_mul(self.threads as u64);
        self.scan(header, start, count, stop, tried)
    }
    fn describe(&self) -> Value {
        json!({"kind":"cpu","threads":self.threads,
            "sha256":if self.hardware { "instructions" } else { "sha2" }})
    }
}

// ---- The GPU and the CPU together -------------------------------------------------

/// The GPU and the CPU on one range: the GPU on its first part, the CPU on the
/// rest, shared by how fast each was on the last call, so that both finish at
/// about the same moment.
pub struct Both {
    gpu: Arc<Gpu>,
    cpu: Arc<Cpu>,
    /// The GPU's share of a range.
    share: Mutex<f64>,
}

impl Both {
    pub fn new(gpu: Arc<Gpu>, cpu: Arc<Cpu>) -> Self {
        Self {
            gpu,
            cpu,
            share: Mutex::new(0.75),
        }
    }

    /// The first nonce in `count` from `start` that meets the target, as
    /// [`Cpu::scan`] finds it.
    pub fn scan(
        &self,
        header: &Header,
        start: u128,
        count: u64,
        stop: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        let quit = || stop.load(Ordering::Relaxed);
        let Some(work) = Work::new(header) else {
            return unreachable_target(count, &quit, tried);
        };
        let share = *self.share.lock().unwrap();
        let low = ((count as f64 * share) as u64).min(count);
        // A nonce in the GPU's part comes before any in the CPU's.
        let gpu_found = AtomicBool::new(false);
        let timed = |run: &dyn Fn() -> Option<u128>| {
            let began = Instant::now();
            (run(), began.elapsed().as_secs_f64())
        };
        let ((low_found, gpu_time), (high_found, cpu_time)) = std::thread::scope(|scope| {
            let gpu = scope.spawn(|| {
                timed(&|| {
                    let found = self.gpu.scan_work(&work, start, low, &quit, tried);
                    gpu_found.store(found.is_some(), Ordering::Relaxed);
                    found
                })
            });
            let cpu = timed(&|| {
                let quit = || quit() || gpu_found.load(Ordering::Relaxed);
                let from = start.wrapping_add(u128::from(low));
                self.cpu.scan_work(&work, from, count - low, &quit, tried)
            });
            (gpu.join().expect("GPU search"), cpu)
        });
        // Whole parts only, each run to its end, give the two rates.
        if low_found.is_none() && high_found.is_none() && !quit() && low > 0 && low < count {
            let gpu = low as f64 / gpu_time.max(1e-6);
            let cpu = (count - low) as f64 / cpu_time.max(1e-6);
            let mut share = self.share.lock().unwrap();
            *share = (*share + gpu / (gpu + cpu)) / 2.0;
        }
        low_found.or(high_found)
    }
}

impl Search for Both {
    fn search(
        &self,
        header: &Header,
        start: u128,
        attempts: u64,
        stop: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        self.scan(header, start, attempts.saturating_mul(SPAN), stop, tried)
    }
    fn describe(&self) -> Value {
        json!({"kind":"both","gpu_share":*self.share.lock().unwrap(),
            "gpu":self.gpu.describe(),"cpu":self.cpu.describe()})
    }
}

// ---- Choosing ----------------------------------------------------------------------

/// How long `auto` times each search.
pub const BENCH: Duration = Duration::from_millis(500);
/// How often `auto` times them again while it mines.
pub const RECHECK: Duration = Duration::from_secs(600);

/// The automatic search: times every candidate on a header no nonce meets, for
/// `bench` each, mines with the fastest, and times them all again every
/// [`RECHECK`], or at once when the chosen one stops getting anywhere, as a
/// GPU that was lost.
pub struct Auto {
    candidates: Vec<(&'static str, Arc<dyn Search>)>,
    bench: Duration,
    timing: Mutex<Timing>,
}

#[derive(Default)]
struct Timing {
    using: usize,
    /// Hashes per second of each candidate, when last timed.
    rates: Vec<f64>,
    at: Option<Instant>,
}

impl Auto {
    pub fn new(candidates: Vec<(&'static str, Arc<dyn Search>)>, bench: Duration) -> Self {
        assert!(!candidates.is_empty(), "a search to choose");
        Self {
            candidates,
            bench,
            timing: Mutex::default(),
        }
    }

    /// Times every candidate and chooses the fastest; its name. Stops early
    /// when `stop` is raised, keeping the last choice.
    pub fn time(&self, stop: &AtomicBool) -> &'static str {
        let mut rates = Vec::with_capacity(self.candidates.len());
        for (_, search) in &self.candidates {
            if stop.load(Ordering::Relaxed) {
                return self.using();
            }
            rates.push(rate(search.as_ref(), self.bench, stop));
        }
        let using = (0..rates.len())
            .max_by(|&a, &b| rates[a].total_cmp(&rates[b]))
            .unwrap_or(0);
        *self.timing.lock().unwrap() = Timing {
            using,
            rates,
            at: Some(Instant::now()),
        };
        self.candidates[using].0
    }

    /// The name of the search in use.
    pub fn using(&self) -> &'static str {
        self.candidates[self.timing.lock().unwrap().using].0
    }
}

/// Hashes per second of `search` over about `bench`, on a header no nonce
/// meets: it runs whole slices and is stopped when the time is up.
fn rate(search: &dyn Search, bench: Duration, stop: &AtomicBool) -> f64 {
    let header = unmeetable();
    let tried = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    let began = Instant::now();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while began.elapsed() < bench && !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            done.store(true, Ordering::Relaxed);
        });
        let mut start = 0u128;
        while !done.load(Ordering::Relaxed) {
            search.search(&header, start, 1 << 24, &done, &tried);
            start = start.wrapping_add((1 << 24) * u128::from(SPAN));
        }
    });
    tried.load(Ordering::Relaxed) as f64 / began.elapsed().as_secs_f64()
}

impl Search for Auto {
    fn search(
        &self,
        header: &Header,
        start: u128,
        attempts: u64,
        stop: &AtomicBool,
        tried: &AtomicU64,
    ) -> Option<u128> {
        let due = self
            .timing
            .lock()
            .unwrap()
            .at
            .is_none_or(|at| at.elapsed() >= RECHECK);
        if due {
            self.time(stop);
        }
        let search = &self.candidates[self.timing.lock().unwrap().using].1;
        let before = tried.load(Ordering::Relaxed);
        let found = search.search(header, start, attempts, stop, tried);
        // A search that returns having tried nothing, unasked, has failed:
        // time them all again on the next call.
        if found.is_none()
            && attempts > 0
            && !stop.load(Ordering::Relaxed)
            && tried.load(Ordering::Relaxed) == before
        {
            self.timing.lock().unwrap().at = None;
        }
        found
    }
    fn describe(&self) -> Value {
        let timing = self.timing.lock().unwrap();
        json!({"kind":"auto",
            "using":timing.at.map(|_| self.candidates[timing.using].0),
            "mhs":self.candidates.iter().zip(&timing.rates)
                .map(|((name, _), rate)| (name.to_string(), json!((rate / 1e4).round() / 100.0)))
                .collect::<serde_json::Map<_, _>>(),
            "timed_seconds_ago":timing.at.map(|at| at.elapsed().as_secs()),
            "candidates":self.candidates.iter()
                .map(|(name, search)| (name.to_string(), search.describe()))
                .collect::<serde_json::Map<_, _>>()})
    }
}

// ---- The GPU -----------------------------------------------------------------------

/// Without the `gpu` feature there is no GPU: no value of this type exists.
#[cfg(not(feature = "gpu"))]
pub enum Gpu {}

#[cfg(not(feature = "gpu"))]
impl Gpu {
    /// The machine's GPU; never one in a build without the `gpu` feature.
    pub fn open() -> Option<Arc<Self>> {
        None
    }
    pub fn scan(&self, _: &Header, _: u128, _: u64, _: &AtomicBool, _: &AtomicU64) -> Option<u128> {
        match *self {}
    }
    fn scan_work(&self, _: &Work, _: u128, _: u64, _: Quit<'_>, _: &AtomicU64) -> Option<u128> {
        match *self {}
    }
}

#[cfg(not(feature = "gpu"))]
impl Search for Gpu {
    fn search(&self, _: &Header, _: u128, _: u64, _: &AtomicBool, _: &AtomicU64) -> Option<u128> {
        match *self {}
    }
    fn describe(&self) -> Value {
        match *self {}
    }
}

#[cfg(feature = "gpu")]
pub use gpu::Gpu;

#[cfg(feature = "gpu")]
mod gpu {
    use super::{K, Quit, SPAN, Search, Work, unreachable_target};
    use serde_json::{Value, json};
    use std::{
        fmt::Write,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };
    use ting_core::protocol::Header;

    /// Invocations per workgroup, and workgroups per dispatch at most: each
    /// invocation tries every `stride`-th nonce of a batch.
    const WORKGROUP: u32 = 256;
    const WORKGROUPS: u32 = 4096;
    /// How long one dispatch should take: short enough that a stop is seen
    /// soon and no driver takes the GPU for hung, long enough that the time
    /// between dispatches does not count.
    const DISPATCH: Duration = Duration::from_millis(80);
    /// The u32s handed to the shader: the state after the fixed blocks, the
    /// state after the last block's first eight rounds, the last block, the
    /// target, the batch's first nonce as little-endian u32s, the batch's size
    /// and the stride.
    const PARAMS: usize = 46;

    /// The machine's GPU, through wgpu, with the search's pipeline on it.
    pub struct Gpu {
        name: String,
        device: wgpu::Device,
        queue: wgpu::Queue,
        pipeline: wgpu::ComputePipeline,
        /// Set when the device reports an error, is lost or hangs: it searches
        /// no more.
        failed: Arc<AtomicBool>,
        /// Nonces per dispatch, grown or shrunk toward [`DISPATCH`]; outside
        /// `run`, so the miner's status can read it during a search.
        batch: AtomicU64,
        run: Mutex<Run>,
    }

    struct Run {
        params: wgpu::Buffer,
        found: wgpu::Buffer,
        readback: wgpu::Buffer,
        group: wgpu::BindGroup,
    }

    impl Gpu {
        /// The machine's fastest GPU, opened once per process; `None` when
        /// there is none, or only a software one, which the CPU search beats.
        pub fn open() -> Option<Arc<Self>> {
            static GPU: OnceLock<Option<Arc<Gpu>>> = OnceLock::new();
            GPU.get_or_init(|| Self::connect().map(Arc::new)).clone()
        }

        fn connect() -> Option<Self> {
            let instance = wgpu::Instance::new(
                wgpu::InstanceDescriptor::new_without_display_handle_from_env(),
            );
            let adapter =
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    ..Default::default()
                }))
                .ok()?;
            let info = adapter.get_info();
            if info.device_type == wgpu::DeviceType::Cpu {
                return None;
            }
            let (device, queue) =
                pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                    label: Some("ting-miner"),
                    ..Default::default()
                }))
                .ok()?;
            let failed = Arc::new(AtomicBool::new(false));
            {
                let failed = failed.clone();
                device.on_uncaptured_error(Arc::new(move |error| {
                    eprintln!("ting-miner: GPU error, the GPU search stops: {error}");
                    failed.store(true, Ordering::Relaxed);
                }));
            }
            let scope = device.push_error_scope(wgpu::ErrorFilter::Validation);
            let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("ting-miner search"),
                source: wgpu::ShaderSource::Wgsl(shader().into()),
            });
            let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("ting-miner search"),
                layout: None,
                module: &module,
                entry_point: Some("main"),
                compilation_options: Default::default(),
                cache: None,
            });
            if let Some(error) = pollster::block_on(scope.pop()) {
                eprintln!("ting-miner: the GPU search does not build: {error}");
                return None;
            }
            let buffer = |label, size, usage| {
                device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some(label),
                    size,
                    usage,
                    mapped_at_creation: false,
                })
            };
            use wgpu::BufferUsages as U;
            let params = buffer("params", 4 * PARAMS as u64, U::STORAGE | U::COPY_DST);
            let found = buffer("found", 4, U::STORAGE | U::COPY_SRC | U::COPY_DST);
            let readback = buffer("readback", 4, U::MAP_READ | U::COPY_DST);
            let group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("ting-miner search"),
                layout: &pipeline.get_bind_group_layout(0),
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: params.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: found.as_entire_binding(),
                    },
                ],
            });
            Some(Self {
                name: format!("{} ({:?})", info.name, info.backend),
                device,
                queue,
                pipeline,
                failed,
                batch: AtomicU64::new(1 << 20),
                run: Mutex::new(Run {
                    params,
                    found,
                    readback,
                    group,
                }),
            })
        }

        /// The first nonce in `count` from `start` that meets the target, as
        /// [`super::Cpu::scan`] finds it.
        pub fn scan(
            &self,
            header: &Header,
            start: u128,
            count: u64,
            stop: &AtomicBool,
            tried: &AtomicU64,
        ) -> Option<u128> {
            let quit = || stop.load(Ordering::Relaxed);
            match Work::new(header) {
                Some(work) => self.scan_work(&work, start, count, &quit, tried),
                None => unreachable_target(count, &quit, tried),
            }
        }

        pub(super) fn scan_work(
            &self,
            work: &Work,
            start: u128,
            count: u64,
            quit: Quit<'_>,
            tried: &AtomicU64,
        ) -> Option<u128> {
            let run = self.run.lock().unwrap();
            let mut params = [0u32; PARAMS];
            params[..8].copy_from_slice(&work.state);
            params[8..16].copy_from_slice(&rounds8(&work.state, &work.tail));
            params[16..32].copy_from_slice(&work.tail);
            params[32..40].copy_from_slice(&work.target);
            let mut done = 0;
            while done < count {
                if quit() || self.failed.load(Ordering::Relaxed) {
                    return None;
                }
                let batch = self.batch.load(Ordering::Relaxed);
                let size = batch.min(count - done);
                let first = start.wrapping_add(u128::from(done));
                let workgroups = (size.div_ceil(u64::from(WORKGROUP)) as u32).min(WORKGROUPS);
                for (i, limb) in params[40..44].iter_mut().enumerate() {
                    *limb = (first >> (32 * i)) as u32;
                }
                params[44] = size as u32;
                params[45] = workgroups * WORKGROUP;
                let began = Instant::now();
                let Some(offset) = self.dispatch(&run, &params, workgroups) else {
                    self.failed.store(true, Ordering::Relaxed);
                    return None;
                };
                // Toward a dispatch of about [`DISPATCH`], within what the
                // shader's u32 offsets allow.
                let took = began.elapsed();
                if size == batch {
                    if took < DISPATCH / 2 {
                        self.batch
                            .store((batch * 2).min(1 << 31), Ordering::Relaxed);
                    } else if took > DISPATCH * 2 {
                        self.batch
                            .store((batch / 2).max(1 << 16), Ordering::Relaxed);
                    }
                }
                if offset != u32::MAX {
                    tried.fetch_add(u64::from(offset) + 1, Ordering::Relaxed);
                    return Some(first.wrapping_add(u128::from(offset)));
                }
                tried.fetch_add(size, Ordering::Relaxed);
                done += size;
            }
            None
        }

        /// Runs one batch; the lowest offset in it that meets the target,
        /// `u32::MAX` for none, or `None` when the GPU failed.
        fn dispatch(&self, run: &Run, params: &[u32; PARAMS], workgroups: u32) -> Option<u32> {
            let bytes: Vec<u8> = params.iter().flat_map(|p| p.to_le_bytes()).collect();
            self.queue.write_buffer(&run.params, 0, &bytes);
            self.queue
                .write_buffer(&run.found, 0, &u32::MAX.to_le_bytes());
            let mut encoder = self.device.create_command_encoder(&Default::default());
            {
                let mut pass = encoder.begin_compute_pass(&Default::default());
                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &run.group, &[]);
                pass.dispatch_workgroups(workgroups, 1, 1);
            }
            encoder.copy_buffer_to_buffer(&run.found, 0, &run.readback, 0, 4);
            self.queue.submit([encoder.finish()]);
            let slice = run.readback.slice(..);
            slice.map_async(wgpu::MapMode::Read, |_| {});
            // A dispatch takes about [`DISPATCH`]; one that takes far longer
            // is a GPU that hangs.
            self.device
                .poll(wgpu::PollType::Wait {
                    submission_index: None,
                    timeout: Some(Duration::from_secs(10)),
                })
                .ok()?;
            let offset = u32::from_le_bytes(slice.get_mapped_range().ok()?[..4].try_into().ok()?);
            run.readback.unmap();
            Some(offset)
        }
    }

    impl Search for Gpu {
        fn search(
            &self,
            header: &Header,
            start: u128,
            attempts: u64,
            stop: &AtomicBool,
            tried: &AtomicU64,
        ) -> Option<u128> {
            if self.failed.load(Ordering::Relaxed) {
                // Not a busy loop of templates for a miner told to use only
                // this GPU; `auto` times its searches again and moves on.
                std::thread::sleep(Duration::from_millis(200));
                return None;
            }
            self.scan(header, start, attempts.saturating_mul(SPAN), stop, tried)
        }
        fn describe(&self) -> Value {
            json!({"kind":"gpu","adapter":self.name,"batch":self.batch.load(Ordering::Relaxed),
                "failed":self.failed.load(Ordering::Relaxed)})
        }
    }

    /// The state after the first eight rounds of `block`, which see only its
    /// first eight words, all before the nonce: the same for every nonce, so
    /// the shader starts at round 8.
    fn rounds8(state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..8 {
            let t1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(block[i]);
            let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            (h, g, f, e, d, c, b) = (g, f, e, d.wrapping_add(t1), c, b, a);
            a = t1.wrapping_add(t2);
        }
        [a, b, c, d, e, f, g, h]
    }

    /// The WGSL search, rounds 8 to 63 written out. Each invocation tries every
    /// `stride`-th offset of the batch and records the lowest that meets the
    /// target; it stops once a lower one is recorded.
    fn shader() -> String {
        let mut s = String::from(
            "@group(0) @binding(0) var<storage, read> p: array<u32>;
@group(0) @binding(1) var<storage, read_write> found: atomic<u32>;

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn bsig0(x: u32) -> u32 { return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn bsig1(x: u32) -> u32 { return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn ssig0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u); }
fn ssig1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u); }
fn ch(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (~x & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
// Four nonce bytes: the last two of `lo` and the first two of `hi`, as one
// big-endian word.
fn nonce_word(lo: u32, hi: u32) -> u32 {
    return (((lo >> 16u) & 0xffu) << 24u) | ((lo >> 24u) << 16u) | ((hi & 0xffu) << 8u) | ((hi >> 8u) & 0xffu);
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let count = p[44];
    let stride = p[45];
    for (var offset = id.x; offset < count; offset += stride) {
        if (atomicLoad(&found) < offset) { break; }
        // The nonce, the batch's first plus the offset, wrapping at 2^128.
        let n0 = p[40] + offset;
        var carry = select(0u, 1u, n0 < offset);
        let n1 = p[41] + carry;
        carry = select(0u, 1u, carry == 1u && n1 == 0u);
        let n2 = p[42] + carry;
        carry = select(0u, 1u, carry == 1u && n2 == 0u);
        let n3 = p[43] + carry;
",
        );
        for i in 0..16 {
            let value = match i {
                8 => "p[24] | ((n0 & 0xffu) << 8u) | ((n0 >> 8u) & 0xffu)".to_string(),
                9 => "nonce_word(n0, n1)".to_string(),
                10 => "nonce_word(n1, n2)".to_string(),
                11 => "nonce_word(n2, n3)".to_string(),
                12 => "p[28] | (((n3 >> 16u) & 0xffu) << 24u) | ((n3 >> 24u) << 16u)".to_string(),
                _ => format!("p[{}]", 16 + i),
            };
            writeln!(s, "        var w{i} = {value};").unwrap();
        }
        for (i, v) in ["a", "b", "c", "d", "e", "f", "g", "h"].iter().enumerate() {
            writeln!(s, "        var {v} = p[{}];", 8 + i).unwrap();
        }
        s.push_str("        var t1: u32;\n        var t2: u32;\n");
        for (i, k) in K.iter().enumerate().skip(8) {
            let w = i % 16;
            if i >= 16 {
                writeln!(
                    s,
                    "        w{w} = ssig1(w{}) + w{} + ssig0(w{}) + w{w};",
                    (i - 2) % 16,
                    (i - 7) % 16,
                    (i - 15) % 16
                )
                .unwrap();
            }
            writeln!(
                s,
                "        t1 = h + bsig1(e) + ch(e, f, g) + 0x{k:08x}u + w{w};
        t2 = bsig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;"
            )
            .unwrap();
        }
        s.push_str(
            "        var x = array<u32, 8>(p[0] + a, p[1] + b, p[2] + c, p[3] + d, p[4] + e, p[5] + f, p[6] + g, p[7] + h);
        // At or below the target, word by word from the first.
        for (var k = 0u; k < 8u; k++) {
            if (x[k] != p[32u + k]) {
                if (x[k] < p[32u + k]) { atomicMin(&found, offset); }
                break;
            }
            if (k == 7u) { atomicMin(&found, offset); }
        }
    }
}
",
        );
        s
    }
}
