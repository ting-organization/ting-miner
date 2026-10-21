# Ting miner

This repository is the Ting reference node with a mining policy for pay. It is the
whole Ting implementation, kept in step with [Ting](https://github.com/ting-organization/ting)
by merging its changes, and the `ting` binary it builds runs, synchronizes and
validates exactly as Ting's does. Only how a template picks its transactions, and how
fast the miner finds a nonce for it, differ.

## What it adds

The selector in `node/src/payout.rs`, which `ting run` uses:

1. **Reward claims.** For each coin listed under `claims`, every block this node
   builds starts with that coin's reward claim, kept only if it succeeds. The reward
   goes to the payout account in the block's producer data, so it is this miner's.
2. **Paid transactions first.** Each pending transaction is tried once on a block,
   and the producer payments it emits to this miner's payout account are added up,
   each asset valued as `assets` says. Its rank is that value per share of the
   block, the largest fraction of any capacity it uses, and is remembered while the
   transaction is pooled: what a transaction pays does not change with the tip.
   Transactions are taken best first, each kept only if it still succeeds and pays
   after what the block holds by then. These tries count against Ting's allowance
   for the work a template throws away (`node/mining`): a transaction it leaves
   untried is ranked by a later template, not counted as paying nothing.
3. **The rest.** The others are tried once more in arrival order. One that pays now,
   such as a second payment from an account whose first the block already holds, is
   kept and ranked by what it paid. With `unpaid` on, the default, one that succeeds
   and pays nothing is kept too.
4. **A full pool.** When the pool is full, the transaction that pays least per
   share of the block gives way to a newcomer that pays more. Only transactions of
   addresses holding at least as many as the newcomer's address can give way, so an
   address cannot push out others' transactions, with payments of its own that
   will fail, beyond an equal share. When none pays less, Ting's rule decides, but
   never against a transaction that pays more than the newcomer. Transactions this
   node's own API or CLI submitted never give way. The pool's size is Ting's
   `mempool_transactions` and `mempool_mib` in `config.json`.

Everything comes from the program conventions of the Ting wiki
(`programs/conventions`): the payout account in producer data, and the producer
payment event every paying program emits. A new coin needs no code, only an entry
in `miner.json`.

Without a payout account in the producer data, nothing is claimed or ranked, and
the node selects as Ting does.

## Finding nonces

The search in `node/src/search.rs`, which `ting miner start` uses, finds nonces as
fast as the machine can. Each attempt compresses one SHA-256 block, the header's
last, which holds the nonce:

- **`cpu`**: the miner's threads, each on its own share of the nonces, on the CPU's
  SHA-256 instructions: ARMv8's SHA2 extension, which Ting's search leaves unused
  (its `sha2` uses them only with the `asm` feature), or SHA-NI on x86.
- **`gpu`**: a WGSL compute shader through wgpu: Metal on a Mac, Vulkan on Linux and
  Windows (NVIDIA, AMD, Intel), DX12 on Windows. It starts at the block's ninth
  round, the first eight being the same for every nonce.
- **`both`**: the GPU and the CPU on one range, shared by how fast each was on the
  last.
- **`reference`**: Ting's own CPU search.
- **`auto`**, the default: times every search the machine has, half a second each on
  a header no nonce meets, mines with the fastest, and times them again every ten
  minutes, or at once when its search stops getting anywhere, as a GPU that was
  lost. The choice follows the machine: a GPU that slows as it heats, a CPU that
  other work takes.

Every search finds exactly the nonce Ting's plain `valid_pow` loop finds first in a
range (`node/tests/search.rs`); the GPU's tests pass untested on a machine without
one. On a MacBook Air M3 with 8 threads, `reference` hashes 42 MH/s, `cpu` 387,
`gpu` 502 and `both` 690, so `auto` mines with both. This prints a machine's rates
without mining:

```sh
cargo test -p ting-node --release --test search -- --ignored --nocapture search_speed
```

While the miner runs, `ting miner status` shows the search, each one's rate and the
one in use. The GPU search is the `gpu` feature, on by default; `cargo build
--no-default-features` leaves it and wgpu out. A GPU needs its driver: on Linux one
with Vulkan, as NVIDIA's own or Mesa for AMD and Intel.

## Configure

`miner.json` in the node's data directory, read when the node starts:

```json
{
  "assets": { "<coin ContractId in hex>": 1.0 },
  "claims": ["<coin ContractId in hex>"],
  "unpaid": true,
  "search": "auto"
}
```

- `assets`: the value of one unit of each asset this miner accepts, by the paying
  program's ContractId. Payments in other assets count as nothing.
- `claims`: the coins whose block reward to claim in every block.
- `unpaid`: whether transactions that pay nothing still fill the block.
- `search`: how to find nonces: `auto`, `cpu`, `gpu`, `both` or `reference`
  ([finding nonces](#finding-nonces)). `gpu` and `both` fall back to the CPU on a
  machine without a GPU. The CPU searches use the miner's threads, 1 unless
  `ting miner start --threads` says more.

Every field is optional; without the file the node behaves as Ting. The payout
account is the node's producer data, 44 bytes naming the account
(`ting miner producer <hex>`; `ocoin payout <account>` prints the hex).

```sh
ting miner producer <hex from ocoin payout>
ting stop
ting start
ting miner start --threads 2
```

`ting miner producer <hex>` answers with the selection in use, its assets and claims.
Without a hex it clears the producer data; `ting miner status` shows it.

### The production network

`miner.production.json` mines Daler (DLR), the coin of ContractId
`305378d17f6af84a563d0f8a8455084948aff7330b62b4f2f98a44b82ba113c4`, deployed at
height 443 of the production network: it claims Daler's block reward and values
payments in it. A ContractId belongs to one chain, so the file is for the production
network only.

```sh
cp miner.production.json ~/.ting/miner.json
```

## Keep in step with Ting

```sh
git fetch upstream
git merge upstream/master
```

The miner changes as little of Ting as it can, so merges stay clean:

- `node/src/payout.rs`, `node/src/search.rs`, their tests in `node/tests/`,
  `miner.production.json` and this file are the miner's own;
- `node/src/lib.rs` declares the two modules, and `node/src/main.rs` runs the daemon
  with `payout::mining` instead of the defaults: a line each;
- `node/Cargo.toml` adds wgpu and pollster under the `gpu` feature, and
  `Cargo.lock` their crates;
- `src/vm/runtime.rs` gives the block candidate two read-only accessors, `producer`
  and `limits`.

Consensus is Ting's and stays untouched: a miner on other rules would be on another
chain.
