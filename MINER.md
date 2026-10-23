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
- **`gpu`**: every GPU of the machine, each running a WGSL compute shader through
  wgpu: Metal on a Mac, Vulkan on Linux and Windows (NVIDIA, AMD, Intel), DX12 on
  Windows. The shader starts at the block's ninth round, the first eight being the
  same for every nonce. Several GPUs split each range, each part sized by how fast
  that GPU was on the last; a GPU that fails gets no part.
- **`both`**: every GPU and the CPU on one range, split the same way.
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

A card can show under more than one graphics API, as under both Vulkan and DX12 on
Windows, so the GPUs all come from the API that shows the most of them. Hashing
needs nothing from one GPU to the next, so more GPUs hash about as many times
faster. One limit stays Ting's: its miner loop asks a search for 2^30 nonces at a
time and then builds a new template, so past some tens of GH/s, a handful of fast
GPUs, building templates starts to take a share of the time.

## Download a release

Each [release](https://github.com/ting-organization/ting-miner/releases) carries the
`ting` binary for five platforms, built by `.github/workflows/release.yml`:

| Platform | Archive |
|---|---|
| Mac, Apple silicon | `ting-miner-<tag>-aarch64-apple-darwin.tar.gz` |
| Mac, Intel | `ting-miner-<tag>-x86_64-apple-darwin.tar.gz` |
| Linux, x86_64 | `ting-miner-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux, ARM | `ting-miner-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| Windows, x86_64 | `ting-miner-<tag>-x86_64-pc-windows-msvc.zip` |

Each holds the binary, `README.md`, whose [start mining](README.md#start-mining) takes
it from there, this file, `miner.production.json` and the licences. The
binary is the whole node, the seed blocks, wiki and explorer included, and one build
mines at full speed on every machine of its platform: as it runs, the CPU search
finds the SHA-256 instructions the CPU has, and the GPU search the Metal, Vulkan or
DX12 driver. On Linux it needs glibc 2.35 or later, as in Ubuntu 22.04 and Debian 12.

```sh
tag=v0.1.0-miner.1
archive=ting-miner-$tag-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/ting-organization/ting-miner/releases/download/$tag/$archive
curl -LO https://github.com/ting-organization/ting-miner/releases/download/$tag/SHA256SUMS
shasum -a 256 --check --ignore-missing SHA256SUMS
tar -xzf $archive
```

`gh attestation verify $archive --repo ting-organization/ting-miner` checks that
this repository's release workflow built the archive, and from which commit. On
Windows, `Get-FileHash` prints an archive's SHA-256 to compare with `SHA256SUMS`, and
`Expand-Archive` unpacks it.

The binaries are not signed. A Mac refuses to run one downloaded in a browser until
`xattr -d com.apple.quarantine ting` clears the browser's mark; one downloaded with
`curl` has none. Windows SmartScreen asks before running it the first time.

A release is a tag `v<version>-miner.<n>`, the version being `node/Cargo.toml`'s,
which is Ting's and which the miner leaves as it is; `ting --version` prints it. The
tag starts the release workflow, which makes a draft release of the five, and CI,
which tests the same commit; the draft is published once CI passes. On a pull request
that changes the workflow, or run by hand from the Actions tab, it builds the five
without a release.

```sh
git tag v0.1.0-miner.1
git push origin v0.1.0-miner.1
```

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

Every field is optional; without the file the node behaves as Ting. The node reads
it when it starts, so a change to it takes a `ting stop` and a `ting start`.

The account the blocks pay is set apart from it, with the node running or not:

```sh
ting miner payout <account>
```

The account is 64 hex digits, as a wallet shows one: in Ting ID, Receive shows your
Spending account. The command sets producer data naming it as the payout account,
44 bytes ([producer data](node/wiki/programs/conventions.md#producer-data)), and
answers with the account, as `ting miner payout` alone does and `ting miner status`
does under `payout`; anything but 32 bytes of hex is refused. `ting miner producer
<hex>` sets other producer data, and without a hex clears it: the blocks then pay
nobody, and claim nothing.

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
  `miner.production.json`, `.github/workflows/release.yml` and this file are the
  miner's own;
- `node/src/lib.rs` declares the two modules, and `node/src/main.rs` runs the daemon
  with `payout::mining` instead of the defaults: a line each. `main.rs` also has
  `ting miner payout` and the payout account in `ting miner status`, a few lines
  calling `payout.rs`;
- `README.md` starts with the miner's own part, above Ting's title, which a merge
  leaves alone unless Ting changes that title;
- `node/Cargo.toml` adds wgpu and pollster under the `gpu` feature, and
  `Cargo.lock` their crates;
- `src/vm/runtime.rs` gives the block candidate two read-only accessors, `producer`
  and `limits`.

Consensus is Ting's and stays untouched: a miner on other rules would be on another
chain.
