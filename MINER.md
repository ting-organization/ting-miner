# Ting miner

This repository is the Ting reference node with a mining policy for pay. It is the
whole Ting implementation, kept in step with [Ting](https://github.com/ting-organization/ting)
by merging its changes, and the `ting` binary it builds runs, synchronizes and
validates exactly as Ting's does. Only how a template picks its transactions differs.

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

## Configure

`miner.json` in the node's data directory, read when the node starts:

```json
{
  "assets": { "<coin ContractId in hex>": 1.0 },
  "claims": ["<coin ContractId in hex>"],
  "unpaid": true
}
```

- `assets`: the value of one unit of each asset this miner accepts, by the paying
  program's ContractId. Payments in other assets count as nothing.
- `claims`: the coins whose block reward to claim in every block.
- `unpaid`: whether transactions that pay nothing still fill the block.

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

- `node/src/payout.rs`, `node/tests/payout.rs`, `miner.production.json` and this
  file are the miner's own;
- `node/src/lib.rs` declares the module, and `node/src/main.rs` runs the daemon with
  `payout::mining` instead of the defaults: one line each;
- `src/vm/runtime.rs` gives the block candidate two read-only accessors, `producer`
  and `limits`.

Consensus is Ting's and stays untouched: a miner on other rules would be on another
chain.
