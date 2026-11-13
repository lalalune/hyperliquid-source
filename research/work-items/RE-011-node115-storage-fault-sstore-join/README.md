# A folded storage-read fault reaches the normal SSTORE continuation

This advances **HL115-075** for node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It joins the already reconstructed fallible storage loader to its **actual** host-store and interpreter consumers. In the selected case below, a database read error is converted to zero, that zero supplies both original and current storage values, and the opcode can return its normal result after writing a nonzero replacement into the cache.

This is a conditional static path proof to the local opcode return. It is not proof that the transaction commits, that a consensus root includes the write, or that no other layer records the database error.

## Prior work and new boundary

* [#3904](https://github.com/lalalune/hyperliquid-source/pull/3904), `RE-011-storage-cache-load-115`, owns `0x433bcf0`: fault folding, cache insertion, original/current values and warming journal entries.
* [#3343](https://github.com/lalalune/hyperliquid-source/pull/3343) owns the host SSTORE twin at `0x2977910` and compares its body with `0x2977cd0`, while excluding the fallible loader's behavior.
* [#3931](https://github.com/lalalune/hyperliquid-source/pull/3931) owns interpreter SSTORE and gas/refund behavior from supplied host results, while excluding the fallible `0x2977cd0` boundary.
* `RE-011-node115-sstore-warm-source` supplies a different warm-hit provenance path and excludes the fallible miss studied here.

The new result binds these concrete calls and data lanes: `0x29945da` → `0x2977cd0` → relocation `0x64e6d98` / `0x433bcf0` → `0x3d48700`, then follows the returned zero values back through the real journal write and gas/refund calls. The credited leaf algorithms are not reimplemented.

## Explicit selected-case premises

The interpreter is not in static mode, has at least two stack words, and has raw revision byte **0..5**. Its requested replacement `V` is nonzero. The host account lookup succeeds, its account is already touched, and the selected storage key is vacant in the slot cache. The cold-access lookup misses; the created-account bit is clear. The account database lookup takes its nonzero success arm, then the storage database call returns outer tag 2, inner tag 2 with its owned error object.

All objects and their backing storage are valid and nonaliasing. Error destruction, cache allocation and journal reserve helpers return normally. Host byte `+0x265` is zero, selecting the branch that skips separate reserve accounting. Both interpreter gas subtractions succeed without borrow. These premises select a trace; they do not assert that this is the only fault path or that these configurations are currently used on the network.

## From the actual error to the actual host result

`0x2977cd0` constructs the loader context from the located account payload, the host journal at host+0x288, the access-list structure at host+0x2e0, the database wrapper at host+0x398, the current generation and the same 20-byte address. It copies the requested 32-byte storage key, passes its cold-rejection flag and calls the fallible loader at `0x2977ec4`.

At the selected cache miss, `0x433bf81` sets the cold flag to 1. The interpreter's lower-revision arm passed a zero cold-rejection flag. The storage read at `0x433c105` returns the selected error tags; `0x433c38b..0x433c391` destroys the error, and `0x433c399..0x433c3a3` creates the zero value. The insertion path copies it twice into the returned slot payload: **original=0, current=0**. It appends warming journal tag 9 and returns the actual cache payload pointer with `dl=1` at `0x433c51a..0x433c568`.

The host store rejects only `dl=2` at this boundary. With `dl=1`, it saves both zero values, compares the actual cached current value with `V`, writes `V` at payload+0x20, and appends tag 8 carrying the previous current value **0** (`0x2977f6c..0x2978031`). It returns the three concrete 32-byte values:

| Host result | Value in this trace |
| --- | --- |
| `+0x00..+0x1f` | original zero |
| `+0x20..+0x3f` | previous current zero |
| `+0x40..+0x5f` | replacement `V`, nonzero |
| `+0x60` | cold flag 1 |

The warming tag 9 precedes this tag 8 on the selected path. This order describes these two writes; it does not claim an exhaustive journal for the transaction.

## Interpreter consequence

At `0x29945bc..0x29945da`, the lower-revision arm passes the actual key and value to `0x2977cd0` with cold-rejection flag zero. The returned flag is 1, so the `flag==2` error-status branch is not taken. The interpreter reconstructs the complete result, including the first byte, at local stack+0x10 and passes it to the actual cost helper `0x299f910`.

For raw revision 0..5, that helper receives mode 0. Its current-zero/new-nonzero arm selects schedule word **+0xa0**. The interpreter has already deducted schedule word **+0x98**, so the final remaining gas on this selected successful trace is the incoming amount minus those two deductions. No hardcoded network gas constants are assumed.

Host+0x265=0 bypasses the separate reserve path. The actual refund call `0x299f680` receives the same triplet and mode 0; current zero selects refund delta **0** at `0x299f7ef..0x299f81a`. The interpreter leaves its refund accumulator unchanged and returns **AL=0** at `0x2994928`.

Thus this storage-read error is not represented by a separate fault status at this local opcode boundary. Under the listed premises, it reaches the same value-dependent store/cost/refund branches as a zero read. The cache already contains `V`; whether later frame or transaction handling reverts, commits, or invalidates it remains unresolved.

## Reproduction and limits

```sh
python3 research/work-items/RE-011-node115-storage-fault-sstore-join/verify.py --target /path/to/original/hl-node
```

The verifier authenticates the complete target digest, 13 windows (2428 bytes, 553 instructions), and 227 facts, with 227 semantic corruption controls. It checks the actual call binding, error tags, zero stores, payload offsets, journal tags, mode checks, gas/refund selectors and return. Independent review is still required for the conditional dataflow argument. No native target code was executed or emulated; no live database fault was induced.

The source-owned load/store/gas models remain in the credited contributions. This packet supplies their missing native composition witness, not a synthetic callback implementation. Remaining HL115-075 work includes other failure tags and callers, higher revisions and reserve modes, independent error side channels, and the frame/transaction/persistence path to a consensus-facing result.
