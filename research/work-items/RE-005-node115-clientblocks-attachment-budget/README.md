# RE-005: #115 ClientBlocks attachment-vector budget

The [ClientBlocks grammar packet](../RE-001-node115-client-block-success-grammar/README.md) maps the attachment vector and its hash/blob elements but leaves full budget accounting open. This packet adds the selected **40-byte attachment-vector** reservation, callback and failure ordering and binds it to the independently studied nested blob. It is distinct from open [#5061](https://github.com/lalalune/hyperliquid-source/pull/5061), which analyzes the outer 16-byte Client vector, and [#5062](https://github.com/lalalune/hyperliquid-source/pull/5062), which analyzes one byte-blob reader. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses; captured instructions are neither executed nor emulated.

## Binding and reservation

The earlier grammar packet identifies `0x5ab7f10 -> 0x4fbad90` as a selected Client decoder route. The child preserves its state argument into `0x4fbad90`, which saves it in a callee-saved register and, at `0x4fbaec1..0x4fbaed0`, supplies callback `0x4e04e90`, the saved state pointer, and result storage to vector helper `0x5824840`. On each selected element iteration the helper passes that same saved state to its callback. The callback's selected hash-success arm in turn calls blob helper `0x5824b60`. These are conditional call bindings, not proof of a live response or a complete Client decoder.

After the vector count reader has returned tag `0x12`, let `N` be its returned qword, `C` the then-current state `+0x20` qword, and `L` the limit at `+8`. Earlier count-reader and Client-header charges are not included in this starting `C`. When the qword at state `+0` is zero, this helper skips its own reservation and per-element refund. Otherwise:

1. It forms the unsigned product `40*N`; product overflow returns byte tag 2 without a new charge store.
2. Carry from adding `C` likewise returns tag 2 without storing the sum.
3. Otherwise it stores `C + 40*N` at state `+0x20`, then compares with `L`; greater-than returns tag 2 with that sum already stored, while equality passes this gate.

The helper's initial capacity is `min(N, 0x6666)` records, at 40 bytes each: `0x6666` is 26,214 and the largest initial allocation is 1,048,560 bytes. This is an initial allocation cap, not an `N` limit. Zero `N`, after prior gates, returns raw vector triple `(0, 8, 0)` with tag `0x12` and no callback. Allocation failure and growth-helper internals remain uncharacterized.

## Callback and cross-layer boundary

Before each callback, nonzero mode checks that the current state charge is at least 40, subtracts 40, stores the result and calls the supplied callback. Smaller charge reaches a panic call. For one element, if no intervening code changes the state and the reservation passes, the local reservation and immediate refund take `C -> C+40 -> C` before the callback; this says nothing about the count-reader or the callback's own charges.

The selected `0x4e04e90` callback reads a hash and calls the blob helper. On its selected normal blob-success path and successful allocation, it stores a nonzero allocated pointer in callback output `+0x20`; on its hash/blob error paths it writes zero there. The vector tests this qword: nonzero selects the 40-byte append path; zero copies the first 32 output bytes to its error result and enters selected cleanup. The callback's blob-length charge and cursor ordering are separately analyzed in #5062; the hash reader and count readers can also affect state, so these observations must not be collapsed into a complete formula for the whole ClientBlocks message. In particular, precharge/refund at one layer does not prove the final charge after nested decoding.

## Evidence and limits

`instructions.tsv` records complete FDEs for the outer Client adapter, Client body, attachment vector, callback and blob helper. `verify.py` authenticates the target digest, five indexed FDE bounds/body hashes, 513 instruction spans, 66 pins, 12 targets and three relative relocations. Six arithmetic examples include multiplication overflow and the allocation cap; ten modified anchors are rejected. Reproduce from repository root with `PYTHONPATH=tools python research/work-items/RE-005-node115-clientblocks-attachment-budget/verify.py` using Capstone. These checks do not execute or emulate captured instructions.

Nested scalar and hash budget semantics, indirect-helper side effects, full error cursor/cleanup behavior, allocation failures, pointer aliasing, runtime reachability and cross-version equivalence remain open. No component gate is requested.
