# RE-009: deploy-action dispatcher 0x50d3f40, pair registration 0x55c1110 and the ring-or-tree record handles (node #115)

With this packet the whole control flow of the seven-way action dispatcher `0x50d3f40` (jump table, per-arm checks, error tags, length limit 0x65, asset-number rule `100000 + n`, cleanup of the caller-owned string buffers) and of the pair registration body `0x55c1110` that its last arm reaches (index/identity/ownership/code-hash/uniqueness gates and the update-or-insert split) can be re-implemented from bytes, together with the three small handle functions it runs (`0x4da8da0`/`0x4da8e10` record accessors, `0x4da8390` vacant insert), the character searcher `0x43cd290` and the address-set lookup `0x4ef42f0`, each run as real instruction bytes in an offline interpreter and compared with a Python model on the result block, the ordered callee log and the whole fixture heap (16,000 cases, 478 negative controls, 467 detected, 11 justified as equivalent).

- Component ID: `hl-quantities` (bundle `base/l1_map/entry.rs`, `l1/exchange/impl_outcome_deploy.rs`, `l1/spot_meta.rs`; the source-file attribution is not re-verified here), advancing RE-009 state and storage compatibility
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository checkout at `a8616af9432b`; no reference source and no #94 material used
- Claim status: observation (boundaries, tags, constants, offsets, strides, call order, results of the byte-vs-model comparison) and inference (names, meaning of the stubbed callees); unresolved items are listed below
- Scope included: `0x50d3f40` (2569 bytes, 496 instructions), `0x55c1110` (220 instructions), `0x4da8da0`, `0x4da8e10`, `0x4da8390`, `0x43cd290`, `0x4ef42f0`.
  Excluded and stubbed by a recorded contract (`contracts.tsv`): every other callee, in particular the two bundle members `0x4dd59a0` (map insert, 1968 bytes) and `0x55cfe90` (8544 bytes) and the emitter `0x538cd30` (44576 bytes). No PROGRESS gate is requested.

## Reproduce

Run from the repository root with the node #115 artifact in place (the binary is never executed; the tool only reads ELF bytes and fails if the SHA-256 differs):

```
python3 tools/hl_quantities_deploy_dispatch_115.py --out research/work-items/RE-009-quantities-deploy-dispatch-115
python3 -m unittest tests.test_hl_quantities_deploy_dispatch_115
sha256sum -c research/work-items/RE-009-quantities-deploy-dispatch-115/MANIFEST.sha256
```

A regeneration took 306 s while a second one ran beside it (about 250 s alone) with a peak resident set of 205 MB; two runs with different hash seeds and time zones gave byte-identical output. Output is deterministic (fixed seeds, no clock, no dict-order dependence).
The ELF, `.eh_frame` and FDE views come from the repository's `tools/elf_index.py` and `tools/fde_extents.py`; the instruction interpreter is a copy of the shared offline x86-64 interpreter used by earlier #115 tools, extended nowhere in this packet.

## Evidence

All addresses are virtual addresses of the #115 ELF (the `.text` file offset follows from the section table).

Boundaries (`coverage.tsv`, from the FDE of each start): dispatcher `0x50d3f40..0x50d4949`, pair body `0x55c1110..0x55c157c`, accessors `0x4da8da0..0x4da8e06` and `0x4da8e10..0x4da8e76`, vacant insert `0x4da8390..0x4da8434`, searcher `0x43cd290..0x43cd582`. `body.tsv` lists every instruction with its bytes and `hits.tsv` the number of cases that execute each one.

Dispatcher (observation):
- The first word of the action is the tag. `idx = tag - 0x800000000000000d` when `tag > 0x800000000000000c`, else 5 (`cmova`), then a relative jump through the table at `.rodata` `0x91a344` (`jumptable.tsv`: seven 4-byte entries `0x50d3f8c, 0x50d4190, 0x50d40d9, 0x50d4169, 0x50d407c, 0x50d41d5, 0x50d4230`, all inside the function). Tag `0x8000000000000012` therefore shares slot 5 with every tag word `<= 0x800000000000000c`; no arm distinguishes them.
- Slot 0 (`...0d`): a String (capacity, pointer, length at action+8/+0x10/+0x18). Length `>= 0x65` frees the buffer and returns tag `0x158`. Otherwise the char searcher `0x43cd290` looks for the first `:` (needle word `0x3a0000003a`, size byte 1); the text before it (or an empty string) goes to the lookup slot `0x64e6a68`, then the full text and the looked-up value to the asset slot `0x64e69b8`. The asset number is the value when `<= 0x270f`, `value + 100000` (32-bit) when `<= 0x5f45a5f`, else `0xffffffff`; it is emitted as record tag `0x35` (`u32`, flag byte 1) through `0x538cd30`. Errors from either slot are copied whole (0x70 bytes); the buffer is freed on every path.
- Slot 1 (`...0e`): 21 bytes from action+8 are emitted as record tag `0x2d`; nothing is freed.
- Slot 2 (`...0f`): the String is checked through slot `0x64e4e58`; on error it is freed and the result copied, otherwise the 24-byte key at action+8 and 20-byte value at action+0x20 are inserted in the map at state+0x338 (`0x4dd59a0`) and the result is `0x1a2` (no free).
- Slot 3 (`...10`): length limit as in slot 0, lookup through `0x64e6c18`; `dex[0x378] == 0x8000000000000000` gives `0x156`; otherwise the flag byte at action+0x20 selects writing 2 (and replaying the elements `0x5acc8c0` returns through `0x54ca190`) or writing 0 at `dex+0x468`.
- Slot 4 (`...11`): lookup `0x55bd6b0`; `dex[0x378] == sentinel` gives `0x156`, `dex[0x408] != 0x8000000000000001` gives `0x1a1`, then the slot `0x64e6c20` answer is compared with 2 against the flag byte, and the amount (result+0x10) divided by 10000 (multiply-high by `0x346dc5d63886594b`, shift 11; a one-bit change of the constant is separated only by amounts that are multiples of 10000, which the case maker produces on purpose) goes through `0x64e6ad8` and `0x64e6c28`.
- Slot 5 (default): the whole 0xb0-byte action is copied by `memcpy` and given to `0x55cfe90` with a zeroed 20-byte value, then dropped through `0x50f1840`.
- Slot 6 (`...13`): position at action+8 must be below `state[0xb8]` (else tag `0xfa` with the position at +8); the parameter block (position, four 20-byte values) is passed to `0x55c1110`.

Pair body (observation, `branches.tsv` shows both sides of every conditional executed): position must be 0 (else `0x101`; the dispatcher's bounds check admits others), A != B (else `0x166`), both A and B pass `0x55cdd30` (flags 0 and 1), `state[0xb8] != 0` (else panic location `0x64768d8`), element 0 byte `+0x12c` must be 1 (`0x167`) and its 20 bytes at `+0x12d` must differ from D (`0x168`), the account for C must have the code hash `c5d24601...5d85a470` (the 32 bytes at `0x4537f0` and `0x452020`, which equal the default at `0x4585a0`) else `0x169`, C must not be in the address set at state+0x968 (`0x4ef42f0`: empty gives not-found, one entry is compared in place at entry+0x48, more go through the hash `0x4ef4560` and the table find `0x4eff000`; else `0x169`). Then the map at state+0x398 is searched: an occupied handle must match D at record+0x84 (`0x168`) and C at record+0x70 (`0x169`) and receives A at +0x48 and B at +0x5c; a vacant handle gets a new 0x99-byte record (two empty vectors, A, B, C, D, a zero byte) through `0x4da8390`, then `0x4da8e10` resolves it.

Handles (observation): `0x4da8da0`/`0x4da8e10` are byte-identical twins: a tree handle (node pointer != 0) designates `node + 0xa0 * index`; a ring handle (pointer 0, ring at +8, index at +0x10) designates `buf + ((head + index) mod cap) * 0xa8 + 8` with a panic (`0x9171a2`, 0x14, location `0x649cc08`) when `index >= len`. `0x4da8390` copies 0xa0 bytes and calls the ring insert `0x57ec4d0` (raising the length) or the tree insert `0x51f3910` (the record is not passed).

Callee targets of the called slots, read from `.rela.dyn` (`constants.tsv`): `0x64e4e58 -> 0x4308890`, `0x64e69b8 -> 0x421a8b0`, `0x64e6a68 -> 0x446af70`, `0x64e6ad8 -> 0x446b3f0`, `0x64e6c18 -> 0x446b070`, `0x64e6c20 -> 0x449d7f0`, `0x64e6c28 -> 0x448d090`, `0x64e6ff8 -> 0x434d930`, `0x64df4a0 -> 0x635de30`.

## Implementation and comparison

`tools/hl_quantities_deploy_dispatch_115.py` runs the real bytes of the seven functions in the interpreter and compares, per case, the 0x80-byte result area (initially filled with 0xcc), the ordered log of every callee call with the data it read, the returned register and the first 128 KiB of the fixture heap, against `dispatch_model`, `pair_model`, `record_model`, `insert_model` and `search_model`. The callees listed in `contracts.tsv` are shared by both sides (`Env`), so a disagreement can only come from the function bodies. Case sets: dispatcher 6,500, pair body 4,500, searcher 5,000 (all arms, all error tags, boundary lengths 0x64/0x65, thresholds 0x270f/0x2710/0x5f45a5f/0x5f45a60, ring wrap and range panic, haystack lengths 0 to 130 with 16 alignments, 1 to 4 byte needles, guard orders of the finger pair).

Negative controls (`controls.tsv`): for every executed instruction a single-byte mutation (condition flip, immediate low bit, or displacement low bit), replayed in two stages against 380 sampled cases and then 6000 more; a control counts as detected when any case differs in result, log, heap, return register or crash. 478 were made, 467 detected. The 11 undetected ones are listed in `equivalent-mutants.tsv` with their reason (`4 in char-search: word-at-a-time accelerator of the char searcher: a changed mask, bound, alignment or loop test only moves the hand-over to the byte loop, which finds the same first match; 6 in record-at-twin: return value of 0x4da8e10 dropped at 0x55c1537: next instruction 0x55c153c only overwrites rdi from another register; 1 in set-has: loads the found slot's index into rdx, the second return word; the only caller (0x55c131d) compares rax alone`).

Unit tests (`tests/test_hl_quantities_deploy_dispatch_115.py`, 34 tests, no binary needed) cover the tag-to-slot map, thresholds, bounds, panics, ring wrap, searcher edge cases, mutation mechanism on a tiny function, determinism and the path rule.

## Results and limitations

`measure.json`: cases 16,000, negative controls 478, detected 467, equivalent 11 (detected + equivalent = all). `coverage.tsv` gives executed/total instructions per function; instructions never executed (unwind pads, the needle size >= 5 branch of the searcher, unreachable overflow checks) are not mutated and are not claimed.

Limits:
- Everything past the contracts is assumed, not shown: the stubbed callees return random but fixed blocks. Names such as "pair", "dex", "asset" are inferences from field use.
- The bundle members `0x4dd59a0` (ring-or-tree map insert with migration after 0x20/0x40 entries, callees `0x5b76b30 0x51dcf80 0x57fc670 0x5163150 0x57ed5e0 0x51f2d60`) and `0x55cfe90` are only reached through recorded contracts; their bodies are not reconstructed. The source-file attribution of the bundle is not verified.
- The searcher's memchr slot `0x64dfcb0` and memcmp slot `0x64df9f8` are modelled by their standard meaning; the memchr path is only reached for needles of 5 or more bytes, which `str` needles never produce, so it is not executed.
- The 0xa0-byte copy in `0x4da8390` reads 7 stack bytes the caller never wrote; the log therefore compares only the 0x99 defined bytes.

Next question: the ring-or-tree insert `0x4dd59a0` (1968 bytes) that slot 2 uses for the 24-byte key and 20-byte value, then `0x55cfe90` for the default arm.
