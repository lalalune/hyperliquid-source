# fees: reconstruct node #115 fee-credit caller 0x3c10000 as an executable model and replay it against the machine code

- Component ID: fees (consumer of RE-004 amount scaling; calls the fee credit distribution 0x3c1ae50 packet)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository head at authoring time (`git rev-parse HEAD` of the checkout); the reference tree under `references/can1357-hl` was not copied and supplies no names here
- Claim status: observation for the control flow, offsets, constants and helper-call order (replayed from the bytes); inference for the names and for the helper contracts
- Scope included and excluded: the whole function at 0x3c10000..0x3c1128e (4,750 bytes, one FDE, 1001 instructions) from entry to return, every panic exit, and the 18 distinct callees (17 stubbed, the ring search real) and 8 imported slots it uses. Excluded: the bodies of 16 helpers (they are served by a seeded oracle with an argument-checking contract; the ring search 0x45547e0 runs for real) and the body of 0x3c1ae50 (separate packet). No progress gate is requested.

**What this packet lets a reimplementation do.** The function is now a runnable Python reconstruction (`model` in `tools/fees_credit_caller_115.py`) that says, for one tracked fill row, which amount is credited (priced amount, scaled amount, or a looked-up amount times a multiplier, each clamped), how that amount becomes the mode value (as is, one fifth, or an f64 factor with saturation), which owner class the row has, which ledger cells and tally cells are credited in which order with which saturating adds, when the 128-bit-reciprocal division by 1,000,000 applies, what argument block the fee-credit distribution call receives (including the cloned vector and its release afterwards), and which exits panic with which operands. The model and the original bytes agree on the helper-call trace, the panic, and every heap byte for 12,000 generated cases, and 116 of 117 deliberately wrong variants are caught (1 proven equivalent).

## Reproduce

Working directory: repository root; Python 3 standard library only; the binary is only read as bytes (SHA-256 checked first), nothing is executed.

```
python3 tools/fees_credit_caller_115.py --out research/work-items/fees-credit-caller-115
python3 -m unittest tests.test_fees_credit_caller_115
python3 tools/artifacts.py verify
```

The generation takes about 80 seconds and under 400 MB; it is deterministic (two runs with different hash seeds and time zones are byte-identical; `MANIFEST.sha256` lists the SHA-256 of every file). The tool needs no external program.

## Evidence

Coordinates: virtual addresses of the ELF image; the function is the single FDE starting at 0x3c10000 and ending at 0x3c1128e (`functions.tsv`, `tests` assert it). `coverage.tsv` lists every one of the 1001 decoded instructions with its executed flag; `unexecuted.tsv` lists the 21 that no case reaches and why (alignment padding, the unwrap-failure exit that cannot occur because every amount source is clamped below 2^63, and the landing pad after the never-returning allocation-error call).

Arguments (System V): rdi = A (fee state), rsi = B (fill step with two 0x128-byte side blocks), edx = side (0 or 1), rcx = C (ledger). Offsets below are observed accesses; the names are inferences.

| object | offset | use |
| --- | --- | --- |
| A | +0x18 / +0x20 | row table pointer and count; row = 32 bytes, +0 owner, +8 key |
| A | +0x350/+0x358, +0x338/+0x340, +0x210/+0x218 | three B-tree sets of u64 (keys at +8, u16 length at +0x62, edges at +0x68): priced keys, owners with a value, special owners |
| A | +0x298..+0x2b0 | value store: either a B-tree map (marker 2^63 in +0x298; keys +8, values +0x60, u16 length +0xba, edges +0xc0) or a ring of (key,value) pairs (+0x298 capacity, +0x2a0 pointer, +0x2a8 head, +0x2b0 length); miss falls back to the hash lookup slot 0x64e7168 |
| A | +0x1c8 | f64 factor for mode 2 |
| A | +0x58/+0x60/+0x68, +0xe8/+0xf8 | two position tables (24-byte records, owner at +8, link at +0x10) that classify the owner |
| A | +0x370/+0x388/+0x3a8, +0x4d0 | tally map, its probe table and hasher words; totals map |
| B | +0x250/+0x258/+0x260 | price, row index, multiplier |
| B | block at +0 and +0x128 | +0x38 kind (2 = nothing to credit, bit 0 = subtract offset), +0x40 offset, +0x98 amount, +0x60/+0x78 optional threshold (2^63 = none), +0x68/+0x70 vector to clone (32-byte elements), +0x80, +0x48, +0x58, +0xa0, +0xa8 copied words, +0x100 20-byte key |
| B | +0x278, +0x284 | 32-bit kind for the per-kind tallies, flag byte compared with side |
| C | +0xb0, +0xb8, +0xc8, +0xe8/+0xf0 | ledger map, probe context, table, hasher words |

Flow, in the order the bytes execute it (each step is a section of `model`):

1. Bounds check of the row index (panic exit at return address 0x3c1121b with the index and the count). Amount: if the row key is 0 or in the first set, `r14 = price * multiplier` (zero when the 128-bit product overflows or exceeds 0x7ffffffffffffffe), the value store gives the token value, the scaler 0x434f660 returns (ok, scaled), and the amount is `scaled` only when ok and scaled < 0x28f5c28f5c28f5c, else `r14`. Otherwise the owner is looked up in the second set and the amount is `value * multiplier` (same clamp) or 0.
2. Mode query 0x3d4e450: 0 keeps the amount, 1 divides it by 5 (the byte sequence is a multiply by 0xcccccccccccccccd then `shr 2`; my first model said 10 and the comparison caught it), anything else converts through f64: a negative amount would panic (unreachable here), amount times the factor at A+0x1c8, non-finite results give 0, the result is clamped to [-2^63, 2^63], truncated, forced to 0x7fffffffffffffff above 9223372036854774784.0 and to 0 when not positive.
3. Tallies: `Q = hi(amount * 0x431bde82d7b634db) >> 18` and `X = hi(mode_amount * 0x431bde82d7b634db) >> 18`, i.e. division by 10^6.
4. Owner class flag (1 = plain user): 0 when the owner is in the third set or when the position tables resolve it (one-element table compared directly, larger tables through hash 0x47172c0 and the probe 0x3ed2180; the second table through 0x3ed2280; an index at or past the count panics at 0x3c11256).
5. If the side block kind is not 2: the other side's key is credited X in the ledger (only when the flag is 0 and the metric `amount - offset` (offset subtracted only when kind bit 0 is set) exceeds the threshold), then this side's key is credited X (also when the flag is 1); each credit is hash 0x4717440, probe 0x3ee6280, entry 0x4717c50 (occupied or vacant), inner entry 0x3cd7aa0 by row key, then a saturating add that calls the overflow recorder on carry. The argument block for 0x3c1ae50 (tag, offset, three words, optional 16+4 bytes, optional cloned vector: allocate 32*len bytes, copy, free afterwards, capacity-overflow and allocation-failure panics) is built and passed.
6. Tallies per record (this side, plus the other side when the flag is 0 and the metric test passes): with the raw mode amount below 1,000,000 only Q is added to the tally cell +0x48; otherwise X to +0x40, Q to +0x48, and X to a per-kind pair cell indexed by the record flag. Finally the totals pair (X, Q) is credited when the flag is 1 and side is 1, or when the flag is 0 and the metric test passes.

Raw evidence files: `trace-sample.txt` (first 40 cases, every helper call with its arguments), `events.tsv` (helper calls by kind over all cases), `panics.tsv`, `constants.tsv` (the three f64 bounds as bits), `functions.tsv` (helper addresses, roles, FDE ends), `cases.tsv` (every 6th case with a trace digest).

## Implementation and comparison

`tools/fees_credit_caller_115.py` carries (1) the shared x86-64 interpreter, (2) the oracle `World` (hash, probes, entries, cells, scaler, mode, position probes, allocator and the overflow recorder; each stub is argument-checked because it logs its decoded arguments and the model must log the same ones), (3) `model`, the reconstruction, (4) `gen_case`, a seeded builder of a complete heap image (trees of height 0 to 2 with stale keys past the node length, rings with wrapped heads, counters near the u64 ceiling, boundary amounts), and (5) the negative controls. A case passes only if the interpreter run and the model produce the same status (including the panic return address and operands), the same sequence of helper calls with arguments (the distribution-call block is compared under the mask of the words that the model defines), and the same heap bytes. One third of the cases run with a zero-filled stack, the rest with a marked stack, to expose reads of uninitialised locals.

Negative controls (117): 15 wrong model variants (`BUG_TEXT`), 100 byte mutants of the function (condition flips, immediate flips, add/sub swaps, removed stores), and 2 corrupted inputs (wrong binary digest, damaged heap byte). 116 are detected; 1 byte mutant(s) are proven equivalent (`equivalent-mutants.tsv`). `controls.tsv` records the case that first caught each.

## Results and limitations

- cases: 12,000, mismatches: 0; statuses ok 11,066, panic 934; instructions executed 980 of 1001.
- negative controls: 117, detected 116, equivalent 1 (see above).
- Limits: the helper bodies are not reconstructed, so what is proved is the function's own logic and its calling contract: argument values, order, count of calls and the memory it touches. The key hashed by 0x4717440 is read as 20 bytes; whether the callee also reads the flag byte that follows it in the tally records is not shown. The entry helpers' occupied/vacant record layout (tag, table, hash or pointer, key copy) is inferred from what the code stores. The names (`fee`, `ledger`, `tally`) are inferences. The unwrap-failure exit is unreachable only under the clamps found in this function; it was not executed.
- No component gate is requested.

Next question: the bodies of the two probe tables and entry helpers (0x3ee6280/0x4717c50 and 0x3ee69c0/0x4717fb0, hashbrown over a 20-byte key), then the scaler 0x434f660 inside this caller's contract.
