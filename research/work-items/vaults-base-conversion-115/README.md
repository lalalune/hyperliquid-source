# vaults: reconstruct the base conversion loop 0x3beb980 with its per-entry amount body 0x448b800 and B-tree step 0x37c5ba0 on node #115

This packet reconstructs, from the node #115 bytes, the complete contract of the amount accumulation body at 0x3beb980 that the vault amount helper 0x44a9430 reaches through a stored code pointer: how a map of 64-byte parameter rows (a ring buffer or a B-tree, chosen by one niche word) is walked in order, which rows are skipped, how each key selects an amount word of a second array by `key % 10000`, how the per-entry body 0x448b800 turns a row, an amount word, a mode byte, a cap byte and a context word into five numbers, and how four saturating accumulators with two distinct overflow locations absorb them. A Rust port can now take `spec_loop` and `amount_spec` in `tools/vault_base_conversion115.py` as its oracle: 11,866 cases, every result and every overflow event identical to the real bytes.

- Component ID: vaults (area: vault and sub-account amount arithmetic; follow-up of the vault amount helper work in this component)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied. The evaluator core (decoder, memory, scalar operations) is adapted from the repository's `tools/funding_rate115.py`; the imul flag handling was fixed here.
- Claim status: observation (behavior of the #115 bytes under a byte evaluator) plus inference (names and roles, listed under Results and limitations)
- Scope included: body 0x3beb980 (994 bytes, one FDE), per-entry body 0x448b800 (359 bytes, one FDE, run as real code through the pointer slot 0x64e95d8) and B-tree step 0x37c5ba0 (548 bytes, one FDE, real code) with the ring-buffer path inside the loop body. Scalar stubs: the overflow event slot, the two panic slots and the three slots behind rounding modes 2 and 3. Excluded: those stub bodies (0x4524e40, 0x1680cbf, 0x1680c10, 0x3c43150, 0x38b54b0, 0x38b5300), the 37 indirect callers (listed, not proved), any live parameter.

## Reproduce

From the repository root (the binary is the linked read-only `artifacts/node/115/hl-node`; nothing is executed):

```sh
python3 tools/vault_base_conversion115.py --out research/work-items/vaults-base-conversion-115
python3 -m unittest tests.test_vault_base_conversion115
```

The tool checks the SHA-256 first and fails on any other image. A run takes about 70 s and about 280 MB of resident memory; the test file takes about 17 s. Output is deterministic (no clock, no random source, no absolute path; two runs with different hash seeds and time zones into different folders compare equal with `diff -r`). `MANIFEST.sha256` lists every file of the folder except itself. The tool imports `tools/fde_extents.py` and `tools/elf_index.py` for sections and FDEs and calls no external program. The tool exits non-zero if any case differs from the rule list, if a byte edit survives without a written reason, or if a written reason is stale.

## Evidence

Coordinates are virtual addresses of the #115 image; file bytes are reached through the section table (NOBITS sections are refused).

- `owner-fields.tsv`: every displacement used through a base register by the three bodies (stack accesses excluded), taken from decoded operands: map words +0/+8/+0x10/+0x18/+0x48, array header +8/+0x10, row fields +0/+4/+8/+0x10/+0x38, result words +0..+0x28, B-tree node words +0x2c0 (parent), +0x2c8 (keys), +0x320 (parent index), +0x322 (length), +0x328 (edges).
- `pointer-slots.tsv`: the seven relocation slots the bodies use, with the FDE size of each target: 0x64e6d20 -> 0x3beb980 (this body), 0x64e95d8 -> 0x448b800 (run as real code), 0x64e4ea8 -> 0x4524e40 (overflow event), 0x64df620 -> 0x1680cbf (bounds panic), 0x64df830 -> 0x1680c10 (unwrap panic), 0x64e6dc0 -> 0x3c43150, 0x64e8ba8 -> 0x38b54b0 and 0x64e9508 -> 0x38b5300 (the three slots behind modes 2 and 3).
- `locations.tsv`: the three source locations the overflow events name, decoded from the Location records: 0x64765b8 = `l1/src/qtys/mod.rs:834`, 0x64765d0 = `l1/src/qtys/mod.rs:833`, 0x648ba50 = `l1/src/qtys/impl_ntl.rs:70`.
- `jump-table.tsv`: the five-entry jump table at 0x7cf4cc used by 0x448b800 with each target (all inside the body).
- `direct-callers.tsv`: rel32 call/jump sites into 0x3beb980 and 0x448b800: none. `slot-callers.tsv`: the 39 `call *slot(%rip)` sites that go through 0x64e6d20 (this body) or 0x64e95d8 (the per-entry body), with the owning function. 37 sites call this body from 34 distinct owners (the vault amount helper 0x44a9430 among them); two sites call the per-entry body: 0x3bebbaf inside this body and 0x3beb901 inside the sibling 0x3beb700, which therefore also uses the same amount rule.
- `function-rows.tsv`: every decoded instruction of the three bodies with the number of case-runs that reached it (425 of 467 distinct instructions are reached). `branch-coverage.tsv`: every conditional jump with its taken and not-taken counts over all runs.
- `reciprocal.tsv`: for 32 edge keys, the quotient by the multiply-high constant 0x346dc5d63886594b followed by a shift of 11, the exact quotient by 10000 and the remainder; all agree.
- `outcomes.tsv`, `cases-sample.tsv` (every 6th loop case: expected result, event count, distinct instructions reached), `amount-grid.tsv` (all 1,400 combinations of the per-entry body: expected words, event count).
- `variants.tsv`, `structural-controls.tsv`, `mutants.tsv`, `equivalent-mutants.tsv`: the negative controls.

Reconstructed behavior. Notation: M is the map argument (rsi), A the row array header (r9), c the context word (first stack argument), f the flag byte (dl), m the mode byte (cl), k the cap byte (r8b).

Loop 0x3beb980:

1. Shape. M+0 equal to 0x8000000000000000 (the `neg` overflow test at 0x3beb99a) selects a B-tree: root M+8, height M+0x10, length M+0x18; a null root gives an empty walk. Any other M+0 is the capacity of a ring buffer of 72-byte entries (key word, then the 64-byte row) at M+8 with head M+0x10 and length M+0x18; a head not below the capacity is reduced by one capacity (0x3beb9db) and the entries are walked as two slices, first slice then second, in logical order.
2. Start. Both signed accumulators a0 and a3 start at the word M+0x48; the two unsigned accumulators a1 and a2 start at zero.
3. Walk. Ring entries are visited in logical order. B-tree entries are visited in ascending key order by the real step 0x37c5ba0, which counts down the length word and returns null when it reaches zero.
4. Skip rule (0x3bebb13..0x3bebb21). If the low byte of f is zero and the first dword of the row is not zero, the entry is skipped. Only the low byte of f counts (a set bit above bit 7 does not disable the skip); only the low dword of the row word counts.
5. Index (0x3bebb53..0x3bebb76). i = key mod 10000, done by a multiply-high with 0x346dc5d63886594b, a shift of 11, a multiply by 10000 and a subtract. If i is not below A+0x10 (array length) the body writes the four accumulators to the result and calls the bounds slot (panic); otherwise the amount word is the qword at A+8 + 96 i + 0x20.
6. Call. The 64-byte row is copied to the stack and the per-entry body is called through slot 0x64e95d8 with (result pointer, row copy, amount word, m, k, c).
7. Accumulate, always in this order: a0 += w1 (signed), a1 += w2 (unsigned), a2 += w3 (unsigned), a3 += w4 (signed) where w1..w3 are result words +8, +0x10, +0x18 and w4 is result word +0x20 if the flag word of the result is nonzero, else zero. A signed overflow raises one event with location 0x64765b8 and saturates to INT_MAX when the added word is positive, else INT_MIN; an unsigned overflow raises one event with location 0x64765d0 and saturates to 2^64-1.
8. Result: (a0, a1, a2, a3) in four qwords. The body writes nothing else on the heap.

Per-entry body 0x448b800 (row R, amount word v, m, k, c):

1. p = v * R[+0x10] as signed 64-bit. v with bit 63 set (negative) or a signed overflow of the product calls the unwrap slot (panic). a = |p| (|INT_MIN| = 2^63).
2. Mode m selects the quotient q by the jump table: 0 gives 0; 1 gives a / R[+4] (unsigned 32-bit divisor); 4 gives a / min(R[+4], k); 2 and 3 call the slot 0x64e6dc0 with (scratch, c, dword R[+0x38]) and then the slot 0x64e8ba8 (mode 2) or 0x64e9508 (mode 3) with (scratch, a), q being the returned word. A zero divisor is a hardware division fault (no check exists in the bytes). Modes 5 and up index outside the five-entry table and are not modelled.
3. If the first dword of R equals 1: s = p + R[+8] with signed saturation (event location 0x648ba50 on overflow); the result is flag 1 and words (s, max(s,0), a, R[+8], q). Otherwise the result is flag 0 and words (p, q, a); words +0x20 and +0x28 are not written.

Branch table of the loop (taken / not taken over all runs is in `branch-coverage.tsv`):

| address | decision | meaning |
|---|---|---|
| 0x3beb9a2 | `jno` after `neg` | map word equals the niche: B-tree |
| 0x3beb9cf | `je` on length | ring buffer with zero entries |
| 0x3beb9ee | `ja` | ring tail does not wrap into a second slice |
| 0x3bebaa5 | `jne` on state 2 | ring (state 2) versus B-tree step |
| 0x3bebab4 | `jne` | first slice not exhausted |
| 0x3bebaec / 0x3bebb0a | `jne` / `je` | cursor or step returned no entry: exit |
| 0x3bebb16 / 0x3bebb1b | `jne` / `jne` | flag byte set / row first dword nonzero: skip |
| 0x3bebb76 | `jae` | index not below the array length: bounds panic |
| 0x3bebbbd | `je` | result flag zero: fourth addend is zero |
| 0x3bebbf5 / 0x3bebc01 / 0x3bebc09 / 0x3bebc1a | `jo` / `jb` / `jb` / `jo` | the four saturating additions in order |

## Implementation and comparison

`tools/vault_base_conversion115.py` holds a small x86-64 evaluator (decoder raises on any unknown form; adapted from the repository's funding-rate evaluator with the `imul` overflow flags added), a written rule list (`spec_loop`, `amount_spec`) that never decodes instructions, and the harness. Cases are built into memory per run (ring buffers with every head rotation, B-trees of height 0..2 with varied chunking and parent links, a 96-byte row array, the context word as stack argument) and compared immediately; nothing is accumulated except counters, branch counts and sample rows. The loop, the per-entry body and the B-tree step run as real code; the per-entry body is also called directly by the grid.

- Cases: 11,866 = 66 named (empty and one-entry maps in both shapes, skip rule with the flag byte and its upper bits, bounds panics, key reduction at 20001/30000/2^64-1615, zero divisors, negative amounts, product overflow, offset saturation both ways, accumulator saturation, magnitude sum overflow, order dependence, all five modes, 11/12/23-entry trees of height 0..2 and four ring rotations) + 10,400 generated from a fixed seed + 1,400 direct calls of the per-entry body (5 modes x 8 amount words x 7 multipliers x 5 rows).
- Result: 0 mismatches; result words and the order of overflow, prep and rounding events compared; the heap outside the result must be unchanged after every run. Outcomes: 8,364 ok, 778 bounds panics, 972 unwrap panics, 352 division faults among loop cases, and the grid's 925 ok / 475 unwrap panics (`outcomes.tsv`).
- Negative controls: 167, detected 160, equivalent 7. Twenty-eight named wrong readings (skip rule ignored, inverted, flag ignored; index mod 9999 / 10001 / off-by-one bound; each accumulator wrapping instead of saturating; fourth addend added without the flag; start sum zeroed; second and third words swapped; event locations swapped; reversed or first-entry-only order; negative amounts allowed; wrapping product; no absolute value; mode 0 quotient one; mode 1 using the cap; mode 4 ignoring the cap or using the maximum; modes 2 and 3 swapped; offset added for any nonzero tag; wrapping offset; unclamped second word) are each refused by at least 8 cases; thirteen structural controls (wrong digest, mid-function FDE start, NOBITS address, window ending inside the body, truncated section table, missing event model, per-entry body or tree step not run as real code, int3 at the entry, reciprocal constant located and tampered, reciprocal checked on 32 edge keys, one-bit wrong reciprocal refused); and 126 byte edits of every reached conditional jump, immediate and field displacement of the three bodies, run on 420 loop cases, the named cases and every sixth grid case.
- Byte edits: 119 of 126 changed an outcome. The seven survivors are explained one by one in `equivalent-mutants.tsv` and the tool fails on an unlisted survivor or a stale entry: 0x3beba40 (zeroes the unused back handle of the iterator), 0x3bebb2b (copies row bytes 0x28..0x38 instead of 0x20..0x30; the per-entry body reads only +0, +4, +8, +0x10, +0x38), 0x3bebc31 (an address computed into a dead register on the null-entry path), 0x37c5be7 and 0x37c5d86 (iterator handle words that are rewritten before they are read), 0x37c5c25 and 0x37c5d08 (the threshold 8 versus 9 on paths entered only with a nonzero remainder modulo 8).

## Results and limitations

Machine-readable metrics are in `measure.json` (cases 11866, negative controls 167, detected 160, equivalent 7) and `evidence.json` (425 instructions reached, 126 byte edits, 119 killed, no unexplained survivor).

Observations: the behavior above for the evaluated cases; the 39 indirect call sites; the three source locations. Inferences: that m is a rounding mode and k a cap on the divisor, that the four accumulators are signed total, clamped second, magnitude and offset sums, that `key mod 10000` splits a composite asset key (a higher part and an asset index below 10000), and that the 64-byte rows are per-asset conversion parameters; these are role names from layout and arithmetic alone.

Limits. (1) The stub bodies behind modes 2 and 3 (0x3c43150 prepares a scratch object from the context word and a precision, 0x38b54b0 and 0x38b5300 are two range searches over an ordered tier container that divide by a per-tier byte; they call 0x3cd80d0, 0x4550ee0, 0x45510d0 and 0x35c14a0) are modelled by a deterministic rule that is checked for argument shape only; their bodies are the next question. (2) The unrolled descent loops of the B-tree step (0x37c5c30, 0x37c5d30) need a tree of height eight or more and are never reached (`branch-coverage.tsv` shows zero counts); B-trees are built only up to height two. (3) The panic and event slots are recording stubs; what they do after the call is outside the scope. (4) Division by zero is observed as a fault of the evaluator; the Rust-level guarantee that prevents it is not in the bytes of these functions. (5) Observation data is about 64% of the lines (the repository target is 60%, so this packet misses that target): `cases-sample.tsv` and `amount-grid.tsv` are compared records, regenerated byte for byte by the tool. No progress gate is requested.

Next question: the sibling 0x3beb700 (a second user of the same amount rule through slot 0x64e95d8), the caller 0x3beb390 of this body, and the tier lookups 0x38b54b0 / 0x38b5300 with their range search 0x3cd80d0 that decide modes 2 and 3.
