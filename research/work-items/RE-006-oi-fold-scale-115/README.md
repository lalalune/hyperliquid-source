# RE-006: rebuild the node #115 open-interest fold, its owner, the weight collector, the ring search and the two f64 scale clamps

This packet makes the sum behind the open-interest style total reconstructable as code: it states, and proves on the bytes, exactly how the six functions at 0x37c0fd0 (fold), 0x44810d0 (owner), 0x37bfc90 (weight collector), 0x45547e0 (ring search) and 0x44811d0 / 0x44812b0 (f64 scale clamps) turn a market block, two per-key value containers and a step range into a checked i64 sum, which panics they raise, when they stop early, and how the first container is consumed afterwards. A Python specification (`fold_spec`, `owner_spec`, `collect_spec`, `spec_ring`, `scale_spec`) was written separately from the bytes, and the real bytes of all six functions run in a Python x86-64 evaluator on 15,500 generated cases with identical results; 220 byte mutations show the comparison can fail.

- Component ID: RE-006 (book transitions; open-interest arithmetic that the price-update gate and the at-cap test sit on)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied, none was needed
- Claim status: observation for every behaviour listed under Evidence (checked against the bytes by the evaluator); names and meanings under Inferences are inference; callers are unresolved
- Scope included and excluded: included are the six function bodies below, their direct callee 0x45547e0 run as real bytes, and the allocator, B-tree consumer and panic edges as stubs; excluded are the callers (see Callers under Evidence), the B-tree consumer body 0x3908620, the unwind pad 0x44def00, and any gate or progress claim

## Reproduce

Working directory is the repository root; platform Linux x86-64; Python 3 standard library only; the node binary is read, never executed; no network.

```
python3 tools/artifacts.py verify
python3 tools/oi_fold_scale_115.py --out research/work-items/RE-006-oi-fold-scale-115
python3 -m unittest tests.test_oi_fold_scale_115
python3 tools/catalogue.py --check
sha256sum -c research/work-items/RE-006-oi-fold-scale-115/MANIFEST.sha256
```

The tool checks the binary SHA-256 first and fails on a mismatch. It reads the ELF sections, relocations and `.eh_frame` through `tools/elf_index.py` and `tools/fde_extents.py`, decodes the six bodies with its own small decoder, and parses no disassembler output. Regeneration takes about 20 s and about 355 MB peak memory; the unit file runs 44 tests in about 51 s. Two regenerations are byte-identical (a test builds twice and compares every file).

## Evidence

Coordinates are virtual addresses of the target ELF; function bounds are `.eh_frame` FDE records (`functions.tsv`).

| function | start | end | bytes | role (observation) |
| --- | --- | --- | --- | --- |
| fold | 0x37c0fd0 | 0x37c132d | 861 | checked sum over a step range |
| owner | 0x44810d0 | 0x44811ce | 254 | runs the fold from zero, then consumes the first container |
| scale, floored | 0x44811d0 | 0x44812b0 | 224 | u64 -> clamped non-negative value |
| scale, signed | 0x44812b0 | 0x4481374 | 196 | u64 -> clamped signed value |
| ring search | 0x45547e0 | 0x4554901 | 289 | lookup in a sorted ring of 16-byte pairs |
| weight collector | 0x37bfc90 | 0x37bfe96 | 518 | appends the second container's value for every key in a range to a vector |

Fold (arguments: iterator {ctx, cursor, end} in rdi, initial sum in rsi, closure {first container, market} in rdx). For each cursor value `k` below `end` (the cursor is written back before the work, so a panic leaves `k + 1`):

1. `key = 10000 * [ctx + 0x50] + k`; an unsigned overflow in the multiply or in the add reaches a panic slot (`edges.tsv`: slots 0x64df870 and 0x64df520).
2. The first value is looked up under `key` in the first container. A container is a B-tree when its first word is 0x8000000000000000 (root at +8, height at +0x10: node keys at +8, values at +0x60, 16-bit length at +0xba, children at +0xc0) and otherwise a ring (capacity, buffer, head, length; 16-byte pairs, value at +8; searched by the shared function 0x45547e0). If the key is absent the value is `array[key % 10000]`, where the array pointer is at market +0x150, its length at +0x158, the stride is 0x60 and the value sits at +0x20; an index at or past the length reaches the bounds panic slot 0x64df620 with the index and the length.
3. The second value is looked up under the same key in the container at market +0xf0 (same two shapes); absent means a product of 0.
4. A negative first value stops the fold with flag 0 before anything is added. Otherwise the product `second * first` is a signed 64-bit multiply; an overflow stops the fold with flag 0 and leaves the sum unchanged. Otherwise the product is added; a signed overflow stops with flag 0 and the wrapped sum.
5. Running out of range returns flag 1 with the sum. The result pair is (flag, sum).

Owner (rdi market block, rsi first container): fold from cursor 0 to `[market + 0x10]` with initial sum 0, result pair returned unchanged. Afterwards the first container is consumed: a B-tree is walked by the dying-next function 0x3908620 until it reports nothing (the iterator holds the root, height and length twice, front and back; an absent root gives an empty iterator), a ring with non-zero capacity has its buffer released through slot 0x64df4a0 with size `capacity << 4`, a ring of capacity 0 is left alone. A panic in the fold skips the consumer.

Collector (rdi iterator {ctx, cursor, end, market}, rsi sink {pointer to the length cell, starting length, buffer}): for every cursor value below `end` it forms the same key (`10000 * [ctx + 0x50] + k`, same two panic slots), looks it up in the container at market +0xf0 (B-tree or ring, the ring through the shared search) and stores the value, or 0 when the key is absent, at `buffer[length]`, then increments the length; after the loop (or an empty range) it stores the final length through the length cell. Panics skip that store in the straight-line code (the two unwind pads at 0x37bfe76 and 0x37bfe86 store it and are not executed by the evaluator).

Scale helpers (rdi block with an f64 at +0x4e0, rsi value): the product `value * f64` is limited, converted and clamped. Non-finite products become 0.0; a product outside [-2^63, 2^63] is limited to the two constants at 0x459808 / 0x459360 (read from the bytes in `constants.tsv`); a limited value above the constant at 0x458e50 becomes the saturated integer 0x7fffffffffffffff; the integer 0x8000000000000000 after conversion raises the negate-overflow panic (slot 0x64e00c0); an absolute value above 0x147ae147ae147ae is clamped to plus or minus that bound. The floored form first returns its input unchanged when it exceeds 0x028f5c28f5c28f5c and finally floors negative results at 0.

Callers (`references.tsv`): the fold has one direct call site, inside the owner; the collector has one direct call site, at 0x3d6f307 inside the 259-byte function 0x3d6f260 (not analysed here); the ring search has 86 candidate rel32 sites across other functions (not analysed here); the owner and both scale helpers have no rel32 call or jump site and appear only as relative-relocated 8-byte entries in function-pointer tables whose neighbours are unrelated functions. The scan is a byte pattern (E8 / E9 plus displacement), so rows are candidates and a missing row does not prove no caller.

Raw files beside this record, all generated by the tool: `functions.tsv`, `edges.tsv`, `constants.tsv`, `references.tsv`, `cases-fold.tsv`, `cases-owner.tsv`, `cases-ring.tsv`, `cases-scale.tsv`, `cases-collect.tsv` (every fourth generated case of each kind, with the specified result), `outcomes.tsv` (how many cases reach each exit), `controls.tsv`, `equivalent-mutants.tsv`, `measure.json`.

## Implementation and comparison

The executable reconstruction is the specification half of `tools/oi_fold_scale_115.py` (`fold_spec`, `owner_spec`, `spec_ring`, `scale_spec`, `collect_spec`, plus the memory layout writer `Layout`); an independent Rust path is not yet implemented. Comparison: each generated case is written into the evaluator's heap (a market block, an array, two containers built as real B-tree nodes up to height 2 or rings with a rotated head, a stack iterator), the real bytes run with the shared ring search as real code and only the panic slots, the deallocation slot and the dying-next function stubbed, and the returned pair, the written-back cursor, every panic (with index and length for bounds), and every consumer call (the iterator words or the freed size) are compared with the specification. Stack balance and callee-saved registers are checked by the evaluator.

Cases: fold 4,500, owner 3,500, collector 3,000, ring search 1,500, scale 3,000 (1,500 per helper): 15,500 in total, zero disagreements. Fold exits reached: 1835 exhausted, 657 stopped early, 906 multiply panics, 397 add panics, 705 bounds panics (`outcomes.tsv`).

Negative controls: 220 byte patches on the six bodies (15 cmov, 51 disp, 80 imm, 68 jcc, 6 set); 210 are detected by at least one case, 10 are listed with a reason in `equivalent-mutants.tsv` (they are provably output-neutral: a constant that only changes a value the later clamp absorbs, a branch whose two sides convert to the same integer, a no-op extra pass of the halving loop, a store reachable only by an inconsistent ring), and none is unexplained. The unit file adds a wrong-stride specification, a patched collector branch, a wrong top constant, a corrupted digest, non-FDE and unmapped addresses, and a patched ring-search branch.

The evaluator is a small x86-64 subset that runs only these bytes; its `imul` forms set the overflow flag, which the fold depends on.

## Results and limitations

Metrics (denominators in the text above): cases 15,500, disagreements 0; negative controls 220, detected 210, equivalent 10; unit tests 44.

Inferences, not observations: the stride 10000 and the multiplier at +0x50 look like a (dex, index) asset-id scheme; the first container and the array are per-key values and the second is a per-key weight; the sum is an open-interest style notional; the market block is the per-market record the f64 at +0x4e0 belongs to. None of this changes the byte-level behaviour above.

Unresolved: who holds the owner and scale entries in the function-pointer tables, what the consumed first container is built from, the exact element type of the B-tree values beyond 8 bytes, and the unwind pad 0x44def00.

No progress gate is requested; this is a partial result for RE-006 and does not cover the component.

Next question: find the table that holds 0x44810d0 / 0x44811d0 / 0x44812b0 and the writer of the first container, so the fold can be placed in the price-update flow.
