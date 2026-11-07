# RE-014: re-prove the funding rate value body 0x44d8590 on node #115 (rule list, 24 refused readings, byte edits)

This packet reconstructs, from the node #115 bytes, the complete value contract of the funding rate body at 0x44d8590: how one asset key selects a sample vector from a two-shape store (ring buffer or B-tree), how the ordered sample sum becomes an average, how the interest term is pulled toward that average by a symmetric clamp, how a per-key multiplier, a fixed rate band and a fixed output scale turn it into the returned rate, and which lookups and refusals happen in what order. A Rust port can now take the rule list in tools/funding_rate115.py as its oracle: 12023 cases, every result and every lookup identical to the real bytes.

- Component ID: RE-014 (migration validation; area: funding rate value of the exchange state)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; lead only: the deleted #94 packet `RE-007-funding-rate-values-94` (git object `8fd8db680^`), kept on its own digest and not credited here
- Claim status: observation (behavior of the #115 bytes under a byte evaluator) plus inference (names of fields and roles, listed under Results and limitations)
- Scope included: body 0x44d8590 (0x47f bytes, one FDE) and the deque binary search 0x45562e0 (0x121 bytes, one FDE) run as real code; the B-tree descent inside the body; the three index-map lookups as recording stubs (hash 0x47172c0, probe 0x3ed2810); all constants read from the image. Excluded: the hash and the probe bodies, the callers (no direct call site exists, see Evidence), allocation, scheduling, any live parameter.

## Reproduce

From the repository root (the binary is the linked read-only `artifacts/node/115/hl-node`; nothing is executed):

```sh
python3 tools/funding_rate115.py --out research/work-items/RE-014-funding-rate-value-115
python3 -m unittest tests.test_funding_rate115
```

The tool checks the SHA-256 first and fails on any other image. It takes about 100 s and about 300 MB of resident memory. Output files are deterministic (no clock, no random source, no absolute path); two runs into different folders compare equal with `diff -r`. `MANIFEST.sha256` lists every file of the folder except itself. The tool imports `tools/fde_extents.py` and `tools/elf_index.py` for sections and FDEs, and calls no external program.

## Evidence

Coordinates are virtual addresses of the #115 image; file bytes are reached through the section table (NOBITS sections are refused).

- `constants.tsv`: seven constants read from the bytes, with the decoded instruction that references each: the sum start is negative zero, the default interest is 0x3f1a36e2eb1c432d (1e-4), the default multiplier is 1.0, the sign mask is bit 63, the rate band is -0.04 .. +0.04 and the output scale is 0.125.
- `owner-fields.tsv`: every displacement the body uses off the owner register (0x48/0x50 multiplier map, 0x90/0x98 interest map, 0xd8/0xe0 clamp map, 0x120..0x138 sample store, 0x140 default clamp, hasher words at +0x38/+0x40 of each map), taken from decoded operands.
- `pointer-slots.tsv`: relocations whose addend is one of the four addresses: 0x00000000064e7898 -> 0x44d8590 (.got). `direct-callers.tsv`: rel32 call/jump sites into them: none into 0x44d8590; 4 into the deque binary search 0x45562e0 (0x3cc8eb0, 0x3cc96d0, 0x3ce2d10, 0x44d8590); 238 into hash 0x47172c0 and 3 into probe 0x3ed2810, a generic map helper used all over the image. So the body is reached only through a stored code pointer; its caller is the next question.
- `function-rows.tsv`: every decoded instruction of both bodies with the number of case-runs that reached it.
- `outcomes.tsv`, `cases-sample.tsv`: outcome counts per store shape (btree/none 1188; btree/panic 742; btree/some 4053; deque/none 1173; deque/some 4867) and every third case (about 4,000 rows) with its expected result, the number of distinct instructions it reached and a digest of the real result and lookup log.
- `variants.tsv`, `structural-controls.tsv`, `mutants.tsv`: the negative controls.

Reconstructed behavior (key k, owner object o):

1. Sample store: word o+0x120 equal to 0x8000000000000000 selects a B-tree (root o+0x128, height o+0x130, length o+0x138; node keys at +8, values at +0x60 with stride 24 as capacity, pointer, length, key count (u16) at +0x16a, edges at +0x170). Any other word is the capacity of a ring buffer of 32-byte entries (key, capacity, pointer, length) with head o+0x130 and length o+0x138, searched by the real binary search 0x45562e0. An absent key or an empty vector returns the empty result (flag 0).
2. The samples are added in stored order starting from negative zero (the loop is unrolled eight wide but keeps the order), then divided by the signed count converted to a double.
3. Interest comes from the interest map (default 1e-4), the clamp from the clamp map (default the double at o+0x140). A map with zero entries gives the default without a call; one entry is compared with the key directly; two or more call hash 0x47172c0 then probe 0x3ed2810. A probe index not below the length reaches the bounds panic.
4. d = interest - average. If d and the clamp are both finite, d is limited to [min(c,-c), max(-c,c)] with the x86 min/max operand rules (second operand on ties and NaN); a non-finite value skips the clamp. (An empty-band assertion exists and cannot fire for a finite clamp.)
5. The multiplier map is read last (default 1.0). value = (average + d) * multiplier. A finite value is limited to the rate band, a non-finite one is kept. The result is value * 0.125 with flag 1.

## Implementation and comparison

`tools/funding_rate115.py` holds a small x86-64 evaluator (decoder raises on any unknown form; its core (decoder, memory, scalar and vector operations) is adapted from the evaluator of the BOLE rate-curve draft for #115, and the scalar double operations were changed here to use the x86 NaN rules on raw bits), a written bit-level rule list (`spec_rate`) that never decodes instructions, and the harness. Cases are built into memory per run and compared immediately; nothing is accumulated except counters and sample rows.

- Cases: 12023 total = 23 named (both store shapes, wrapped ring, empty store/vector, tree heights 0..2, full 11-key nodes, signed-zero clamp and sample pairs) plus 12,000 generated from a fixed seed (ring capacity and head rotation, B-trees of height 0..2 with varied chunking, 0..33 samples covering every unroll remainder, map sizes 0/1/2/3/5, keys present or absent, floats from zero/inf/NaN/subnormal/boundary classes, and a faulty-probe flavour that returns an index equal to the length).
- Result: 0 mismatches in 12023 runs; result bits and the order of hash/probe calls compared; the heap must be unchanged after every run.
- Negative controls: 35, detected 35. Twenty-four named wrong readings of the rule list (sum from +0 is not among them: it is unobservable, see below) such as reversed or two-lane summation, divide by count+1, no output scale, no floor/ceiling, asymmetric clamp, swapped difference, multiplier looked up first, single-entry map ignoring the key, empty vector as zero, second NaN wins, unquieted NaN, positive indefinite, min/max keeping the first operand on ties; and eleven structural controls (wrong digest, mid-function FDE start, NOBITS address, window ending inside the body, truncated section table, missing hash model, binary search not run as real code, int3 at the entry, tampered scale / ceiling / default multiplier constants). All are refused.
- Byte edits (reported separately): 115 edits of every reached conditional jump, immediate and structure displacement in both bodies, run on a 3,000-case subset; 110 changed an outcome. The survivors are 0x4556336 (immediate), 0x4556372 (condition), 0x4556374 (immediate), 0x45563aa (immediate), 0x45563e5 (immediate). Each is arithmetic-equivalent: `cmp $1` edits (0x4556336, 0x45563aa) switch between a skipped loop and a loop whose body adds zero, the `je` edit at 0x4556372 skips an `adc` whose carry is already clear when the keys are equal, and the `adc` immediates (0x4556374, 0x45563e5) only change the returned index on the not-found path, where the caller 0x44d8590 ignores the index.
- A start of +0 instead of -0 in the sum is an equivalent reading: every zero-sum route ends in +0 after the `average + (interest - average)` step, so the sign of the start is unobservable in the result; it is therefore not counted as a control.

## Results and limitations

Machine-readable metrics are in `measure.json` (cases 12023, negative controls 35, detected 35, byte edits 115, killed 110) and `evidence.json`.

Observations: the behavior above for the evaluated cases. Inferences: the roles (sample vector = funding premium samples, interest map, clamp map, multiplier map), the 24-byte index-map entry shape (hash word, key at +8, value at +0x10, used by the single-entry path and the value read), and the VecDeque / BTreeMap identities of the two store shapes, from layout alone.

Cross-check with #94 (lead only): the #94 contract text for the old address 0x3750610 states the same default interest bits, default multiplier 1.0, a sum starting at negative zero and an eight-at-a-time loop bound; the #115 bytes agree on all four. The #115 band (+-0.04) and output scale (0.125) are not in that text and are recorded here as #115 observations only. No #94 binary was used.

Limits: hash 0x47172c0 and probe 0x3ed2810 are stubs with checked arguments (hasher words, key, hash) and a model of an index map; their bodies are not proved here. The evaluator runs on Python doubles with explicit NaN rules; the rounding mode, DAZ/FTZ and exception masks are the defaults. The stored-code-pointer caller is unresolved. Observation data is about 70% of the lines (the repository target is 60%): `cases-sample.tsv` was widened to every third case to reach the scope floor, and the tool regenerates it byte for byte. No progress gate is requested.

Next question: resolve the stored pointer that reaches 0x44d8590 (the owner object builder) and the writer of the sample store.
