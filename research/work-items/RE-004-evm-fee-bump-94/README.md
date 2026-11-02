# RE-004: node 94 replacement fee-price rounding and overflow

The node 94 replacement scan compares fee-price-compatible 128-bit fields against a checked `110/100` floor, fixing the order of multiplication, overflow, division, and comparison for a future reconstruction.

- Component ID: RE-004 (quantities and rounding; EVM transaction fee-price path).
- Target release and full SHA-256: Linux x86-64 node 94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only to locate questions, not copied as implementation or treated as authoritative.
- Claim status: machine-byte observations and a conditional arithmetic proof; field and object identity across the separate paths remain an inference.
- Scope included and excluded: one row of the replacement scan, its preceding row gates, both numeric checks, their results, a separate five-variant serializer and the compatible two-stage error formatter. The complete caller, transaction decode, network behavior, whole-node equivalence, and a Rust implementation are excluded.

## Reproduce

From the repository root with the pinned target installed, Python 3 standard library and the repository's `elf_index.py` and `fde_extents.py` are sufficient. This extraction does not execute the node, call a disassembler, use a network, or require binutils. The test invocation below has no skipped tests. Validation used Python 3.12.3 on Linux x86-64; address interpretation is ELF virtual address before load bias, with corresponding file offsets recorded independently.

```sh
python3 tools/evm_fee_bump94.py --out research/work-items/RE-004-evm-fee-bump-94
python3 -m unittest tests.test_evm_fee_bump94
(cd research/work-items/RE-004-evm-fee-bump-94 && sha256sum -c MANIFEST.sha256)
```

For independent deterministic outputs, choose two empty relative directories:

```sh
OUT_A=work/re004-evm-fee-a
OUT_B=work/re004-evm-fee-b
PYTHONHASHSEED=1 TZ=UTC python3 tools/evm_fee_bump94.py --out "$OUT_A"
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/evm_fee_bump94.py --out "$OUT_B"
diff -r "$OUT_A" "$OUT_B"
```

The generator verifies the full artifact hash first, excludes fileless sections from VA mapping, imports the shared CIE/FDE parser, rejects an FDE overlapping any other FDE, checks the full hash of each selected extent, checks specific instruction patterns and resolves the relevant relocation slots. `evidence.json` retains all ten selected extents as hex bytes and their SHA-256 values, FDE and CIE coordinates; `windows.tsv` exposes the 15 manually selected code windows; `branches.tsv` gives 20 selected branch sites and decoded targets. These are byte extractions and fixed-pattern decodes, not text parsed from a disassembler. The 20 branches are the selected path, not a count of all branches in the ten extents.

## Evidence

### Variant and field observations

The serializer extent begins at `0x2430350`. Its jump table selects five tagged variants, passes the payload at tagged-base plus `0x10` to a variant-specific field serializer, and refers to the variant names in file-backed bytes. The five serializer extents begin at `0x1e650b0`, `0x1e66730`, `0x1e658a0`, `0x242c3a0`, and `0x1e67470`. For each variant, the generator follows its table entry and call, reads the named field labels, and checks the field loads. Offsets below are relative to the tagged base, rather than to the serializer's payload pointer.

| Tag | Byte-backed variant label | First 16-byte field | Second 16-byte field | Eight-byte `nonce` field |
| --- | --- | --- | --- | --- |
| 0 | `Legacy` | `gasPrice` at `0x40` | none observed | `0x70` |
| 1 | `Eip2930` | `gasPrice` at `0x50` | none observed | `0x68` |
| 2 | `Eip1559` | `maxFeePerGas` at `0x50` | `maxPriorityFeePerGas` at `0x60` | `0x78` |
| 3 | `Eip4844` | `maxFeePerGas` at `0x50` | `maxPriorityFeePerGas` at `0x60` | `0x88` |
| 4 | `Eip7702` | `maxFeePerGas` at `0x50` | `maxPriorityFeePerGas` at `0x60` | `0x78` |

A vector serializer at `0x1e478a0` calls the variant serializer for successive elements at stride `0x150`. The scanner uses a `0x160` old-row stride with a `0x10` prefix before the matching tagged base. This is additional compatible layout evidence, not a proof of a runtime handoff.

The separate scanner FDE is `[0x3428000, 0x3428462)`. It selects the same five nonce offsets, first-value offsets and second-value offsets. Old rows have stride `0x160`, and their tagged base is at row offset `0x10`; new offsets in the table use the new tagged base directly. The two 16-byte values are read as two unsigned 64-bit limbs in the arithmetic. The byte-backed labels and matching tag-dependent offsets support interpreting these as transaction fee-price fields; the separate serializer-to-scanner object handoff is not proven by these windows alone. Exact economic units and any upstream value validation are unresolved.

### Row gates, failure results, and comparison

The scanner searches a keyed collection and iterates rows. Its timestamp comparison can skip a row, and two exceptional branches lead to the time-error path. It compares a 32-byte cached value before the nonce check. If those bytes are equal, it writes outer tag `3` and payload `0`; if the variant-selected nonce differs, it continues to the next row. The path described below starts only when the preceding gates select a row with unequal cached bytes and equal nonce. `branches.tsv` preserves the selected branch conditions and destinations, including exhaustion, duplicate, arithmetic failure, and the time-error paths.

| Order | Condition | Static result |
| --- | --- | --- |
| First field | `110 * old_first` overflows 128 bits | Return tag `3`, payload `4`; division is not reached. |
| First field | Product fits, `new_first < floor(110 * old_first / 100)` | Return tag `3`, payload `4`. Equality passes this check. |
| Second field | New tag is below `2` | Continue to the next row; no second comparison. |
| Second field | Old tag is below `2`, or either effective second value is zero | Continue to the next row; no second comparison. |
| Second field | Both values nonzero and checked old product overflows | Return tag `3`, payload `4`. In this branch the quotient helper is called on the wrapped limbs before the overflow flag is tested. |
| Second field | Both values nonzero, product fits and `new_second` is below its floor threshold | Return tag `3`, payload `4`; equality continues to the next row. |
| Search exhausted | No row returned an error | Write result byte `0x21`. This is the local scan result, not a proof of whole-transaction acceptance. |

At `0x4e59850`, an independently located formatter reads an outer byte tag. Its table maps tag `3` to a tail call with the payload pointer advanced by eight bytes. A relocation at `0x5776e50` points to the inner formatter at `0x4e59f80`, whose table maps payload `0` to `already known` and payload `4` to `replacement transaction underpriced`. The result representation and formatter are byte-compatible; an actual runtime handoff between them has not been demonstrated. The generator checks both tables, the pointer adjustment, relocation, and message bytes.

### All-domain arithmetic argument

Write `B = 2^64`, `x = h*B + l`, and let `110*h = a*B + b`, `110*l = c*B + d`, with limbs and remainders in `[0, B)`. The selected bytes perform the two unsigned limb multiplications, form `b+c`, and OR the high-product overflow flag with the addition carry. The identity

```text
110*x = a*B^2 + (b+c)*B + d
```

shows that this OR is exactly the condition `110*x >= B^2` for every unsigned 128-bit `x`. Thus the largest fitting input is `floor((2^128-1)/110) = 3093476062917622395121587340288801922`; the next integer overflows even if an unbounded calculation of the divided result would fit.

For every nonnegative `x = 10*q + r`, `0 <= r < 10`, the integer coefficient identity `110*10 = 100*11` and all ten rows of `residues.tsv` imply

```text
floor(110*x/100) = 11*q + r = x + floor(x/10).
```

`arithmetic-proof.json` records the coefficient, residue and endpoint obligations. This is an algebraic all-input result conditional on the decoded bytes and the nonzero-divisor contract of the existing shared helper. The helper relocation resolves to the unsigned quotient routine previously studied in `research/work-items/RE-004-u128-division-94`; this packet does not claim new ownership or re-prove that helper. For example, a selected first-field value from `1` through `9` has an equal threshold, while `10` has threshold `11`. These are arithmetic consequences, not captured executions.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler, lockfile, build flags, two-build comparison, normalized masks, helper closure beyond the cited division contract, and whole-ELF equivalence: **not yet measured**. The generated scalar and row tables are models derived from the byte-checked lift, not target fixtures or execution traces. The row model starts after the gates named above and records continuation separately from returned error values.

## Results and limitations

The regenerated packet contains 10 selected FDE extents, 5 variant paths, 20 selected branch records, 15 raw byte windows, 120 scalar model cases, 250 row model cases covering all 25 old/new tag pairs, and 10 residue obligations. The focused suite has 23 tests, including wrong digest, missing or changed FDE, corrupted instruction, altered branch destination, altered field offset, incorrect relocation, NOBITS/out-of-range mapping, both limb-overflow mechanisms, exact thresholds and zero-bypass controls. Every row-model case is checked against a separately enumerated expected-path table for the four old/new tag classes. Two generations with different hash seeds and time zones are compared byte for byte. No component progress gate is requested.

The selected extents do not establish complete CFG reachability, the serializer's runtime object handoff, exact fee denomination, upstream field constraints, or the complete transaction acceptance path. The formatted messages are tied to compatible result layouts rather than an observed formatter call from this scan. A concrete next question is to trace the transaction object from its binary decoder through the scan and formatter while preserving the existing handler evidence and target digest.
