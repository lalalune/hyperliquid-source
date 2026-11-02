# RE-004: Decimal quotient in the price conversion path of node #94

This packet establishes the zero-division precedence and three width-dependent half-even rounding branches needed to reconstruct the Decimal divide-by-two used after price aggregation, including the difference between numeric value and stored decimal scale.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only, and no reference code was copied.
- Claim status: observation for the checked bytes, FDE extents and replay results; a conditional mathematical proof for the three rounding fragments and a complete zero-test proof; the general quotient model is an inference supported by the stated vectors, not an all-input proof.
- Scope included and excluded: one Decimal quotient entry, two reached arithmetic helpers, one divide-by-two caller window, input zero/error precedence, ties at three divisor widths, output representations and finite numeric-model comparison. Other caller paths, the unvisited helper reached by two error-related paths, malformed Decimal encodings, and the complete Decimal or quantity implementation are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the standard library. No target code is executed and no external disassembler or subprocess is invoked by the generator or tests. The generator checks the full target digest before parsing. It uses `tools/elf_index.py` and `tools/fde_extents.py`; its instruction decoder and concrete evaluator are adapted from the repository's MIT-licensed `tools/decimal_scaled_u64.py`.

```sh
python3 tools/artifacts.py verify
python3 tools/decimal_quotient94.py --out research/work-items/RE-004-decimal-quotient-94
python3 -m unittest tests.test_decimal_quotient94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-decimal-quotient-94 && sha256sum -c MANIFEST.sha256)
python3 tools/decimal_quotient94.py --out <tmp-dir-a>
python3 tools/decimal_quotient94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Two generated directories compared byte-for-byte under distinct Python hash seeds and time zones.

## Evidence

All addresses below are ELF virtual addresses before load bias. The input and each FDE body's SHA-256, file offset, FDE address, instruction count and coverage are generated in `evidence.json`. `landmarks.tsv` records instruction bytes and branch destinations; `branch-edges.tsv` records both sides and the first vector reaching each side. These are generated directly from ELF bytes, not from disassembler text. FDE extents bound unwind ranges; they are not a complete census of node functions.

| Observed object | VA | End VA | File offset | Instructions reached / decoded |
| --- | --- | --- | --- | --- |
| Quotient entry | `0x4eafb60` | `0x4eb08a6` | `0x4eaeb60` | 793 / 901 |
| Limb division helper | `0x4eae280` | `0x4eae3f3` | `0x4ead280` | 80 / 106 |
| Scale-selection helper | `0x4eae400` | `0x4eae52b` | `0x4ead400` | 61 / 80 |

The divide-by-two caller window at `0x3bb843e` loads a 16-byte constant at `0x2036a0` with words `(0, 0, 2, 0)`, copies it into the second argument, and calls the entry through relocation slot `0x57762d0` at `0x3bb8460`. The first argument is loaded from a separate stack slot. On return, this window checks the output status word. It is an anchor only: this packet does not claim the entire surrounding caller or its earlier aggregation is reconstructed. The adjacent u32 table at `0x7c62ec` contains `10^0` through `10^9`.

The entry treats each input as flags and three u32 mantissa limbs. The scale byte is extracted from bits 16 through 23 and the sign from bit 31. The output is a four-byte status followed by a 16-byte Decimal on success. The decoder reads the original code; the test memory begins with a distinct sentinel, so changes on error are visible.

| Condition | Observed result | Evidence and scope |
| --- | --- | --- |
| Right mantissa is zero, including both inputs zero | status 2; payload untouched | Entry ORs all three right limbs first and branches to the status store. |
| Left mantissa is zero, right is nonzero | status 0, all 16 Decimal bytes zero | The left OR and zero store precede any flags read. |
| Success in the tested nonzero grid | status 0, numeric value matched the independent rational model | 6,427 cases; result encoding need not be minimal. |
| Numeric result cannot fit the tested model | status 1; payload untouched | 721 cases; other unvisited causes of status 1 remain unresolved. |
| Zero denominator in the grid | status 2; payload untouched | 76 cases; the entry-byte proof is wider than this grid. |

For the zero proof, the full entry window and shared return bytes are checked. A bitwise OR of three 32-bit words is zero exactly when each is zero. Thus the ordering above holds for every pair of 96-bit mantissas, independent of sign or scale bits, assuming valid memory and the stated entry ABI. The proof does not extend to arbitrary callers or malformed memory.

For the 32-, 64- and 96-bit remainder branches, `evidence.json` binds the comparison, parity and increment instruction windows. **Conditional on entry registers holding a remainder `r`, nonzero divisor `d` and the quotient parity**, with `0 <= r < d < 2^w`, each fragment increments exactly when `2*r > d`, or `2*r == d` and the quotient is odd. If the top remainder bit is set, doubling exceeds every `w`-bit divisor; otherwise the shift is exact, and unsigned comparisons select above, below or equal. The 96-bit fragment compares high and low limbs in order. An exhaustive 65,280-case 8-bit analogue checks this algebra; it does not establish the fragment-entry invariant. Separate corruption tests change the parity immediate in each of the three real paths and detect a changed tie result.

The 24 rows in `ties.tsv` exercise both signs for odd half-unit numerators across all three divisor widths. At scale 28, positive half-units 1, 3, 5 and 7 divided by two produce mantissas 0, 2, 2 and 4 respectively; this demonstrates nearest, ties to even on those paths. For an exact, larger value, `1 / 2` yields mantissa 50 with scale 2, not a canonical mantissa 5 with scale 1. `vectors.tsv` preserves flags and mantissas so equal numerical values with distinct representations remain distinguishable.

The quotient entry's conditional-edge coverage is 176 of 232 possible branch sides in this grid; its linear decode is an instruction-start hypothesis confirmed at the executed addresses, not proof that every unexecuted byte is code. The helper at `0x4eae280` reaches 18 of 32 sides, and `0x4eae400` reaches 18 of 28. The unreached sides and first reaching vector for every observed side are listed, including failure-directed branches. Some unvisited code calls another helper outside this packet; no semantics are assigned to it.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no source build, Cargo lock, compiler comparison, relocation normalization mask, or target execution. The Python evaluator interprets an allowlisted set of FDEs, checks restored callee-saved registers and stack, rejects unknown reads affecting control flow and writes outside its output/stack, and fails on unsupported instructions. Its numeric oracle uses exact rational arithmetic and selects the finest scale up to 28 whose rounded mantissa fits 96 bits. The oracle compares numeric values, not output scale or sign-of-zero representation; the target bytes in `vectors.tsv` separately retain those encodings. The oracle is a hypothesis outside the stated input grid, not an all-input equivalence claim.

The tests include altered target digest, altered zero-guard bytes, altered comparison bytes, three altered parity immediates, altered relocation target, invalid input scale, and an address outside the permitted FDEs. None runs the node. The grid uses valid input scales 0 through 28, both signs, all scale pairs for four selected mantissa pairs, and a boundary matrix around powers of two. It is neither exhaustive over 96-bit mantissas nor a proof of unreachable branches.

## Results and limitations

The generator compared 7,224 vectors: 6,427 successes, 721 status-1 results and 76 status-2 results, with zero numeric or status mismatches against the stated model. The 24 tie rows are also checked against their width-specific instruction sites. Twelve focused tests passed. The zero precedence proof and the rounding-fragment lemma are restricted as described above; the full quotient algorithm, helper closure, all error causes, canonical result scale, and whole-node behavior remain unresolved. No RE-004 progress gate is requested.

Next question: establish the unvisited helper's scaling and rounding behavior and prove the fragment-entry remainder invariants across all quotient branches before promoting the rational oracle to a complete contract.
