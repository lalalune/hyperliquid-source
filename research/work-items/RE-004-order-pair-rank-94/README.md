# RE-004: two-row quantity ranking and checked product ordering

Node #94 orders a two-row candidate path by a position-and-side predicate followed by a checked 64-bit product, placing an invalid product before a valid one and retaining ties; this fixes the comparison and overflow behavior needed for a compatible reconstruction.

- Component ID: RE-004, quantities and rounding; ordering of two candidate rows.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, a lead only.
- Claim status: observations for ELF bytes, FDE ranges, direct call, selected branch targets and field accesses; the register-level rule is a static interpretation; field names and caller-level meaning are inferences.
- Scope included and excluded: the wrapper and its worker on input lengths 0, 1 and 2, including both comparison outcomes, the pair swap, position-map miss and product boundary. The details and side effects of the position lookup helper, malformed or aliased memory, longer inputs and the general sorting implementation, all other comparator copies, node #115 and target execution are excluded.

## Reproduce

Run from the repository root with Python 3.12.3 and the standard library. The tool checks the input digest first, imports the repository's ELF and FDE parsers, and reads file-backed bytes only. No disassembler or other program is launched by the tool or tests, and the node is never executed.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_order_pair_rank94
python3 tools/order_pair_rank94.py --out research/work-items/RE-004-order-pair-rank-94
python3 tools/order_pair_rank94.py --out <tmp-dir-a>
python3 tools/order_pair_rank94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
(cd research/work-items/RE-004-order-pair-rank-94 && sha256sum -c MANIFEST.sha256)
```

`evidence.json` retains both complete FDE byte ranges, their hashes and ELF/file coordinates, and the extracted product limit. `windows.tsv` contains 15 selected instruction windows and `branches.tsv` decodes 46 manually selected conditional or unconditional targets. `length-cases.tsv`, `lookup-cases.tsv`, `flag-classes.tsv` and `pair-cases.tsv` contain synthetic static-model results, not executions of node code. The manifest hashes all retained evidence and this record.

## Evidence

The source image is node #94; addresses are linked ELF virtual addresses, and file offsets are in `evidence.json`. The wrapper `0x44885a0..0x44886a7` directly calls the worker `0x4dba8f0..0x4dbb6d1` at `0x448863e`. The unwind index and FDE bodies agree on both extents. FDEs describe unwind ranges and alone do not establish every entrypoint or ownership.

The worker accepts a sequence of 40-byte records. Within a record it reads u64 words at offsets `+0`, `+8` and `+0x10`, and a byte at `+0x20`. It uses the `+8` word as a key in a map obtained through an external helper; a missing root or a failed lookup supplies zero. A hit supplies a 64-bit word used as signed `p` in the comparisons below. The helper itself is not evaluated. Given a well-formed returned tree, the selected code scans each node's keys as unsigned words, takes the value on equality, descends the selected child if the remaining height permits, and supplies zero on an exhausted leaf. `lookup-cases.tsv` models an empty root, a leaf, and a two-level tree with hits, misses and child choices; it does not emulate the external helper or malformed memory. Let `a` be the `+0` word, `s` the `+0x10` word and `b` the byte at `+0x20`.

For a two-record input the wrapper selects its stack scratch space and passes the small-input flag. The worker's 0- and 1-record paths return before the comparison. With length 2, it selects the comparison of records 1 and 0, computes these values separately for each, and follows the decision and possible five-word swap:

```
R = (s <= magnitude(p)) AND ((b == 0) XOR (p > 0))
P = a * s                              # unsigned, full product
V = (P <= 2^63 - 2)
K = (R, V, P if V else 0)
```

Here comparisons in `K` are ascending, and the two records are swapped exactly when `K(record 0) > K(record 1)`. `R` and `V` compare as 0 or 1. The first comparison of the size to `magnitude(p)` is unsigned; the `p > 0` test is signed. The `neg`/conditional-move sequence yields `magnitude(-2^63) = 2^63` as an unsigned word. The side-byte test treats every nonzero value alike. Both products are computed before the decision; the comparison uses the invalid flag when the high half is nonzero or the low half exceeds the limit.

| Two-row condition | Observed branch interpretation |
| --- | --- |
| Different `R` values | `R=0` is first; product validity does not decide the pair |
| Same `R`, one invalid product | invalid product is first |
| Same `R`, both products valid | smaller product is first |
| Same `R`, both products invalid | no swap |
| Same `R`, equal valid products | no swap |

The threshold is read from the immediate at `0x4dbacfd` as `9223372036854775806`. Equality with the threshold is valid; threshold plus one is invalid. `mul` sets overflow when the high 64-bit half is nonzero, and the following unsigned test rejects a low half above the threshold. Since that threshold is below `2^64`, these two conditions together are exactly `P > 2^63-2` for every pair of u64 operands. There is no division or fixed-point rounding in this selected comparator. Invalid products are an ordering class here, not saturation to the threshold.

The zero cases are material. A missing position supplies `p=0`; then `s=0` and `b=0` set `R=1`, while a positive `s` sets `R=0`. At `p=-2^63`, `b=0` and `s=2^63` set `R=1`; increasing `s` by one clears it. The path does not establish whether such records occur in valid state.

The two-item swap moves five qwords per record, including the word at `+0x18` and all eight bytes beginning at `+0x20`. The model therefore checks the full 40-byte records rather than fabricating values for opaque bytes. Lengths 0 and 1 perform no comparison. Allocation behavior for larger lengths, recursive sorting and later uses of the rows are outside this bounded question.

### Inferences

The row layout, position-key lookup and the reference's size and price concepts suggest that `s` is a quantity and `a` is a price-like factor, with `R` a direction-sensitive size predicate. Those labels and the unit of `a*s` are not independently proved; the results above are stated in terms of byte offsets and integer operations. In particular, this path does not prove that a side byte is restricted to 0 or 1, nor that either product is a monetary amount. The position map is assumed valid and stable over the two lookups.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Code/data/call-target and whole-ELF comparison: not yet measured. `lower_instructions` is a manually lifted flag-level interpretation; `oracle_key` independently constructs an unbounded-integer tuple. The generator also models 18 hit/miss and descent cases on synthetic trees. It compares the ordering models on 144 abstract flag/order combinations and 324 synthetic pairs, retaining both full input rows, position values, product limbs, class bits, swap decision and modeled resulting rows. A map lookup outcome is supplied as a fixture; this is not a complete emulator or a target execution. The full-domain statements above follow from the instruction operations and arithmetic inequalities, not from claiming exhaustive dynamic tests.

## Results and limitations

The generator validates 2 FDEs, 1 direct call, 15 instruction windows, 46 selected branch destinations, 4 length-model cases, 18 lookup-model cases, 144 abstract flag/order combinations and 324 pair-model cases (142 swaps, zero disagreements with the integer oracle). Twenty-four focused tests passed with no skips, including changed input digest and code, changed branch opcode and displacement, an incorrect cap, swap and tree-opcode corruption, malformed synthetic trees, unbacked and NOBITS addresses, `-2^63`, zero, non-boolean side bytes and exact product-boundary controls. The models do not run the target and do not cover the behavior of arbitrary map helpers, floating-point environment, price scale, other lengths, recursion, or the full node. No progress gate is requested.

Next question: identify an independently unclaimed producer of the two record words and establish the quantity and price scales before this ordering path.
