# RE-001: node115 registry label fallback without dropping the row

Component: exchange. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The registry entry `0x2cfa1e0` constructs paired iteration over two registry storage regions and invokes collector `0x237eb90`. The new result here is the row projection in `0x22b5990`, including its resumed, freshly selected and back-iterator paths. The final sorting/deduplication/map representation is exported only as caller context.

Each row supplies a u64 identifier. The helper computes quotient `id/10000` with multiply-high constant0x346dc5d63886594b and shift11, checks it against descriptor+0x50, then checks remainder `id%10000 < descriptor+0x10`. If either check fails, or the selected label length is zero, it produces **an empty label** with capacity/length0 and pointer1. It still calls the value-copy helper and returns a row; lookup failure does not skip or terminate that row.

A valid nonempty label comes from32-byte metadata rows: pointer+8, length+0x10. The helper allocates exactly that length and uses the authenticated memcpy import to copy the bytes. It returns a96-byte row: label capacity/pointer/length at +0/+8/+0x10, then72 bytes supplied by the value-copy helper at +0x18..+0x60. The helper output's internal type is unresolved. Exhausted iteration is distinguished by first output word0x8000000000000000; an empty label's first word is0 and remains an ordinary row.

All three label-projection sites use the same quotient, remainder, namespace, bounds and zero-length rules. `relations.py` checks their operand agreement and boundary/mismatch/empty-label cases, with actual divisor, namespace-offset and bounds-branch counterfactuals. It does not execute or emulate target instructions. The arithmetic is stated for valid u64 identifiers and valid descriptors; allocation failure/unwind, generic tree iteration and final map behavior remain unclosed.

Prior #2240 recovers a Boolean short-circuit scan across paired registry collections, with opaque predicates. Its question is different from returning a labeled96-byte row and preserving it on label lookup failure. #131 is a registry source/literal/count inventory. Shared registry strides and context are not claimed as new results here.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| registry | `0x2cfa1e0..0x2cfa3e2` | 514 | 103 |
| next_row | `0x22b5990..0x22b6065` | 1749 | 427 |
| collector | `0x237eb90..0x237f0e9` | 1369 | 318 |

The denominator is 3 complete FDEs, **3632 bytes /848 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **26 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-registry-row-labels/export_disassembly.py
python3 research/work-items/RE-001-node115-registry-row-labels/verify.py --controls
python3 research/work-items/RE-001-node115-registry-row-labels/relations.py
python3 -m unittest discover -s tests -p test_node115_registry_row_labels.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
