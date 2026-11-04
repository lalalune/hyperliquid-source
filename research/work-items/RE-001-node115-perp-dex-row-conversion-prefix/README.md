# RE-001: node115 per-DEX row conversion with completed-prefix publication

Component: risk. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The source-bound per-DEX collector at `0x294b8d0` reads source rows with stride0x510 and writes destination records with stride0x110. Empty input publishes the existing destination length directly. Nonempty input starts at destination_base + old_length*0x110 and processes source rows in order; valid row descriptors and sufficient output capacity are premises.

A source qword at+0x378 equal to signed minimum takes a sentinel path: it writes that marker to the temporary output's first word and copies a full0x110-byte record to the next destination slot. It does not omit the row. Other bytes of that temporary are not established by this path and must not be modeled as zero. For other rows, the qword index at+0x50 must be strictly below owner+0x4640. The converter receives the source row, its+0x4a0 qword, and owner+0x4638 + index*512 +0x18. An out-of-range index enters the fatal error path with raw marker0x156 rather than calling the converter.

After either sentinel construction or normal converter return, the full record is copied before the completed-row counter advances. Normal completion publishes old_length + completed_count. The unwind landing path publishes the same completed-prefix length before resuming the unwind. A converter failure before copy therefore does not expose that row as initialized. The converter body, output semantic type and drop behavior are unclosed; this packet establishes layout, selection and publication ordering only.

#1337 studies a different positive-risk collector that filters rows and appends48-byte outputs. This collector preserves one272-byte slot for each source row, including sentinel rows, and has a different indexed converter boundary. #2570's C-string key prefix publication is unrelated. Relations exercise stride arithmetic, unsigned index bounds and failure-after-prefix counts; mutation checks change the actual strides and branch. Complete code, unwind metadata, imports and Location bindings are retained.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| collector | `0x294b8d0..0x294ba67` | 407 | 94 |

The denominator is 1 complete FDEs, **407 bytes /94 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **20 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-perp-dex-row-conversion-prefix/export_disassembly.py
python3 research/work-items/RE-001-node115-perp-dex-row-conversion-prefix/verify.py --controls
python3 research/work-items/RE-001-node115-perp-dex-row-conversion-prefix/relations.py
python3 -m unittest discover -s tests -p test_node115_perp_dex_row_conversion_prefix.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
