# RE-001: node115 DB conversion collector and successful-prefix publication

Component: storage. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The DB-associated collector `0x37bf120` consumes a valid aligned range of64-byte rows. Each row contributes pointer/length fields at +0x30/+0x38 to the RELATIVE-slot-bound converter `0x141e960`. The output descriptor supplies a pointer to the externally visible count, the initial count and an already allocated output buffer. This function does not grow that buffer or validate its capacity.

After conversion, the collector computes signed zero minus the first result qword and branches on overflow. Exactly **0x8000000000000000** is accepted. It copies the following16 bytes into the next output slot, advances its local completed count and proceeds to the next row. A normal exit publishes initial_count + completed_count once; empty input publishes the original count.

A non-sentinel result enters the bound unwrap failure route. Its visible landing pad releases the rejected conversion buffer when the recorded capacity is nonzero, then **publishes the successful prefix count before resuming unwinding**. The rejected row is not copied or counted. Already copied output pairs remain accounted for. A nonreturning or throwing cleanup boundary can interrupt that visible sequence; this is not a complete exception-safety proof.

Prior #2185 already studies the shared converter's short NUL scan in command construction. That converter is existing context here, not claimed again. The new question is this DB caller's64-to16-byte collection boundary and count publication on failure. #2155 studies DB-root validation and opening; its selected path does not close this collector. Source Location db/src/db.rs:629 and the converter binding are retained from actual bytes.

Relations cover input sizes0 through8, three initial counts, every first-failure position, and non-sentinel edge words. They verify copied-prefix offsets, output strides and publication counts. Real branch, pointer-offset and output-step changes produce different results. Safe input rows, preallocated output and nonoverflowing counts are premises. No converter execution, native DB operation or target emulation occurs.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| collector | `0x37bf120..0x37bf231` | 273 | 77 |

The denominator is 1 complete FDEs, **273 bytes /77 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **14 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-db-cstring-prefix-publication/export_disassembly.py
python3 research/work-items/RE-001-node115-db-cstring-prefix-publication/verify.py --controls
python3 research/work-items/RE-001-node115-db-cstring-prefix-publication/relations.py
python3 -m unittest discover -s tests -p test_node115_db_cstring_prefix_publication.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
