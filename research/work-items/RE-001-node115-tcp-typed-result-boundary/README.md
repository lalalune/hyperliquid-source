# RE-001: node115 TCP typed-result and owned-buffer boundary

Component: transport. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The outer reader `0x2b79e30` invokes lower transport reader `0x2b788e0` and distinguishes its first qword before entering typed decoding. Raw0x8000000000000001 returns output byte2, stores outer state3 and performs no decode or outer buffer release. Raw0x8000000000000000 is the transport-error case: after the selected nested cleanup, output byte1 and word+8 contain the supplied transport error, with completed outer state1.

Other valid lower results describe an owned frame buffer: first word capacity, second pointer, third length. The outer routine supplies pointer/length and retained context to decoder `0x2700010`. Decoder byte0x12 is its accepted result at this boundary. That path writes output byte0, copies decoder bytes1/2 into output bytes1/2 and preserves the original frame **length** in output word+8. It does not copy a decoded qword into that output word.

Other decoder tags are passed through error-conversion helper `0x2b7a0b0`, then published as output byte1 and the helper's returned word at +8. Both decode outcomes release the original frame buffer when its capacity is nonzero. Pending and transport-error routes do not use that outer buffer-release step. Output bytes1/2 on error routes are not assigned semantic meaning; the generated register values are not a recovered error payload contract.

Prior #2068/#2076 recover lower prefix, header and read behavior. #1755 reconstructs asynchronous frame I/O and leaves higher typed decoding outside its scope. This contribution addresses the outer continuation's tag conversion, length retention and release boundary. Lower framing, decoder internals, original type names and error conversion are context or opaque dependencies, not repeated claims.

Relations check all256 supplied decoder bytes over pending/error and safe buffer examples, including zero capacity and length boundaries. Changes to the pending marker increment, pending output tag and decoder-success tag alter the projection. The complete FDE, source Location, state table, call edges and byte-corruption controls remain reproducible without executing or emulating the target.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| reader | `0x2b79e30..0x2b7a0a3` | 627 | 155 |

The denominator is 1 complete FDEs, **627 bytes /155 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **15 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-tcp-typed-result-boundary/export_disassembly.py
python3 research/work-items/RE-001-node115-tcp-typed-result-boundary/verify.py --controls
python3 research/work-items/RE-001-node115-tcp-typed-result-boundary/relations.py
python3 -m unittest discover -s tests -p test_node115_tcp_typed_result_boundary.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
