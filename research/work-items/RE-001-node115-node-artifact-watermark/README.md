# RE-001: node115 node artifact update watermark and retry policy

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The watcher `0x4e4cbb0` asks the query boundary for the exact15-byte **node-artifact-2** name. Query tag1 takes an error-report/cleanup path and reaches the delay without advancing its object+8 watermark. On the other valid query outcome, the returned qword is compared unsigned with that watermark. A value less than or equal to the watermark skips loading entirely; only a strictly greater value proceeds.

The loader at `0x50d96c0` receives the candidate value and a formatted path. Its result tag2 likewise reports/cleans up and reaches the delay without a watermark write, so the same candidate remains eligible on a later query. A non-error load proceeds through `0x50de520`; that boundary's nonzero return enters an unwrap failure path instead of the ordinary retry delay. Thus query/load failure and parse failure have distinct continuations.

After the successful parse and visible cleanup/initialization paths normally return, the watcher writes the candidate value into object+8 **before** invoking the named **update_node_artifact** callback. It does not inspect a callback success flag before advancing the watermark. This makes publication ordering visible to a reconstruction: an exceptional update callback would be entered after the new watermark had already been stored. It does not prove that the callback can fail, that the resulting state persists across unwinding, or that any live artifact is skipped.

The retained body includes nested cleanup and sleep context. The claimed projection stops at these helper boundaries; artifact decoding, state application, actual filesystem/network behavior, cleanup completeness, delay duration and public types are unresolved. The target and all altered copies remain unexecuted.

Relations cover unsigned edge values including the high bit, query/load tags and parser outcomes. Three actual changes distinguish query error selection, equality at the watermark and loader error selection. Prior #928 covers artifact-cache naming/consumers, and #23 is storage ownership/fixture context; neither establishes this query/load/parse/commit ordering. The exact node-artifact-2 and update_node_artifact names had no prior PR match in the audit.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| watcher | `0x4e4cbb0..0x4e4d69b` | 2795 | 567 |

The denominator is 1 complete FDEs, **2795 bytes /567 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **53 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-node-artifact-watermark/export_disassembly.py
python3 research/work-items/RE-001-node115-node-artifact-watermark/verify.py --controls
python3 research/work-items/RE-001-node115-node-artifact-watermark/relations.py
python3 -m unittest discover -s tests -p test_node115_node_artifact_watermark.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
