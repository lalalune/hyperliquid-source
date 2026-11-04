# RE-001: node115 critical-message repeat suppression and count draining

Component: foundation. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The handler at `0x1509b70`, reached by the source-bound critical-message caller `0x1544990`, performs two ordered period checks against a per-key record. New records store binary64 300.0 and 1.0 in separate timer regions and initialize the repeat count to zero. Both predicates call the same boundary `0x154ce40`; its time units and internal update semantics remain opaque.

A nonzero low byte from the first predicate proceeds without calling the second and without clearing the retained count. If the first predicate returns zero, the second is called. A zero second result increments the retained count with unsigned saturation and returns signed minimum in the output's first word. The later formatting/reporting body is bypassed. A nonzero second result instead captures the previous count in a local slot, resets the retained counter to zero, then proceeds. Thus the two proceed paths have different count side effects; treating either timer as a generic reset loses information.

The real caller binds the handler to `base/src/crit_msg.rs` and enforces one flag implication before calling it: a nonzero first flag forces the second argument to1, while a zero first flag reads the separately supplied second byte. It copies48 output bytes after normal return. The full caller and handler exports preserve the locking, formatting, reporting and cleanup context without claiming those operations are closed.

The relations exercise all predicate combinations and u64 saturation edges, and change actual branch/step bytes to distinguish skip, drain and suppress outcomes. The supplied predicate results are not a simulated clock. Periods are observed numeric inputs, not measured wall-clock rates. Existing #148 explicitly leaves later occurrence/repeat/statistics behavior outside its entry-gate claim. #1878 covers initialization/configuration publication. This packet establishes the downstream repeat counter behavior, not either earlier topic.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| handler | `0x1509b70..0x150acf5` | 4485 | 861 |
| caller | `0x1544990..0x1544af2` | 354 | 98 |

The denominator is 2 complete FDEs, **4839 bytes /959 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **44 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-critical-message-repeat-throttle/export_disassembly.py
python3 research/work-items/RE-001-node115-critical-message-repeat-throttle/verify.py --controls
python3 research/work-items/RE-001-node115-critical-message-repeat-throttle/relations.py
python3 -m unittest discover -s tests -p test_node115_critical_message_repeat_throttle.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
