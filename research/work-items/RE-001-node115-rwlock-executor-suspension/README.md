# RE-001: node115 rw-lock adapters and executor suspension boundary

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

Two rw-lock-associated adapters, `0x4e462b0` and `0x4e47060`, wrap different opaque core operations. The first returns a scalar; the second supplies a separate output buffer. Their actual Location binds net_utils/src/rw_lock.rs. They share the same measured executor-state policy, while using different preflight and core callees. This packet does not reconstruct the lock implementation or claim thread safety.

A zero mode argument bypasses preflight and invokes the core directly. Nonzero mode initializes two output bytes to zero and calls its preflight. A nonzero returned pointer reaches a formatted failure boundary. A zero return with first output byte0 again invokes the core directly. A nonzero first byte enters the suspension path; preflight internals and the meaning of its second byte remain opaque supplied boundary results.

After obtaining valid thread-local context, the adapter saves the word at TLS+0x44 and clears its first byte. It reads the executor byte at+0x46. Existing value2 reaches **asked to exit when not entered** before the core. Otherwise it stores2, retains the original executor byte, and invokes the core. On normal return it reacquires the context and requires its executor byte still to equal2. Any other value reaches **closure claimed permanent executor**. A missing context takes its separate failure boundary.

The ordinary return restores the original executor byte. If the TLS state is unavailable (raw2), it returns without the budget helper; otherwise it calls `0x5cfa9d0` with the saved word and retained preflight byte, unless the observed executor state is2. The claim is this helper invocation and its inputs, not that all budget/scheduler state has been proven restored. Full exports include unwind cleanup, but the local relation covers normal core return and explicit failure guards.

Relations enumerate the mode/preflight/TLS/executor combinations for both adapters and verify the shared policy. Real suspension-value, return-guard and restoration-skip changes alter the trace. Earlier #9/#37/#1123 contain release-drift source inventories, not this behavior. Shared Tokio/runtime diagnostics alone are not treated as recovery of original source types or a concurrency proof.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| scalar_adapter | `0x4e462b0..0x4e46594` | 740 | 159 |
| output_adapter | `0x4e47060..0x4e4734c` | 748 | 161 |

The denominator is 2 complete FDEs, **1488 bytes /320 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **31 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-rwlock-executor-suspension/export_disassembly.py
python3 research/work-items/RE-001-node115-rwlock-executor-suspension/verify.py --controls
python3 research/work-items/RE-001-node115-rwlock-executor-suspension/relations.py
python3 -m unittest discover -s tests -p test_node115_rwlock_executor_suspension.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
