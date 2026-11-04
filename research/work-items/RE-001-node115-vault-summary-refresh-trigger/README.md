# RE-001: node115 small-vault summary refresh trigger and final-query cutoff

Component: info-api. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The async request at `0x2969340` first submits the exact ten-byte `num_vaults` label. A result with AL bit0 set writes signed minimum to the outer result and stores continuation state3. After readiness it releases that boxed future, then queries `small_vault_summaries_get_len` against the cache region at owner+0x708 through its lock/wrapper region at +0x838.

**Equal counts skip recomputation. Unequal counts trigger it.** The code does not compare summary content, timestamps or a greater-than relation here. The recompute stage carries the exact29-byte `compute_small_vault_summaries` label; its signed-minimum first result word yields with inner state3 and outer state4. On readiness it releases that future and passes the result to the separately labelled `small_vault_summaries_update` wrapper before the final query. The update helper's return value is not inspected before continuing on its normal-return path.

Both routes acquire a clock result and compute a scalar using the retained calendar arithmetic, multiplication by1000 and fractional conversion. Immediately before the final query, the signed scalar is clamped to zero when nonpositive, then reduced by **7,200,000 with unsigned saturation at zero**. The `small_vault_summaries_get` call receives that cutoff and the captured request record. The millisecond/two-hour reading is an inference from those arithmetic scales; the clock and calendar helpers are not reimplemented. The local clamp/subtract rule is the measured claim.

Relations distinguish equal-count reuse from mismatched-count compute/update/query order, the two pending continuation states and cutoff equality boundaries. Complete code and source Locations are exported, including calendar and cleanup paths retained as context. The cache implementation, actual query contents, refresh failures/unwinds and scheduler progress remain unclosed.

Prior #1759 maps small-vault record selection and post-query name gating, including the final query's key/threshold behavior. This packet does not re-claim that query: it establishes the caller's refresh trigger, update ordering and cutoff supplied to it.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| request | `0x2969340..0x29698c1` | 1409 | 340 |

The denominator is 1 complete FDEs, **1409 bytes /340 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **36 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-vault-summary-refresh-trigger/export_disassembly.py
python3 research/work-items/RE-001-node115-vault-summary-refresh-trigger/verify.py --controls
python3 research/work-items/RE-001-node115-vault-summary-refresh-trigger/relations.py
python3 -m unittest discover -s tests -p test_node115_vault_summary_refresh_trigger.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
