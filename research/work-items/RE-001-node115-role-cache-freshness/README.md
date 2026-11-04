# RE-001: node115 user-role cache count and freshness admission

Component: info-api. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The request at `0x2969e50` captures a20-byte key and a12-byte clock record, then calls the exact20-byte `user_role_cache_peek` operation. A raw result byte5 takes refresh immediately with carried count0. The non-5 route reads a saved count and timestamp. Its date-adjustment boundary receives integer argument120; the complete conversion/fallback branches remain in the export, without assuming that120 has a time unit established by this packet.

After that conversion, reuse requires **count >=61 and derived expiry strictly later than the captured clock**. The expiry comparison is lexicographic: signed first DWORD, unsigned second DWORD, unsigned last DWORD. Equality of the entire triple does not reuse the cached value. This is a conjunction: even a future expiry refreshes when count is60 or less. A failed conversion's concrete fallback values are retained in the native listing; relations take the post-conversion triple as input.

For a refresh after a hit, a mismatch between the original cached packed-date DWORD and the current packed-date DWORD resets the carried count to zero. If they match, the code calls `0x1567ad0` on both timestamp records and keeps the previous count only when the returned low bytes match. The classification meaning of that helper is unresolved. This is not a proven weekday or timezone rule.

Refresh constructs one boxed future. Raw output byte5 returns pending with outer state3. Every other result is retained while the future is destroyed, then passed with the key, original captured clock and carried count to the exact22-byte `user_role_cache_update` operation. The fresh result is copied to the output and outer state1 is stored after the update normally returns. No update success flag is inspected at this boundary.

Prior #1847 recovers role selection, peek and update implementation in node94. It explicitly notes that a cache hit still enters a preexisting freshness path and does not establish that path. Here those helpers are context; the new question is the caller's count/freshness reuse rule and refresh-count provenance. Tests cover supplied role tags, count60/61, equality and lexicographic ordering, with actual threshold/branch/retention operand counterfactuals. Calendar conversion, valid source enums and runtime cache policy beyond this caller remain open.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| request | `0x2969e50..0x296a38d` | 1341 | 293 |

The denominator is 1 complete FDEs, **1341 bytes /293 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **29 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-role-cache-freshness/export_disassembly.py
python3 research/work-items/RE-001-node115-role-cache-freshness/verify.py --controls
python3 research/work-items/RE-001-node115-role-cache-freshness/relations.py
python3 -m unittest discover -s tests -p test_node115_role_cache_freshness.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
