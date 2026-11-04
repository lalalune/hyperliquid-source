# RE-001: node115 conditional second-query construction and distinct pending states

Component: info-api. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

Request `0x29698d0` composes two boxed queries conditionally. The first future's vtable is0x6443330, with poll slot0x6443348; the second uses0x64431b0, with poll slot0x64431c8. Both allocations request64 bytes. This packet reconstructs the caller's tag and continuation decisions, without assigning public query/enum names to opaque implementations.

First-stage result tag4 at result+0xc0 is pending: output tag4 and continuation3 preserve the first future. After a ready result the first future is destroyed before further branching. Tags3 and2 both short-circuit to outer tag3. For valid ordinary first tags0/1, only **tag1 constructs and polls the second future**. Tag0 skips it and selects output tag2 while retaining the saved first-stage payload route.

Second-stage pending is a separate DWORD discriminator2 at result+0x40. It returns outer tag4 with continuation4, preserving the second future. After readiness that future is destroyed; the code then checks a different first-qword discriminator. A ready first word2 selects output tag2. Other ready results preserve the second-stage result's leading fields and combine them with the saved first-stage payload. The two uses of2 occur at different offsets and must not be collapsed into one status test. Normal completed routes store continuation1.

The full1400-byte FDE retains both vtable bindings, allocations, cleanup and unwind paths. Relations enumerate the valid first-stage tags and independent second pending/absence classifications, with native trigger/state/default-output changes. They project control flow only: output payload meaning, complete data initialization, boxed helper implementation, original public types and cancellation behavior remain unresolved.

Prior #1759 and #1847 concern different information-query cache/selection paths. The accompanying new vault refresh and role freshness packets are also distinct callers. No prior semantic claim for this conditional second-query composition was found in the all-state title/body/path/patch and reachable-history audit. The generic boxed-future machinery is context, not itself claimed as new.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| request | `0x29698d0..0x2969e48` | 1400 | 307 |

The denominator is 1 complete FDEs, **1400 bytes /307 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **25 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-info-conditional-second-query/export_disassembly.py
python3 research/work-items/RE-001-node115-info-conditional-second-query/verify.py --controls
python3 research/work-items/RE-001-node115-info-conditional-second-query/relations.py
python3 -m unittest discover -s tests -p test_node115_info_conditional_second_query.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
