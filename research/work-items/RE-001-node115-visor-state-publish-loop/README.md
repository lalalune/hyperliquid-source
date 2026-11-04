# RE-001: node115 periodic visor-state observation and publication ordering

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The node-associated routine `0x5a39630` constructs a producer labeled **visor_abci_states**, then begins a loop by requesting **get_visor_state**. It obtains a separate input through `0x5942870`, passes that input and the observed state through `0x50de010`, and examines the returned word. A nonzero result enters the bound unwrap failure route before publication. The helper's parser/schema semantics are not recovered here.

On the zero-result path it frees the temporary input and invokes publication boundary `0x4e3fe00`. Only after that helper normally returns does it initialize a timespec with seconds5 and nanoseconds0. There is no initial delay before the first observation and publication. This is a cadence after work: the routine does not maintain an absolute five-second schedule or compensate for observation/publication duration.

The following imported call is bound through the ELF dynamic symbol **clock_nanosleep**. Its arguments are clock_id1, flags0, and the same timespec pointer for request and remaining time. Return0 completes the current sleep segment. Return4 (EINTR in this target Linux ABI) retries with the remaining seconds/nanoseconds. The loop also supports splitting very large seconds at signed-max, although its ordinary initial request is only5 seconds. Any other nonzero return reaches a separate failure boundary. A zero remaining timespec returns to observation immediately.

The local model supplies parse and sleep results; it never calls a clock, publication service or captured code. It checks immediate acquisition, failure-before-publication, publication-before-delay, EINTR residual retry and other-error termination. Changes to the five-second immediate, EINTR constant and parse branch produce different traces. The model intentionally does not reproduce generic timespec chunking for malformed/out-of-range OS residuals.

Prior #1138 inventories node94 Locations and binds these name strings, but explicitly leaves behavior unresolved. This contribution closes the loop's ordering and retry boundary on node115. It does not duplicate a source census, claim snapshot schema recovery, prove delivery, or infer the effects of opaque helpers.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| publisher | `0x5a39630..0x5a3983c` | 524 | 126 |

The denominator is 1 complete FDEs, **524 bytes /126 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **29 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-visor-state-publish-loop/export_disassembly.py
python3 research/work-items/RE-001-node115-visor-state-publish-loop/verify.py --controls
python3 research/work-items/RE-001-node115-visor-state-publish-loop/relations.py
python3 -m unittest discover -s tests -p test_node115_visor_state_publish_loop.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
