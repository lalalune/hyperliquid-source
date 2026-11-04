# RE-001: node115 rejection greeting send continuation and cleanup

Component: transport. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The node connection continuation `0x5a645e0` constructs an encoded message with the exact **connection_limit_checks error** label and raw initial tag0. Its nested send descriptor receives binary64 60.0, the owner, encoded pointer/length and initial state0. The meaning or units of that parameter remain opaque. This packet does not reconstruct the connection-limit decision that caused entry.

Polling boundary `0x5ab6ce0` returns status and an optional error pointer. Valid status1 is pending: the continuation stores nested/outer state3 and retains the message and owner resources. Valid status0 completes the send attempt. The measured path performs selected nested cleanup and releases the encoded buffer when capacity is nonzero, then tests the error pointer. A zero error skips reporting. A nonzero pointer is formatted while holding the owner-associated lock; a formatting failure reaches a fatal boundary before the report. Normal formatting calls `0x4e3d890` with **could not send rejection greeting** and the retained dword at +0x498, then unlocks and drops the error.

Both ordinary terminal outcomes call the owner and secondary cleanup boundaries, release their reference and set outer state1. This is a continuation/order contract, not proof that a greeting reached a peer, that the lock is race-free or that every unwind path is closed. The complete body retains unwind context, while relations deliberately cover normal-return helper outcomes and supplied formatting failure.

Relations cover valid pending/ready statuses, null/non-null error pointers, every supplied formatting byte and zero/nonzero buffer capacity. Actual pending-tag, error-gate and formatting-gate changes alter the trace. Earlier greeting transport work #1755/#1912 concerns frame exchange and initial reply routing, not this labeled rejection continuation. No prior exact-label/address semantic claim was found.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| sender | `0x5a645e0..0x5a64a92` | 1202 | 260 |

The denominator is 1 complete FDEs, **1202 bytes /260 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **30 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-rejection-greeting-continuation/export_disassembly.py
python3 research/work-items/RE-001-node115-rejection-greeting-continuation/verify.py --controls
python3 research/work-items/RE-001-node115-rejection-greeting-continuation/relations.py
python3 -m unittest discover -s tests -p test_node115_rejection_greeting_continuation.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
