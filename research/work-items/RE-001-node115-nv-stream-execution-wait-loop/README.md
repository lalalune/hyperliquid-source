# RE-001: node115 NV-stream execution wait-loop ownership and stop ordering

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The outer waiter at `0x5a897e0` fills a gap left by the existing retained-buffer reconstruction. After its initial helper produces an ordinary nonempty buffer, it keeps a32-byte buffer descriptor and initializes a warning-period input to binary64 **60.0**. The initial helper and buffer transition algorithm remain opaque here.

Each loop iteration checks bit0 of the receiver state before calling the buffer helper. A set bit logs the receiver-closed diagnostic and exits through raw result0x39. Otherwise the existing `0x5a81650` buffer boundary is called. A non-0x44 result propagates through the error route. An ordinary0x44 result with signed-minimum first buffer word completes with raw0x44. A retained buffer instead continues waiting.

The retained path samples the clock, applies the warning predicate `0x154ce40`, and reports only when its AL is nonzero. The listing preserves the `nv stream is waiting` prefix as contextual evidence, without guessing the formatter's whole structured message. It then copies the retained32-byte descriptor back into the next iteration's buffer and builds the sleep operation with binary64 **0.01**. A nonzero sleep-poll AL stores inner state3, outer continuation3 and output tag0x45. A ready sleep releases its nested resources and loops back to the receiver-closed check. The code therefore does not immediately re-poll the buffer on a pending sleep, nor check closure only after polling the buffer.

The complete FDE retains initial admission, cleanup and unwind context. Relations begin at the inner retained-buffer loop, cover all256 closure bytes and distinguish ordinary/error/empty/pending cases. Numeric60.0 and0.01 inputs are established; time units, actual waiting, warning delivery, executor progress and cancellation correctness are not. Safe descriptor ownership and ABI-preserving helper returns are premises.

Prior #338 is a node94 Location inventory. #999 and #1567 recover the inner client-batch/retained-buffer behavior; #1567 explicitly leaves the outer poll/reset lifecycle open. This contribution closes the outer caller's stop ordering and buffer retention across the wait, without repeating the buffer algorithm.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| waiter | `0x5a897e0..0x5a8a1cc` | 2540 | 468 |

The denominator is 1 complete FDEs, **2540 bytes /468 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **38 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-nv-stream-execution-wait-loop/export_disassembly.py
python3 research/work-items/RE-001-node115-nv-stream-execution-wait-loop/verify.py --controls
python3 research/work-items/RE-001-node115-nv-stream-execution-wait-loop/relations.py
python3 -m unittest discover -s tests -p test_node115_nv_stream_execution_wait_loop.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
