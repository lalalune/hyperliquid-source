# RE-001: node115 channel registration, repoll and terminal precedence

Component: transport. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The receive poll has state bytes +0x28 (outer) and +0x20 (nested). The retained four-entry signed-displacement tables bind initial/resume/completed/unwind routes. Only the encoded valid states are claimed; arbitrary state bytes are not safe inputs.

After the cooperative-budget gate, it polls queue helper `0x2ccf230` at channel+0x1a0, with the second argument channel+0x80. A raw tag other than 1 invokes the registration helper with channel+0x100 and the context, then **polls the queue a second time before examining the closed flag**. The registration helper's internal atomics are not recovered here.

For either poll, raw tag 1 has precedence. A nonzero payload decrements channel+0x1c0 by 2 (with unsigned underflow handling), performs the visible auxiliary decrement and completes with RAX=0/RDX=payload. A zero payload completes with RAX=0/RDX=0. Only after the second non-1 tag does `closed_byte == 1 && counter < 2` synthesize that terminal zero result. Otherwise both state bytes become 3 and EAX=1 denotes the pending return at this boundary.

The queue helper locates a block with index base matching `read_index & ~31`, following +0x108 links and updating the current-block pointer. On that matched block, the ready bitmap is at +0x110. BT on EAX tests `read_index %32`. A set bit loads pointer slot `8*(read_index &31)`, increments read_index and returns tag 1. With the bit clear it returns bit 33 as the tag and zero as payload, without advancing the index. Block recycling and its CAS loop are exported as context; their concurrency/ownership contract is not closed.

Enabled cooperative budget zero yields without queue calls. A nonzero enabled budget is decremented before polling; the ordinary pending route restores its original value. Completed results retain the decrement. The evidence distinguishes a second-poll item from closed-and-empty: neither closure nor the counter is checked first.

Relations enumerate 1,440 supplied-result/gate combinations and 768 bitmap/index/payload combinations, including ready payload zero, terminal bit precedence, budget exhaustion, counter 1/2 and underflow. They are local algebraic/control projections, not a CPU emulator or concurrency test. Three actual operand changes expose counter-step, terminal-threshold and terminal-bit mistakes.

Prior #30 maps a different receiver's wait-to-exit path and explicitly leaves queue/waker/TLS contracts unclosed. #681 inventories channel Locations. #2060 concerns oneshot worker completion. #2297 maps an 88-byte work queue in the slow ABCI driver, including its ready/terminal bitmap and registration/retry pattern. Those generic patterns are context here, not a newly claimed discovery. The distinct question is this pointer-payload receiver's completion rule: a ready payload (including zero) wins before the explicit `closed_byte == 1 && counter < 2` fallback, and ordinary pending restores the cooperative budget. #2297 does not establish that rule or budget contract for this receiver. The full queue export binds the raw return values needed to establish this precedence; it does not claim new queue geometry as an independent outcome.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| receiver | `0x2ced6b0..0x2ced915` | 613 | 152 |
| queue | `0x2ccf230..0x2ccf3c3` | 403 | 94 |

The denominator is 2 complete FDEs, **1016 bytes /246 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **32 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-channel-repoll-terminal/export_disassembly.py
python3 research/work-items/RE-001-node115-channel-repoll-terminal/verify.py --controls
python3 research/work-items/RE-001-node115-channel-repoll-terminal/relations.py
python3 -m unittest discover -s tests -p test_node115_channel_repoll_terminal.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
