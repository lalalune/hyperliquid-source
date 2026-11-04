# RE-001: node115 consensus local versus remote message delivery

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The destination sender at `0x5a7c4d0` captures the twenty-byte local identity at owner+0x160, copies a 0x178-byte message, appends that identity, then compares the supplied destination with the captured identity. The comparison uses sixteen SIMD bytes and a four-byte zero-extended tail, requiring PMOVMSKB ==0xffff. Every one of the twenty bytes participates.

A different destination invokes the named **send_to_destination** route with the destination and copied envelope, then drops that temporary message. It does not attempt the local channel. An equal destination allocates a 0x190-byte envelope and attempts only the local channel. A closed local channel drops the envelope and balances its auxiliary count; it does not fall back to remote delivery. The queue and tracing helper bodies are opaque, so these are call-routing statements, not delivery guarantees.

The paired broadcast entry `0x5a7f3a0` follows a different rule. It copies the message and origin, calls the encoding boundary, and constructs shared encoded storage. It attempts local delivery and then calls the named **broadcast** route on both ordinary local outcomes, including closed-channel disposal. Thus local closure suppresses a self-addressed send, but does not suppress the remote broadcast call. An exception, allocation failure or nonreturning boundary can interrupt either sequence.

Both entries derive a formatting byte from packed word0x0007060403020501. For a negative first message word its low-byte index selects a byte using the x86 shift mask; the eight resulting bytes are1,5,2,3,4,6,7,0. Nonnegative first words select index2. These are formatting inputs, not recovered wire tags. Arbitrary negative values are used only as machine arithmetic controls, not asserted valid source enum variants.

Relations test every single-byte replacement of the twenty-byte identity with both channel outcomes, plus the packed formatting projection. Real equality-mask, branch-polarity and packed-byte changes alter the result. Full exports retain allocation, queue and cleanup context without claiming concurrency or ownership closure.

No prior `send_to_destination` or primary-address claim was found in the all-state audit. #970 provides consensus-server Location inventory context. The new question is the destination identity gate and the different local-failure continuation for explicit sends versus broadcasts.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| destination | `0x5a7c4d0..0x5a7c7cd` | 765 | 164 |
| broadcast | `0x5a7f3a0..0x5a7f6e8` | 840 | 185 |

The denominator is 2 complete FDEs, **1605 bytes /349 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **34 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-consensus-local-delivery/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-local-delivery/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-local-delivery/relations.py
python3 -m unittest discover -s tests -p test_node115_consensus_local_delivery.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
