# RE-001: node115 transaction hash registration before sequence increment and delivery

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

After the receive boundary accepts an item, worker `0x5a7d380` captures its three words in a shared40-byte allocation and samples the clock. The digest boundary initializes a retained context with qword0x88 and word1, calls `0x5cda910`, then asks `0x5cdad40` for32 output bytes. The algorithm and source-level hash API remain opaque.

Those32 bytes, a pointer to **worker+0xc8**, and the exact25-byte `tx_hash_to_seq_num insert` label are passed to wrapper `0x4f1e2d0`. Immediately after that call returns normally, the worker loads the qword at +0xc8 and increments it with **unsigned saturation at u64::MAX**. The registration call therefore precedes the local sequence update. The helper receives a pointer and could mutate it; the arithmetic claim applies to the value read after the call. No assumption that the helper leaves that value unchanged is needed for the ordering result.

Only afterward does the first output-channel attempt begin. Its ordinary accepted item carries the shared input. A separate time-adjustment boundary receives integer70000000, and the second output channel carries the resulting timestamp record plus the same shared input. Channel closure can discard either outgoing copy; neither closure rolls back the already stored sequence word. Both ordinary paths eventually reset nested state and repoll.

Relations check post-call values0,1 and the upper saturation boundaries, plus changed increment direction, conditional-select polarity and field offset. They are a local arithmetic projection. The registration map's internal insertion/duplicate semantics, digest, time-adjustment unit, channel synchronization and delivery remain unclosed. Saturation alone cannot establish globally unique sequence identifiers.

Prior #970 inventories consensus/server source Locations. #2580 studies the separate external-transaction forwarding worker, including remote-before-local ordering. This packet studies the incoming transaction registration and sequence store before two channel attempts; shared queue/TLS code is context, not a second claim.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| worker | `0x5a7d380..0x5a7dcdb` | 2395 | 483 |

The denominator is 1 complete FDEs, **2395 bytes /483 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **49 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-transaction-sequence-registration/export_disassembly.py
python3 research/work-items/RE-001-node115-transaction-sequence-registration/verify.py --controls
python3 research/work-items/RE-001-node115-transaction-sequence-registration/relations.py
python3 -m unittest discover -s tests -p test_node115_transaction_sequence_registration.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
