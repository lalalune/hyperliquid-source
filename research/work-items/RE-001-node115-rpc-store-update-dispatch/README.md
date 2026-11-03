# RE-001: node115 RPC store construction and update dispatch

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The constructor `0x4faf560` creates two separately wrapped store objects. Their initialized input descriptors contain the same qword100000 at +0x40 but different bytes at +0x48: first1, second0. Their original type and the meaning of this limit/flag remain unresolved. The channel builder receives the exact label **rpc update** and integer5000. A 0x88-byte worker capture contains the two store pointers at +0x20/+0x28, its owner at +0x30, binary64 60.0 at +0x38 and zero initial state. The **consensus rpc store** spawn descriptor binds size0x88, alignment8, destructor and poll target `0x4faf9c0` through actual RELATIVE relocations. Caller output retains both store pointers and the channel descriptor.

The worker polls `0x5aabb20`. Raw result tag3 returns pending (AL1), preserving outer state3; tag2 performs cleanup and returns AL0 with completed state1. Other valid update tags proceed to processing. In that update path, it samples time and invokes a gate using capture+0x38. A nonzero gate result reads both stores and reports their sizes **before** applying the incoming update. A zero result skips these reads/reporting. The60.0 field is an input to that helper; exact elapsed-time semantics are not inferred.

The labels **tx_hash_to_tx** and **block_hash_to_signed_block** bind the respective store readbacks in the report. Update tag1 routes the copied32-byte key and accompanying qword through `0x4f25d60` using the first store. The other valid update variant routes the same input shape through `0x4f0f310` using the second store. Both normal paths rearm the receive state and loop. The insertion, deduplication, eviction and transaction/block object semantics inside those helpers are not recovered.

Relations enumerate four valid supplied poll tags and all256 supplied timing-gate bytes, checking pending/terminal precedence and report-before-update ordering. Operand changes to pending tag, first-store selector and stats-branch polarity alter the local projection. Full constructor/worker exports retain ownership and cleanup context; they are not a concurrency proof.

Prior #1032 is a node94 consensus/rpc.rs Location inventory that explicitly leaves behavior unresolved. #2523 closes a different RPC response lookup collector. Neither establishes this worker's tag routing or statistics ordering; no earlier exact-label or primary-address semantic claim was found in the audit.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| constructor | `0x4faf560..0x4faf9c0` | 1120 | 202 |
| worker | `0x4faf9c0..0x4faffc1` | 1537 | 325 |

The denominator is 2 complete FDEs, **2657 bytes /527 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **70 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-rpc-store-update-dispatch/export_disassembly.py
python3 research/work-items/RE-001-node115-rpc-store-update-dispatch/verify.py --controls
python3 research/work-items/RE-001-node115-rpc-store-update-dispatch/relations.py
python3 -m unittest discover -s tests -p test_node115_rpc_store_update_dispatch.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
