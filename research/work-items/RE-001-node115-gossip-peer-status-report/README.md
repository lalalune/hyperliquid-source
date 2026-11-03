# RE-001: node115 gossip peer-status observation and report cache

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The gossip-associated poll `0x5a61e40` initializes cached snapshot word0 to **0x8000000000000001**, stores binary64 **30.0** in its wait descriptor and polls that wait before taking any snapshot. A resumed ready wait reaches snapshot helper `0x4fac310`; a pending wait stores state+0xc8=3 and returns AL=1. Actual elapsed time and time units are outside this packet.

The initial marker bypasses comparison and reaches the report route. Otherwise comparator `0x4e06b40` receives the cached and new snapshots: a nonzero low byte skips reporting and keeps the old cached snapshot; zero reports. The comparator's first guard returns zero when the +0x18 words differ. Its remaining representation conversion and element-comparison call are retained but not claimed as a complete public equality implementation.

The report route acquires the byte lock of the pointed owner+0x10, calls `0x4e3f760` with the literal **child_peers status** and the fresh snapshot, and releases the lock. It then releases the previous cached representation and copies all32 fresh descriptor bytes into the cache. No returned status from the report call is used before that commit. The skipped-report path disposes of the fresh snapshot and keeps the previous cache. Both normal paths rearm the same30.0 wait; there is no ordinary Ready return from this perpetual loop.

This separates three reconstruction decisions: startup observation is deferred until the initial wait completes; a comparison false result triggers reporting; and cache replacement follows the report call's normal return rather than an inspected success flag. Opaque helper errors/unwinds may interrupt the sequence. Logging delivery, snapshot element meaning, allocator/destructor semantics, scheduler progress and thread safety are not established.

Relations enumerate five raw marker examples and all256 comparator bytes (1,280 cases), plus actual marker, branch and delay-literal counterfactuals. Descriptor/state validity and normal ABI-preserving helper returns are premises.

Prior #1386/#2041 recover gossip cache retention, not this child-peer status observation/report cache. #1335 inventories gossip_rpc_client source Locations and explicitly excludes gossip_rpc.rs. No previous `child_peers status` claim or primary address was found in the all-state PR audit.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| poll | `0x5a61e40..0x5a6221b` | 987 | 231 |
| snapshot | `0x4fac310..0x4fac467` | 343 | 88 |
| comparison | `0x4e06b40..0x4e06cd7` | 407 | 110 |

The denominator is 3 complete FDEs, **1737 bytes /429 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **31 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-gossip-peer-status-report/export_disassembly.py
python3 research/work-items/RE-001-node115-gossip-peer-status-report/verify.py --controls
python3 research/work-items/RE-001-node115-gossip-peer-status-report/relations.py
python3 -m unittest discover -s tests -p test_node115_gossip_peer_status_report.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
