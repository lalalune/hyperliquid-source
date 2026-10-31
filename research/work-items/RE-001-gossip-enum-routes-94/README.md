# RE-001 / transport: paired gossip enum selector routes

Question: which decoded enum tags select which helper calls, and where do the
caller wrappers stop on helper errors? Scope: selector verifier, focused controls
and this packet. No completed serialization/transport gate or wire codec is claimed.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed can1357-hl reference revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/gossip_rpc.rs`, supplies
the enum names as leads only; its implementation is not copied.

## Observations

ELF virtual addresses, no masks. Real FDE request owner
`0x438b5c0..0x438b6d7` is **279 bytes / 76 instructions**; response owner
`0x438b6e0..0x438b944` is **612 bytes / 135 instructions**. Total complete
exports: **891 bytes / 211 instructions**, with raw FDE/CIE, body hashes,
response table bytes and range data. Only selector/call/status semantics are
modeled, not every payload-copy instruction or helper implementation.

Both wrappers call `0x466bc10` and check returned byte 18 before reading a
dword tag at local `+4`. On another status, the caller copies error fields
instead of entering its tag selector. The first wrapper's tag selector is
actual TEST/CMP/JE/JNE code interpreted by the offline tool, not a standalone
rewritten enum switch.

| Wrapper | Decoded tag | Selected calls/arm |
| --- | ---: | --- |
| Request | 0 | `0x466bd10` at `0x438b646`, then again at `0x438b65e` only if first status is 18 |
| Request | 1, 2 | Unit stores of 1 or 2 at output `+8`, status byte 18 |
| Request | >2 | Error byte 5, offending tag, literal `GossipRpcRequest` length 16 and captured range record |
| Response | 0 | Table arm `0x438b71e`, call `0x4589b30` with extra decoder argument `0x45920f0` |
| Response | 1 | Table arm `0x438b831`, call `0x496f730` |
| Response | 2 | Table arm `0x438b795`, call `0x466c770` |
| Response | 3 | Table arm `0x438b7d1`, call `0x466dc10` |
| Response | >3 | Error byte 5 in outer-error payload, offending tag, literal `GossipRpcResponse` length 17 and range record |

Each response payload arm checks its helper's status byte against 18. Normal
success arms write outer word 0 and their variant at `+8`; error paths converge
on outer word 1. The two successful request tag-0 values are stored at `+0x10`
and `+0x18`, with tag word 0 at `+8`. No check of their relative order occurs
in this wrapper. Outer/request result shapes differ; original Rust ABIs and
full error types are not assigned from these offsets alone.

Type literals and range-data references are bound to actual operands. Captured
range records at `0x209410` and `0x2032d0` end with u32 values 2 and 3;
their original Rust structure type remains unproved.

## Inferences and unknowns

ClientBlocks/Peers/GossipStatus/Error names follow the reference and callee
context; payload grammar and full callee identities are not recovered here.
Existing bincode varint evidence independently covers the `0x466bd10` fast
path; this packet does not repeat that helper recovery or pretend to decode
its slow paths. Byte 18 is an observed helper success discriminator, not a
wire byte. The model accepts declared raw helper outcomes, including possibly
unreachable status values. No actual network frames, node process or helper runs.

Unknown: wire length/encoding/consumption, helper-side cursor changes, block/peer/
status/string payload types, error ownership, all payload-copy layouts, network
framing and caller validation. Before: reference enum seeds and labels. After:
digest-bound selectors, helper routes, short-circuit checks and error metadata.
Next question: close each response payload helper and cursor consumption before
claiming a complete request/response wire schema.

## Reproduction and controls

Python 3.12.14 with stdlib static ELF readers. Optional complete contiguous
Capstone 5.0.6 x86-64 Intel export. No captured instruction runs natively.

```
python tools/gossip_enum_routes.py --out research/work-items/RE-001-gossip-enum-routes-94/records.json
python research/work-items/RE-001-gossip-enum-routes-94/export_disassembly.py
python -m unittest tests.test_gossip_enum_routes -v
```

Six focused methods pass in 0.861 seconds. All byte-sized tags and four u32
boundary classes exercise the real request selector and response-table resolver.
All 256 header-status classes and first/second field outcomes check conditional
short-circuit behavior. Changing a real compare immediate, table entry or status
immediate changes the derived route; binding checks reject the modified capture.
Other controls mutate helpers, limits, fields, both type/range records, FDEs and
target identity. Make is unavailable, so its Python commands were run directly.
Full suite: **363 tests in 106.739 seconds; 7 failures, 16 errors, 21 skips**.
All six new methods pass. Existing Windows newline/POSIX-path/native-tool
constraints remain failures; this independent base excludes unmerged #227.
Doctor reports missing prerequisites. Eight artifact sizes/digests pass before
missing GPG prevents signature verification. Imports reject the Windows reference
checkout; catalogue-check rejects backslash paths. Reproduce stops at artifact
verification. No full-suite, signature, hosted-CI or native-equivalence success.
