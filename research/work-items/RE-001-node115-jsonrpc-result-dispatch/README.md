# RE-001: node #115 JsonRpcResult alternatives and nested error layout

Task RE-001; foundation remains tentative. Target: Linux x86-64 node #115,105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Reference revision8fd8db680ec4bfef40996e5616bce3d5156d0b86. New code/prose is independently authored; captured evidence retains upstream rights. Partial static research; source types/ABI, runtime equivalence and component completion remain unproved.

| Actual FDE range, ELF VA | Bytes | Native rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` |342|79|
| Caller `[0x1707010,0x17077b2)` |1954|410|
| Completion `[0x1700a10,0x1700ac3)` |179|47|
| First alternative `[0x16fdba0,0x16fdf82)` |994|245|
| Value helper `[0x16fd8b0,0x16fdb94)` |740|185|
| Text decoder `[0x167a9c0,0x167abfb)` |571|143|
| Sequence helper `[0x173fe30,0x173ff4e)` |286|82|
| Element reader `[0x16fce10,0x16fcf18)` |264|73|
| Second alternative `[0x16fdf90,0x16fe4d2)` |1346|303|
| Nested error value `[0x16fe920,0x16ff3b2)` |2706|553|
| Unique total |9382|2120|


## Current findings

The constructor tries result then error alternatives and takes the first nonfailure result under normal-call premises. Earlier evidence binds six-byte result, five-byte error and selected32-byte byte/text/sequence conversion paths. The nested error helper now binds exact code/message/data field recognition, numeric identifiers0/1/2, duplicate-before-conversion checks, required code/message fields and optional data in raw map and sequence forms. This does not recover the complete serialized JSON or source enum domain.

Marker meanings remain scoped: A=0x8000000000000000 is ordinary for the first alternative and absence/failure inside other carriers; B=A+1 is the constructor failure test. The nested error helper passes through the three-word message helper's first word when it differs fromA; whether B is admitted remains unproved. Its data tracker usesA+6 for missing andA+5 for local none/default or a distinct child-failure context. See [observations](observations.md) and [bound error-value data](error-value/referenced-data.json).

The first alternative locally stores40bytes, the nested error helper100bytes, its caller104bytes, and the constructor copies104bytes. Nested ordinary stores are message words+0..23, data marker/carrier+24..95, code DWORD+96..99. Copied tail100..103, first-form tail40..103 and dependent/default-data definedness remain unclassified. Store coverage is not an active-field mask or source ABI/undefined-behavior proof.

## Reproduce and controls

With the pinned complete capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the whole image,135,313 ordered unwind starts, actual supported CIE/FDE records and all2,120 unique native rows. New selected bindings: 358; new evidence-corruption controls: 390, cumulative 1052. It binds the key/numeric tables, direct-call and RIP/data bridges and both ordinary store spans. It rejects3,825 distinct nested field-name mutations through four forms; all earlier controls remain. Thirteen numeric identifier cases,16 map cases and6 sequence-shape cases are conditional static models, not target executions or end-to-end acceptance tests.

## Native evidence and validation

All prior packet paths/receipts remain. Latest native run[41698099363](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41698099363), execution d3c86ed1f250e67c5e2d56f1b3ec72f64024547f: one job/attempt1, GNU objdump2.42 version query and two static decodes capped45seconds each. The renewed second alternative is byte-identical. Complete capture authentication and rootless/zero-capability/no-new-privileges/isolated-loopback/read-only-noexec qualifications are retained. The39,969-byte archive SHA-256 is ed79524ef150396249ca746e46a35a03a99839cca33933e63bd09856ee2fecc2.

This packet freezes before required validation; exact candidate commit/tree and actual current outcomes live on[PR#2127](https://github.com/lalalune/hyperliquid-source/pull/2127), preserving tested/published bytes without a post-validation metadata change. [Historical validation](validation/history.json) applies only to its immutable snapshots. Prior nine-range run41680137820 passed10checks (76modules,382reported cases,4optional skips), not this addition. No captured program/emulator, compiler or VM was invoked by this analysis. No repository/native code ran on the Mac.

## Limits and next step

The message helper's admitted first-word domain, all three field helpers' active-field initialization, default data's inactive storage, copied tail100..103, first-form tail40..103, source types/ABI, formatter/cleanup/exception contracts, wire inputs and runtime equivalence remain unresolved. No gate, compiled comparison, Points or payment is claimed. Next: recover message helper0x16fe790 to narrow the allowed leading-word domain before asserting complete result-layout recovery.
