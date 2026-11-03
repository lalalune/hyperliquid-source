# RE-001: node #115 JsonRpcResult fields and failure-handler operands

Task RE-001;foundation remains tentative. Target:Linux x86-64 node#115,105,896,032 bytes,SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Reference revision `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New prose/checkers are independently authored;captured evidence retains upstream rights. Partial static research;source types/ABI,runtime equivalence and component completion remain unproved.

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
| Message helper `[0x16fe790,0x16fe91b)` |395|103|
| Failure dispatcher `[0x141e264,0x141e279)` |21|6|
| Nonzero-route handler `[0x141e251,0x141e264)` |19|6|
| Zero-route handler `[0x141e280,0x141e29d)` |29|6|
| Unique total |9846|2241|





## Current findings

Earlier evidence binds constructor result/error alternatives,selected32-byte value conversions,nested code/message/data fields,marker contexts and local stores. The message helper writes[n,pointer-or-empty1,n];n is signed-nonnegative on ordinary paths avoiding its failure helper. That conditional bound excludes B=0x8000000000000001 there. Global exclusion remains unproved.

The dispatcher selects two handlers. The nonzero handler swaps incoming RDI/RSI and calls0x5c827a0;the message null-allocation route supplies(n,1) after that swap. The zero handler passes literal-pointer0x456d73,scalar35 and descriptor-pointer0x63f3cf0 to0x1680e80. Referenced data begins with `capacity overflow`;scalar35 is not established as a byte length or message boundary. The descriptor has a relocation-bound80-byte raw_vec/mod.rs path and line-like28/column-like5 fields;Source Location is an inferred layout,not exact-source/type attestation. See[observations](observations.md) and[bound data](failure-handlers/referenced-data.json).

No RET appears in the two new extents. A normal return from the nonzero handler's child enters the known dispatcher;the zero handler's continuation lies outside the decoded ranges. Neither fact proves nonreturn. Callee ABI/continuation,global word domain,validation/allocation/copy/ownership,default-data storage,source types and runtime behavior remain open. First alternative stores40bytes,nested error ordinary stores100,while second/constructor copies104;copied tails40..103 and100..103 remain unclassified. Store coverage is not initialization,padding or undefined-behavior proof.

## Reproduce and controls

With the complete pinned capture,from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the whole image,135,313 ordered unwind starts,actual supported CIE/FDE records and all2,241 unique native rows. New selected bindings:14;new evidence-corruption controls:26,cumulative1,217. It checks two new FDEs,five actual RELATIVE records,the fixed operands,register swap,referenced window,descriptor/path fields and two retained dispatcher boundaries. All earlier controls remain. No target instructions,reconstructed parser or invented callee behavior are executed.

## Native evidence and validation

All prior paths/receipts remain. Latest native run[41735408655](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41735408655),execution `2e4446a01413b193487948f8e559205fd0896c56`:one job/attempt1,GNU objdump2.42 version query and two static decodes capped45seconds each. New ranges total48bytes/12rows. The dispatcher has no fresh GNU decode in this run;its prior six native rows and actual FDE are replayed against the complete target,with both RIP/RELATIVE edges qualified. Rootless/zero-capability/no-new-privileges/isolated-loopback/read-only-noexec qualifications remain. The7,476-byte archive SHA-256 is `390dc36dc9303eb4fecfa04e482ad5b3fbe0de58809200b03b2fd9310af9474d`.

This packet freezes before required validation;exact commit/tree and actual current outcomes live on[PR#2127](https://github.com/lalalune/hyperliquid-source/pull/2127),preserving tested/published bytes. [Historical validation](validation/history.json) applies only to immutable snapshots. Prior twelve-range run41728155064 passed10checks(76modules,382reported cases,four optional skips),not this addition. No captured program/emulator,compiler or VM was invoked by this analysis. No repository/native decoder ran on the Mac.

## Limits and next step

Further targets0x5c827a0/0x1680e80 and the zero handler's continuation remain unproved. Scalar35/message encoding and boundary,Source Location/type/source ownership,nonreturn/global B,dependent memory/ownership,copied tails,exception/signal and runtime equivalence remain open. No gate,compiled reconstruction,Points,payment or security impact is claimed. Next:inspect the further callees and establish the fixed-operand interpretation before stronger return/schema claims.
