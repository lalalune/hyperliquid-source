# RE-001: node #115 JsonRpcResult alternatives and failure dispatch

Task RE-001; foundation remains tentative. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Reference revision `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New prose/checkers are independently authored; captured evidence retains upstream rights. Partial static research; source types/ABI, runtime equivalence and component completion remain unproved.

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
| Unique total |9798|2229|




## Current findings

Earlier evidence binds the constructor's result/error alternatives, selected 32-byte value conversions, nested code/message/data fields, marker contexts and local stores. The message helper writes [n,pointer-or-empty1,n]. Its ordinary first word is signed-nonnegative on paths avoiding failure helper 0x141e264; that conditional bound excludes B=0x8000000000000001 there.

The new failure dispatcher selects two callees through actual relocation-bound slots: selector zero first calls 0x141e280; selector nonzero goes directly to 0x141e251. If the zero-selector call returns, the second call follows with caller-saved registers unclassified. If the last call returns, its next PC is outside the 21-byte FDE. No RET is inside that extent, but this does not prove nonreturn. Global B exclusion remains open. See [observations](observations.md) and [failure-helper bindings](failure-helper/referenced-data.json).

The first alternative locally stores 40 bytes; nested error-value ordinary paths store 100; the second alternative and constructor copy 104. Message words occupy +0..23, data carrier +24..95 and code DWORD +96..99. Copied tails 100..103 and 40..103, default-data and dependent field definedness remain unclassified. Store coverage is not initialization, padding, a source ABI or undefined-behavior proof.

## Reproduce and controls

With the complete pinned capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the whole image, 135,313 ordered unwind starts, actual supported CIE/FDE records and all 2,229 unique native rows. New selected instruction bindings: 14; new evidence-corruption controls: 18, cumulative 1,191. Three RELATIVE records bind both caller sites and two outgoing slots. The two selector routes retain unknown call-return edges. All earlier controls remain, including field/key mutations and conditional length/status/allocation models. No target instructions or reconstructed parser are executed.

## Native evidence and validation

All prior paths/receipts remain. Latest native run [41726809941](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41726809941), execution `4d54bc950c79e93e214a7bfb9fbb6483cff4a228`: one job/attempt 1, GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The renewed message helper counts once. Full capture authentication and rootless/zero-capability/no-new-privileges/isolated-loopback/read-only-noexec qualifications are retained. The 11,072-byte archive SHA-256 is `5258ab944aea1aeaef78a6d8cd88d3e121743a094c470fb9175c5a5f4ebcbb84`.

This packet freezes before required validation; exact candidate commit/tree and actual current outcomes live on [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127), preserving identical tested/published bytes. [Historical validation](validation/history.json) applies only to immutable snapshots. Prior eleven-range run 41717470972 passed 10 checks (76 modules, 382 reported cases, four optional skips), not this addition. No captured program/emulator, compiler or VM was invoked by this analysis. No repository/native code ran on the Mac.

## Limits and next step

Callees 0x141e280 and 0x141e251 and continuation outside the FDE remain the return-contract frontiers. Global message leading-word domain, validation/allocation/copy contracts, pointer validity/ownership, default-data storage, copied tails, source types/ABI, formatter/cleanup/exception/signal contracts, wire inputs and runtime equivalence remain unresolved. No gate, compiled comparison, Points, payment or security impact is claimed. Next: inspect both outgoing callees before asserting global nonreturn or B exclusion.
