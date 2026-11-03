# RE-001: node #115 JsonRpcResult alternatives and message-word bound

Task RE-001; foundation remains tentative. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Reference revision `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code/prose is independently authored; captured evidence retains upstream rights. Partial static research; source types/ABI, runtime equivalence and component completion remain unproved.

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
| Unique total |9777|2223|



## Current findings

Earlier evidence binds the constructor's result/error alternatives, selected 32-byte value conversions, nested code/message/data handling, marker contexts and local stores. The new message helper recognizes four raw text/byte-like record forms, optionally delegates validation, checks signed lengths, allocates/copies positive lengths and writes [n, pointer-or-empty-1, n]. Empty messages write [0,1,0]. Raw record semantics and complete serialized JSON input remain open.

The leading word n lies in 0..2^63-1 on every ordinary path that avoids failure helper 0x141e264, excluding the constructor's disputed B=0x8000000000000001 there. This is conditional: nonreturn and post-call flag contracts of that helper remain unproved, so global B exclusion is not claimed. The validator, allocation and copy contracts, pointer/ownership premises and source String identity remain unresolved. See [observations](observations.md) and [message data bindings](message-helper/referenced-data.json).

The first alternative locally stores 40 bytes; nested error-value ordinary paths store 100; the second alternative and constructor copy 104. Message words occupy +0..23, data marker/carrier +24..95, code DWORD +96..99. This helper binds the three message stores but does not classify copied error tail 100..103, first-form tail 40..103 or default-data definedness. Store coverage is not a source ABI, initialization or undefined-behavior proof.

## Reproduce and controls

With the complete pinned capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the whole image, 135,313 ordered unwind starts, actual supported CIE/FDE records and all 2,223 unique native rows. New selected instruction bindings: 107; new evidence-corruption controls: 121, cumulative 1173. It checks tag dispatch, RIP/relocation/symbol bridges, sign/allocation paths, three-word stores and both caller sites. New 256 tag and 36 boundary cases are conditional static models. All earlier controls remain, including 3,825 nested-field, 1,275 error-key and 1,530 result-key byte mutations. No target instructions or reconstructed parser are executed.

## Native evidence and validation

All prior packet paths/receipts remain. Latest native run [41716002033](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41716002033), execution `68bf824fe5f9d7f3a127b5595630a7a024810f9e`: one job/attempt 1, GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The renewed error-value helper is byte-identical and counted once. Full capture authentication and rootless/zero-capability/no-new-privileges/isolated-loopback/read-only-noexec qualifications are retained. The 31,601-byte archive SHA-256 is `163264703657ef273b511b7e12eb8ca4765e2285d1269214dd69c6205a0522f5`.

This packet freezes before required validation; exact candidate commit/tree and current actual outcomes live on [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127), preserving identical tested/published bytes. [Historical validation](validation/history.json) applies only to its immutable snapshots. Prior ten-range run 41699615001 passed 10 checks (76 modules, 382 reported cases, four optional skips), not this addition. No captured program/emulator, compiler or VM was invoked by this analysis. No repository/native code ran on the Mac.

## Limits and next step

Failure helper 0x141e264's nonreturn/continuation contract is the remaining frontier for a global message-leading-word bound. Dependent field/validation/allocation/copy contracts, pointer validity/ownership, default-data storage, copied tails, source types/ABI, formatter/cleanup/exception contracts, wire inputs and runtime equivalence remain unresolved. No gate, compiled comparison, Points, payment or security impact is claimed. Next: recover that failure-helper frontier before claiming a global B exclusion.
