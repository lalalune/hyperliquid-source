# RE-001: node #115 JsonRpcResult alternatives and local value layout

Task RE-001; `foundation` remains a tentative allocation. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Input/reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code/prose is independently authored; captured evidence retains upstream rights. This is partial static research, not reconstructed Rust, full source types/ABI, runtime equivalence or component completion.

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
| Unique total |6676|1567|

## Current findings

The constructor tries `result` then `error` alternatives, taking the first nonfailure marker under normal-call premises. The first recognizes exact six-byte `result`; selected byte/text/sequence paths supply 32-byte values. The second recognizes five-byte `error` through four key forms and local numeric-zero identifiers, rejects missing/repeated recognized fields and delegates value conversion to 0x16fe920. The complete serialized JSON/input domain remains unknown.

Observed marker words are context-specific: A=0x8000000000000000 is the first alternative's ordinary marker, but the second alternative uses A for absence/child-failure testing. B=0x8000000000000001 is the constructor's failure test. The first form visibly stores 40 bytes, the second 104, and the constructor copies 104. This explains the measured wider span while leaving the first form's copied tail and the child's full initialization/word domain unclassified. Copy coverage is not an active-field, padding or source-ABI proof.

Earlier local evidence remains: 32-byte byte-record guards; text guards for 64 hex digits with optional lowercase `0x`; 32-element collection plus a boundary probe; eight numeric element tags accepting values in 0..255; cursor advance before overflow and counter increment before validation. Normal leaf byte/end paths close local store framing under valid nonaliasing memory. Error/cleanup and serialized-input paths remain conditional. See [observations](observations.md) and [new bound data](second-alternative/referenced-data.json).

## Reproduce and controls

With the complete pinned capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the complete image, 135,313 ordered unwind starts, supported actual CIE/FDE records and all 1,567 unique native rows. The new stage has 127 selected instruction bindings and 181 evidence-corruption cases; cumulative total 662. It checks both tables and call/store/marker bridges against the full capture. The 1,275 new distinct `error` key mutations are checked through four forms; all prior controls, including 1,530 `result` key mutations and numeric/cursor models, remain. The new 23 map-state and 81 constructor word-choice cases are static conditional models, not executed target instructions or end-to-end acceptance tests.

## Native evidence and validation

All earlier packet paths/receipts are preserved. Latest native run [41677848979](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41677848979), execution `6759ad4c0bf7125141a991b6e08745cc95bdabf8`: one job/attempt 1, GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The renewed constructor is byte-identical. Complete target authentication and rootless/zero-capability/no-new-privileges/isolated-loopback/read-only-noexec qualifications are retained. The 21,826-byte archive SHA-256 is `43f344dc10cb828220b4f1bd4df76b407b2fbe19d7000a0fce63552b82da8feb`.

This packet is frozen before required validation. Exact candidate commit/tree and current actual outcomes are recorded on [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127), preserving identical tested/published bytes without a metadata-only followup. [Historical validation](validation/history.json) applies only to its immutable snapshots. Prior eight-range run 41673610260 passed 10 checks (76 modules, 382 reported cases, four optional skips), not this addition. No captured program/emulator, compiler or VM was invoked by the analysis; no repository/native code ran on the Mac.

## Limits and next step

The child 0x16fe920's complete carrier initialization, allowed first-word domain, first-form tail classification, source types/ABI, error/cleanup/formatter/exception contracts, serialized JSON/null construction and runtime equivalence remain unresolved. No gate, compiled comparison, Points or payment is claimed. Next: recover the error-value child before asserting complete result-layout or schema recovery.
