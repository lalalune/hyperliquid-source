# RE-001 / action dispatch: paired cancellation-labelled batch cores

Question: which count is accumulated, how do input limits and two predicates
order work, and what bytes are conditionally copied? Scope: two related cores,
selected normal-helper protocol, tools/controls/packet; no complete cancellation
implementation or action-dispatch progress gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, handlers `03_cancel.rs` and
`04_cancel_by_cloid.rs`, supplies the OID/CLOID labels as leads, not copied code.

## Observations

ELF virtual addresses, no masks. Complete real FDEs:
`0x2721120..0x2721254` (308 bytes / 77 instructions),
`0x2725010..0x2725149` (313 bytes / 78 instructions). Total **621 bytes /
155 instructions**, hashes, raw FDE/CIE and selected boundaries. Only the protocol
below is modeled; full-body exports are not full per-item semantic recovery.

Both cores read the descriptor length at `+0x10` and compare it unsigned with
10001. Length >=10001 takes the rejection path, writes the input length at
output `+0x18` and status word 323. That path may free the incoming allocation;
allocator effects and raw invalid descriptor invariants are unmodeled.

On the normal arm, the OID-labelled core calls `0x2518ad0`, and CLOID-labelled
core calls `0x251a940`. **The returned count at stack +0x20**, not the original
input length, is loaded into R13. It saturating-adds to state `+0x878` using
ADD followed by two CMOVAE instructions separated by a flag-preserving byte store.
That store prepares worker-kind byte 2 or 3. The counter write precedes both
predicate calls. Why a returned count differs from input length is not inferred:
preparation semantics and valid returned-count domains remain opaque.

Two helper slots resolve to `0x37e4fb0` and `0x37e4e50`. A nonzero first AL
skips the second call. If either tested AL is nonzero, the selected copy is:

| Source state | Destination state | Width |
| --- | --- | ---: |
| +0x68 | +0x3aa0 | 4 bytes |
| +0x60 | +0x3a98 | 8 bytes |

This is **12 bytes**, not proof of the reference's 20-byte signer/address plus
lane interpretation. The original field meaning/type and predicate semantics are
unclosed; raw helper status values need not be valid original booleans.

The returned prepared records use an observed 32-byte stride. Both cores call
common worker `0x251a180`, then store status word **390** on normal return.
That outer status is not proof that all items canceled successfully: worker
results/per-item payloads, lookup and order mutation semantics are not modeled.
Both related cores are one packet, not separate contributions.

## Inferences and limits

OID/CLOID, cancellation and marker names follow the reference and action context;
original Rust layouts, complete caller chain, preparator/executor internals,
predicate meanings, field ownership, valid counts, allocator/drop/unwind behavior
remain unknown. The model is conditional on normal helper returns and declared
raw words. It does not execute a cancel, exchange, order, signer or chain action.
Before: reference narrative with broad typed marker assumptions. After: exact
input/returned count distinction, saturation/order, short-circuit predicate calls,
12-byte copy and outer status stores are digest-bound. Next question: close
preparator and worker semantics before assigning per-item behavior or typed fields.

## Reproduce and controls

Python 3.12.14, static stdlib ELF readers. Optional Capstone 5.0.6 x86-64 Intel
contiguous export. No captured instructions execute natively.

```
python tools/cancel_batch_protocol.py --out research/work-items/RE-001-cancel-batch-protocol-94/records.json
python research/work-items/RE-001-cancel-batch-protocol-94/export_disassembly.py
python -m unittest tests.test_cancel_batch_protocol -v
```

Six focused methods pass in 4.361 seconds: both input-limit boundaries, independent
prepared/old counter matrices, all first-helper byte classes with second-helper
boundary classes, and actual limit/second-CMOV mutations changing derived results.
Other capture controls cover preparators, returned-count operands, predicates,
snapshot widths/offsets, kinds, worker/status stores, both FDEs and target identity.
Declared raw count/status combinations include values not proved reachable.
Make is unavailable; required Python commands ran directly. Full suite:
**363 tests in 110.069 seconds; 7 failures, 16 errors, 21 skips**. All six
new methods pass. Existing Windows newline/POSIX-path/native-tool constraints
remain; this branch excludes unmerged #227. Doctor reports missing prerequisites.
Eight artifact sizes/digests pass before missing GPG prevents signature verification.
Imports reject the Windows reference checkout; catalogue-check rejects backslash
paths. Reproduce stops at artifact verification. No full-suite/signature/hosted-CI
or native-equivalence success is claimed.
