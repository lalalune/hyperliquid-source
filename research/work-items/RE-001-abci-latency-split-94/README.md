# RE-001 / transport: ABCI sample cap versus prepared row value

Question: do ABCI latency metrics and the caller's prepared row field receive
the same capped value? Scope: begin/commit caller dataflow, finite normal-return
helper model, controls and this packet; no complete metrics/row writer or gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`,
`net_utils/abci_latency_sampler.rs`, is a lead only, not copied implementation.

## Observations

ELF virtual addresses, no masks. Full FDEs: commit `0x3d22500..0x3d22911`
(1,041 bytes / 204 instructions), begin `0x3d22920..0x3d22a97` (375 bytes /
81 instructions). Total **1,416 bytes / 285 instructions**, full hashes, raw
FDE/CIE, selected boundaries and three source Locations. Only the following
normal-helper dataflow is modeled, not whole-owner semantic coverage.

Both owners obtain the clock before testing the saved first dword at `+0x7d0`.
Zero bypasses the corresponding saved-time calculation; its original Rust type
is not established from this one dword test. Three duration calls resolve through
slot `0x576e8c0` to `0x1447130`; sample calls use slot `0x576efb0` to
`0x14027b0`, with ESI=1. Existing shared-time evidence (#63) concerns that
helper itself; this packet does not repeat its grammar/overflow recovery.

| Selected caller calculation | Sample receiver | Finite sample argument |
| --- | --- | --- |
| Begin, saved first dword nonzero | self+0 | min(raw elapsed,60) |
| Begin, EDX low byte nonzero | self+0x260 | raw backlog elapsed |
| Commit, saved first dword nonzero | self+0x4c0 | min(raw elapsed,60) |

The cap literal at `0x20abf8` is f64 60.0. Begin uses `MINSD XMM1,XMM0`
with cap/raw operands; commit uses `MINSD XMM0,XMM1` with cap/raw operands.
The model declares finite normal helper returns only, preserving the raw source
bits for finite values <=60, including signed zero. It does not assign nonfinite
MXCSR/NaN behavior or assert arbitrary negative finite durations are reachable.

Commit preserves the **uncapped** raw return at stack `+0x70` before sampling
(`0x3d225d0`). After the sample call may clobber XMM0, `0x3d22603` reloads that
saved raw value and `0x3d22609` writes stack `+0xa8`. On a later path reaching
`0x3d22839`, helper `0x3d24ff0` receives the structure at stack `+0xa0`.
Thus a raw 90.0 return produces metric input 60.0 and prepares row-field bits
90.0. This differs from the reference's row construction using capped duration.
Later reporter guards may bypass the helper, and its serializer/persistence
effects are unclosed: **this is not a claim about actual on-disk JSON**.

On normal begin return, the selected final stores copy the supplied timestamp
and current timestamp as 24 bytes into the saved slot. Calendar/row rotation,
logging, flush and unwind behavior remain outside the modeled claim. The three
sample-source Locations resolve to `net_utils/src/abci_latency_sampler.rs` at
67:48, 55:41, 58:34, independently binding the metric contexts.

## Inferences and limits

Block/backlog/commit names follow the reference and receiver offsets. Original
state/chrono/result types, valid value domains, helper failure paths, nonfinite
floating states, full row schema/writer and persistence are not recovered. No
native clock, metric state, file, thread or captured executable is accessed.
Before: a reference formula reusing a capped row value. After: exact raw spill,
sample cap and row preparation are independently byte-bound. Next question: close
the reporter guards and `0x3d24ff0` before assigning persisted row semantics.

## Reproduction and checks

Python 3.12.14, stdlib static ELF readers; optional Capstone 5.0.6 x86-64 Intel.

```
python tools/abci_latency_split.py --out research/work-items/RE-001-abci-latency-split-94/records.json
python research/work-items/RE-001-abci-latency-split-94/export_disassembly.py
python -m unittest tests.test_abci_latency_split -v
```

Six focused methods pass in 0.973 seconds: finite cap neighbors/signed zero,
declared raw dword/low-byte flag classes, nonfinite-domain rejection, and actual
MINSD-to-MAXSD/cap mutations. Those mutations change metric input while leaving
the prepared raw row word unchanged; bindings reject them. Additional capture
controls cover presence, spills/reloads, row pointers, receiver offsets, timestamp
stores, helper bindings, weights, sources, FDEs and identity.

Make is unavailable; required Python commands ran directly. Full suite:
**363 tests in 107.539 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. Existing Windows newline/POSIX-path/native-tool constraints remain;
this branch excludes unmerged #227. Doctor reports missing prerequisites. Eight
artifact sizes/digests pass before missing GPG prevents signature verification.
Imports reject the Windows reference checkout; catalogue-check rejects backslash
paths. Reproduce stops at artifact verification. No full-suite/signature/hosted-CI
or native-equivalence success is claimed.
