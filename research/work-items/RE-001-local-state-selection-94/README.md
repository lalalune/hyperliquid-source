# RE-001: message-bound local-state raw-word selection

- Component: node runtime / local-state startup. Question: which raw comparisons
  select the two stale-reason messages near `0x226ab1d`?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead.
- Status: observed producer/store/branch/message bindings and raw u64 model.
  Upstream producers, reachability, units and full admission remain unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/local_state_selection_static.py --out work/local-state-selection-94.json
python -m unittest discover -s tests -p test_local_state_selection_static.py -v
python research/work-items/RE-001-local-state-selection-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured node, peer query, database or network action executes.

The complete enclosing FDE `[0x22689f0,0x226b503)` is decoded for boundaries
only: **11,027 bytes / 1,876 instructions**. Retained selected excerpts total
**200 bytes / 34 instructions**, covering owner source context, input producers,
arithmetic/branches and the stale join. Raw original FDE/CIE and complete body
hash are retained. Complete poller semantics are not claimed. Coordinates are
ELF VAs; `.text` offsets are VA minus `0x1000`. No masks.

## Captured operands and selection

At `0x226a974..0x226a993`, the routine saves prior R15 to `[RSP+0xc8]`, prior
R14 to `[RSP+0xd0]`, and `[RBX+0xb0]` to `[RSP+0xd8]`. Name those raw u64
words C, B and A respectively; their upstream producers are outside the packet.

The selected branch computes `L = min(A + 20000, u64::MAX)` using unsigned
mathematical addition. The fast path compares A with sign-extended -20,000 and
uses LEA. The upper path uses ADD, initializes RCX to all ones and conditionally
moves the wrapped sum only without carry. It then selects:

| Ordered condition | Selected path |
| --- | --- |
| L <= B | `local height is too far behind` |
| Otherwise, A < C | `local height is from stale hardfork` |
| Otherwise | Continue at `0x226adb1` in this selected window |

Both reason strings are bound by actual RIP-relative LEAs and explicit lengths
30 and 35. The common stale join clears byte `[RBX+0x49f0]`, requests a `0x3ae8`
byte copy and stores the selected reason pointer/length at stack +0x20/+0x28.
It is not a claim of diagnostic emission or a complete state-discard protocol.

Equality enters the first reason. Saturation also matters: A=B=u64::MAX enters
that reason even though mathematical B-A is zero. The model therefore does not
replace this with an unqualified lag-difference rule. The second reason is
tested only after the first comparison fails; A=C takes the continuation there.

An owner-context Location at `0x569e5d0` points to captured
`node/src/local_abci_state.rs:111:18`. It is referenced elsewhere in the same
FDE, not proof of a source line for every selected instruction. The reference
assigns 20,000 to a Duration and separately uses height-lag constant 200. Those
declarations do not establish this selected raw-word predicate, its units or
the absence of other checks. No reference implementation is copied/changed.

## Controls and required checks

Six focused methods pass. The saturating-add model agrees with independent
unbounded addition plus min for **40,002** declared local words: 0..20,000 and
the final 20,001 u64 values. **1,000** declared triples test priority/equality
and saturation, plus explicit threshold and equal-maximum probes. These are
primitive/model populations, not captured executions or reachable node states.
Actual-capture mutations cover input offsets, add/carry/unsigned conditions,
priority, reason bytes, join stores, source Location, FDE and identity.

Make is absent; required Makefile Python commands were run directly. Full
suite: **363 tests in 107.266 seconds; 7 failures, 16 errors, 21 skips**. All
six new methods pass. This independent main-based branch excludes unmerged
#227. Doctor reports missing native prerequisites. Eight artifact size/digest
checks pass before missing GPG prevents signature verification. Imports reject
the Windows reference checkout (reserved `node/aux.rs`, hydrated LFS inputs
retained); catalogue fails on native backslash paths. Reproduce stops at
artifact verification. Those failures are not marked passed.

No full bootstrap/peer-selection policy, height/time units, other admission
checks, async state machine, Rust type, native build/equivalence, hosted CI or
progress gate. Next question: close the three upstream word producers and
their valid domains before assigning a typed freshness/height policy.
