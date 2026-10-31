# RE-001: checkpoint maintenance dispatch and diagnostic joins

- Component: engine / checkpoint maintenance. Question: which calls follow the
  tar/prune result checks in the FDE at `0x432f310`?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, consulted as a lead only.
- Status: observed control/data bindings and conditional call milestones;
  helper side effects and full source-language interface remain unresolved.

## Reproduce

Repository root with CPython 3.12.14 on Windows:

```sh
python tools/checkpoint_flow_static.py --out work/checkpoint-flow-94.json
python -m unittest discover -s tests -p test_checkpoint_flow_static.py -v
python research/work-items/RE-001-checkpoint-maintenance-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected Windows wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Only static file parsing/disassembly occurs. No captured code, archive command,
file removal, database, network or chain operation executes.

`window.capstone.txt` retains the complete unwind window
`[0x432f310,0x432f5ed)`: **733 bytes / 169 instructions**, contiguous complete
byte consumption, raw original FDE/CIE and body SHA-256
`2bc1cee7929de30afb2d6d383af783abd5e0d074216ad1a0b42293989de25a00`.
All selected observations are instruction starts. Coordinates are unrelocated
ELF VAs; `.text` file offsets are VA minus `0x1000`. No normalization masks.

## Source ownership and selected calls

The reference `node/abci_checkpoint.rs` assigns a pending node-checkpoint name
to this seed and describes a Rust Result-returning wrapper with an external
date parameter. The captured diagnostic Locations instead bind to
**`l1/src/abci/engine.rs:279:25` and `286:17`**, via RELATIVE pointers at
`0x571c948` and `0x571c930` to path `0x1f53f5`. They establish those diagnostic
source locations, not an original complete private function name/type.

The captured input pointer is saved and advanced by `0x10` for helper calls.
`TEST ESI,ESI` selects the paths below. No source-level bool layout or function
signature is declared from the register observations alone.

| Path | Selected call/binding |
| --- | --- |
| ESI nonzero | Preparation through slots resolving to `0x151cba0`, `0x151cec0`, `0x151f870`; the third gets ESI `0xffffffff` |
| Prepared tar path | Slot `0x5775e90 -> 0x37e2960` at `0x432f378` |
| ESI zero | Slot `0x5775ea0 -> 0x37e3a70` at `0x432f3f8`, ESI **100** |
| Both diagnostic arms | Slot `0x576e978 -> 0x143d010` |
| Tar followup | Slot `0x5775eb0 -> 0x37e3f40` at `0x432f4ed` |
| Nonzero followup result | Slot `0x576e9a8 -> 0x13cbce0` |

Messages identify `tar_evm_checkpoints failed` and
`prune_lowest_evm_checkpoints failed`. Their original prefixes through the first
embedded zero delimiter are retained in hex, without claiming the complete
format-template grammar. The helper names here are message-based context;
archive/prune/followup internals are not recovered in this packet.

## Result checks and conditional joins

After the tar helper, `XOR EAX,EAX; CMP RAX,[RSP+0x38]; JNO` tests signed
overflow of **0 minus the raw result word**. Overflow occurs exactly for
`0x8000000000000000`; all other u64 words take the no-overflow arm. This is a
raw result-word observation, not an inferred generic Rust Result discriminant.

On the diagnostic arm, a critical-message call and an indirect drop call precede
the jump to `0x432f4ea`, which calls the followup. The no-overflow arm consumes
its returned collection and reaches the same followup after cleanup. A global
initialization slow path rejoins that consumption path. These joins assume
normal returns of out-of-scope helpers, initialization and destructors.

The prune path tests RAX for zero. Nonzero enters its own diagnostic/drop arm,
then joins `0x432f501`; zero goes there directly. Both bypass the tar followup.
The common normal cleanup decrements the input's reference-count word and calls
the bound destruction helper only on the zero result. Unwind routes and panic
arms remain exported but outside the simplified milestone model.

Thus, conditional on normal helper returns and successful date preparation:

| Input/result class | Selected milestones |
| --- | --- |
| Tar, raw result INT64_MIN | tar -> diagnostic/drop -> followup -> cleanup |
| Tar, other raw result | tar -> returned-value cleanup -> followup -> cleanup |
| Prune, nonzero result | prune(100) -> diagnostic/drop -> cleanup |
| Prune, zero result | prune(100) -> cleanup |

This does not establish whether diagnostics are emitted, whether a helper aborts,
which files are retained/deleted or whether the followup succeeds. In particular,
the reference's immediate `?` propagation does not establish this captured
conditional join. The function's scheduling period and full return ABI remain
unknown; no reference code is copied or modified.

## Controls, required checks and limits

Six focused methods pass. They compare the overflow primitive with an
independent sign-bit formula, exercise **196** declared milestone combinations
(four mode words x seven tar result words x seven prune result words), and
mutate actual dispatch/result/join/count operands, call slots/relocations,
message/source bytes, FDE extent and identity. These are primitive/conditional
models, not target executions or complete async/maintenance equivalence.

Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 109.651 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. These failures are not marked passed. No imported evidence,
complete Rust signature, helper/file-operation closure, hosted-CI success or
progress gate is claimed. Next question: close the tar/prune/followup callees
and date conversion before reconstructing maintenance behavior end to end.
