# RE-001: selected runtime state brackets in four wrappers

- Component: foundation / runtime adapters. Question: which raw state-cell
  stores and checks bracket the selected normal body path in four wrappers?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead only.
- Status: instruction/store/source observations and conditional raw-byte model;
  complete runtime, body and scheduler semantics remain unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/runtime_state_static.py --out work/runtime-state-94.json
python -m unittest discover -s tests -p test_runtime_state_static.py -v
python research/work-items/RE-001-runtime-state-brackets-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code, native TLS, runtime task, scheduler or thread action executes.

Complete owner exports retain raw FDE/CIE, body hashes and contiguous full-byte
instruction decoding:

| FDE start..end exclusive | Bytes | Instructions |
| --- | ---: | ---: |
| `0x28302f0..0x283069c` | 940 | 215 |
| `0x28306a0..0x2830a4c` | 940 | 215 |
| `0x2830a50..0x2830e18` | 968 | 224 |
| `0x2830e20..0x28313ec` | 1484 | 315 |

Total **4,332 bytes / 969 instructions exported**. Only the selected state-cell
semantics below are modeled; that total is not a matched/recovered-instruction
denominator. Selected operations and failure targets are instruction starts.
Addresses are ELF VAs; `.text` file offsets are VA minus `0x1000`. No masks.

## Observed selected protocol

The reference `base/u.rs` associates these four seeds with a blocking adapter.
The captured paths have entry bypasses, TLS initialization and scheduler/park
operations before the selected bracket. They are retained but not closed here.
Reaching the selected bracket and normal body return are explicit assumptions.

Each selected path reads a word at context offsets `+0x44/+0x45`, saves it,
and clears only byte `+0x44`. It reads the prior byte at `+0x46`; raw value 2
selects a pre-body failure route. Otherwise it stores 2 at that byte, then runs
its body. The first three include different direct bodies; the fourth also
contains inline body operations. No body function/type/effects are invented.

After ordinary body return each calls `0x4f72510`, tests its returned pointer,
and, if nonnull, compares byte `+0x46` on the returned object with 2. In the
fourth copy a MOV reload occurs between pointer TEST and JE and preserves flags.
Null selects its missing-context route; a different byte selects the post-body
failure route. If the byte is 2, the saved prior byte is stored at that offset
on the returned object.

The identity of that returned object with the earlier FS-relative context is
not independently closed through the resolver helper. Thus the model proves
selected stored values and conditional routes, not full TLS object identity or
thread-state restoration. Further helpers consume the saved flag word and other
state; restoring all flags, scheduler resources and unwind behavior is unproved.

| Selected raw class | Observed model milestone |
| --- | --- |
| Prior byte 2 | Pre-body failure route |
| Other prior byte, resolver null | Body state 2; missing-context route |
| Other prior byte, resolver nonnull, returned byte not 2 | Body state 2; post-body failure route |
| Other prior byte, resolver nonnull, returned byte 2 | Store saved prior byte on returned object |

Both failure source routes resolve through captured RELATIVE records to
`tokio-1.44.2/src/runtime/context/runtime_mt.rs`: 28:9 and 17:17. They establish
captured source context, not a complete Rust enum layout, original adapter name
or library equivalence. No upstream implementation is copied or modified.

## Controls and required checks

Six focused methods pass. All **131,072** declared raw prior/returned-byte and
pointer-presence combinations agree with the selected route model. All **65,536**
flag words preserve the saved word and clear only its low byte in the model.
Raw byte domains include representations that need not be valid runtime enums
or reachable states; none is described as an executed runtime call.

Actual-capture mutations cover all four save/clear/state/store sequences,
context-pointer checks, source routes, resolver calls, both source records,
four FDE extents and target identity. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 116.713 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Those failures are not marked passed.

No full entry/runtime enum, TLS initialization/destruction, resolver identity,
flag/scheduler/park/body/unwind closure, native build/equivalence, imported change,
hosted CI or progress gate. Next question: close the resolver and flag-restoration
helper before assigning a full typed runtime-adapter contract.
