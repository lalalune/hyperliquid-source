# RE-001: map node115 abstraction direct and wrapped dispatch

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2c6bbf0,0x2c6bed9)`: 745 bytes.

Export denominator: **745 bytes /152 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

State byte+0x80 equal0 returns raw WORD0x10a. Otherwise a20-byte key lookup supplies a mode byte at returned+0x3c. Mode4 with state byte+0x7b8 equal1 goes directly to0x2c3d2e0. Other modes go directly when mode<3 or state byte+0x7b9 has bit0 set; mode4 does not use that latter predicate.

The wrapped route first calls0x239e390, requiring WORD0x1a2 or propagating its112-byte result. Its ordinary route calls0x2a88af0, then the central0x2c3d2e0 into a saved local result. Post-processing is mode-dependent: mode4 calls0x2a88380 with the actual impl_abstraction.rs Location; other modes call0x2a83ef0 and may clean a non0x1a2 result.

The returned result on ordinary continuation is the saved central operation result, not the post-processing result. All helper effects, raw mode names and rollback/transaction contracts remain unclosed. This resolves routing and result ownership at the local handoff boundary only.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-abstraction-wrapper-dispatch/collect.py --output work/abstraction-replay --check
python3 -m unittest discover -s tests -p test_twenty_abstraction_static.py -v
```

Ubuntu24.04, Python3.12.3, GNU binutils2.42. The digest-first collector uses a
private non-executable input copy and checks complete FDE bounds, contiguous
native instruction bytes, raw unwind/LSDA records, actual calls/RELA slots and
source Location metadata. GNU text trailing spaces are trimmed only after raw
instruction verification. Original and mutated bytes are never executed or emulated.

The focused checks regenerate native records/exports exactly, reject a changed
target before native tools/output, and corrupt actual instruction groups and
semantic operands/conditions in private Python bytearrays. These are evidence
integrity controls, not equivalence of an invented source implementation.
No normalized or compiled source-body comparison is introduced.

All component gates remain false. No root Cargo graph, recovered public Rust ABI,
source-built node, complete helper closure, live fixture, captured execution,
network/chain action, signing or paid dataset is claimed. New material uses root
MIT; imported inputs retain existing rights. Remaining questions are explicit
above; the next step is to close the referenced opaque helpers and caller-owned
layouts before implementing any whole-component behavior.
