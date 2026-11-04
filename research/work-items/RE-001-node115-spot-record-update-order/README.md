# RE-001: map node115 spot record update and optional scaling gates

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3bfa910,0x3bfac09)`: 761 bytes.

Export denominator: **761 bytes /189 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

After the retained lookup/create helpers select a record, a nonzero raw direction byte takes the subtract route. The amount is subtracted from record word0 with a borrow diagnostic; the resulting word0 is stored before subtracting the same amount from word+8. That second borrow has its own diagnostic/continuation, so this is not a combined atomic two-word update.

The zero-direction route calls0x3c003c0 before loading/increasing word0. Its overflow diagnostic continuation selects UINT64_MAX for the store. These are local arithmetic and call-order observations conditioned on normal ABI-preserving diagnostic return, not a claim that diagnostics return or that a partial update is safe.

The later scaling follow-up requires both incoming R9 and incoming RDX nonzero. It consults record+0x10 and opaque numeric helpers before conditional writes there. Numeric units, ratio rounding, native ownership, public direction meaning and complete helper closure remain unknown. The packet separates those unclosed calculations from the proven initial writes and optional admission gates.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-spot-record-update-order/collect.py --output work/spottypes-replay --check
python3 -m unittest discover -s tests -p test_twenty_spottypes_static.py -v
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
