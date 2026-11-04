# RE-001: map node115 bole free-entry selection and counter ordering

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2c80670,0x2c80a3d)`: 973 bytes.

Export denominator: **973 bytes /189 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

A zero incoming index returns raw qword2. A nonzero index must be below the primary length before selecting a344-byte row. That row supplies a sequence of u64 indices; each is length-checked against a secondary32-byte row collection. Rows whose+8 word is nonzero are skipped, and the first zero-word row is selected. The associated keyed lookup must also succeed before the later operation.

Before numeric preparation and the opaque operation, state word+0x38 is incremented with saturation at UINT64_MAX and stored. This store therefore precedes any operation result interpretation; no rollback or atomic counter contract is inferred. Numeric calculation and conversion are retained but units, rounding and the conversion helper remain unclosed.

The later call through0x64e7f30 receives the selected secondary index and actual impl_bole.rs:384:35 Location. A returned head dword2 selects output qword2; other results are projected with the retained large payload copies. No public order type, success/error meaning, price policy or complete operation behavior is claimed.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-bole-entry-counter-order/collect.py --output work/bole-replay --check
python3 -m unittest discover -s tests -p test_twenty_bole_static.py -v
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
