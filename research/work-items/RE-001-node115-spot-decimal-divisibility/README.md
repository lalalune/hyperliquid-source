# RE-001: map node115 spot metadata decimal divisibility guard

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x29aea00,0x29aeaf2)`: 242 bytes.

Export denominator: **242 bytes /73 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The incoming index is checked against the first descriptor length, then its32-byte row supplies a second index checked against a second length. The second row has344-byte spacing; byte+0x48 is the decimal selector d. Both out-of-range indices reach actual retained diagnostics before data access.

For d>8 the body returns raw WORD0x6a. For d in0..8 it constructs divisor10^(8-d) through conditional multiplications by10,100,10000 and100000000. The incoming unsigned amount must be divisible by that divisor with zero remainder. A32-bit division shortcut is used only when the OR of amount and divisor has no high32 bits; otherwise the64-bit division is used.

Zero remainder writes the quotient at output+8 and WORD0x1a2; nonzero remainder writes0x6a without assigning inactive payload bytes. This recovers a concrete decimal-granularity acceptance boundary and quotient, not public asset names, economic units, original Rust types or complete metadata construction. Caller-owned lengths/layouts remain native validity preconditions.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-spot-decimal-divisibility/collect.py --output work/spotmeta-replay --check
python3 -m unittest discover -s tests -p test_twenty_spotmeta_static.py -v
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
