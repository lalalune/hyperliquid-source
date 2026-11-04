# RE-001: map node115 oracle-kind row window and output layout

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3db4e40,0x3db50ed)`: 685 bytes.

Export denominator: **685 bytes /158 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The descriptor contributes a shared-object pointer, an index i at+8 and an offset O at+0x10. Checked increments and additions precede the ordinary bounded construction. Under valid nonoverflow native values, rows are emitted for indices i <= k < 3-O; i>=3 or O+i+1>=4 produces the raw empty descriptor (0,8,0). Overflow reaches diagnostics rather than ordinary wraparound.

Each output row spans56 bytes: byte0 is1, byte1 is the current index, word+8 reloads the shared object's first word, words+0x10/+0x20 are zero, and bytes+0x30..+0x32 are2. Other padding/inactive bytes receive no invented values. The initial allocation is224 bytes/capacity4 and the growth handoff is retained.

The cursor/clamp arithmetic is local: this body does not store an advanced index back into the input descriptor. This distinguishes constructing an owned bounded row window from a mutating public iterator. Oracle names, original enum variants, shared-object contents and allocation/helper contracts remain unclosed.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-oracle-kind-row-window/collect.py --output work/oraclekind-replay --check
python3 -m unittest discover -s tests -p test_twenty_oraclekind_static.py -v
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
