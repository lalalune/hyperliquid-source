# RE-001: map node115 raw-volume tag and threshold result boundary

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2a82220,0x2a825b2)`: 914 bytes.

Export denominator: **914 bytes /214 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

Tag1 takes the20-byte key from its pointed object+0xc8; other raw tags take the key inline at descriptor+1. The keyed record helper supplies a word L at+0x20. L<1000 selects raw head0x800000000000001b before the later threshold computation. Tag1's nonzero pointed field+0xb8 and the all-ones key check also select that head.

Other tag/property gates select raw head0x8000000000000018 without traversing the later aggregates. One predicate helper can choose threshold10000. The fallback retains aggregate helper calls, saturating additions and a reciprocal calculation followed by a min4000 clamp and addition1000. Its units and full mathematical conversion remain unclosed; no volume policy is inferred from source names.

At the final threshold boundary L<threshold selects head0x800000000000001b; equality is on the0x8000000000000018 side. This establishes key provenance, early short circuits and the final strict comparison, without closing the shared aggregation callees, original tag names, result schema or public volume semantics.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-raw-volume-tag-threshold/collect.py --output work/rawvolume-replay --check
python3 -m unittest discover -s tests -p test_twenty_rawvolume_static.py -v
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
