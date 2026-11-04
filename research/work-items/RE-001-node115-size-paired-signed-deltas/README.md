# RE-001: map node115 size-associated paired signed deltas

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x22f6090,0x22f6366)`: 726 bytes.

Export denominator: **726 bytes /167 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The descriptor's direction byte selects one of two20-byte keys. On the first pass a nonzero direction chooses the key at+0x10 and the signed-saturating negation of the pointed amount; zero chooses key+8 and the unchanged amount. Negation maps INT64_MIN to INT64_MAX. The helper bound through0x64e4f90 receives that selected key and another pointed word, and the selected signed amount is subtracted from its RAX result.

The second pass chooses the opposite key and the opposite amount-sign relation, then repeats the same helper/subtraction boundary. Signed overflow in either subtraction reaches the actual impl_sz.rs Location and chooses the appropriate signed endpoint if the diagnostic returns normally. Helpers can mutate pointed inputs, so the two passes' reloaded values are not silently assumed identical.

Each pass also consults an optional indexed u64 word: an index outside the descriptor length selects zero rather than reading past the array. The output retains two native288-byte blocks with raw tag1, the corresponding signed difference, and associated key/optional word. Other locally uninitialized bytes receive no invented values. This resolves paired direction and arithmetic boundaries, not original size units, helper semantics, public record schema or complete order behavior.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-size-paired-signed-deltas/collect.py --output work/sizeguard-replay --check
python3 -m unittest discover -s tests -p test_twenty_sizeguard_static.py -v
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
