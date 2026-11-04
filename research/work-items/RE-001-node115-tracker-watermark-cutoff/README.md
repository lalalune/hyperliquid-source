# RE-001: map node115 tracker watermark and saturating cutoff pair

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x27604d0,0x27605cd)`: 253 bytes.
- Complete FDE `[0x27605d0,0x27606cd)`: 253 bytes.
- Complete FDE `[0x2760380,0x27604c7)`: 327 bytes.

Export denominator: **833 bytes /199 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The two complete tracker-associated bodies are one outcome. Both first store unsigned max(previous object+0x80,incoming RSI) to object+0x80. A trace/global-initialization route then rejoins the same processing path; this is not a signed maximum or a counter increment.

Both call0x2daf740 with object+0x60, the incoming value and the fourth argument's +0x60 field, supplying the actual line174 Location. Afterwards equality between the incoming value and fourth-argument object+0x10 writes WORD1 at target+0x90. The unequal path does not locally clear that marker; its meaning and initial state are not inferred.

The original incoming word, rather than the stored maximum, is reduced by50000 with unsigned borrow selecting zero. Thus cutoff=max(incoming-50000,0). This cutoff and saved third argument are passed to distinct tail helpers:0x28aced0 in the first body and0x28ac490 in the second, both with the line184 Location. Their returned allocation-like descriptor can trigger the observed scaled cleanup. Neither helper's data pruning semantics, hashing/signature algorithm, persistence nor complete ownership is recovered. Valid native objects and normal ABI-preserving helper returns are preconditions.

The retained complete caller contains the actual direct call at `0x2760454`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-tracker-watermark-cutoff/collect.py --output work/tracker-replay --check
python3 -m unittest discover -s tests -p test_tnext_tracker_static.py -v
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
