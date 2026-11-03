# RE-001: map node115 hash-associated snapshot handoff and error branch

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x38c2580,0x38c268f)`: 271 bytes.
- Complete FDE `[0x38c2690,0x38c2a3e)`: 942 bytes.

Export denominator: **1213 bytes /245 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

This maps the preparation and error boundary of one hash-associated native body; it does not claim to recover the hash algorithm. After preparing a message-like three-word local object, the body copies three2064-byte blocks from self offsets0xf8,0xa00 and0x1308 into consecutive stack destinations0x30,0x840 and0x1050. Source spacing is0x908 while destination spacing is0x810, so these are not one contiguous source slice.

All three register-indirect copy calls use R15 loaded through the actual0x64df508 relocation slot. The record preserves that binding as well as the unresolved register-indirect call sites; no original state type or Rust layout is assigned. The first snapshot address, prepared message pointer/length and the real hash.rs:68:27 Location are passed to0x422f030.

Its zero RAX route reaches local cleanup and returns. A nonzero RAX is dereferenced for another indirect call; that target is unclosed, and nonreturn is not assumed from source labels. The complete immediate caller is retained as handoff context only. Message formatting, the diagnostic consumer, dynamic method target, cleanup contracts and all hash/state semantics remain unknown. The concrete advance is the exact three-region snapshot boundary and conditional error route.

The retained complete caller contains the actual direct call at `0x38c292d`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-hash-diagnostic-snapshots/collect.py --output work/evmhash-replay --check
python3 -m unittest discover -s tests -p test_tnext_evmhash_static.py -v
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
