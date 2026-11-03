# RE-001: map node115 utility serialization and digest handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x38d2ce0,0x38d2ee5)`: 517 bytes.

Export denominator: **517 bytes /105 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The utility begins with a local three-word buffer descriptor (0,1,0) and calls0x41d4b30 using the original incoming RSI. Only raw result head0x8000000000000004 enters the ordinary digest path. Other heads first clean the buffer when its first word is nonzero, then reach the retained utils.rs:19:42 diagnostic and UD2.

The ordinary route reads the buffer pointer and length directly, initializes a local state including word0x88 and WORD1, and calls slots0x64e0148 and0x64e0150 with a retained224-byte state copy and requested32-byte final output. Unlike the action-associated append body, this utility inserts no locally authored suffix between serialization and update.

The final32 bytes are copied to the caller's output and the original serialized allocation is conditionally released. This bounds the plain serialization-to-digest handoff, not a recovered serializer schema or hash algorithm. Original input type, hash names, error ownership and caller validity remain unknown; all helper closure gates stay false.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-utils-serialization-digest/collect.py --output work/utilsparse-replay --check
python3 -m unittest discover -s tests -p test_twenty_utilsparse_static.py -v
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
