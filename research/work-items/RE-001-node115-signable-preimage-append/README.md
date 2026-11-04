# RE-001: map node115 signable preimage append layout

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3c267e0,0x3c26bec)`: 1036 bytes.

Export denominator: **1036 bytes /228 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The bounded question is what this action-associated body appends after its serialization helper, before passing the buffer to opaque digest helpers. The serializer must return raw head 0x8000000000000004; other heads reach the retained rmp_signable.rs diagnostic and UD2. No original serializer schema or algorithm is recovered.

On that ordinary route the suffix starts with descriptor+0x10 as eight big-endian bytes. Descriptor byte+0x18 exactly equal to 1 appends byte1 followed by twenty bytes from +0x19; other values append byte0 alone. Descriptor dword+0 exactly equal to 1 additionally appends byte0 then the +8 word in big-endian order. These are exact equality predicates, not arbitrary nonzero tests. Capacity checks and growth handoffs remain in the full export.

The final buffer pointer/length goes through slots0x64e0148 and0x64e0150 with a 32-byte output request. Their algorithms remain unclosed. The body projects the resulting32 bytes to output+0x20, copies32 original input bytes from +0x48 to output, and stores the descriptor+0x10 word at output+0x40 and incoming EDX low byte at+0x48. Public signing formats, keys, hash names, caller validation and complete ownership remain unknown.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-signable-preimage-append/collect.py --output work/signable-replay --check
python3 -m unittest discover -s tests -p test_twenty_signable_static.py -v
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
