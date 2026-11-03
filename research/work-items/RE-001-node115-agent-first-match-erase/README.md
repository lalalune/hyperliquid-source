# RE-001: map node115 agent first-match erase ordering

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3be79a0,0x3be7e79)`: 1241 bytes.

Export denominator: **1241 bytes /263 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

An outer keyed lookup selects a bounded56-byte row, or calls a create-shaped helper before scanning. Consequently an eventual inner miss is not proved side-effect-free. The selected row supplies an inner data pointer at+8 and count at+0x10; the scan visits56-byte records in order.

The first record with length at+0x10 equal to incoming R9 and zero EAX from the comparison loaded through0x64df9f8 is selected. The binding of that loaded slot is retained separately from the register-indirect call. The following `(count-index-1)*56` bytes are moved left through0x64df568 and the count is decremented. Only then is the removed record's first word checked for the min-i64 sentinel and later conversion/recording work attempted. No rollback or atomicity follows from a later diagnostic.

Empty/exhausted inner scans write raw WORD0x5c. The later ordinary operation route can write0x1a2, but its numeric/time helpers, public result meanings, original account types and caller contracts remain unclosed. This resolves selection and erase ordering, not the whole agent policy.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-agent-first-match-erase/collect.py --output work/agent-replay --check
python3 -m unittest discover -s tests -p test_twenty_agent_static.py -v
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
