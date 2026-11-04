# RE-001: map node115 outcome bypass and membership insertion boundary

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2c269b0,0x2c26b7a)`: 458 bytes.

Export denominator: **458 bytes /108 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

Raw CL equal0x25 returns WORD0x1a2 before the later state flag store or diagnostic-shaped handoff. Every other selector stores byte1 at state+0x2a8 before checking the input. The input must have first byte1 and a nonzero20-byte payload at+1 to reach the membership lookup; other inputs still retain that preceding flag mutation.

The lookup traverses the native keyed structure at state+0xb78/+0xb80 using20-byte comparisons, u16 node counts at+0xe6 and children at+0xe8. An existing key returns raw WORD0x155. A missing root or missing descent calls0x26dc590 with the prepared insertion-shaped descriptor, and afterwards also returns0x155, independent of that helper's returned value.

Thus0x155 alone cannot distinguish precheck rejection, existing membership and the observed missing-key helper handoff. No success/error label or idempotence claim is assigned. Original key type, tracing effects, insertion internals, tree invariants and public selector validity remain unclosed.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-outcome-bypass-membership/collect.py --output work/outcome-replay --check
python3 -m unittest discover -s tests -p test_twenty_outcome_static.py -v
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
