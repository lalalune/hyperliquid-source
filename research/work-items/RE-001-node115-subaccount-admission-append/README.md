# RE-001: map node115 subaccount admission and append ordering

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x366a620,0x366ac91)`: 1649 bytes.

Export denominator: **1649 bytes /333 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

Incoming R8 below10000000 returns raw WORD0xec with a floating payload conversion. At/above that boundary an existing record from0x4716880 can reject with0xe5 when its word+0x10 reaches the retained reciprocal-derived capped threshold. The exact reciprocal is retained, but the threshold's public units and policy name are unclosed.

The identity-producing helper must return0x1a2 or its payload is propagated. A20-byte existing-identity match returns0xe7. Otherwise the incoming descriptor length at+0x10 must be below101 to call0x366b350; length>=101 emits0x158. That helper also requires raw result0x1a2 before later preparation.

After the observed lookup invariant (a byte1 result reaches the actual sub_account.rs:75:13 diagnostic and UD2), the body prepares a64-byte append record. Capacity growth precedes writing the record at index*64, then length is incremented, then WORD0x1a2 and retained payload are returned. Public identity/account types, numeric formula semantics, helper mutations and rollback/ownership remain unclosed. This supplies real admission boundaries and append order without claiming full creation semantics.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-subaccount-admission-append/collect.py --output work/subaccount-replay --check
python3 -m unittest discover -s tests -p test_twenty_subaccount_static.py -v
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
