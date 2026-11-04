# RE-001: map node115 user encoded-tag admission routes

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2c77640,0x2c77ba5)`: 1381 bytes.

Export denominator: **1381 bytes /268 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The native tag expression is ((raw+0x8000000000000001) mod2^64) AND the arithmetic sign mask of raw. Consequently nonnegative raw words produce0, and raw0x8000000000000001 produces2 and the early WORD0x92 result. The remaining negative-word encodings follow a different admission route; no Rust enum representation is invented.

State flag+0x10e4 selects the current admission path versus an alternate20-byte keyed lookup at+0x1060/+0x1068. The alternate lookup's miss returns WORD0x98. Later raw mode and descriptor flags can also produce0x92; identity comparison and helper gates are retained without assigning public authorization semantics. The tag0 route additionally checks descriptor amount+0x58 against0x0ccccccccccccccc, emitting0x154 with that word when outside the strict bound.

The remaining budget checks, optional identity helper, central operation and follow-up effects are intentionally unclosed. Their raw result codes are retained in the body but are not translated into invented business meanings. This packet resolves the encoded-tag partition and observable admission boundary, not full account permissions or security behavior.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-user-encoded-tag-admission/collect.py --output work/user-replay --check
python3 -m unittest discover -s tests -p test_twenty_user_static.py -v
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
