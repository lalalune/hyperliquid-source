# RE-001: map node115 clearing result gate and paired append ordering

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3d987f0,0x3d98b32)`: 834 bytes.

Export denominator: **834 bytes /202 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The wrapper assembles two optional native lookup words before calling0x447c620: a keyed value from the first collection (zero on its observed miss routes), and a word at+0x118 in a288-byte row of a second optional collection. The second row index is the incoming unsigned key's remainder modulo10000, with a real length guard before access. The reciprocal sequence is retained; original key units and collection types are not inferred.

The helper receives those words, original key and raw selector byte together with clearinghouse.rs:544:18. A returned first word equal to min-i64 bypasses both append sequences and makes AL1 at the final comparison. A different first word is appended with the next two returned words into a24-byte destination slot, incrementing its length before the later formatting helper runs.

A second24-byte formatted record is appended afterwards and increments length again. There is no local rollback of the first append if later work fails. The formatting-only key transformation and cleanup remain in the export but are not a recovered policy. AL is solely the final sentinel equality, not an invented success enum. Helper behavior, allocation ownership and complete clearing semantics remain open.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-clearing-result-append/collect.py --output work/clearing-replay --check
python3 -m unittest discover -s tests -p test_twenty_clearing_static.py -v
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
