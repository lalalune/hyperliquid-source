# RE-001: map node115 staking nested lookup and comparison handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x36c7f70,0x36c8424)`: 1204 bytes.

Export denominator: **1204 bytes /283 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

The first descriptor's min-i64 head selects tree-shaped lookup; the alternative calls0x4551810, checks its flag/index and maps a56-byte row with one capacity subtraction under valid ring invariants. An outer miss constructs raw WORD0x9b, hands it to0x36dae30 and returns EAX0. The diagnostic/formatting effects of that helper remain unclosed.

The selected row contains another descriptor whose ring traversal uses104-byte elements; its tree form passes the retained root/height words. That iterator is handed to0x3bcb550, producing a separate materialized descriptor. A zero resulting length skips the later comparator and returns0 after observed cleanup routes.

Nonempty materialization is converted into a native iterator with40-byte steps, paired with an iterator prepared from the third input, and passed to0x422e0f0 with staking.rs:185:9. Its AL result is preserved across subsequent cleanup. This closes the outer-miss/empty/compare handoff partition and the distinct traversal widths, not the comparator's relation, stake units, original container types or complete lifecycle.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-staking-nested-comparison/collect.py --output work/staking-replay --check
python3 -m unittest discover -s tests -p test_twenty_staking_static.py -v
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
