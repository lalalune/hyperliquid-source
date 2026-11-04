# RE-001: map node115 level replacement and aggregate update pair

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x25da200,0x25da3d7)`: 471 bytes.
- Complete FDE `[0x25da3e0,0x25da5b7)`: 471 bytes.

Export denominator: **942 bytes /228 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

These two variants implement the same bounded replacement ordering with different retained change-record widths, so they are one submission. Both compare incoming RDX to object+0xe0 and return immediately if equal. Otherwise object+0xe0 is overwritten before preparing/appending the change record and before updating aggregate-like words. Therefore a later arithmetic diagnostic does not establish rollback of the earlier store.

The append capacity check may call a growth helper, then the native copy call writes712 bytes in the first variant or696 in the second, and increments the destination length. Only explicitly written fields of the stack record have assigned meaning; padding, original enum names and the full event schema are not invented.

The external word referenced by incoming R8 is updated by subtracting the old value, diagnosing borrow and selecting zero, then adding the new value with overflow selecting UINT64_MAX. These relations describe local continuation only if diagnostics return normally and preserve the ABI. If incoming R9 is nonnull, its +0x70 word undergoes the same subtraction/readdition ordering. The optional path is pointer nonnull, not a recovered public account type. Calls, original values, record widths and both FDEs are retained; helper capacity/ownership, units and full book transition semantics remain open.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-level-replacement-accounting/collect.py --output work/level-replay --check
python3 -m unittest discover -s tests -p test_tnext_level_static.py -v
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
