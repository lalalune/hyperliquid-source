# RE-001: map node115 clearinghouse row materialization and count handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2705070,0x270527b)`: 523 bytes.
- Complete FDE `[0x231ad80,0x231aebb)`: 315 bytes.

Export denominator: **838 bytes /199 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The native body materializes a sequence into a caller-owned destination; it does not establish an original clearinghouse row type. It reads the source cursor/end at input+8/+0x18 and starts destination index from the second descriptor+8. Each source iteration advances112 bytes, while the destination slot advances160 bytes. Source/destination extents and preallocated capacity are native validity preconditions; no new capacity protection is invented.

For each row the word at source+0x28 is retained and its unsigned quotient by10000 is passed in R8 to0x2c3c2b0. The record construction copies the observed source fragments, duplicates the20-byte metadata at+0x58 into helper arguments, and retains the actual cl_trait.rs:720:28 Location. Helper output plus the saved16-byte fragment is copied into the160-byte destination slot. The row schema, constructor result, units and helper behavior are unclosed.

After ordinary traversal, the final destination index is published through the pointer at second descriptor+0, including an initially empty source. The exceptional cleanup path also publishes the current index before releasing source storage and resuming unwind, so count publication is not confined to success. Cleanup ownership and complete unwind contracts remain unknown. The complete small caller establishes a real invocation; its other behavior is context only. All gates stay false.

The retained complete caller contains the actual direct call at `0x231ae48`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-clearinghouse-row-materialization/collect.py --output work/cltrait-replay --check
python3 -m unittest discover -s tests -p test_tnext_cltrait_static.py -v
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
