# RE-001: map node115 engine row window and stable retention

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3d5dca0,0x3d5dfb0)`: 784 bytes.

Export denominator: **784 bytes /180 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The body consumes32-byte source rows and writes a stable retained prefix at the source allocation base. The input cursor is advanced and stored BEFORE its predicate helper runs. The helper bound through0x64e0950 receives a formatted/local pointer-length pair; if AL is nonzero, the current row is retained without testing the later numerical window. No filesystem or public predicate meaning is assigned.

On a false predicate, the raw word from row+0x18 is tested against three pointed bounds. Value<lower reaches the actual engine.rs:557:17 diagnostic; if that call returns normally, the subsequent tests still apply. Under stable pointed bounds and ordinary helper returns, the retaining window is unsigned `value>=lower && value<upper && value<=ceiling`. Equality is included at lower/ceiling and excluded at upper. Original height/time/sequence units, bound stability across helpers and diagnostic nonreturn remain unclosed.

Retained rows are copied32 bytes and advance only the output pointer; discarded rows take their conditional cleanup route and do not advance it. The final descriptor preserves the incoming allocation/base and reports `(write-base)>>5`. An empty source publishes length0. Full helper effects, input ownership and unwind cleanup contracts are not recovered. The next step is closing the predicate and caller-owned bound construction before any higher-level engine-policy implementation.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-engine-row-window/collect.py --output work/engine-replay --check
python3 -m unittest discover -s tests -p test_tnext_engine_static.py -v
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
