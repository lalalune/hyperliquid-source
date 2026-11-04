# RE-001: map node115 chain selector dispatch and retained globals

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x46f3fc0,0x46f40b0)`: 240 bytes.

Export denominator: **240 bytes /58 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

This retains the leading four actual signed-relative entries used by the raw DIL-indexed jump table, independently decoding their destinations and requiring instruction boundaries in the measured FDE. There is no local range guard, so four measured entries are not a proof of the full public enum domain.

Three ordinary arms select distinct retained addresses0x64fdb50,0x64fdb30 and0x64fdb70 with corresponding state dwords0x64fdb68,0x64fdb48 and0x64fdb88. A nonzero state takes the common initialization-shaped helper through0x64df9f0 before returning the selected address. The fourth measured destination reaches the chain_ext.rs:109:29 diagnostic; its nonreturn behavior remains unclosed.

The authenticated table records supply the actual selector-to-destination relation. No chain/environment names, initialized object contents, public enum bounds or original global type are assigned. BSS runtime state and initialization helper internals are unmeasured.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-chain-dispatch-globals/collect.py --output work/chain-replay --check
python3 -m unittest discover -s tests -p test_twenty_chain_static.py -v
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
