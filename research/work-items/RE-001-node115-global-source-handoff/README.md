# RE-001: map node115 global source selection and descriptor handoff

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x2420b60,0x2420c88)`: 296 bytes.

Export denominator: **296 bytes /68 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The bounded question is which raw selector chooses which retained source, and how an empty source reaches the same downstream consumer. Only DIL is compared: byte3 selects the pointer loaded through0x64dfff8; all other raw byte values select0x64e0000. The two actual relocation records are retained without assigning enum names or object semantics.

The chosen object's dword+0x28 can invoke the initialization-shaped helper before the presence word+0x10 is tested/retested. If present, object+0 must be nonzero before helper0x2463400 receives it and object+8; the incoming RSI is preserved across that preparation. If absent, the local first and third words are zeroed, while the middle raw word is NOT initialized here. No fabricated empty allocation pointer or original Rust container is assigned.

The three words are handed to0x28abef0 with the source Location at impl_global.rs:970:46. A nonzero first word in its separate output selects a cleanup call; the input descriptor is subsequently cleaned on the ordinary route. The helpers' ownership, effect, result interpretation and nonreturn contracts remain open. This records native selection and call order, not a recovered global policy or source-built execution.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-global-source-handoff/collect.py --output work/global-replay --check
python3 -m unittest discover -s tests -p test_tnext_global_static.py -v
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
