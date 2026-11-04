# RE-001: map node115 paired registry scan and short-circuit result

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x560f890,0x560fa10)`: 384 bytes.
- Complete FDE `[0x560eb10,0x560f890)`: 3456 bytes.

Export denominator: **3840 bytes /795 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

The bounded question is how two registry collections are scanned together and which local predicates short-circuit the Boolean-like return. This does not give the opaque predicates source-level names such as emptiness, permission or balance.

Context+0/+8 point to two descriptors whose +0x10 lengths are compared. A mismatch calls the diagnostic associated with `l1/src/dex_registry/dex_registry.rs:37:48`. If that call returns, both lengths are reloaded and their unsigned minimum bounds the scan. The equal-length route uses that shared count. A zero count skips the loop but DOES NOT skip the tail checks.

The first descriptor's data pointer+0x60 and the second's data pointer+0x188 start the paired scan. Each iteration advances those positions by 0x510 and 0x200 respectively. The 20 raw bytes referenced by context+0x18 are copied into local arguments before each predicate call. The first helper is `0x4716be0`; its returned pointer is replaced by the global fallback at 0x64fda80 if null, after the observed global-initialization helper route where needed. A nonzero word at selected pointer+0x20 immediately returns low-byte true.

Only if that test is zero does helper `0x5a1d500` inspect the second row. Its nonzero RAX also short-circuits true. Otherwise both row pointers advance and the count decrements. After all pairs, helper `0x5a1d230` receives context+0x10's pointed object and the same 20-byte argument. A nonzero return is true; zero continues to the word at the object referenced by context+0x20, offset+0x20, whose nonzero status supplies the final low-byte result.

The real caller invokes this body at `0x560f550` and `0x560f586` and tests AL. Its two true paths write raw reasons 0x182 and 0x183 respectively before their common exit. No original policy naming or complete caller behavior is assigned. Valid descriptors/extents and normally returning ABI-preserving helpers are explicit preconditions; global construction, predicate internals and ownership remain open.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-registry-paired-scan/collect.py --output work/dex-replay --check
python3 -m unittest discover -s tests -p test_next4_dex_static.py -v
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
