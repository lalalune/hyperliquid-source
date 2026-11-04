# RE-001: map node115 perp metadata tier selector and projection

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x3c43150,0x3c432f4)`: 420 bytes.
- Complete FDE `[0x3f17df0,0x3f17f19)`: 297 bytes.

Export denominator: **717 bytes /191 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

Raw unsigned EDX below50 selects a32-byte-spaced global row, after the observed initialization route if required. This arm writes four output words:1,0,the global row address, and self+0x58's retained word. Global construction/content and public tier names remain unclosed.

For indices>=50, self+0x30 equal to the min-i64 sentinel selects an inline tree-shaped lookup. Its native count is u16 at node+0x2f6, first compared key at+0x2c8 and child links at+0x2f8; traversal and row-address arithmetic use64-byte steps. Other raw descriptor forms call opaque0x4556c50, test AL bit0, bound the returned index against self+0x48, add the head-like word at+0x40 and subtract capacity once when needed. That single subtraction depends on valid native ring invariants; it is not arbitrary-index modulo validation.

The alternative data row uses72-byte spacing plus8. Both lookup arms converge on a common selected address A: outputs are `[A+8]`, `[A+0x10]`, `A+0x18`, `[A+0x38]`. Miss/bounds paths reach the actual perp_meta.rs:247:72 diagnostic, whose nonreturn contract is unclosed. The full small caller is retained as actual invocation context. Original container types, values/units, lifetime and complete helper/global closure are not claimed.

The retained complete caller contains the actual indirect call at `0x3f17e46`; only that target binding is adopted, not its broader behavior or a recovered public ABI.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-perp-tier-projection/collect.py --output work/perp-replay --check
python3 -m unittest discover -s tests -p test_tnext_perp_static.py -v
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
