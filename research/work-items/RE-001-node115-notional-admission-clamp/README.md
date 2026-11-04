# RE-001: map node115 notional-associated admission and quotient clamp

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x4483920,0x4483baa)`: 650 bytes.

Export denominator: **650 bytes /184 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
Unmeasured callers are not part of this evidence extent; no public ABI is inferred.

## Bounded native result

A nonzero AL from predicate slot0x64e5ae8 or a missing0x47171f0 lookup returns zero. An existing record with no selected nested row returns its baseline word+0x48. Single-row lookup compares the requested word directly against row+0x40; multirow lookup uses the retained helpers and bounds the returned index before selecting a72-byte row. Public account/predicate meanings remain unclosed.

For a selected row, the low incoming ECX byte indexes a raw word at row+8+8*selector without a local selector range check. Dividing that word by the nonzero native dword at row+0x30 and adding the baseline forms an upper amount. A32-bit shortcut is selected only when the dividend fits32 bits. Addition overflow diagnoses and saturates to UINT64_MAX on ordinary continuation; nonzero divisor and valid selector/layout are explicit caller/native preconditions.

The central signed/multiply/clamp calculation is retained but deliberately unclosed. Its eventual nonnegative word is divided by the same row divisor, then subtracted from the upper amount. Borrow invokes the actual impl_ntl.rs diagnostic and returns zero if it returns normally. This closes the zero/baseline/selected partition and final quotient clamp boundary without inventing financial units, the central formula's full semantics or helper effects.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-notional-admission-clamp/collect.py --output work/ntlguard-replay --check
python3 -m unittest discover -s tests -p test_twenty_ntlguard_static.py -v
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
