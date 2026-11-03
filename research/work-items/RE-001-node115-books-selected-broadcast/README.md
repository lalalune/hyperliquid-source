# RE-001: map node115 selected-book versus full-scan dispatch

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static evidence; no inferred source copied.

- Complete FDE `[0x22f2000,0x22f215c)`: 348 bytes.
- Complete FDE `[0x2c472c0,0x2c47651)`: 913 bytes.

Export denominator: **1261 bytes /288 instructions**.
These are exported evidence extents, not source-built or reconstructed comparison coverage.
The complete caller is context, not a claim that its entire behavior is recovered.

## Bounded native result

This asks whether the books-associated wrapper visits one row or every row, and whether its second consumer runs on an empty collection. It recovers local dispatch and call order only, not matching/cancellation semantics or original action variants.

The incoming descriptor's raw qword+0 is compared with exactly1. On that selected route its +8 word is reduced modulo10000 using the retained reciprocal multiplication, high-word shift11, multiplication by10000 and subtraction. The constant M=0x346dc5d63886594b obeys 10000*M=2^75+432, and 432*(2^64-1)<2^75. Thus for unsigned64 n, floor(n*M/2^75)=floor(n/10000): the reciprocal error is strictly below1/10000 and cannot cross the next integer even at remainder9999. This proves the local integer relation; no target instructions are executed or emulated.

The remainder is compared unsigned against collection length at descriptor's +0x10 pointer object's +0x10. An out-of-bounds index reaches the source-associated diagnostic; its nonreturn contract is unclosed. The ordinary route computes data+288*index and calls `0x23e33b0` once. On raw tags other than1, count zero skips that call, while a nonzero count traverses all rows at288-byte intervals. The same helper receives a copied20-byte argument, EDX=1, retained pointer arguments and the zero-extended byte from descriptor+0x45.

After either route the separately saved byte at descriptor+0x44 is tested for zero. Any nonzero value calls `0x2d34fc0` with the preserved raw tag/index and arguments, even when the all-row collection was empty. No exact1 test or Boolean validity rule is inferred for that byte. Broad helper side effects, row ownership, original types and arbitrary invalid tag behavior remain unclosed.

The actual caller at `0x2c47393` passes its stack descriptor to this body. Its full FDE is retained, while only this handoff is interpreted. The actual diagnostic LEA at `0x22f214f` binds `l1/src/books.rs:19:47`. This is partial RE-001 mapping within the order-book component; no RE-006 transition completion is claimed.

## Reproduction and controls

```sh
python3 research/work-items/RE-001-node115-books-selected-broadcast/collect.py --output work/book-replay --check
python3 -m unittest discover -s tests -p test_next4_book_static.py -v
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
