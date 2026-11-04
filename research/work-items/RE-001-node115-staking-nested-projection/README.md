# RE-001: map node115 staking lookup and nested-result projection

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static research; no inferred source was copied.

- Complete FDE `[0x36c7b30,0x36c7f6d)`: 1085 bytes /262 instructions.
- Complete FDE `[0x44d7f10,0x44d83e2)`: 1234 bytes /233 instructions.

Export denominator: **2319 bytes /495 instructions**.
These are evidence extents, not recovered or compiled-comparison coverage.

## Question and local convention

How does a staking-associated keyed lookup turn nested native collection state
into the caller's result, and how are a miss and an empty traversal distinguished?
This maps local layout/ownership boundaries, not original staking amounts,
validator policy, withdrawal rules or a persistent schema.

The incoming RDI is an output address, RSI an outer collection-like object and
RDX an unsigned key retained for the successful result. An outer min-i64 tag
selects a native tree-shaped lookup; other tags call opaque0x4551810 and use
the returned index under local bounds. Tree node counts are u16 at+0x272,
keys start at+0x218 and child pointers at+0x278. The greater-only scan and
height-decrement borrow determine local misses. The tree's value stride is48;
the alternate caller-local ring row stride is56 with an8-byte key prefix.
Complete tree construction, helper probing and validity invariants are unknown.

## Hit/miss and nested traversal

A null root or local miss writes word **0x9b** at output+0 and qword0 at+8,
then returns. Other output bytes are not assigned meaning on that path.

A hit obtains another collection-shaped descriptor. Its ordinary iterator path
advances by **104 bytes**, selecting a72-byte value view at row+0x20. The
alternate traversal calls0x37c5530; that helper's full behavior is unclosed.
For each selected value view, the code copies20 bytes from+0x20 and another20
from+0x34. In the ordinary104-byte-row path those are row offsets+0x40 and
+0x54, respectively. They are raw metadata, not proven account addresses.

The value's initial collection descriptor prepares nested boundaries using an
ordinary **32-byte row-address scale**. The helper's actual traversal remains
unmeasured. This prepared descriptor is passed to0x4351de0
with the actual source Location. That helper's returned word is placed in a
local record, followed by the two20-byte metadata copies:48 local bytes in all.
The result is handed to0x3901070 together with the accumulator-like three words
at stack+0x58. The original types and append/allocation contract are unknown.
AL==0 resumes iteration; nonzero reaches the diagnostic route at0x36c7f35.

Two accumulator words are initially zeroed; the middle word's raw initial value
is not independently established for a no-iteration path. No Rust Vec layout,
initialized padding or empty-pointer value is invented. On ordinary traversal
completion, those three words are copied to output+8,+0x10,+0x18, the retained
query is stored at output+0x20, and word **0x1a2** is written at output+0.
Thus a found entry with no yielded rows does not use the earlier local miss tag;
this is not a proof that every arbitrary native collection state is valid.

## Actual caller and constraints

The actual call at0x44d8005 resolves through a RELATIVE slot to this body. It
passes output stack+0x10, an object in R15, and the retained R13 word as key.
Immediately afterwards it reads the result word and branches away unless it is
0x1a2, then copies32 bytes of its payload for another consumer. The complete
caller is retained, but its other state/bridge behavior is not closed here.

The actual LEA at0x36c7d06 binds `l1/src/staking.rs:239:36`. All meanings above
are local native observations under valid object/extent invariants and ordinary
helper returns. No whole staking reconstruction, allocator closure, source-built
execution, atomicity or semantic identity for opaque helper results is claimed.

## Reproduction and negative controls

Linux Python3.12.3 and GNU binutils2.42; no target execution or emulation:

```sh
python3 research/work-items/RE-001-node115-staking-nested-projection/collect.py --output work/staking-replay --check
python3 -m unittest discover -s tests -p test_four_staking_static.py -v
```

The collector authenticates the complete target before any native command or
output, uses a private non-executable copy, agrees on complete unwind ranges
and relocation records with independent readelf, and verifies contiguous native
instruction bytes. Full original bodies, raw FDE/CIE, LSDA coordinates, every
measured direct/RIP call and source Location binding are retained. Text exports
trim trailing whitespace only after instruction-byte validation.

5 focused tests cover original anchors, exact export regeneration, wrong
artifact identity rejection before output, independent corruption of all claim
anchor groups and mutations of actual semantic sites. The dedicated sites
change the raw tag/condition, field displacement, arithmetic or callback/result
branch relevant to this question. Changes occur only in private Python arrays;
neither original nor altered instructions are executed or emulated.

All component gates remain false. No root Cargo graph, source-built node, binary
equivalence, complete original Rust types, protocol execution, signing, chain
action, paid dataset or live user fixture is introduced. New code/analysis is
root MIT; imported artifacts retain their existing terms. Full repository checks
and generated inventory integration are recorded with the final submitted head.
