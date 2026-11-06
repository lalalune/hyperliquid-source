# RE-015 — node 115 sub-vector drain callees: what the record drops' drains do per element

Question: what do the four sub-vector drain callees of the
record element drops do per element, and are the two same-size
pairs clones? The record element drops packet (#2714) traced
the drops that destroy the assembled 0x40-byte records — each
drop hands the record's +0x18 sub-vector to a drain callee on
its normal path and to an alternate drain callee from its
first landing pad — but left all four callees hash-pinned. Its
recorded next question is this packet: "What do the four
sub-vector drain callees do per 0x10-byte element of the
record's +0x18 sub-vector — and are the two drain pairs
(normal `0x153deb0` / `0x474e8a0`, 235 bytes each; unwind
`0x1539990` / `0x474e270`, 86 bytes each) also
shape-identical clones of one another, as their matching
sizes suggest?" One overlap is disclosed up front: the
merge-delegate packet (#2615, merged) had already hash-pinned
the reader normal drain `0x474e8a0` as a boundary ("0x10
sub-vector drop", not traced) and recorded one call to it
from the merge delegate; this packet traces the body itself,
which #2615 expressly left unopened.

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| vec-A sub-vector drain | `0x153deb0..0x153df9b` | 235 | `77384034eb0db4b419f2ae44c146d2b4b1d234915d41503715cc2f93235ea2be` |
| vec-A sub-vector drain, unwind | `0x1539990..0x15399e6` | 86 | `8bf08c4e4144116fc33dc99728b6575dfbe2fa7e8a60badb30148531415e7b6e` |
| reader sub-vector drain | `0x474e8a0..0x474e98b` | 235 | `21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e` |
| reader sub-vector drain, unwind | `0x474e270..0x474e2c6` | 86 | `6307eff4fed38574504cb88e145950f5d83deb72ee5d032e082f767dd3de1680` |

All four bodies are retained in full. The two element drops
(#2714 owners) and the two pair-destroy helpers the normal
drains' landing pads use are retained as hash-pinned boundary
context.

## Trace

### Stage 1 — the header the drains read

All four drains take the sub-vector header itself in `rdi` —
in the drops, the `lea` of record +0x18 (#2714). The header
is 24 bytes: the word at +0x0 is the capacity word (the drops
size their post-drain buffer free by it, word × 0x10, and the
unwind drains free by it the same way); the word at +0x8 is
the buffer pointer; the word at +0x10 is the live element
count. The normal drains load exactly the +0x8 and +0x10
header words (header census over both dumps), so the record
word at +0x28 that #2714 found never loaded by the drop
bodies is the sub-vector length, and it is loaded here — as
header +0x10. The buffer holds 0x10-byte elements.

### Stage 2 — what the normal drain does per element

The normal drains (`0x153deb0` / `0x474e8a0`) walk the buffer
in order with a cursor seeded at buffer + 0x18 (loads at
cursor −0x18 / −0x10, advancing 0x10 per element, counted by
the header +0x10 word). Each element is a tagged pair {data
at +0x0, descriptor at +0x8} — the same element shape #2559
staged and the drops consume at record level. For each pair:

1. Descriptor word 0 is called on the data when non-null
   (`0x153deff` / `0x474e8ef`).
2. Descriptor word +0x8 is loaded as the size and, when
   non-zero, the data is freed through the dealloc target
   loaded once from slot `0x64df4a0` (RELATIVE, target
   `0x635de30`, called through `r13`) with the size class
   computed from descriptor words +0x8 (size) and +0x10
   (align) by the tzcnt/cmov idiom (tzcnt at `0x153df0e` /
   `0x474e8fe`; class 0 when align <= size, the tzcnt
   otherwise, and the tzcnt whenever align >= 0x11) — the
   same descriptor protocol as the drops' tagged pair, one
   level down.

The normal drain does **not** free the buffer: on the drops'
normal path the caller frees it afterwards by the capacity
word (#2714 stage 2). A zero length returns immediately.

### Stage 3 — the unwind drains are drain-and-free wrappers

The 86-byte bodies (`0x1539990` / `0x474e270`) are not a
second drain implementation: each calls its own module's
normal drain on the header (`0x1539997` / `0x474e277`), then
frees the buffer itself — capacity word at header +0x0
(`0x153999c` / `0x474e27c`), buffer pointer at +0x8, size
word << 4, align 0 — as a tail jump through the dealloc slot
`0x64df4a0`, gated on the capacity word. This is exactly the
free the drops perform inline on their normal path, which is
why the drops' first landing pads route here: on the unwind
path the inline free never runs. Each wrapper's own landing
pad saves the exception, re-runs the same buffer free
through the slot (`0x15399d8` / `0x474e2b8`), and resumes
through `_Unwind_Resume` (PLT `0x63f0a50`).

Inside the normal drains, the landing pad (`0x153df39` /
`0x474e929`) saves the exception, re-runs the interrupted
element's descriptor free through the dealloc slot with the
pad cmov variant (class 0 unless align > size), hands each
remaining element pairwise — data word, descriptor word,
cursor advancing 0x10 — to the pair-destroy helper
(`0x1537b00` / `0x474e0b0`, 130 bytes each, hash-pinned
boundaries here), and resumes through `_Unwind_Resume`. The
normal-drain FDE's final instruction is a call through the
cleanup slot `0x64df4c0` (RELATIVE, target `0x1680cab`) at
`0x153df95` / `0x474e985`, whose continuation lies outside
the FDE.

### Stage 4 — both pairs are clones

Both same-size pairs are clones at the pinned instruction
shape, judged by the #2714 method (unmasked instruction diff
+ consumption order). The 235-byte normal drains decode to
identical instruction offsets (72 instructions each) and,
after masking the address-dependent tails of branch and slot
instructions, byte-identical streams; the unmasked
difference is exactly five sites — three RIP-relative
displacements (the dealloc slot load, the pad dealloc call,
and the cleanup-slot tail call, all to the same slots in
both instances) and two rel32 calls (the module-local
pair-destroy helper and the shared `_Unwind_Resume`). The
86-byte unwind drains are identical under the same test (29
instructions each, exactly four differing sites): two
RIP-relative dealloc-slot references to the same slot and
two rel32 calls (the module-local normal-drain target and
the shared `_Unwind_Resume`). Consumption order is the same
in both pairs: the vec-A and reader instances read the same
header words, walk the same cursor, and free through the
same slots. The bodies' own hashes differ (owners table);
identity is claimed at the masked instruction shape only.

### Stage 5 — where the drains sit (call census)

A direct-call census over the whole `.text` (sites
attributed by containing FDE) shows the drains are shared
helpers, not drop-private. Each normal drain has exactly
nine direct call sites and each unwind drain exactly two,
with matching counts per module. The vec-A normal drain
`0x153deb0` is called by the element drop `0x1538ec0`
(`0x1538f28`), by its unwind wrapper (`0x1539997`), from FDE
`0x1538460` (`0x1538559`) and from six further FDEs
(`0x1569cd0`, `0x156a010`, `0x158b8e0`, `0x15ac910`,
`0x15bb960`, `0x15bf200`); the vec-A unwind drain
`0x1539990` only from the element drop's first landing pad
(`0x1538f92`) and from FDE `0x1538460` (`0x15386a3`). The
reader normal drain `0x474e8a0` is called by the reader
element drop (`0x474dd38`), by its unwind wrapper
(`0x474e277`), by the merge delegate `0x4748500`
(`0x47487ed` — the call the merge-delegate packet #2615
recorded while leaving this body a hash-pinned boundary),
and from six further FDEs (`0x4747cb0`, `0x4747f50`,
`0x474dba0`, `0x47530e0`, `0x47531d0`, `0x4753450`); the
reader unwind drain `0x474e270` only from the reader drop's
first landing pad (`0x474dda2`) and from FDE `0x474dba0`
(`0x474dc56`). All non-drop callers are recorded by FDE
range only; several are 86-byte FDEs whose shape matches
the unwind wrappers, not traced here. No other direct
caller of any of the four exists in the binary.

## Boundaries

Hash-pinned, not traced: the two element drops
`0x1538ec0` / `0x474dcd0` (#2714 owners, context only), the
two pair-destroy helpers `0x1537b00` / `0x474e0b0` the
normal drains' landing pads hand remaining elements to, the
dealloc target `0x635de30`, the cleanup target `0x1680cab`,
and `_Unwind_Resume`. Non-drop callers of the drains are
recorded by FDE range only, and whether every caller passes
the same 24-byte header layout is established only for the
drops' sites (record +0x18) and the merge delegate's element
+0x18/+0x20 site recorded by #2615. What the elements'
descriptor drop functions do beyond the call, and any
semantic name for the element type, are not claimed. No
captured code executed, no runtime value or reconstruction
gate is claimed.

## Next question

Are the two pair-destroy helpers the normal drains' landing
pads hand remaining elements to (`0x1537b00` / `0x474e0b0`,
130 bytes each, hash-pinned in this packet) also clones of
one another — and do the 86-byte caller FDEs in the drains'
census (several per module) form a wrapper family of the
same drain-and-free shape over other vector headers?

## Reproduce

```sh
python3 tools/subvec_drain_callees_static.py \
  --binary artifacts/node/115/hl-node \
  --output research/work-items/RE-015-node115-subvec-drain-callees
python3 -m unittest tests.test_subvec_drain_callees_static
```
