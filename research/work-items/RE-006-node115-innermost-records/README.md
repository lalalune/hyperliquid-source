# RE-006 node 115: who produces the innermost records

PR #2590 traced the producers of the drivers' element-argument
inputs one level up and left four boundaries: the s1 giants'
tail-source records, the sub-lookups' inner decode records, the
0xf8 helpers' internal production of their output records, and the
inputs of the wrappers'/giants' own callers. This packet answers
all four. Two of the four premises turn out to be wrong in an
instructive way: the "inner decode" body produces no record at all,
and the giants' tail source is not a record — it is a parking
buffer for the element's own tail.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address in
that artifact; every body is pinned by FDE extent and SHA-256
digest, and every file offset is resolved through the section
table (`.rodata` identity-mapped, `.text` delta `0x1000`,
`.data.rel.ro` delta `0x2000`).

## Caller boundary (binary-wide censuses)

- The body behind the decode calls, `0x24cb0a0`, has exactly **18**
  E8 call sites binary-wide: 8 in sub-lookup `0x2bb7270`, 4 in
  helper `0x2c62820`, 2 in inner body `0x2bbbba0`, and one each in
  `0x2bbd0b0`, `0x2b92a50`, `0x2c61b30` and driver caller
  `0x2dc3900`. Sub-lookup clone `0x2bb52a0` and helper clone
  `0x55e16d0` contain **zero** decode calls — their searches are
  inlined or use the sibling search directly.
- The three join-consumer B wrappers have exactly 4/5/5 E8 call
  sites, all in eleven caller FDEs packeted here; the three s1
  giants have exactly 4 each — one recursive self-call plus three
  sites in two caller FDEs each. The sub-lookups are called only by
  their helpers (`0x2762570` at `0x27626a6`, `0x27622f0` at
  `0x27623ae`); the 0xf8 helpers only by their s3 caller FDEs and
  the two big driver FDEs of #2590.
- For every traced target: zero E9 sites, zero rip-relative `lea`
  rows inside the packet bodies, and no `R_X86_64_RELATIVE`
  relocation addend names any of them.

## (i) The giants' tail source: a parking buffer, not a record

In each giant the element at `[rsp+0x20]` receives its 0xff tail
from a region at the frame top — `[rsp+0xd49, rsp+0xe48)` in giant
A (frame `0xe48`), `[rsp+0xd29, rsp+0xe28)` in giants B/C (frame
`0xe28`). A direct-store census finds **zero** stores into those
regions in all three giants. The only writer is a **park memcpy**:
before the element is rebuilt, its own tail is parked there
(`memcpy [rsp+0xd49] <- [rsp+0x29]`, `0xff`, at `0x28d75c2` in A;
`0x539665f` / `0x53a147f` in B/C), and the restore memcpy reads it
straight back into the element (`0x28d771e`; `0x53967bb` /
`0x53a15db`), immediately before the tag store (`r12` at
`[rsp+0x20]`), the byte store (`r13b` at `[rsp+0x28]`) and the s1
slot call. The restore block is reached only by the `jne` after
`cmp $0x2,%r12d` following the park (`0x28d75cc` -> `0x28d7700`;
`0x5396669` -> `0x539679d`; `0x53a1489` -> `0x53a15bd`). The
similar-looking stores at `[rsp+0xd20]`/`[rsp+0xd40]` in giant A
belong to a different structure: a 0x140-byte argument buffer at
`[rsp+0xce0]` (giants B/C: `[rsp+0xcc0]`), filled by seven direct
stores copying fields of the incoming `(r15)`/`(r13)` struct and
passed as `rdx` to a per-clone consumer call (`0x2bef4a0` in A,
`0x54cb650` in B, `0x54cb960` in C) with `rdi = &[rsp+0x20]`, the
element itself. Classification: the tail source is **the element's
own tail, parked** — neither an incoming record nor a produced
one.

## (ii) The "decode" body produces nothing; the chains are copies

Body `0x24cb0a0..0x24cb1d4` (308 bytes, every instruction pinned)
is a two-phase binary search (lower_bound) over a **0xb8-stride**
array — six `imul $0xb8` rows — keyed on each element's first
qword. It reads the collection header through `rdi` and the key
through `rsi`, and contains **zero stores**: its only outputs are
the flag in `rax` and the index in `rdx`, which the callers turn
into an element pointer (`[hdr+0x8] + index*0xb8`) and read fields
from. There is no decode output record for the sub-lookups to
consume.

What the sub-lookups' staging/middle records are actually built
from is a memcpy chain inside each sub-lookup, pinned site by
site (8 memcpy executions in `0x2bb7270`, 4 in `0x2bb52a0`):

- The staging record (`[rsp+0x4c8]` in `0x2bb7270`, `[rsp+0x570]`
  in the clone) receives exactly **nine** direct stores — tag,
  byte, closing qword at `+0x108`, closing byte at `+0x110`, on the
  main and unwind paths — and its tail `[+9, +0x108)` arrives by a
  0xff memcpy from the middle buffer.
- The middle buffer is a 0xff-byte tail buffer at the frame top
  (`[rsp+0x769, rsp+0x868)` / `[rsp+0x689, rsp+0x788)`): **zero**
  direct stores into it; it is written by one memcpy from the
  inner record's tail and read only by the staging-tail memcpys.
  Its head bytes are never read as a record head.
- The inner record (`[rsp+0x140]`, `0x110` bytes) is built in its
  final phase by a tag store (`0x2bb8d40`, from `[rsp+0x28]`), a
  byte store (`0x2bb8d4d`, from `[rsp+0x30]`), a 0xdf tail memcpy
  (`0x2bb8d64`) from a byte buffer at `[rsp+0x688]` — itself the
  concatenation of a 0xa7 memcpy from `[rsp+0x5e0]` (`0x2bb8d12`)
  and direct field stores through `rcx = &[rsp+0x72f]` — and a
  closing qword store at `+0xe8` (`0x2bb8d67`). The `[rsp+0x5e0]`
  buffer is in turn a 0xa7 memcpy of the `[rsp+0x280]` record's
  tail (`0x2bb8b0d`). The same `[rsp+0x140]` region serves an
  unrelated 0xb0-stride cursor struct in the search phases — 35
  rsp-relative stores land in the region across all phases;
  stack-slot reuse, stated per phase.
- The final output is `memcpy(output+8, staging+8, 0x110)` plus a
  tag store through the saved output pointer, exactly as #2590
  pinned.

## (iii) The 0xf8 helpers: in-FDE assembly over a memcpy chain

Helpers `0x2c62820` and `0x55e16d0` produce their 0xf8 output
records **inside their own bodies**, in the family idiom — but the
tail is never built per field and the record is not a verbatim
copy of any single input. The complete memcpy census (ten
executions per helper; the two helpers mirror each other with a
uniform **+0x10** stack-displacement shift) is a chain of tail
hops between frame buffers: the input record's tail is first
copied in from the query pointer (`memcpy [rsp+0xa9] <- rbx`,
`0xdf`, at `0x2c64330`), then hops `0xa9 -> 0x7ea` (0xff),
`0x7ea -> 0x8e9` (0xdf), `0x8e9 -> 0x629` (0xdf), and the final
`0xa7` hop lands at `output+9` (`0x2c6474c`); a second chain
through `[rsp+0x580]` feeds the twin stack records at `[rsp+0x28]`
and `[rsp+0x3b8]` (tag/byte by direct stores at `0x2c6407c`,
`0x2c64081`, `0x2c64089`, `0x2c6408e`) and the `[rsp+0x700]`
record, whose fields `[0xb0, 0xf8)` are copied field-wise into the
second output pointer on the full-record exit arm (six direct
stores at `0x2c6476d`..`0x2c647a6`). Exit arms write the tag
directly: `movq $0x2, (%r14)` at `0x2c646a6` on the
fallback-found arm (the helpers call the shared fallback
`0x4556410` themselves), `movq $0x3`/`$0x2` through the second
output pointer at `0x2c646db`/`0x2c64722`. Four stores through
`(%r14)` per helper are censused. The clone `0x55e16d0` contains
zero decode calls; `0x2c62820` contains four, plus three calls to
inner body `0x2bbd0b0`. Classification: **per-field stores for
tag/byte and the `[0xb0, 0xf8)` field block; wholesale copies for
the tail**.

## (iv) The wrappers'/giants' own callers

**B wrappers.** At all 14 call sites, `r8` is a `lea` of a record
in the **caller's own frame** — never a heap or global pointer.
Two assembly shapes, uniform across the sites:

- Shape X (11 sites; record `0x118` at `[rsp+0xa0]`/`0xb0`/`0xd0`/
  `0x190`): the caller stores tag and byte directly, then fills
  the tail with `memcpy(record+9, scratch, 0x10f)`, where the
  scratch tail was itself filled by an earlier memcpy — either
  from a plain frame buffer (e.g. `[rsp+0x369]` in `0x2a84e60`) or
  by round-tripping a sibling lookup helper's output record
  (helpers `0x2761fe0`, `0x5492440`, `0x5630000`; the record at
  `[rsp+0x70]`, tail round-trip through `[rsp+0x2a9]`).
- Shape Y (3 sites; the `0x4f8`-byte clone FDEs `0x2c3e8b0`,
  `0x55983f0`, `0x559c260`): the record at `[rsp+0x1d0]` is first
  produced **wholesale** by a sibling lookup helper called with
  `rdi = &[rsp+0x1d0]` (`0x2761cd0` at `0x2c3eb8e`, `0x5490660` at
  `0x55986ce`/`0x559c53e`), then its tail is parked out to
  `[rsp+0xd0]` and restored — the same park/restore idiom as the
  giants — and tag/byte are re-stored before the call.

**Giants.** The nine external sites bind ordinary pointer/context
arguments: six pass `rsi = &[rsp+0x80]`, a small caller-frame
struct whose head word is stored as `0x2d` (or `0x35` on the
second site) with the remaining fields copied from an incoming
`(rsi)` struct, with `rdi = %rbx` and `rdx = %r14`; three pass
`rdi`/`rsi` as pointers to caller-frame buffers (`&[rsp+0x430]` /
`rsp`, `&[rsp+0x180]` / `&[rsp+0x40]`) and `rdx` as a loaded
value. No site passes a record of the idiom family: **the element
record is entirely the giant's own construction**, and the
giants' inputs are incoming arguments one level further up.

**Boundary.** Static evidence stops at: the internal production
of the inner bodies `0x2bbbba0` (called three times by
`0x2bb7270`, itself holding two decode sites) and `0x2bbd0b0`
(called three times by `0x2c62820`, one decode site) — both
packeted here as boundary bodies — and at the caller FDEs' own
lookup-phase inputs (the queries and collections their producer
helpers consume), which are the next level up.

## Files

- `records.json` — the machine-readable evidence: artifact and
  body pins, the memcpy slot fact, the binary-wide caller
  censuses, the memcpy tables, the staging/giant/helper censuses,
  per-site production records, counters and the verdict.
- `frames.txt` — the `readelf --debug-dump=frames` FDE lines of
  all 33 bodies (4 traced targets' callers and kin, 11 B-wrapper
  caller FDEs, 6 giant caller FDEs, 5 boundary bodies, the decode
  body, the wrappers and the giants).
- `*_objdump.txt` — full-body disassembly exports of the 20 bodies
  ≤ ~4 KB. Larger bodies are pinned by digest + instruction rows
  around every cited feature (`PINNED_ROWS_PARTIAL` in the
  extractor); `decode` and the three B wrappers are pinned by
  their full instruction rows.
- `tools/innermost_records_static.py` — the extractor; regenerates
  every file here from the authenticated artifact and fails closed
  on any drift.
- `tests/test_innermost_records_static.py` — byte-for-byte
  regeneration, counters and verdict shape, and digest/pin drift
  failures.

## Verification

- `python3 -m unittest tests.test_innermost_records_static` — 7
  tests pass with the artifact materialised (byte-for-byte
  regeneration of `records.json`, `frames.txt` and all 20 exports;
  wrong-artifact rejection; digest drift in the decode body;
  full-pin drift in a B wrapper; partial-pin drift in the
  sub-lookup; memcpy-table drift in helper `0x55e16d0`).
- Independent check: all 33 body digests recomputed from the
  standalone artifact through a separate section-table
  implementation — all match.
- Isolated-root verifier: `Verified 1 evidence-packet manifests
  and 23 entries (0 grandfathered rows reference no committed
  file).`

## Next question

Who produces the records inside the two inner bodies this packet
leaves as boundaries — `0x2bbbba0` (three calls from `0x2bb7270`,
two decode sites, one sibling-search and one fallback call) and
`0x2bbd0b0` (three calls from `0x2c62820`, one decode site) — and
what are the caller FDEs' own lookup-phase inputs (the queries and
collections consumed by the producer helpers `0x2761cd0`,
`0x2761fe0`, `0x5490660`, `0x5492440`, `0x5630000`) one level up?
