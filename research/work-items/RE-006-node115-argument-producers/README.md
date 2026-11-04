# RE-006 node 115: who produces the drivers' element-argument inputs

PR #2584 classified the 13 direct call sites of the four
insert-or-assign drivers by how the 0xb0-byte element argument is
produced and left the inputs of the six incoming-argument (`(c)`-kind)
FDEs as boundaries. This packet traces those boundaries one level up:
who produces the inputs of the three join-consumer clones
(`0x2a89500`, `0x55a07e0`, `0x55a12e0`) and the three adapters
(`0x369a3d0`, `0x369b650`, `0x3f10ac0`), the lookup-phase records `r12`
points to in `0x2c64870` and `0x55e3770`, the serialised tail of lookup
helper `0x2762570`'s result record, and the `[rsp+0x410]` record in
`0x55defd0` — and whether the `{tag, byte, serialised tail}` record
idiom behind all of them has a single decode-site producer.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address in that
artifact; every body is pinned by FDE extent and SHA-256 digest, and
every file offset is resolved through the section table (`.rodata`
identity-mapped, `.text` delta `0x1000`, `.data.rel.ro` delta
`0x2000`).

## Caller boundary (binary-wide censuses)

- The join consumers have **no** callers besides the ones below: no
  relocation names any of them, and a binary-wide E8 census finds
  exactly two direct call sites each, all in small wrapper FDEs —
  `0x2a89500` from `0x2a890d0` (`0x2a8921a`) and `0x2a892f0`
  (`0x2a89434`); `0x55a07e0` from `0x55a01a0` (`0x55a02ea`) and
  `0x55a03c0` (`0x55a0504`); `0x55a12e0` from `0x559ff80`
  (`0x55a00ca`) and `0x55a05d0` (`0x55a0714`).
- The adapters have **zero** direct callers. Each is reached through
  exactly one GOT slot (R_X86_64_RELATIVE): `0x369a3d0` via slot
  `0x64e6be0`, `0x369b650` via `0x64e6488`, `0x3f10ac0` via
  `0x64e7e60`. A binary-wide `ff15` census finds every call through
  those slots: s1 from three giant FDEs (`0x28cd7a0`, `0x538cd30`,
  `0x5397b50`), s2 from `0x2761c40` / `0x5490540` / `0x54905d0`, s3
  twice each from `0x2c619b0` and `0x55debb0`.
- Helpers: `0x2762570` is called only by `0x2c62590`; `0x27622f0` only
  by `0x2a890d0`; `0x5491190` only by `0x55a01a0` and `0x559ff80`; each
  sub-lookup (`0x2bb7270`, `0x2bb52a0`) only by its helper; the 0xf8
  helpers `0x2c62820` / `0x55e16d0` by their s3 caller FDE and by
  `0x2c64870` / `0x55e3770` respectively.

## (i) The six (c)-kind inputs

**Join consumers.** In the A wrapper of each pair (`0x2a890d0`,
`0x55a01a0`, `0x559ff80`) the 5th argument is `&[rsp+0x80]`: the
0x118-byte output record of a sibling lookup helper (`0x27622f0` for
jc1, `0x5491190` for jc2/jc3), called with `rdi = &[rsp+0x80]`. Before
the join call the record's 0x10f-byte tail round-trips through a
second staging record (`memcpy [rsp+0x199] <- [rsp+0x89]`, then back;
offsets are record+9 / record+0x119 in each frame). In the B wrapper
(`0x2a892f0`, `0x55a03c0`, `0x55a05d0`) the array is a verbatim
`memcpy([rsp+0xb0], r8, 0x118)` of the wrapper's **own incoming 5th
argument**; the extractor asserts no store touches the buffer between
the copy and the call — the wrapper produces nothing.

**s1 (`0x369a3d0`, element = 3rd argument).** Each giant caller
assembles the record **in its own frame** at `[rsp+0x20]`: tail
`memcpy` of 0xff bytes from a record at `[rsp+0xd40]` (giant A) or
`[rsp+0xd20]` (giants B/C), a tag store of `r12` at `[rsp+0x20]` and a
byte store of `r13b` at `[rsp+0x28]`, then `lea rdx, [rsp+0x20]` and
the slot call (sites `0x28d7741`, `0x53967de`, `0x53a15fe`). The idiom
is inlined in the giants; there is no shared producer body.

**s2 (`0x369b650`, element = head of the 4th-argument struct).** Each
caller first calls helper `0x369b770` through slot `0x64e6480` with
`rdi = rsp`. The helper builds a 0xc8-byte record **per field**: 22
stores through `rbx` (its result pointer), zero `memcpy` calls. The
caller then re-stages the record at `[rsp+0xc8]` — tag store, byte
store at `[rsp+0xd0]`, tail `memcpy([rsp+0xd1], [rsp+0x9], 0xbf)` —
and passes `rcx = &[rsp+0xc8]`.

**s3 (`0x3f10ac0`, element = 1st argument).** Each caller builds a
query at `[rsp]`, calls its sibling helper (`0x2c62820` /
`0x55e16d0`) with `rdi = &[rsp+0x50]`, and the element is a verbatim
`memcpy(..., [rsp+0x50], 0xf8)` of the helper's output record (two
sites per caller FDE).

## (ii) The r12 records in `0x2c64870` / `0x55e3770`

The complete value-write set of `r12` is pinned for both FDEs (5
writes in big1, 15 in big2). On both driver phases, `r12` is bound by
`lea r12, [rsp+0x140]` (big1) / `lea r12, [rsp+0x150]` (big2) — the
FDE's **own staging buffer** — and the sibling 0xf8 helper
(`0x2c62820` / `0x55e16d0`) is then called with `rdi = r12`, writing
the record the FDE goes on to use: the FDE checks the tag
(`cmpl $3, [rsp+0x140]` / `[rsp+0x150]`) and `memcpy`s 0xf8 bytes from
`r12` into the element buffer. So the record is neither an incoming
argument nor a found record from a table: it is a helper-produced
record in a caller-owned staging buffer. The staging buffers also
receive 55 (big1) / 56 (big2) direct stores, censused in
`records.json`. (The `r12` definitions in the earlier search phase of
each FDE are a separate cursor use and are pinned as the remaining
writes.)

## (iii) Helper `0x2762570`'s serialised tail

The result record (`rbx` = output pointer) is assembled as follows,
all pinned instruction by instruction:

- Error arms write `{tag 3, byte}` directly: byte `0xa` at entry
  (`0x27625d3`/`0x27625cf`), `0xc` when the second shared predicate
  rejects (`0x2762775`/`0x2762771`).
- Otherwise the helper builds a sub-query at `[rsp+0x10..0x70)`,
  checks it with shared predicate `0x369a210` (slot `0x64e6498`), and
  calls sub-lookup `0x2bb7270` at `0x27626a6` with output buffer
  `[rsp+0x90]`.
- If the sub-lookup's tag is 3, `{3, sub-byte}` is written directly
  (`0x27626c5`/`0x27626c1`). Otherwise the sub-record's tail is copied
  verbatim — `memcpy([rsp+0x1b9], [rsp+0x99], 0x10f)` at `0x27626e6`,
  i.e. bytes `[9, 0x118)` of the sub-output — the tag and byte are
  stored at `[rsp+0x1b0]`/`[rsp+0x1b8]`, and after the gates (tag 2,
  or staging byte `+0x110 == 0`, or predicate `0x3bf4fa0` via slot
  `0x64e64a0` returning true) the whole record is copied out:
  `memcpy(rbx, [rsp+0x1b0], 0x118)` at `0x2762756`.

So the tail is the sub-lookup's output tail, copied — never
re-encoded. The sub-lookup's own final assembly is pinned too: the
output pointer is saved at entry (`[rsp+0x250]`) and reloaded into
`rbx` at `0x2bb979a`; the record's staging area at `[rsp+0x4c8]`
receives exactly 9 direct stores; the output record is written
exactly by `memcpy(output+8, [rsp+0x4d0], 0x110)` at `0x2bb97c4` plus
the tag store `mov %r12, (%rbx)` at `0x2bb97ca` (on the error arm a
single byte store `movb $0xc, (%rdi)` at `0x2bb97ac`, `rdi = output+8`,
replaces the memcpy). The staging record's tail itself arrives by a
0xff-byte `memcpy` from a middle record at `[rsp+0x760]` which
receives **no** direct stores — its bytes are filled by the preceding
`memcpy` chain from the sub-lookup's inner decode record at
`[rsp+0x140]` (36 direct stores).

The clone pair behaves identically with shifted offsets: helper
`0x27622f0` / sub-lookup `0x2bb52a0` (staging `0x578`, error byte
`0x5`). Helper `0x5491190` (jc2/jc3) has **no** sub-lookup call — its
E8 targets are the sibling search `0x35bf460` and fallbacks directly;
its record at `[rsp+0x380]` goes through the same two-stage tail
round-trip (`[rsp+0x4e0]`) and a final 0x118 copy to the saved output
pointer.

## (iv) The `[rsp+0x410]` record in `0x55defd0`

It is assembled **inside the FDE**, in the sub-lookup shape: exactly
11 direct stores into `[rsp+0x410, rsp+0x528)` (tag initialised to 4
at `0x55df0e4`; main build — tag, byte at `+8`, qword at `+0x108`,
byte at `+0x110`; two later-phase stores; four unwind-path twins) and
a tail-copy chain `[rsp+0xa9] -> [rsp+0x98a] -> [rsp+0x419]`
(record+9) via `memcpy` at `0x55e125d`, `0x55e0313` and `0x55e168d`
(offsets stated exactly as decoded; the middle buffer's would-be
record base, `0x98a - 9`, is not a round displacement and is not
guessed). The record is consumed in place: a
slot call at `0x55e137d` takes `rsi = &[rsp+0x410]`, a 0xa7-byte tail
copy at `0x55e1425` reads from it, and the unwind path passes it to
`0x5628210` at `0x55e16b7`.

## Sub-question: one record type, single producer?

The `{tag qword, byte, 0x10f-byte serialised tail}` shape is **one
record family** — sizes 0xc8 (helper `0x369b770` output), 0xf8 (the
s3 helpers' output), 0x118 (the 0x118 helpers and sub-lookups) — but
it has **no single decode-site producer**. The pinned producers are:
a clone family of helpers (`0x27622f0`, `0x2762570`, `0x5491190` —
the last with its decode phase inlined), two distinct sub-lookup
bodies (`0x2bb7270`, `0x2bb52a0`), per-field construction in
`0x369b770`, and inlined copies of the same assembly inside
`0x55defd0` and the three s1 giant callers. The only code shared by
all producers is the `memcpy` GOT slot `0x64df508` and, for the three
0x118 helpers, the two predicate bodies `0x369a210` / `0x3bf4fa0`.

## Files

- `records.json` — the machine-readable evidence: artifact and body
  pins, slot facts, the binary-wide caller censuses, per-site
  production records, per-FDE evidence, counters and the verdict.
- `frames.txt` — the `readelf --debug-dump=frames` FDE lines of all
  34 bodies (7 boundary anchors + 27 traced bodies).
- `*_objdump.txt` — full-body disassembly exports of the 16 bodies
  ≤ ~4 KB (wrappers, small helpers, predicates, s2/s3 callers).
  Larger bodies are pinned by digest + instruction rows around every
  cited feature (`PINNED_ROWS_PARTIAL` in the extractor).
- `tools/argument_producers_static.py` — the extractor; regenerates
  every file here from the authenticated artifact and fails closed
  on any drift.
- `tests/test_argument_producers_static.py` — byte-for-byte
  regeneration, counters and verdict shape, and digest/pin drift
  failures.

## Verification

- `python3 -m unittest tests.test_argument_producers_static` — 7
  tests pass with the artifact materialised (byte-for-byte
  regeneration of `records.json`, `frames.txt` and all 16 exports;
  wrong-artifact rejection; digest drift in a small body and in
  `0x55defd0`; full-pin drift in `0x2761c40`; partial-pin drift in
  `0x55defd0`).
- Independent check: all 34 body digests recomputed from the
  standalone artifact through a separate section-table
  implementation — all match.
- Isolated-root verifier: `Verified 1 evidence-packet manifests and
  19 entries (0 grandfathered rows reference no committed file).`

## Next question

Who produces the innermost records this packet leaves as boundaries:
the giants' `[rsp+0xd20]`/`[rsp+0xd40]` tail-source records, the
sub-lookups' inner decode records (built around the `0x24cb0a0`
decode calls), the 0xf8 helpers' internal production of their output
records, and the inputs of the wrappers' and giants' own callers.
