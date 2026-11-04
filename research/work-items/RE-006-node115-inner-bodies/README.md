# RE-006 node 115: the two inner bodies, and the producer helpers' own inputs

PR #2598 packeted the innermost record production of the RE-006
chain and left two boundaries: the two inner bodies called from
inside sub-lookup `0x2bb7270` and helper `0x2c62820`, and — one
level up — the inputs of the helpers that produce the B-wrapper
caller-frame records. This packet answers both. Two premises of
the question turn out to be wrong in an instructive way: the
wrapper sites call **six** distinct helpers, not five, and two of
the six "producer helpers" produce nothing at all — they are
zero-store inspectors of a serialised form, called on a record
head the caller has just assembled.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address in
that artifact; every body is pinned by FDE extent and SHA-256
digest, and every file offset is resolved through the section
table (`.rodata` identity-mapped, `.text` delta `0x1000`,
`.data.rel.ro` delta `0x2000`).

## Caller boundary (binary-wide censuses)

- Inner body `0x2bbbba0` has exactly **3** E8 call sites, all in
  sub-lookup `0x2bb7270` (`0x2bb7bb9`, `0x2bb8f8c`, `0x2bb9515`);
  inner body `0x2bbd0b0` has exactly **3**, all in helper
  `0x2c62820` (`0x2c62ff8`, `0x2c63586`, `0x2c644d2`).
- The fourteen B-wrapper producer sites of #2598 call six
  distinct helpers: `0x2761cd0` ×1, `0x2761fe0` ×2, `0x2aae850`
  ×1, `0x5490660` ×2, `0x5492440` ×4, `0x5630000` ×4.
  `0x2aae850` (the sixth, at bwc_a1 site 1) was not in the
  question's list of five. Binary-wide, `0x2761cd0` has 1 E8 site,
  `0x2761fe0` 3 (one extra, inside bwc_a1, is not a wrapper site),
  `0x5490660` 2, `0x5492440` 8 (four more inside the same caller
  FDEs feed the inspector sites below), and `0x5630000` 445 — it
  is a widely used serialised-form walker; only the four wrapper
  sites are in scope here.

## (A) The inner bodies produce no idiom record

`0x2bbbba0..0x2bbc74d` (2,989 B, digest prefix `f3e69ec027f6`)
and `0x2bbd0b0..0x2bbdb9a` (2,794 B, digest prefix `889874f50471`)
have the same shape: both are **consumer-side aggregation
bodies**, not record producers of any of the series' classes
(a)/(b)/(c).

Signature (both): `rdi` = out pointer (saved to the frame),
`rsi` = a 0x28-stride cursor-source descriptor, `rdx` = a
collection struct, `rcx` = an opaque context value forwarded to
a gate predicate, `r8` low byte = "final segment" flag, `r9` = a
stop key. Per cursor item (cursor-next body `0x2388380`, one call
each: `0x2bbbda8` / `0x2bbd2d5`), the body looks the item's key up
in a cascade of collections and accumulates a scaled product.

Lookup cascade. A collection whose head qword differs from the
sentinel `0x8000000000000000` is a flat 0xb8-stride array searched
with the decode body `0x24cb0a0` of #2598; the sentinel form is a
0xb0-stride tree node (keys at node +0x798, count u16 at +0x7f2,
per #2542) searched inline or with the sibling-search body
`0x35bf460`; the remaining form goes to the fallback body
`0x4556410`. `0x2bbbba0` cascades over **three** levels — the
`rdx` struct itself (decode at `0x2bbbe7d`), the struct at
`[rdx+0x20]` (decode at `0x2bbbf9b`), and the struct at
`[[rdx+0x20]+0x20]` (sibling body at `0x2bbc00a`, fallback at
`0x2bbc03b`). `0x2bbd0b0` cascades over **two** — the `rdx`
struct (decode at `0x2bbd3ad`, its only decode site) and the
struct at `[rdx+0x20]` used directly as a collection (sibling
body at `0x2bbd43a`, fallback at `0x2bbd495`).

Computation per found element: `[element+0x78] × [value+0x18]`
(u128), divided by 1e17 through the helper behind GOT slot
`0x64dfaf8` — statically the `__udivti3`-shape body `0x63efec0`
of #2561 (this packet re-resolves the slot: one
`R_X86_64_RELATIVE`, addend `0x63efec0`). Each quotient is gated
by two calls through GOT slot `0x64e71b8` (one `R_X86_64_RELATIVE`,
addend `0x434f790`; the callee body is not pinned here), which
must return 1; checked u128 adds accumulate into frame pairs,
and the overflow arms call the panic helper behind slot
`0x64e4ea8` (addend `0x4524e40`).

Store census (mechanical): `0x2bbbba0` has 51 stores, `0x2bbd0b0`
50. **Neither body references the memcpy slot `0x64df508` at
all.** The only stores through a non-frame pointer are the
twelve per body through the saved frame pointer registers: one
16-byte frame store, two accumulator stores through an `lea`'d
frame pointer, and the nine exit stores through the saved `rdi`.

Exit contract — the only thing either body "produces" is a
0x38-byte tagged result struct written through `rdi`:
success (tag store `0x2bbc725` / `0x2bbdb72`): byte `[rdi]` = 0
and six accumulated qwords at `[rdi+0x8..0x30]` copied from
frame accumulator slots; failure (tag store `0x2bbc738` /
`0x2bbdb85`): byte `[rdi]` = 1 and a code byte at `[rdi+1]`.
Failure arms (the `mov $code,%cl` rows): code 2 = arithmetic
zero/overflow arm, 3 = u128 compare overflow, 7 = gate predicate
returned ≠ 1, 9 = lookup miss. In the (a)/(b)/(c) terms of the
series the answer is a precise negative for the idiom family:
no `{tag, byte, 0x10f tail}` record is written, per-field or by
copy; the inputs are incoming (below) and the output is the
aggregation result above.

Caller consumption (all six sites, measured): the result buffer
is `[rsp+0x140]` in sub-lookup `0x2bb7270` and `[rsp+0xa0]` in
helper `0x2c62820`; after each call the caller tests the tag
byte (`cmpb` at `0x2bb7bbe`/`0x2bb8f91`/`0x2bb951a` and
`0x2c62ffd`/`0x2c6358b`/`0x2c644d7`) and on success reads the
payload qwords at +0x8/+0x18/+0x20 (site 1 of each caller) or
+0x8 (sites 2–3). Argument origins, one level: every argument is
a prologue copy of an incoming value — classification (c). The
cursor descriptor is the caller's own second argument verbatim
(sub-lookup, stored at `0x2bb73d0`) or the `[arg3+0x10]` field
(helper, `0x2c6285a`); the collection argument is the
`[arg3+0x20]` field (sub-lookup, `0x2bb72cb` — at site 1 it
arrives in `r10`, which the prelude block at `0x2bb7ba0` proves
is the same value: the block is entered only from jumps at
`0x2bb7885`/`0x2bb78f9`/`0x2bb7986`, all in the region where
`r10` is reloaded from that slot) or the `[arg3+0x18]` field
(helper, via `r13` at `0x2c62863`); the forwarded context is
`[arg3+0x28]` (sub-lookup, `0x2bb72eb`) or the helper's own
second argument adjusted in its prologue block (helper,
`0x2c628dd`/`0x2c628e4`).

Site-3 boundary (both callers, stated exactly): the third call
passes a frame-built descriptor (`[rsp+0xf8]` / `[rsp+0x1c8]`).
Each buffer receives exactly **one** direct store before the
call (`0x2bb896d` / `0x2c63ed1`, its first qword) and no memcpy;
its remaining fields are produced outside the callers' direct
stores — the buffer is handed by address to an earlier phase
call of the same family, body `0x2db34c0` (`0x2bb8983` /
`0x2c63eef`, `rsi` = the descriptor). How `0x2db34c0` fills the
remaining fields is outside this packet.

## (B) The producer helpers and their sites

Four of the six helpers are genuine producers of the 0x118
record — {tag qword, byte at +8, 0x10f serialised tail} — through
their `rdi` out pointer; two are inspectors.

- `0x2761cd0..0x2761fd6` (774 B): signature (`rdi` out, `rsi`
  context, `rdx` query). The prologue stages the query's fields
  (offsets 0x0–0x38 and the byte at 0x60) into a frame query
  record. Predicate slot `0x64e6490` at `0x2761d36` gates an
  early-exit record {tag 3, byte = its return} unless it returns
  13; then, via slot `0x64e6498` and sub-lookup clone `0x2bb68e0`
  (`0x2761df3`), it assembles the record on its frame (tail
  memcpy `0x2761e43`, 0x10f) and copies it out with a final
  memcpy of 0x118 (`0x2761eb7`). Stores through the out register:
  exactly the six early-exit stores.
- `0x2761fe0..0x27622e6` (774 B): the same shape in the other
  clone family — sub-lookup clone `0x2bb48c0` (`0x2762116`),
  context bytes read at +0x14c/+0x14d, dispatch on the query's
  +0x10 field, tail memcpy `0x2762156`, final memcpy 0x118 at
  `0x27621c6`, six early-exit stores through the out register.
- `0x5490660..0x549118e` (2,862 B) and `0x5492440..0x5493013`
  (3,027 B): the large variants. Same query-staging prologue
  (query offsets through +0x60/+0x61; `0x5492440` also reads the
  context bytes +0x14c/+0x14d), but the search phases are inlined
  (sibling body `0x35bf460` at `0x5490a78`/`0x54928d1`, fallback
  `0x4556410` at `0x5490ab5`/`0x54928f8`) and the family's own
  sub-lookup bodies `0x548f430` and `0x548ebd0` are called. The
  record is assembled through a two-hop 0x10f tail chain plus
  0xff park copies and copied out at 0x118 (`0x5491038` /
  `0x5492ecd`). Stores through the out register: 5
  (`0x5490660`, via `r14`) and 6 (`0x5492440`, via `rdi`/`rbx`).
- `0x5630000..0x563034a` (842 B) and `0x2aae850..0x2aaea38`
  (488 B): **inspectors — zero stores in either body.** Each
  walks a serialised tagged value through `rdi`: u16 tag at
  `[rdi]`, range checks (≤0xef → a jump table; ≤0x15f → a second
  phase), field walks at +0x8..+0x48, and calls through GOT slot
  `0x64df4a0` with (pointer, length, 0) leaf spans. The result is
  discarded at every wrapper site. They are not producers, and
  their `rsi`/`rdx` at the sites are prelude spillover.

The fourteen sites, one level up (all measured; per-site detail
in `records.json`):

- **Context (`rsi`) — uniform, incoming-derived.** At every
  producer site the context argument is the caller's context
  struct + 0x670: stored once per FDE from `lea [r13+0x670]`
  (bwc_a1 `0x2a855b1`, bwc_b2 `0x55828b6`, bwc_c2 `0x55859c6`),
  held in `r15` from `lea [r13+0x670]` (bwc_a3/b3/c3), or
  computed as `lea [r14+0x670]` where `r14` is the FDE's own
  `rsi` (bwc_a2/b4/c4).
- **Query (`rdx`) — per-field assembly in the caller, class
  (a) one level.** The query buffer (`[rsp+0x2f8]` in bwc_a1,
  `[rsp+0x8]` in bwc_a2/b4/c4, `[rsp+0xd0]` in bwc_a3/b3/c3,
  `[rsp+0x3f8]` in bwc_b2/c2) is filled by direct stores only —
  16–17 stores per buffer, refreshed per call (8–14 stores
  between the previous call and each site) — and no memcpy ever
  writes it. The stored values come from the callers' earlier
  phases; tracing them further is outside this packet.
- **Record transfer.** Where the helper's out buffer is not the
  wrapper record (bwc_a1 `0x2761fe0` site, bwc_a2/b4/c4,
  bwc_b2/c2 `0x5492440` sites), the caller loads tag and byte
  from the out buffer, parks the tail with a 0x10f memcpy into a
  scratch buffer, stores tag/byte at the record displacement
  (#2598's `record_disp`, re-verified at every site: the wrapper
  call's `r8` equals it), and restores the tail. At the shape-Y
  sites (bwc_a3/b3/c3) the out buffer **is** the record buffer at
  `[rsp+0x1d0]` and the park/restore runs over the query scratch
  at `[rsp+0xd0]` with 0xff copies, exactly as #2598 recorded.
- **Inspector sites.** The inspected head is copied by vector
  stores from the preceding call's output buffer, between that
  call and the inspector call: bwc_a1 — from the `0x2761fe0`
  output at `[rsp+0x360]` (3 stores); bwc_b1 — from lookup body
  `0x5580d10`'s output at `[rsp+0x730]` (7 stores; its query
  buffer at `[rsp+0x3c0]` is likewise caller-assembled, 19
  stores, and its `rsi` is bwc_b1's own second argument);
  bwc_c1 — from lookup body `0x55806e0`'s output (7 stores);
  bwc_b2/c2 — from the **first** `0x5492440` call's output at
  `[rsp+0x2e0]` (3 stores; that first call, at `0x5583707` /
  `0x5586817`, is the producer call of the inspector site's
  phase, distinct from the second `0x5492440` call packeted as
  the FDE's producer site).

## Slot facts (re-resolved by the extractor on every run)

- `0x64dfaf8`: one `R_X86_64_RELATIVE`, addend `0x63efec0`
  (the #2561 u128 divider).
- `0x64e71b8`: one `R_X86_64_RELATIVE`, addend `0x434f790`
  (the inner bodies' gate callee; body not pinned here).
- `0x64e4ea8`: one `R_X86_64_RELATIVE`, addend `0x4524e40`.
- `0x64df508`: `R_X86_64_GLOB_DAT`, symbol `memcpy`.

## Open boundaries

- The gate callee `0x434f790` behind slot `0x64e71b8`: what its
  two per-item calls decide (the inner bodies require return 1).
- The site-3 descriptor fields written by phase body
  `0x2db34c0`.
- The values feeding the caller FDEs' per-field query assembly.
- The lookup bodies `0x5580d10` / `0x55806e0` behind the b1/c1
  inspector sites.

## Files

- `records.json` — bodies, inner-body censuses and exit
  contracts, the six call sites of each caller pair, the six
  helpers, the fourteen producer/inspector sites, slot facts.
- `frames.txt` — the retained FDE lines for all 21 bodies.
- `*_objdump.txt` — full-body exports for the 14 bodies at or
  under ~4 KB (both inner bodies, all six helpers, six caller
  FDEs); the remaining caller FDEs are digest- and pin-pinned.
- `tools/inner_bodies_static.py` regenerates this directory from
  the authenticated artifact and fails closed on any drift;
  `tests/test_inner_bodies_static.py` checks byte-for-byte
  regeneration, the counters, and mutation rejection.
