# RE-001: the node #115 lu central flush — full class lists move into segment-owned shared records, unlocked before the push

This packet answers packet #203's explicitly stated next question:
**decode the central-flush helpers `0x63ead50` / `0x63eb870`: what
shared structure do they move full class lists into — its layout,
locking, and the per-entry pushes (`0x63612b0` / `0x63bd640`)?**

## The answer

**Short version: there is no single "central pool array".** A full
thread class list is moved into two linked shared structures, both
derived from the block's segment: (1) a per-segment/per-class
statistics-and-lock record **C** (mutex at C+0x40, contention flag
at C+0x68), and (2) the segment's push-list object at **seg+0x2998**,
which is what the per-entry push helpers feed through `0x63c0340`.
Large classes additionally maintain a per-class atomic (bytes,
count) pair outside the segment mutex. And the ordering matters:
**both helpers unlock C before the push phase** — pushes are not
done under C's mutex (see Corrections).

## FDE table (bounds from `.eh_frame`, not from the first `ret`)

| Function | FDE (end exclusive) | Size | Strict instrs | Main `ret` |
|---|---|---|---|---|
| small-flush `0x63ead50` | `0x63ead50..0x63eb79f` | 2639B | 579 | `0x63eb586` |
| large-flush `0x63eb870` | `0x63eb870..0x63ec1d8` | 2408B | 566 | `0x63ec0ae` |
| push-small `0x63612b0` | `0x63612b0..0x636131a` | 106B | 28 | `0x6361303` |
| push-large `0x63bd640` | `0x63bd640..0x63bd6ba` | 122B | 31 | `0x63bd6a4` |

## Arguments: one 5-argument shape `(rdi, rsi, rdx, rcx, r8d)`

`rdi` = thread/TLS object, `rsi` = class-list array base (TLS+0x358),
`rdx` = the slot's head-field address (slot+8), `rcx` = class,
`r8d` = a count from the global u16 table, shifted right by 1
(meaning of the table and the shift: unresolved). Entry count is
`(total u16 >> 3) - r8d` in both helpers. Call sites in the slow
FDE: small at `0x635ce27` and `0x635d3c0` (the second site is new
here — #203 listed only the first); large at `0x635c97e`,
`0x635cc2d`, and `0x635c111` (also new here); large via the
seg-drain `0x6363260` at `0x6363435` with class `0x24` (36).

## The shared structure: record C and the segment

**Segment resolution (both helpers).** For each block pointer B,
segment index = `(*B) & 0xfff`; segment = `.bss` table at
`0x65096c0` indexed by it (small `0x63eaf0c`, large `0x63eb9e7`,
push-large `0x63bd66d`). The table is runtime-populated, so only
the indexing formula is static evidence. Small sub-index =
`((*B) >> 38) & 0x3f`.

**Record C.** Small: `C = seg_table[hdr & 0xfff] +
class_u32_table[class] + sub_index * 224`, with the class table in
`.bss` at `0x6511780` (`small_lock.hex`: `lea 0x6511780` at
`0x63eaf1c`, `sub*224` at `0x63eaf33-0x63eaf41`). Large:
`C = seg + 0x2928`, so its mutex is seg+0x2968 and its flag byte
seg+0x2990 (= C+0x68). Layout, all offsets relative to C:

| Offset | Field | Evidence |
|---|---|---|
| +0x28 | owner-change count (+1 iff C+0x30 != caller arg1) | small `0x63eaf73`, large `0x63ebee0` |
| +0x30 | last-owner pointer (= caller arg1) | small `0x63eaf79`, large `0x63ebee8` |
| +0x38 | total update count (+1 per locked block / threshold lock) | small `0x63eaf62`, large `0x63ebecb` |
| +0x40..0x67 | pthread mutex (40 bytes) | small `0x63eaf48`, large `0x63ebea8` |
| +0x68 | contention flag (1 = taken via slow path, 0 = clean) | set small `0x63eb2a0`, large `0x63ec0bc`; cleared small `0x63eb245`, large `0x63ebc57` |
| +0x78 | batch in-count (+= blocks processed for this C) | small `0x63eb238` |
| +0x80 | bytes moved (+= thread slot's byte total, once per home segment) | small `0x63eafb9` |
| +0x88 | batch out-count (-= same block count) | small `0x63eb23d` |
| +0x98 | home-segment visit count (+1 once per flush) | small `0x63eafac` |
| +0xc0 | block-identity check field (equality only; purpose unknown) | small `0x63eb102` |

The same +0x28/+0x30/+0x38/+0x40/+0x68 pattern recurs for a
second C in the small flush's cold path and in the standalone
routine at `0x63c04a0` — a reused struct, not a coincidence.
C+0x00..+0x17 and the direction semantics of +0x88 are not fixed
by static evidence.

**Segment fields.** +0x2920 block-list head (unlink path);
+0x2928 C_large base; +0x2998 push-list object fed to `0x63c0340`
(= C_large+0x70); +0x13450 segment counter, compared against the
`.bss` threshold u32 at `0x650969c` (`large_gate.hex`).

**Large per-class atomic pair (outside the segment mutex).**
Base P = `(*(*arg2 + 0x28)) + 0x18`; bytes target =
P + 48\*class − 760, count target = P + 48\*class − 744. The
−760/−744 bias (what object P points 760 bytes into) is
unresolved; the formulas are exact. **Small per-class array:**
runtime base `0x6711b40` (via GOT slot `0x64ee138`, RELATIVE
addend verified in `.rela.dyn`), stride 40, +0x10 compared against
`(block_header >> 28) & 0x3ff`; what +0x10 counts is unresolved.
**Home-segment pointer S** = `*(*arg2 + 0x28)`; proven a segment
pointer by equality gates against per-block segments. The
once-only statistics below fire only for blocks whose segment
equals S, and only on the first such block.

## Locking

PLT targets: trylock `0x63f17b0`, unlock `0x63f0b70`, lock
`0x63f0b60` (inside the lock-wait helper only). **Small:**
unconditional trylock of C+0x40 (`0x63eaf51`); on failure the
lock-wait helper `0x63bf680`(C) spins/blocks internally, flag
C+0x68 is set to 1, and the flush proceeds as if locked — no
retry loop, no partial move. Under lock: +0x38, +0x28/+0x30
owner update, once-only +0x98/+0x80. **Large:** threshold-gated
— only if seg+0x13450 >= `*(0x650969c)` does control reach the
trylock of seg+0x2968 (`0x63ebeba`); same blocking fallback
(`0x63bf680`, flag seg+0x2990 = 1 at `0x63ec0bc`). **Unlock
before push:** small unlocks at `0x63eb24f` after the batch
counts and flag clear; large unlocks at `0x63ebc6a`, but only if
the threshold still holds on re-check — if seg+0x13450 dropped
below threshold, the unlock is skipped, and the invariant making
that safe is unresolved.

## The move loop and the thread-list aftermath

Order: prepare (`0x63e9cd0`) → collect/sort into a stack VLA
(`0x63e94a0`; sort key unresolved) → per-block loop (segment
resolution; class-tag checks; mismatches go to the unlink helper
`0x63bd5a0` for large, to re-queue helpers `0x6363660` /
`0x6363560` for small — internals not decoded here) →
once-only home-segment statistics (small, mutex-protected:
C+0x98 += 1, C+0x80 += slot+0x10 bytes, slot+0x10 = 0; large,
atomic outside the mutex: `lock add` slot bytes into
P+48\*class−760 at `0x63eba30`, `lock addq $0x1` into
P+48\*class−744 at `0x63eba3b`, slot+0x10 = 0 at `0x63eba40`) →
batch counts and unlock → push phase (7 unrolled push sites per
helper) → tail compaction with `memmove@plt` (small `0x63eb538`,
large `0x63ec055` in `large_tail.hex`), slot head advanced by
remaining\*8, slot+0x18 u16 clamped. **Aftermath: the list is not
unconditionally emptied** — flushed entries are gone, survivors
are compacted to the slot head by `memmove`, and the slot byte
total is zeroed exactly once per home segment, not per block.

## The push helpers

Both are `void` and converge on the same inner call:
`0x63c0340(alloc, seg+0x2998, block, &flag_byte)` with the flag
byte initialised to 0; if it is nonzero after the call, the
fallback `0x6360610`(alloc, seg) runs. Push-small (`push` sites
in the small flush) pre-resolves the segment at the call site
and adds 0x2998 at `0x63612b8`; push-large (`push_large.hex`)
resolves the segment inside the wrapper (`0x63bd650-0x63bd67b`)
and calls `0x63c0340` at `0x63bd682`. The wrappers touch no
central offsets directly. Inside `0x63c0340` (characterised, not
fully decoded): it reads a dispatch field at
(seg+0x2998)+0x10aa8, atomically decrements the push-list
object's +0x8 field by the block's page count
(`lock sub %rdx,0x8(%rbx)` at `0x63c0397`), then tail-jumps
through a vtable slot — obj+0x18 if block-header bit 0x4000 is
clear, obj+0xf338 if set (`jmp *0x20(%rsi)` at `0x63c03ca`).
Those two virtual methods and the exact meaning of the `&flag`
byte are unresolved.

## Census (whole `.text`, byte scan + disassembly check per site)

| Target | Direct E8 | E9 | LEA | GOT (`.rela.dyn`) |
|---|---|---|---|---|
| small-flush `0x63ead50` | 12 | 0 | 0 | 0 |
| large-flush `0x63eb870` | 14 | 0 | 0 | 0 |
| push-small `0x63612b0` | 14 | 0 | 0 | 0 |
| push-large `0x63bd640` | 14 | 0 | 0 | 0 |

Small E8 sites: `0x6351525, 0x6351599, 0x635210b, 0x635219b,
0x635b3a6, 0x635ce27, 0x635d3c0, 0x6365fe1, 0x63bdd75,
0x63eb83b, 0x63ec643, 0x63ec957`. Large E8 sites: `0x635120d,
0x63521f8, 0x63526f6, 0x6352be4, 0x635c111, 0x635c97e,
0x635cc2d, 0x6363435, 0x636675e, 0x63be137, 0x63ec337,
0x63ec4a7, 0x63ec668, 0x63ecae0`. Each push helper is called
from exactly two places: the prepare helper `0x63e9cd0` (7 sites
each) and its own flush helper (7 sites each) — the prepare
helper itself pushes blocks. No function-pointer (LEA/GOT)
references to any of the four targets exist. (Note: the
push-large call is at `0x63ebd6c`, not `0x63ebd68` — the latter
is the preceding `mov`; see records.)

## Corrections to earlier packets

**#203's ordering shorthand is corrected.** #203 described the
small flush as "per-entry pushes via `0x63612b0`, then
`pthread_mutex_unlock`" (and likewise for large). The evidence
shows the reverse order: the small flush unlocks at `0x63eb24f`
after the batch counts (`0x63eb238`/`0x63eb23d`) and flag clear
(`0x63eb245`), and only then runs its 7 push sites
(`0x63eb3f1` onwards); the large flush unlocks at `0x63ebc6a`
before its 7 push sites (`0x63ebcbf` onwards). Pushes are not
under C's mutex. #203's guard list, slot arithmetic, and
call-site addresses are otherwise confirmed; its census is
extended here with the second small site `0x635d3c0` and the
large site `0x635c111`, both inside the slow FDE.

## Explicitly unresolved (not inferred)

- All `.bss` contents: segment table `0x65096c0`, class tables
  `0x6511780`/`0x6511820`, threshold `0x650969c`, per-class array
  `0x6711b40`, global u16 table at `*(0x6728868)` — zero-filled
  in the file, runtime-populated; no static values or sizes.
- Atomic-pair base P's object chain and the −760/−744 bias;
  home-segment pointer S's object chain; C+0x00..+0x17,
  C+0x70..+0x77 (small), +0x88 direction semantics, +0xc0
  purpose; the `r8d` count's table and `sar 1`; the 1-vs-0 `r8d`
  difference in the `0x63e9cd0` prepare calls.
- Helpers not fully decoded: `0x63e9cd0` (prepare),
  `0x63e94a0` (VLA sort key), `0x6363660`/`0x6363560`
  (small re-queue), `0x63bd5a0` link direction,
  `0x63c0340`'s two virtual methods and `&flag` meaning.
- Why the large unlock is skipped when the threshold drops on
  re-check; slot+0x18 vs #203's slot+0x1a bound reconciliation
  (u32 holding two u16s, or slot bases differing by 2).
- No live `.bss` bytes, segment-table entries, or mutex states
  are claimed.

## Next question

Decode the actual central push `0x63c0340`: what is the
seg+0x2998 push-list object, what are its two virtual methods
(obj+0x18 vs obj+0xf338, selected by block-header bit 0x4000),
and what does the `&flag` out-parameter mean (nonzero =
fallback to `0x6360610`)? Behind it, still open: the drain
helper `0x51e8720`, the field-drop callees `0x5a50a10` /
`0x5a4d200`, and #200's delegates `0x51f3e20` / `0x57ec1b0`
and unwind callee `0x1680cab`.
