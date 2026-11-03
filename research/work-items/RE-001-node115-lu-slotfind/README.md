# RE-001: the node #115 lu slot-find helper — exact slot, best key, covering block

## Question

Packet #225's next question: decode the FDE `0x63b0980..0x63b15e9`
end to end — what it does with its slot and nodes, why it calls the
slot-head helper `0x63abd00` four times (sites `0x63b0bc7`,
`0x63b1131`, `0x63b1490`, `0x63b14ed`), and how its slot relates to
the allocator's pool slots.

## Answer (short)

`0x63b0980(record, length, align, flag, shift)` = (rdi, rsi, rdx,
ecx low byte, r8d) finds a block node in the record's size-class
slots and returns it, or `NULL`. It never stores to the record or to
any slot: every mutation it causes goes through the slot-head helper
it calls. It works in two phases:

- **Phase 1** (class at or above the "certainly big enough"
  threshold): if `flag` is nonzero, it takes the threshold class's
  slot directly (after an empty test); if `flag` is zero, it scans
  the record's presence bitmap upward from the threshold class and
  keeps the set class whose stored cached key is smallest among
  classes passing the table check. Each new best is restructured by
  the slot-head helper.
- **Phase 2** (only when the request's alignment exceeds one page
  and phase 1 found nothing): it scans set classes in the band
  below the threshold, restructures each with the slot-head helper,
  and returns the first head whose block range covers the request
  under the alignment. Otherwise it returns `NULL`.

The four slot-head calls are the four places a slot is consumed:
exact-slot (`0x63b0bc7`), first-candidate best (`0x63b14ed`),
steady-state best replacement (`0x63b1490`), and phase-2 loop
(`0x63b1131`). The two replace sites are the same logical step in
the compiler's duplicated loop heads, not two different operations.

Its slots are the record's 32-byte class slots — the same table
#224's release helper uses — not the allocator pool's 16-byte slot
array. The two share the `[slot]` / `[slot+8]` prefix, so every
chain helper operates on either; only the record's extra cached-key
words differ.

## The function

FDE `0x63b0980..0x63b15e9` (3177 bytes), a single `ret` site
(`0x63b132b`), 8 `call` instructions: 3 to the size helper
`0x63e8c80` (at `0x63b09cb`, `0x63b0f62`, `0x63b0fbc`), 1 to the
empty test `0x63abcf0` (at `0x63b0bbb`), 4 to the slot-head helper
`0x63abd00` (at `0x63b0bc7`, `0x63b1131`, `0x63b1490`,
`0x63b14ed`). All jump targets lie inside the FDE. No store in the
FDE targets the record, a slot, or a node — only stack spills.

Arguments, as used (not as named at source level):

- `rdi` = record `P` (`rbx` throughout).
- `rsi` = length `L` (`r12` throughout; compared against the
  remaining bytes in the phase-2 range check).
- `rdx` = alignment-ish input, page-rounded to `A`
  (`(rdx + 0xfff) & ~0xfff`); `A` is the alignment modulus in the
  phase-2 range check, and `rdx <= 0x1000` skips phase 2.
- `ecx` low byte = flag: nonzero selects the exact-slot phase-1
  path, zero selects the bitmap-scan phase-1 path.
- `r8d` = shift/mode: `0x40` is the default sentinel (shift 63,
  which makes the table check vacuous for `r13 >= 1`); any other
  value is used directly as the shift in the table check. The
  single caller passes `0x40` when its flag byte is zero and a
  loaded DWORD otherwise.

## Entry and the class index

- `endbr64`; `A = (rdx + 0xfff) & ~0xfff`
  (`0x63b098d`–`0x63b0995`); `r13 = A + L - 0x1000`
  (`0x63b099c`).
- Entry guard (`0x63b09b2`): if `r13 < L` — i.e. `A < 0x1000`,
  i.e. `rdx == 0`, since `A` is a multiple of `0x1000` — return
  `NULL` at once (`0x63b1318`).
- `v = 0x63e8c80(r13)` at `0x63b09cb` (a sibling of #224's
  `0x63e8bf0`, not the same helper; cited by address only).
- The `bsr` index idiom (same shape as #224's release index,
  #216's allocator index, #218's remainder index): if
  `v >= 0x7000000000000000`, the huge path (`0x63b15c4`)
  hardcodes index 199 (`0xc7`); otherwise
  `edi = max(ceil_log2(v), 14)`,
  `shift = (edi == 14) ? 12 : edi - 3`,
  `index = (edi - 14) * 4 + (((v - 1) >> shift) & 3)`.
  Index range is 0..199.

Why `A + L - 0x1000` is the threshold: block bases are page
aligned (the phase-2 check masks the base to a page), so aligning
a base up to `A` moves it by a multiple of `0x1000` strictly below
`A` — at most `A - 0x1000`. A block of size at least
`L + A - 0x1000` therefore serves the request whatever its base's
alignment slack is. Classes at or above this threshold are the
certainly-big-enough classes (phase 1); classes from `idx(L)` up
to this threshold may serve only with favorable slack (phase 2).

## Record and slot layout (same table as #224)

With `P = record` and `i = index`:

- `P + 0x00 .. P + 0x20`: presence bitmap, one bit per class
  (4 words cover 200 classes). A set bit means the class has
  blocks; #224 clears a bit when a class empties.
- `P + 0x20 + i * 32`: slot object `T`, 32 bytes per class.
  `T = P + (i + 1) * 32` in the code. `[T]` is the chain head
  (#223); `[T+8]` is the second word (identity unresolved, #223);
  `[T+0x10]` / `[T+0x18]` hold the slot's cached key (see below).
- This FDE never touches #224's accounting (`P + 0x1920 + i * 16`),
  cursor (`P + 0x25a0`), or page counter (`P + 0x25a8`): it reads
  the bitmap and the slot cache words only.

Node words used here (consistent with #224/#225):

- `+0x8` = block base (page-masked in the phase-2 range check).
- `+0x10` = block size (page-masked in the range check; the same
  size word #224's release helper reads).
- `+0x20` / `+0x8` = two-word sort key; the slot's cached key is
  (`[head+0x20]`, `[head+0x8]`) per #224's refresh mapping, stored
  at `[T+0x10]` / `[T+0x18]`.

## Phase 1: exact slot (flag nonzero)

At `0x63b0bac`: `T = P + (index + 1) * 32`.

- Empty test `0x63abcf0(T)` at `0x63b0bbb` (12 bytes:
  `cmpq $0,(%rdi); sete %al; ret`): if `[T] == NULL`, the
  not-found path (`0x63b0ba0`: result `NULL`, found-flag set)
  goes to convergence.
- Otherwise slot-head `0x63abd00(T)` at `0x63b0bc7` restructures
  the slot and returns its head; the head is the result
  (`0x63b0bcc`–`0x63b0bd6`).

## Phase 1: bitmap scan (flag zero)

The bitmap scan finds the first set bit at class `>= index`:
word `= index >> 6`, mask `= -(1 << (index & 63))` (bits from the
index upward in that word), then an unrolled scan of words up to
word 3. No set bit, or a found class above 199, means not-found
(`0x63b0ba0`).

Then the loop iterates set classes in increasing order. For each
candidate class `c`:

- Table check (`0x63b0c15` / `0x63b0d41`): `table[c] >> shift`
  against `r13 = A + L - 0x1000`, where `table` is the `.bss`
  table at `0x6728180` (the same table #224 cited for the size
  helper) and `shift` is 63 when `r8d == 0x40`, else `r8d`. If
  `r13 < table[c] >> shift`, the loop exits to convergence with
  the current best (possibly `NULL`) — it does not skip to the
  next class, because table values increase with class. With
  shift 63 the value is a single bit (0 or 1), so the check is
  vacuous for `r13 >= 1` and every set class is considered.
- First candidate (no best yet): replace path (`0x63b14d8`):
  slot-head on slot `c`; best node = returned head; best key =
  the slot's stored cached key (`[T+0x10]`, `[T+0x18]`), re-read
  after the call. Slot-head itself does not rewrite those words
  (per #225's store list), so the tracked best key is the stored
  cache, not necessarily the new head's key.
- Later candidates: the stored cached key of slot `c` is compared
  against the best key with the two-sided `setb`/`sbb` signum
  idiom (`[T+0x10]` first, `[T+0x18]` on a tie — read as
  `[record + c*32 + 0x30]` / `[record + c*32 + 0x38]`). If the best
  key is greater (`eax == -1`), replace path (`0x63b1480`):
  slot-head on slot `c` and update best. Otherwise keep the best.
- Advance to the next set bit (`0x63b0c6e` / `0x63b0d9a`); `c ==
  199` ends the loop at convergence.

Result: the smallest stored cached key among eligible set classes,
or `NULL` if no candidate passed the table check. The two loop
heads (`0x63b0c15` first-iteration form, `0x63b0d41` steady form)
are the compiler's duplication of one loop: the `r8d == 0x40`
test at `0x63b0d31` only routes between them and changes nothing
about the scan, the check, or the selection.

## Convergence

At `0x63b0f40` / `0x63b0f47`, with `bpl` = (result == `NULL`):

- If the original `rdx <= 0x1000`, return the phase-1 result
  directly — phase 2's band is empty in this case, since
  `A = 0x1000` makes `A + L - 0x1000 == L`.
- Else if a node was found (`bpl == 0`), return it.
- Else (not found, `rdx > 0x1000`), run phase 2.

## Phase 2: covering-block band

- Recompute indices with the size helper: `j1` from `L`
  (`0x63b0f62`: `0x63e8c80(r12)`), `j2` from `A + L - 0x1000`
  (`0x63b0fbc`: `0x63e8c80(r13)`); huge inputs hardcode 199
  (`0x63b15d3`, `0x63b15de`).
- Bitmap scan from `j1` for the first set class `f`. None means
  class 200, which is `>= j2` (since `j2 <= 199`), so return
  `NULL`. If `f >= j2`, return `NULL`.
- Loop over set classes `f, ...` while class `< j2`
  (`0x63b1120`): slot-head on the class's slot (`0x63b1131`,
  no empty test first — a set bitmap bit implies a non-empty
  slot), then the range check (`0x63b1136`–`0x63b116c`):
  - `base = [head+0x8] & ~0xfff`,
    `sizep = [head+0x10] & ~0xfff`,
    `aligned = (base + A - 1) & -A`.
  - If `aligned < base` (overflow guard) or
    `aligned >= base + sizep`, try the next class.
  - If `base + sizep - aligned >= L`, return `head`.
- No table check, no cached-key comparison, and no cache refresh
  in this loop: the first covering head wins. If no class in the
  band covers, return `NULL` (`0x63b1318`).

All exits funnel through the single `ret` at `0x63b132b` with
`rax = rsi` (the result node or `NULL`).

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Finder `0x63b0980`: 1 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x63b49a3` (in the FDE starting `0x63b4630` — the
same FDE #225 cited as the release helper's fourth caller). That
caller passes (record, a stack length, a stack alignment-sized
value, a byte flag, `0x40` when its flag byte is zero else a
loaded DWORD), checks the return for non-`NULL`, and takes a
success path on non-`NULL`; its own purpose is not decoded here.

## Relation to the allocator's pool slots

- **Different tables.** This function's slots are the record's
  32-byte class slots (bitmap + 200 classes, stride 32). The
  allocator pool's slots (#216) are a separate array at
  `pool+0xa8..pool+0xf28` with a 16-byte stride (index 65 scans
  from `pool+0x4b8`: `(0x4b8 - 0xa8) / 65 = 16`).
- **Shared prefix.** Both slot kinds start with `[slot]` (head)
  and `[slot+8]` (second word), and every chain helper operates
  on that prefix alone: #217's slot-claim, #219's slot-insert,
  #223's slot-remove, #225's slot-head. A record class slot can
  therefore be passed to any of them as a basic slot.
- **The difference is the cache.** Only the record's 32-byte
  entries carry `[T+0x10]` / `[T+0x18]` (the cached key). This
  function reads those words for selection; #224's release
  helper writes them on refresh. No chain helper touches them.
- **The nodes are blocks.** The chains here hold blocks whose
  `+0x8` is a base and `+0x10` is a size (phase-2 range check;
  #224's size word), indexed by size class in the record — while
  the pool's chains hold free blocks indexed by the pool's own
  slots. Whether a block can appear in both a record chain and a
  pool chain is unresolved.

## Corrections to earlier packets

- **#225 confirmed.** The four slot-head call sites
  (`0x63b0bc7`, `0x63b1131`, `0x63b1490`, `0x63b14ed`) are
  exactly this function's calls, and the FDE
  `0x63b0980..0x63b15e9` is one function with one `ret` and
  8 calls — not a fragment. Its "five non-release callers"
  note is now resolved for the four sites here: exact-slot,
  first-candidate replace, steady-state replace, phase-2 loop.
  The remaining slot-head caller (`0x63bca0f`, FDE
  `0x63bc730..0x63bcb12`) is still undecoded.
- **#225 refined.** The steady-state replace site (`0x63b1490`)
  and the first-candidate replace site (`0x63b14ed`) are not two
  different operations: they are the same best-replacement step
  in the compiler's duplicated loop heads.
- **#224 confirmed.** The record layout (bitmap, 32-byte slots,
  cached key at `[T+0x10]` / `[T+0x18]`) matches exactly, and
  the `.bss` table at `0x6728180` is the same table #224 cited.
  The size helper here (`0x63e8c80`) is a distinct sibling of
  #224's `0x63e8bf0`, not the same function.
- **#216 / #218 refined.** The allocator pool's slot array uses
  a 16-byte stride and is a different table from the record's
  32-byte class slots; any reading that treats them as one table
  is wrong. The slot-entry prefix, and the chain helpers that
  operate on it, are shared.
- No bytes claimed by packets #183–#225 are re-claimed. All
  exhibits lie strictly inside the finder FDE; the size helper,
  the empty test, the slot-head helper, the table, and all caller
  FDEs are cited by address only.

## Unresolved, stated not inferred

The semantic identity and units of `table[0x6728180][c]`; what
representative value the size helper `0x63e8c80` returns for an
input (its code is cited by address only, and its table lives in
`.bss`, not in the file); the semantic identity of node `+0x20`
(the first cached-key word) and of `[slot+8]`; why phase 1 keeps
the smallest cached key — a best-fit reading is conjecture until
`+0x20` is identified; the purpose of the single caller FDE
(starting `0x63b4630`) beyond its argument setup and non-`NULL`
success path; whether record chains and pool chains share nodes.

## Next question

Decode the size helper `0x63e8c80` end to end: what representative
value it returns for its input, and how it uses the `.bss` table
at `0x6728180` — this decides what the class index and the table
check in this packet actually measure.
