# RE-001-node115-lu-tail-route

## Question

Packet #206 asked: decode the tail route `0x635f4b0` end to end —
what does it do with (thread, seg, C, arg4), and what distinguishes
its two call shapes (arg4 = 0 from the gate vs arg4 = [C+0x6e8]
from the inner route)?

## Answer (short)

`0x635f4b0` is a per-segment table-entry worker, not a record-C
worker. It takes (thread, seg, C, arg4), looks up one 208-byte
table entry from the segment counter, locks that entry's embedded
record C first and the passed C second, and runs a gated sequence
that ends in one of two drains. The 4th argument matters exactly
once: nonzero arg4 adds the accumulator helper's return to the
entry's +0xb8 accumulator before a 0x400 threshold check; zero
arg4 skips the accumulation but the threshold check still runs.
And #206's "two call shapes" is really three: the gate passes 0,
the inner route passes [C+0x6e8] conditionally, and FDE `0x6360ed0`
forwards its own spilled argument.

## Targets

- Tail route: FDE `0x635f4b0..0x635f697` (423B, push prologue —
  no `endbr64`, like the inner route).
- Table entry: 208 bytes, `entry = [qword at .bss 0x6711aa0] +
  208 * ([seg+0x13450] % [qword at .bss 0x6711aa8])`.
- Helpers (characterised only, not decoded): predicate `0x6369790`
  (15B FDE), drain `0x63697a0` (50B FDE), accumulator `0x63a96f0`
  (90B FDE), C-sequence stubs `0x63bfb90` / `0x63bfb60` /
  `0x63bfc00` / `0x63bfc40` (8–11B FDEs each).

## The table entry embeds a record C at +0x38

The entry's owner/lock/flag fields line up exactly with #204's
record-C layout under a single +0x38 base shift:

- entry+0x60 owner-change count = C+0x28
- entry+0x68 last owner = C+0x30
- entry+0x70 update count = C+0x38
- entry+0x78 mutex = C+0x40
- entry+0xa0 contention flag = C+0x68

So the entry is not a bare slot: it carries a full record C at
entry+0x38, plus its own fields at entry+0xac (drain-trigger
byte, = C+0x74 under the shift — inside #204's unresolved
C+0x70..+0x77 gap, now given a role), entry+0xb0 (address passed
to `0x63bfb90`, = C+0x78), and entry+0xb8 (accumulator vs 0x400,
= C+0x80). The C+0x78/C+0x80 correspondence is consistent with
#204's "batch in-count" / "bytes moved" labels, not proof of
them — the shift alignment itself is the claim.

## The tail route, end to end

Signature: `(thread, seg, C, arg4)` = (rdi, rsi, rdx, rcx).
Prologue maps rdi → thread (rbp), rsi → seg, rdx → C (r12),
rcx → arg4 (r13).

1. **Entry lookup** (`tail_lookup.hex`): eax = [seg+0x13450]
   (the segment counter #204/#206 used), edx = eax % [qword at
   .bss `0x6711aa8`] via `divq`, rbx = table_base + 208*idx
   (13*16, built as rdx*3, then rdx + rbx*4, then shl 4).
   r14 = entry+0x78, the embedded C's mutex.
2. **Entry lock**: trylock entry+0x78. On failure: set
   entry+0xa0 = 1 and return — no wait, no C phase. On success:
   entry+0x70 += 1; if [entry+0x68] != thread, entry+0x60 += 1
   and [entry+0x68] = thread (the same owner dance #204/#206
   saw on C).
3. **Predicate** (`tail_pred.hex`): call `0x6369790(entry)`.
   False → clear entry+0xa0, unlock entry, return. The passed
   C is never touched on this path. True → read the table
   byte at entry+0xac: if nonzero, call drain `0x63697a0`
   (entry, 0), then clear entry+0xa0, unlock entry, return —
   again without touching C. Only a zero byte reaches the
   C phase.
4. **C lock**: trylock C+0x40 (the entry lock is still held —
   lock order is entry-then-C). On failure: set C flag
   C+0x68 = 1, then clear entry+0xa0, unlock entry, return.
   On success: C+0x38 += 1; if [C+0x30] != thread, C+0x28
   += 1 and [C+0x30] = thread (re-confirms #204's C layout
   on the passed C).
5. **C+0x78 gate**: r8 = [C+0x78]. If <= 0: clear C flag,
   unlock C, clear entry+0xa0, unlock entry, return. If > 0:
   call `0x63bfb90(entry+0xb0, stackbuf)`,
   `0x63bfb60(stackbuf, result)`, `0x63bfc00(stackbuf,
   C+0x88)`; if the third call's return is <= 0, take the
   same C-unlock exit; else call `0x63bfc40(stackbuf)` and
   continue to the arg4 branch.
6. **Arg4 branch** (`tail_accum.hex`): test arg4. Zero →
   skip. Nonzero → call `0x63a96f0(C, stackbuf, arg4)` and
   add its return to entry+0xb8.
7. **Threshold** (`tail_drain.hex`): clear C flag, unlock C,
   then compare entry+0xb8 against 0x400. If <= 0x400:
   clear entry+0xa0, unlock entry, return. If > 0x400:
   entry+0xb8 = 0, call drain `0x63697a0(entry, stackbuf)`,
   then clear entry+0xa0, unlock entry, return.

Flag discipline, verified on every path: the entry flag
(+0xa0) is set only on entry-trylock failure and cleared on
every exit that held the entry lock; the C flag (+0x68) is
set only on C-trylock failure and cleared on every C-phase
success exit. The entry lock is released last on all paths.

Return contract: none observed. The function is void in
effect — its epilogue returns whatever the last helper left
in eax — and all three direct callers discard it (below).

## The three call shapes

- **Gate** (`0x6360695`, E9 tail jump; #206's `gate_tail.hex`
  already exhibits it): arg4 = 0, C = seg+0x10ec8. The
  accumulation is skipped, but the threshold check still
  runs — a gate call can still trigger the drain if a prior
  accumulation left entry+0xb8 above 0x400.
- **Inner route** (`0x635fc19`, E8; `tail_callsite.hex`):
  arg4 = [C+0x6e8], C = the inner route's C — but only
  conditionally: the inner route first clears C's flag and
  unlocks C's mutex, then calls the tail route only if a
  runtime byte is nonzero AND its 6th argument is zero.
  The tail call therefore never nests inside the inner
  route's C lock; the tail route re-acquires C+0x40 fresh.
- **FDE `0x6360ed0`** (`0x6361129`, E8): arg4 = the caller's
  own spilled argument — its incoming rcx, saved to the
  stack at `0x6360f93` and overwritten by its incoming r8
  at `0x6361050` on one path, reloaded at `0x6361119`.
  This call is also conditional (skipped when the caller's
  r12b flag is nonzero). Its exact path selection between
  the rcx and r8 values is unresolved.

So arg4 is not a mode flag: it is the accumulation helper's
third argument, supplied as 0 (skip), as [C+0x6e8] (inner),
or as a forwarded caller argument (FDE `0x6360ed0`).

## Census (whole `.text`, byte scan + per-site disassembly check)

- Tail route `0x635f4b0`: 2 direct E8 (`0x635fc19` inner
  route, `0x6361129` FDE `0x6360ed0`), 1 E9 (`0x6360695`
  fallback gate), 0 LEA, 0 GOT (`.rela.dyn` RELATIVE scan).
  Confirms #206's census exactly.
- The predicate, drain, accumulator, and C-sequence stubs
  were not census-counted: they are first-level helpers of
  this packet, not its target, and their callers beyond the
  tail route are out of scope.

## Corrections to earlier packets

- **#206 refined.** Its "two call shapes" becomes three: the
  FDE `0x6360ed0` caller forwards its own spilled argument
  as arg4 — neither 0 nor [C+0x6e8]. Its inner→tail picture
  is completed: the call is conditional (runtime byte
  nonzero AND 6th argument zero) and happens after the inner
  route unlocks C, not under the inner route's C lock.
- **#206 extended.** The table entry's layout beyond stride
  208 and byte +0xac is now known: it embeds a record C at
  +0x38, with +0xb0 passed to `0x63bfb90` and +0xb8 as the
  0x400-threshold accumulator. C+0x6e8's downstream role is
  now fixed (accumulator helper's third argument); its
  semantic label is still unresolved.
- **#204 confirmed.** Its C layout (+0x28/+0x30/+0x38/+0x40/
  +0x68) is re-confirmed on the passed C, and its C+0x78
  field gates a sequence, consistent with "batch in-count".
- No other earlier packet is corrected.

## Unresolved (stated, not inferred)

- Full decodes of predicate `0x6369790`, drain `0x63697a0`,
  accumulator `0x63a96f0`, and the C-sequence stubs
  `0x63bfb90` / `0x63bfb60` / `0x63bfc00` / `0x63bfc40`
  (what the drain does with (entry, buffer-or-NULL), what
  the accumulator counts into entry+0xb8, what the stubs
  do with entry+0xb0 / C+0x88).
- Semantic labels of arg4's values ([C+0x6e8], the forwarded
  argument), of the runtime byte gating the inner→tail call,
  and of entry+0xb8's units (bytes? entries?) beyond the
  0x400 comparison.
- All `.bss` contents (divisor, table base, table bytes).
- The identity of FDE `0x6360ed0` beyond its call sites, and
  the exact path selection between its rcx and r8 values for
  arg4.
- Whether the tail route's return is observed by any caller
  beyond the three known ones (all three discard it).

## Next question

Decode the drain helper `0x63697a0` end to end: what does it
do with (entry, buffer-or-NULL), and what does the entry+0xb8
accumulator count? Behind it, still open: the workers
`0x63c19a0` / `0x63c1930`, the two runtime method pointees
([seg+0x29d0] / [seg+0x11cf0] writers), the drain helper
`0x51e8720`, the field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0` and unwind
callee `0x1680cab`.

## Verification

- Static verifier `tools/node115_lu_tail_route.py`: exit 0
- Unit tests `tests/test_node115_lu_tail_route.py`: 8/8 pass
- MANIFEST: 15/15 entries match
- `make doctor`: analysis_ready true
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8
