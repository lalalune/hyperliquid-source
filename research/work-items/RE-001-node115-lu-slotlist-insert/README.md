# RE-001: the node #115 lu per-slot list insert — append, bitmap set, no flag read

This packet answers packet #246's next question: what the `+0x13`-gated
callee FDE `0x63d88d0..0x63d8a00` does with the (first-arg, block) pair
it receives when `+0x13` is set — whether it reads `+0x13` itself, what
it establishes in return, and how it relates to the handoff and the
register.

## Summary

`0x63d88d0(first-arg, block)` is the per-slot list **insert**: the exact
mirror of #244's post-remove unlink. It appends the block to the
per-slot circular doubly-linked list over the `+0x40`/`+0x48` links
(neighbours linked to each other, block inserted between tail and head,
slot head unchanged), and it **sets** the slot's bit in the
`first-arg+0x1488` bitmap — but only when the slot was empty. It frees
nothing, never writes a block key, never calls the handoff or the
register, and never writes `[block+0x12]`.

And the flag question is answered by a negative: this function **never
reads `[block+0x13]`** — nor `+0x11`, `+0x14`, `+0x20`, or `+0x23`. The
flag gates the *call* (in #246's re-register tail and in #237's
register tail, the only two call sites), and inside the callee it is
irrelevant. So the drivers' flag is finally consumed as a call gate by
its callers, not as a read in this function.

This function is distinct from the merged `0x63ac0d0` slot-insert helper
(a class-chain insert over `+0x28`/`+0x30`/`+0x38` links, different
function, different list); that packet's slug (`lu-slotinsert`) is
unrelated to this packet's per-slot list insert, and no byte of it is
claimed here.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`, kept live).
- `rsi` = block pointer (saved in `rbx`).
- No return value is established by these bytes: both `ret` paths
  return through the pops epilogue with no value set in `rax`.
- Block fields, as used here: `+0x10` = byte selecting a slot number
  (see below); `+0x40` = forward link of the per-slot list; `+0x48` =
  back link of the per-slot list; `+0x68` = dispatch key (zero vs
  nonzero); `+0xb0` = the other term of the size input. The
  `+0x11`/`+0x12`/`+0x13`/`+0x14` flags from #245/#246 are never read
  or written here.

## Entry and dispatch

1. `push %rbp`; `rbp := rdi`; `push %rbx`; `rbx := rsi`;
   `sub $0x8, %rsp`.
2. `rax = [block+0x68]`. If nonzero, jump to the size arm (step 4).
   If zero, take the zero arm (step 3).

## Zero arm: byte slot number

3. `rcx = [block+0x10]` (zero-extended byte) `+ 0x7e`;
   `rdx = rcx + 0x210`; slot address =
   `first-arg + 8 + 8*rdx` = `first-arg + 0x1478 + 8*byte`
   (equivalently `first-arg + 0x1088 + 8*rcx`, same as the size
   arm). Load `rax = [slot]`; if `rax == 0`, go to the empty
   case (step 6); otherwise go to the splice below.

## Size arm: mapped slot number

4. `rdi = ([block+0xb0] - [block+0x68]) << 12`; call
   `0x63e8bf0` (cited only — the same size-mapping helper
   #237/#238/#242/#243/#244/#246 cited). Note the input is the
   difference of the `+0xb0` and `+0x68` fields, shifted — the
   same input as #244, not `[block+0x60] << 12` as in
   #242/#243/#246. If the result exceeds `0x7000000000000000`,
   take the overflow stub (`r10d = 0x18e = 2*199`, jump into
   the slot-number computation: index 199 — verified by key
   bytes, not exhibited, same convention as #237/#238/#242/
   #243/#244/#246). Otherwise compute the index by the
   identical scheme as #242: `bsr`, `+1` unless a power of two
   (via `cmp`/`sbb`), clamped to a minimum of 14, shift =
   `clamped - 3` except `12` when `clamped == 14`, index =
   `((result - 1) >> shift) & 3 + 4 * (clamped - 14)`.
5. Slot number `rcx = ([block+0x10] ^ 1) + 2*index`; jump to
   the shared slot load: `rdx = rcx + 0x210`; slot address =
   `first-arg + 8 + 8*rdx` = `first-arg + 0x1088 + 8*rcx`.
   Load `rax = [slot]`; if `rax == 0`, go to the empty case
   (step 6); otherwise go to the splice below.

## The splice (shared by both arms)

With `H := [slot]` (the old head) and `T := [H+0x48]` (the
tail, since the head's back link points at the tail in this
circular list), the stores are, in order:
`[block+0x48] := block`; `T := [H+0x48]`;
`[block+0x40] := T`; `[H+0x48] := block`;
`[block+0x48] := T` (via the block's own back link);
`[block+0x40] := H`; `[T+0x40] := block`;
`[slot] := H` (the loaded head value, unchanged).
Read against the circular invariant, the net effect is
exactly: the block is inserted between tail and head
(`[block+0x40] := H`, `[block+0x48] := T`,
`[H+0x48] := block`, `[T+0x40] := block`) and the slot
head is unchanged. Then pops and `ret` at `0x63d8939`.
No bitmap write happens on this path — the bit is set
only on the empty path.

## The empty case

6. Slot was `0`. `r10 = rcx >> 6`; `r11 = 1 << cl`;
   `or %r11, [first-arg + 0x1488 + 8*r10]` — i.e. set bit
   `rcx mod 64` of qword `rcx / 64` at `first-arg+0x1488`,
   where `rcx` is the slot number from step 3 or step 5.
   Then the block's `+0x40`/`+0x48` pair is made
   self-linked in one 16-byte store (`movups %xmm0`
   with `xmm0 = (block, block)`), `[slot] := block`,
   and pops and `ret` at `0x63d89f0`. The bit is set,
   never cleared, here; the clear side is #244.

## What this decides

- The `+0x13` question is answered: the flag is **not**
  read here at all. Its consumption is the call gate in
  #246 (re-register tail: `+0x13 != 0` calls here) and in
  #237's register tail (same gate, second call site) —
  and the callee then inserts unconditionally.
- The #244 open items are closed on both sides: the
  per-slot bitmap's set side is this function (empty slot
  only), and the `+0x40`/`+0x48` list's insert side is
  this function (append between tail and head).
- The slot table is unified with #244's: slot address =
  `first-arg + 0x1088 + 8*slot-number` on both arms, with
  slot number `byte + 0x7e` (zero arm, range 126..381) or
  `2*index + (byte ^ 1)` (size arm, range 0..653). The
  same overlap reservation as #244 applies (see below).
- The size input matches #244 exactly
  (`([block+0xb0] - [block+0x68]) << 12`, overflow stub
  `r10d = 0x18e`), confirming the two functions share one
  slot-numbering scheme, one table, and one bitmap.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d88d0..0x63d8a00`, 304 bytes); `push %rbp` entry
  (no `endbr64` — the #238/#244 caution, confirmed against
  `.eh_frame` rather than assumed); `int3` padding
  `0x63d88c4..0x63d88d0` (12 bytes, after #238's handoff,
  which ends at `0x63d88c4`) and none after (the next FDE
  starts at `0x63d8a00`). Static analysis only; the binary
  was never executed.
- 6 exhibits, 285 bytes, 74 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `in_entry` | `0x63d88d0..0x63d88e5` | 21 | 8 | Entry, arg saves, `[block+0x68]` load, dispatch |
| `in_zero` | `0x63d88e5..0x63d8902` | 29 | 6 | Zero arm: byte slot number, slot load, empty test |
| `in_splice` | `0x63d8902..0x63d893a` | 56 | 16 | Append splice, slot unchanged, pops, ret |
| `in_size` | `0x63d8940..0x63d89ba` | 122 | 29 | Size call, overflow test, index, slot number |
| `in_empty` | `0x63d89c0..0x63d89f1` | 49 | 13 | Bitmap bit set, block self-link, slot := block, ret |
| `in_over` | `0x63d89f8..0x63d8a00` | 8 | 2 | Overflow stub: `r10d = 0x18e`, jump into slot-number computation |

- The `nopw`/`nopl` gaps (`0x63d893a..0x63d8940`,
  `0x63d89ba..0x63d89c0`, `0x63d89f1..0x63d89f8`) are
  padding, not claimed.
- Census: direct `E8` call sites to `0x63d88d0`: 2 —
  `0x63d9247` (#246's re-register, `+0x13`-gated) and
  `0x63d967f` (#237's register tail, `+0x13`-gated, cited
  only — it lies inside #237's FDE, no byte of it claimed
  here). Direct `E9` jump sites: 0. Rip-relative `LEA`
  sites: 0 (all `48`/`4c`/`49`/`4d 8d` forms). `.rela.dyn`
  addends equal to `0x63d88d0`: 0 of 60,723 entries.
  Internal calls within the FDE: 1 (`0x63e8bf0`).
  Internal jump targets: all lie inside
  `0x63d88d0..0x63d8a00`. Two `ret` sites: `0x63d8939`,
  `0x63d89f0`.
- Disjointness: this FDE overlaps no claimed range from
  packets #183–#246 (including the merged `0x63ac0d0`
  slot-insert helper's ranges, which are a different
  function at a different address) and no other
  contributor's topic, addresses, or tables. The
  re-register function, the register, the size mapper,
  the handoff, the post-remove unlink, the give-back,
  the removal entry, the class remove, the entry probe,
  the gate, the driver, and the allocator thunk are cited
  by address, not claimed here.

## Corrections to earlier packets

- **#246 confirmed and completed.** Its `+0x13`-gated
  callee is this FDE: the call at `0x63d9247` lands here,
  and this function inserts the block into its per-slot
  list without reading the flag.
- **#244 confirmed and completed.** Its bitmap set side
  is this function (empty slot only), and its list
  insert side is this function (append between tail and
  head). Its slot-numbering scheme, table base, and
  bitmap address are all shared with this function.
- **#237 confirmed and completed in part.** Its register
  tail also gates a call to this function on `+0x13`
  (site `0x63d967f`, cited only): after calling the
  handoff, it tests `[block+0x13]` and, if nonzero,
  calls this insert before rejoining its loop. The
  register's own bytes are not re-claimed here.
- **#243 confirmed.** The give-back's counters and flags
  are untouched here; this function runs downstream of
  give-back, on the per-slot list.
- **#242 confirmed.** The removal entry's queue and size
  paths are not repeated here.
- **#241 confirmed.** The class remove's chains are not
  touched here.
- **#240 confirmed.** The probe's empty verdict is not
  re-tested here; the bitmap set here is the slot
  bitmap (`first-arg+0x1488`), not the class bitmap
  (`first-arg+0x400`).
- **#239 confirmed.** The class insert's chains are not
  touched here.
- **#238 confirmed.** The handoff's flag (`[block+0x12] :=
  1`) and queue are not touched here; the handoff's
  size-mapping scheme is repeated here for the slot
  index, but with a different size input and table.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches this function on the zero
  arm, which books it by byte slot number.
- **#235 confirmed.** The gate's paths reach this function
  only indirectly, through the register, the handoff,
  the re-register, and the `+0x13` gates.
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff; per-slot insertion
  runs through this function, not the driver path.
- **#233 confirmed.** The loop caller is not involved with
  this function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the caller FDEs, the give-back,
  the re-register, and the `+0x13` gates, never directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- The bitmap overlap question, carried from #244: the
  bitmap qword range at `first-arg+0x1488` numerically
  overlaps the slot-pointer range (bitmap qword `k` sits
  at the address of slot pointer `128 + k`), so how the
  set side here (and the clear side in #244) avoids
  clobbering live slot pointers — or whether the ranges
  are disjoint in practice — is still unresolved.
- What establishes the `+0x13` state the register tail
  tests before its call here, beyond #245's driver flag
  pattern (the register's own path to that test is not
  decoded here).
- Whether the zero arm's `byte + 0x7e` slot numbers and
  the size arm's `2*index + (byte ^ 1)` slot numbers
  address one table with shared semantics, or two uses
  of one address range (same reservation as #244).
- The domain meaning of the `[block+0x10]` byte beyond
  its slot-number role, and of the `+0xb0` field beyond
  its size-input role.
- What the neighbour FDE `0x63d8a00..0x63d8b15` does —
  its entry, its calls, and its relation to this insert.
  This is #248's question.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Next question (#248)

Decode the neighbour FDE `0x63d8a00..0x63d8b15` end to
end: what it does with its arguments, what it calls, and
how it relates to this per-slot insert — deciding what
sits next to the insert in the call graph.

## Verification

- `tools/node115_lu_slotlist_insert.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, two `ret` sites, one call rel32, key
  bytes, jump targets internal, no flag-displacement reads or
  writes, full census, neighbour disjointness, MANIFEST coverage
  (17 entries).
- `tests/test_node115_lu_slotlist_insert.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout (verified for #242; base unchanged
  since), so this is pre-existing upstream staleness from
  the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone. Note: the worktree's `AGENTS.md`
  says to run `make verify test catalogue-check`, but the
  parent task's explicit no-full-`make test` rule outranks
  it; the deviation is disclosed here, as in #245/#246.
