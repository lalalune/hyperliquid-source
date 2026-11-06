# RE-001: the node #115 lu post-remove — list unlink, slot head, bitmap clear

Packet #244. Target: node #115, `artifacts/node/115/hl-node`
(105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`),
upstream main `05bc2de30` (confirmed before analysis).
Static analysis only; the binary was never executed.

## Question

Packet #243's next question: what the tail-jump target FDE
`0x63d84e0..0x63d8622` does with the (first-arg, block) pair it
receives by tail jump from the #243 give-back function — deciding
what happens to a block after removal.

## Answer

It unlinks the block from a per-slot circular doubly-linked list
and clears the slot's nonempty bitmap bit when the list empties.
It is a single FDE, `0x63d84e0..0x63d8622` (322 bytes, `push %rbp`
entry — no `endbr64`, confirmed against `.eh_frame` rather than
assumed — two `ret` sites at `0x63d8551` and `0x63d8609`, one
internal call, no tail jump out). It frees nothing and never
writes a block key.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`, kept live).
- `rsi` = block pointer (saved in `rbx`).
- No return value is established by these bytes: both `ret`
  paths return through the pops epilogue with no value set in
  `rax`.
- Block fields, as used here: `+0x10` = byte selecting a slot
  number (see below); `+0x40` = forward link of the per-slot
  list; `+0x48` = back link of the per-slot list; `+0x68` =
  dispatch key (zero vs nonzero); `+0xb0` = subtrahend of the
  size input. The `+0x12`/`+0x13` flags from #243 are never
  read or written here — the tail jump already consumed them.

## Entry and dispatch

1. `push %rbp`; `rbp := rdi`; `push %rbx`; `rbx := rsi`;
   `sub $0x8, %rsp`.
2. `rax = [block+0x68]`. If nonzero, jump to the size arm
   (step 4). If zero, take the zero arm (step 3).

## Zero arm: byte slot number

3. `rcx = [block+0x10]` (zero-extended byte) `+ 0x7e`;
   `rdx = rcx + 0x210`; slot address =
   `first-arg + 8 + 8*rdx` = `first-arg + 0x1478 + 8*byte`
   (equivalently `first-arg + 0x1088 + 8*rcx`, same as the size arm).
   Load `rax = [slot]`; if `rax == block`, go to the head
   case (step 6); otherwise go to the unlink (step 5).

## Size arm: mapped slot number

4. `rdi = ([block+0xb0] - [block+0x68]) << 12`; call
   `0x63e8bf0` (cited only — the same size-mapping helper
   #237/#238/#242/#243 cited). Note the input differs from
   #242/#243: here it is the difference of the `+0xb0` and
   `+0x68` fields, shifted, not `[block+0x60] << 12`. If the
   result exceeds `0x7000000000000000`, take the overflow
   stub (`r10d = 0x18e = 2*199`, jump into the slot-number
   computation: index 199 — verified by key bytes, not
   exhibited, same convention as #237/#238/#242/#243).
   Otherwise compute the index by the identical scheme as
   #242: `bsr`, `+1` unless a power of two (via `cmp`/`sbb`),
   clamped to a minimum of 14, shift = `clamped - 3` except
   `12` when `clamped == 14`, index =
   `((result - 1) >> shift) & 3 + 4 * (clamped - 14)`.
5. Slot number `rcx = ([block+0x10] ^ 1) + 2*index`; jump to
   the shared slot load: `rdx = rcx + 0x210`; slot address =
   `first-arg + 8 + 8*rdx` = `first-arg + 0x1088 + 8*rcx`.
   Load `rax = [slot]`; if `rax == block`, go to the head
   case (step 6); otherwise go to the unlink (step 5b).

## The unlink (shared by both arms)

5b. With `A := [block+0x40]` (forward link) and
`B := [block+0x48]` (back link), the stores are, in order:
`[B+0x40] := A`; `[A+0x48] := B`; `[block+0x48] := C`;
`[C+0x40] := block`, where `C` is the old `[A+0x48]`.
Read against the doubly-linked invariant — `C` is the block
itself when the list is consistent (A's back link points at
the block) — the net effect is exactly: the neighbours are
linked to each other (`[B+0x40] := A`, `[A+0x48] := B`)
and the block is left self-linked (`[block+0x40] := block`,
`[block+0x48] := block`). Then: if the loaded slot value
was `0`, fall through to the bitmap clear (step 7);
otherwise pops and `ret` at `0x63d8551`. One observation,
stated rather than smoothed over: there is no empty-list
guard — when the slot was `0`, the unlink stores still
execute against the block's own link words, and the bitmap
bit is cleared anyway.

## The head case

6. Slot holds the block itself. `rax = [block+0x40]`
   (forward link):
   - If `rax == block` (self-linked: the list's only node),
     `[slot] := 0` — the slot is emptied — then fall through
     to the bitmap clear (step 7).
   - Otherwise `[slot] := rax` — the slot advances to the
     block's forward neighbour — then jump back into the
     unlink (step 5b), which unlinks the block and returns
     (the loaded value was nonzero, so no bitmap clear).

## The bitmap clear

7. `rbx = rcx`; `rax = ~1`; `rbx >>= 6`; `rol %cl, %rax`;
   `and %rax, [first-arg + 0x1488 + 8*rbx]` — i.e. clear bit
   `rcx mod 64` of qword `rcx / 64` at `first-arg+0x1488`,
   where `rcx` is the slot number from step 3 or step 5
   (unchanged by the unlink and head paths). Then pops and
   `ret` at `0x63d8609`. The bit is cleared, never set,
   here; the set side is not decoded in this packet.

## What this decides

- The post-removal question is answered in form: after the
  #243 give-back books the counters and (when `+0x12` is
  set) removes the block from its size class or queue, a
  `+0x13`-set block is handed here by tail jump, and here
  it is unlinked from its per-slot `+0x40`/`+0x48` list,
  with the slot head advanced or emptied and the slot's
  nonempty bit cleared exactly when the list empties (or
  when the slot was already `0`).
- The slot table is unified: slot address =
  `first-arg + 0x1088 + 8*slot-number` on both arms, with
  slot number `byte + 0x7e` (zero arm, range 126..381) or
  `2*index + (byte ^ 1)` (size arm, range 0..653, since
  `byte ^ 1` is the byte with its low bit flipped, i.e.
  `byte ± 1`, not a 0/1 pair selector). The two ranges
  overlap; whether the two arms address one table with
  shared semantics or two uses of one address range is not
  proven by these bytes, and is stated as arithmetic, not
  as a table-identity claim.
- The bitmap qword range at `first-arg+0x1488` numerically
  overlaps the slot-pointer range (bitmap qword `k` sits at
  the address of slot pointer `128 + k`), so how the bitmap
  set side avoids clobbering live slot pointers — or whether
  the two ranges are disjoint in practice — is not decoded
  here, and is carried as an unresolved item below.
- The bitmap at `first-arg+0x1488` is indexed by the same
  slot number on both arms; its set side and its readers
  are not decoded here.

## Evidence

- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d84e0..0x63d8622`, 322 bytes); `push %rbp` entry;
  `int3` padding `0x63d84d1..0x63d84e0` (15 bytes, after the
  previous FDE, which ends at `0x63d84d1`) and
  `0x63d8622..0x63d8630` (14 bytes, before #242's removal
  entry at `0x63d8630`). Static analysis only; the binary
  was never executed.
- 6 exhibits, 281 bytes, 73 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `tj_entry` | `0x63d84e0..0x63d84f5` | 21 | 8 | Entry, arg saves, `[block+0x68]` load, dispatch |
| `tj_zero` | `0x63d84f5..0x63d8512` | 29 | 6 | Zero arm: byte slot number, slot load, head test |
| `tj_unlink` | `0x63d8512..0x63d8552` | 64 | 18 | Unlink stores, self-link, slot-zero test, ret |
| `tj_size` | `0x63d8558..0x63d85cd` | 117 | 28 | Size call, overflow test, index, slot number |
| `tj_head` | `0x63d85d8..0x63d85ea` | 18 | 4 | Slot==block: self-link test, slot clear |
| `tj_bitmap` | `0x63d85ea..0x63d860a` | 32 | 9 | Bitmap bit clear, pops, ret |

- The overflow stub (`0x63d8610..0x63d8618`: `r10d = 0x18e`,
  jump into the slot-number computation) and the head-join
  block (`0x63d8618..0x63d8622`: slot `:= [block+0x40]`,
  jump into the unlink) are verified by the static
  verifier's key-byte checks, not exhibited, to keep the
  packet at 18 files. The `nopw` gaps (`0x63d8552..0x63d8558`,
  `0x63d85d2..0x63d85d8`, `0x63d860a..0x63d8610`) are
  padding, not claimed.
- Census: direct `E8` call sites to `0x63d84e0`: 0. Direct
  `E9` jump sites: 1 (`0x63d9017`, the #243 give-back tail
  jump, confirmed by rel32 — and the only branch from
  outside the FDE into it). Rip-relative `LEA` sites: 0
  (all `48`/`4c`/`49`/`4d 8d` forms). `.rela.dyn` addends
  equal to `0x63d84e0`: 0 of 60,723 entries. Internal calls
  within the FDE: 1 (`0x63e8bf0`). Internal jump targets:
  all lie inside `0x63d84e0..0x63d8622`. Two `ret` sites:
  `0x63d8551`, `0x63d8609`.
- Disjointness: this FDE overlaps no claimed range from
  packets #183–#243 (1400 exhibit ranges checked across
  the merged tree and the prior worktree records) and no
  other contributor's topic, addresses, or tables. The
  give-back function, the size mapper, the removal entry,
  the class remove, the entry probe, the handoff, the
  register, the gate, the driver, and the allocator thunk
  are cited by address, not claimed here.

## Corrections to earlier packets

- **#243 confirmed and completed.** Its tail-jump target is
  this FDE: the give-back's `[block+0x13]`-gated tail jump
  at `0x63d9017` lands here, and this function unlinks the
  block from its per-slot list — the post-removal step
  #243 left open.
- **#242 confirmed.** The removal entry's queue and size
  paths are not repeated here; this function runs after
  them, on the `+0x40`/`+0x48` list, not on the queue or
  the size-class chains.
- **#241 confirmed.** The class remove's chains are not
  touched here; this function only unlinks the per-slot
  list node.
- **#240 confirmed.** The probe's empty verdict is not
  re-tested here; the bitmap cleared here is a different
  bitmap (`first-arg+0x1488`, slot-numbered) from the
  class bitmap (`first-arg+0x400`, class-indexed).
- **#239 confirmed.** The class insert's chains are not
  touched here.
- **#238 confirmed.** The handoff's flag (`[block+0x12] :=
  1`) and queue are not touched here; the handoff's
  size-mapping scheme is repeated here for the slot index,
  but with a different size input and a different table.
- **#237 confirmed.** The register's size-class entries are
  not the slots updated here.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches this function on the zero
  arm, which books it by byte slot number.
- **#235 confirmed.** The gate's paths reach this function
  only indirectly, through the register, the handoff, the
  give-back, and the tail jump.
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff; post-removal runs
  through the give-back and this function, not the driver
  path.
- **#233 confirmed.** The loop caller is not involved with
  this function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the caller FDEs, the give-back,
  and the tail jump, never directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- What sets the per-slot bitmap bits at `first-arg+0x1488`,
  and who reads them: only the clear side is decoded here.
  In particular, the bitmap qword range numerically overlaps
  the slot-pointer range (bitmap qword `k` at the address of
  slot pointer `128 + k`); how the set side avoids
  clobbering live slot pointers, or whether the ranges are
  disjoint in practice, is unresolved.
- Whether the zero arm's `byte + 0x7e` slot numbers and the
  size arm's `2*index + (byte ^ 1)` slot numbers address
  one table with shared semantics, or two uses of one
  address range.
- Which of the `+0x40`/`+0x48` list's other members or
  writers exist beyond this unlink: no insert side is
  decoded here.
- What the three caller FDEs (`0x63b7900..0x63b7ee6`,
  `0x63b7ef0..0x63b8157`, `0x63b8820..0x63b8d85`) establish
  before calling the give-back function — the give-back's
  fan-in, still undecoded. This is #245's question.
- The domain meaning of the `[block+0x10]` byte beyond its
  slot-number role, and of the `+0xb0` field beyond its
  size-input role.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Verification

- `tools/node115_lu_postremove.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, FDE bounds, entry bytes, two `ret` sites, one
  call rel32, key bytes, jump targets internal, full census,
  neighbour disjointness, MANIFEST coverage (17 entries).
- `tests/test_node115_lu_postremove.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout (verified for #242; base unchanged
  since), so this is pre-existing upstream staleness from
  the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
