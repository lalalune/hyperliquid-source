# RE-001: the node #115 lu removal entry — queue unlink, size dispatch, probe tail

Packet #241's next question: what the neighbour caller FDE
`0x63d8630..0x63d8790` does with the (first-arg, block) pair it
receives — its `+0x1080` queue unlink, its size-class dispatch,
and its probe-then-bitmap-clear tail — and whether it is the
removal entry point for both queued and size-classified blocks.

## Answer in one paragraph

Yes. It is a single FDE, `0x63d8630..0x63d8790` (352 bytes,
push entry, three `ret` sites at `0x63d8690`, `0x63d8745`, and
`0x63d876c`, three internal calls). It clears `[block+0x12]`
on entry — undoing the flag #238's handoff set — then dispatches
on `[block+0x68]`: `0` unlinks the block from the doubly-linked
queue anchored at `[first-arg+0x1080]` and returns; `0x200`
returns immediately; any other value computes the size-class
entry by the same scheme as #238, calls the #241 class remove
with `(entry, block)`, probes the entry with the #240 probe, and
clears the class bitmap bit at `first-arg+0x400` exactly when
the probe reports the entry empty. It frees nothing itself and
never writes a block key. Its only caller is the FDE
`0x63d8e70..0x63d906b` (site `0x63d9000`, cited only).

## Target and bounds

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032
  bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d8630..0x63d8790`, 352 bytes); push entry (`push
  %r14`, no `endbr64` — the #238 caution, confirmed against
  `.eh_frame` rather than assumed); `int3` padding
  `0x63d8622..0x63d8630` (14 bytes, after the previous FDE,
  which ends at `0x63d8622`) and none after (the next FDE,
  #238's handoff, starts at `0x63d8790`). Static analysis only;
  the binary was never executed.
- Three `ret` sites: `0x63d8690` (shared queue/`0x200`/probe-
  nonzero epilogue), `0x63d8745` (size-path epilogue after the
  bitmap clear), `0x63d876c` (anchor-emptied epilogue). Three
  internal calls: `0x63e8bf0` (size mapper), `0x63b9d10`
  (class remove), `0x63b9680` (entry probe). Every direct jump
  target lies inside the FDE (verified by the static
  verifier's whole-FDE scan).

## Entry contract

- `rdi` = first-argument object (saved in `rbp` on the size
  path; overwritten by the successor on the queue path, where
  it is no longer needed). At the single call site it is the
  caller's first argument (cited only).
- `rsi` = block pointer (saved in `rbx`): the gate's stamped
  block, via the register and the handoff for size-classified
  blocks, or a queued block for the queue path.
- No return value is established by these bytes: every path
  returns through a pops epilogue with no value set in `rax`,
  and the single caller does not read a return (it tests
  `[block+0x13]` afterwards instead, cited only).

## Entry and dispatch

1. Pushes `r14, r13, r12, rbp, rbx`; `rbp := rdi`,
   `rbx := rsi`.
2. `[block+0x12] := 0` (byte), immediately, on every path.
   This is the flag #238's handoff set to `1`; the removal
   entry clears it before doing anything else.
3. `rax = [block+0x68]`. If `0`, take the queue path (step 4).
   If nonzero, jump to `0x63d8698`: if `0x200`, return via
   the shared epilogue (nothing else happens for such a
   block); otherwise take the size path (step 5).

## Queue path (`[block+0x68] == 0`)

4. `cmp [first-arg+0x1080], block`:
   - If the anchor equals the block, jump to `0x63d8750`:
     `r11 := [block+0x28]`; if `r11 == block` (the block is
     self-linked, i.e. the queue's only node), then
     `[first-arg+0x1080] := 0` — the queue is emptied — and
     return. Otherwise `[first-arg+0x1080] := r11` (the
     anchor moves to the block's `+0x28` neighbour) and
     control jumps back to the splice at `0x63d8658`.
   - Otherwise (anchor differs) fall through to the splice.
   The splice, with `P := [block+0x28]` and
   `S := [block+0x30]`, performs exactly these stores in
   order: `[S+0x28] := [P+0x30]`; `[P+0x30] := S`;
   `[block+0x30] := [P+0x30]` (old value);
   `[S+0x28] := P`; `[old[P+0x30]+0x28] := block`.
   Read against the neighbour invariant — `P`'s successor
   is the block and `S`'s predecessor is the block, which
   #238's insert establishes for queue members — the old
   `[P+0x30]` is the block itself, so the net effect is
   exactly: unlink the block (`[P+0x30] := S`,
   `[S+0x28] := P`) and leave the block self-linked
   (`[block+0x28] := block`, `[block+0x30] := block`).
   Then pops and `ret`. No probe call, no bitmap write,
   no size computation happens on this path.
   One observation, stated rather than smoothed over: the
   FDE performs no membership test. When `[block+0x68]`
   is `0` it unlinks unconditionally, so correctness
   depends on the caller passing a block that is actually
   in the queue.

## Size path (nonzero, non-`0x200` `[block+0x68]`)

5. `rdi = [block+0x60] << 12`; call `0x63e8bf0` (cited only
   — the same size-mapping helper #237/#238 cited). If the
   result exceeds `0x7000000000000000`, take the overflow
   stub (`r12 = 0xc70`, `r13 = 0xc7`, `r14 = 0xc7`, jump
   back into the entry computation: entry =
   `first-arg + 0xc700`, bitmap index `199` — verified by
   rel32, not exhibited, same convention as #237/#238).
   Otherwise compute the size-class index by the identical
   scheme as #238: `bsr`, `+1` unless a power of two (via
   `cmp`/`sbb`), clamped to a minimum of 14, shift =
   `clamped - 3` except `12` when `clamped == 14`, index =
   `((result - 1) >> shift) & 3 + 4 * (clamped - 14)`,
   entry = `first-arg + 16 * index`.
6. Call `0x63b9d10(entry, block)` — the #241 class remove
   (cited only). Then call `0x63b9680(entry)` — the #240
   entry probe (cited only) — and test `%al`: on `0`
   (nonempty) return via the shared epilogue; on nonzero
   (empty) clear one bitmap bit, bit `index mod 64` of
   qword `index / 64` at `first-arg+0x400` (via `rol` of
   the `~1` mask), then pops and `ret`.

## What this decides

- The removal entry point question is answered yes for both
  populations: queued blocks (`[block+0x68] == 0`) are
  unlinked from the `+0x1080` queue here, and
  size-classified blocks (nonzero, non-`0x200`
  `[block+0x68]`) are removed from their size-class entry
  here via #241, with the bitmap cleared exactly when the
  entry becomes empty.
- The `0x200` case is the exception that proves the
  dispatch: such a block gets only the `[block+0x12]`
  clear and returns — it is neither queue-unlinked nor
  class-removed here.
- The bitmap mirror image from #240 is now complete on
  both sides: #238's handoff sets the bit when it finds
  an empty class it is about to fill; this function
  clears the bit when it finds an empty class after a
  removal.

## Evidence

- 6 exhibits, 300 bytes, 87 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab +
  mnemonic; objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `re_entry` | `0x63d8630..0x63d8658` | 40 | 13 | Entry, arg saves, `[block+0x68]` load, flag `:= 0`, dispatch |
| `re_queue` | `0x63d8658..0x63d8691` | 57 | 18 | Queue unlink splice, pops, shared epilogue ret |
| `re_anchor` | `0x63d8750..0x63d876d` | 29 | 10 | Anchor==block: self-link test, anchor `:= 0`, ret |
| `re_200` | `0x63d8698..0x63d86a0` | 8 | 2 | `0x200` dispatch, early return |
| `re_size` | `0x63d86a0..0x63d8709` | 105 | 26 | Size call, overflow test, index, entry computation |
| `re_tail` | `0x63d8709..0x63d8746` | 61 | 18 | Remove call, probe call, `%al` test, bitmap clear, ret |

- The anchor-update block (`0x63d8784..0x63d8790`: anchor
  `:= [block+0x28]`, jump back to the splice) and the
  overflow stub (`0x63d8770..0x63d8784`) are verified by
  the static verifier's key-byte checks, not exhibited,
  to keep the packet at 18 files.
- The `nopl` gaps (`0x63d8691..0x63d8698`,
  `0x63d8746..0x63d8750`, `0x63d876d..0x63d8770`) are
  padding, not claimed.
- Census: direct `E8` call sites to `0x63d8630`: 1.
  Direct `E9` jump sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63d8630`: 0 of 60,723
  entries. E8: `0x63d9000` (FDE `0x63d8e70..0x63d906b`,
  unclaimed neighbour; args `(rbp, rbx)`, then tests
  `[block+0x13]` and tail-jumps to `0x63d84e0` on nonzero
  — cited only). Internal calls within the FDE: 3
  (`0x63e8bf0`, `0x63b9d10`, `0x63b9680`). Internal jump
  targets: all lie inside `0x63d8630..0x63d8790`. Three
  `ret` sites: `0x63d8690`, `0x63d8745`, `0x63d876c`.
- Disjointness: this FDE overlaps no claimed range from
  packets #183–#241 (912 exhibit ranges checked across
  the merged tree and the #235–#241 worktree records) and
  no other contributor's topic, addresses, or tables. The
  caller FDE, the size mapper, the class remove, the
  entry probe, the handoff, the register, the gate, the
  driver, and the allocator thunk are cited by address,
  not claimed here.

## Corrections to earlier packets

- **#241 confirmed and completed.** Its neighbour caller is
  this FDE: this FDE calls #241's remove at `0x63d870f`
  and probes at `0x63d8717`, exactly the sequence #241
  cited for its caller. This FDE's own caller is the
  `0x63d8e70..0x63d906b` FDE (site `0x63d9000`, cited
  only).
- **#240 confirmed and completed.** The probe-then-clear
  tail is this FDE's size path: remove, probe, clear on
  empty, with the `~1` mask rotation at `0x63d8732`.
- **#239 confirmed.** The class insert's chains are the
  chains removed from here on the size path; the insert
  itself is never called here.
- **#238 confirmed and completed.** The handoff's flag
  (`[block+0x12] := 1`) is cleared here on entry, and the
  handoff's size-class entry computation is repeated here
  verbatim for removal.
- **#237 confirmed.** The register's size-class entries are
  the entries removed from here; the register never calls
  this function directly.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches this function only via the
  queue path — the handoff queues it, and this function
  unlinks it.
- **#235 confirmed.** The gate's paths reach this function
  only indirectly, through the register, the handoff, and
  this removal entry's caller.
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff; removal runs through
  this function, not the driver path.
- **#233 confirmed.** The loop caller is not involved with
  this function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the register, the handoff, and
  this removal entry's caller, never directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- What the caller FDE `0x63d8e70..0x63d906b` does with the
  (first-arg, block) pair before and after calling this
  function, and what the `[block+0x13]`-gated tail jump to
  `0x63d84e0` does. This is #243's question.
- Which writers produce `[block+0x68] == 0x200` blocks,
  and why such blocks return from this function with only
  the flag cleared.
- Whether the `+0x1080` queue anchor here is the same slot
  #230's class-64 fallback value named — same offset, but
  the objects are not proven identical (same reservation
  as #238).
- The domain meaning of the `first-arg+0x400` bitmap bit
  beyond the set-on-empty-before-insert / clear-on-empty-
  after-removal pattern: the nonemptiness reading is
  inference, not bytes.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Next question (#243)

Decode the caller FDE `0x63d8e70..0x63d906b` end to end:
what it does with the (first-arg, block) pair before and
after calling this removal entry, and what the
`[block+0x13]`-gated tail jump to `0x63d84e0` does — this
decides who drives removal and what happens to a block
after it is removed.
