# RE-001: the node #115 lu block handoff — flag, queue, size-class tail

## Question

Packet #237's next question: what does `0x63d8790` do with the
(first-arg, block) pair it receives whenever `[block+0x11]` is
nonzero — which, for every consume-stamped block, is always — and
does it consume, queue, or further transform the counted block?

## Answer

`0x63d8790` (single FDE `0x63d8790..0x63d88c4`, 308 bytes, single
`ret` at `0x63d87f7`) **queues** the block. It first sets
`[block+0x12] := 1` on every path, then dispatches on
`[block+0x68]`:

- `0` → the block is inserted into the doubly-linked list anchored
  at `[first-arg+0x1080]` (via its `+0x28`/`+0x30` links), the
  anchor is updated to the block, and the function returns.
- `0x200` → return immediately after the flag store; the block is
  neither queued nor classified here.
- anything else → the block is size-classified (same index scheme
  as #237's main path, 16-byte entries at `first-arg + 16*index`),
  the class bitmap at `first-arg+0x400` is optionally marked, and
  control tail-jumps to `0x63b99d0(entry, block)` — it never
  returns to this function.

For a block exactly as #236 stamped it (`[block+0x68] == 0`), only
the first case runs: the block is counted by #237, flagged here,
queued into the `+0x1080` list, and returned to. It is not freed,
not unlinked, and not transformed into anything else here.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`). At #237's call
  site it is the register's first argument (cited only); at the
  second call site it is that caller's first argument (cited only).
- `rsi` = block pointer (saved in `rbx`): the gate's stamped block.
- No return value is established by these bytes on the queue and
  `0x200` paths (plain `ret` after pops); the size path never
  returns here at all (tail jump).

## Entry and dispatch

1. Pushes `r14, r13, r12, rbp, rbx`; `rbp := rdi`, `rbx := rsi`.
2. `[block+0x12] := 1` (byte, `movb $0x1,0x12(%rsi)`), immediately,
   on every path.
3. `rax = [block+0x68]`. If `0`, take the queue path (step 4). If
   nonzero, jump to `0x63d8800`: if `0x200`, return via the
   epilogue; otherwise take the size path (step 5).

## Queue path (the consume-stamped case)

4. `xmm0 := (block, block)` (`movq` + `punpcklqdq`), then
   `movups` writes it to `[block+0x28]`, so `[block+0x28] :=
   block` and `[block+0x30] := block` — a self-linked node.
   `r11 := [first-arg+0x1080]` (the list anchor).
   - If the anchor is `0`, the block stays self-linked and control
     jumps to step 4c.
   - Otherwise the block is spliced between the anchor node and
     its successor, in this exact order:
     - `rax := [r11+0x30]`
     - `[block+0x28] := rax`
     - `[r11+0x30] := block`
     - `rdx := [block+0x30]` (still the block itself)
     - `rdi := [rdx+0x28]` (i.e. `rax`)
     - `[block+0x30] := rdi` (i.e. `rax`)
     - `[block+0x28] := r11` (overwriting the earlier store)
     - `[rax+0x28] := block`
   - 4c. `[first-arg+0x1080] := block`; pops; `ret`.

   Net effect, stated exactly: the block ends up linked to the
   old anchor via `+0x28` and to the old anchor's former
   successor via `+0x30`, and the anchor now holds the block.
   Whether traversal starts at the anchor or the anchor is a
   most-recent pointer is not proven by these bytes — only the
   pointer writes are.

## Size path (blocks with nonzero, non-0x200 `[block+0x68]`)

5. `rdi = [block+0x60] << 12`; call `0x63e8bf0` (cited only — the
   same size-mapping helper #237 cited). If the result exceeds
   `0x7000000000000000`, take the overflow stub (step 6).
   Otherwise compute a size-class index:
   - `rdi = bsr(result)`; if the result is not a power of two,
     `rdi += 1` (via `cmp`/`sbb`); clamp to a minimum of 14.
   - shift = `clamped - 3`, except `12` when `clamped == 14`.
   - `index = ((result - 1) >> shift) & 3 + 4 * (clamped - 14)`.
   - entry = `first-arg + 16 * index`.
   Then call `0x63b9680(entry)` (cited only). If it returns
   nonzero, set one bitmap bit: bit `index mod 64` of qword
   `index / 64` at `first-arg+0x400`. Then pops and tail-jump
   `jmp 0x63b99d0(entry, block)` (cited only).

## Overflow stub

6. `r12 = 0xc70`, `r13 = 0xc7`, `r14 = 0xc7`, jump back into the
   entry computation: entry = `first-arg + 0xc700`
   (`0xc70 << 4`), bitmap index `199` (qword `3`, bit `7`, i.e.
   `[first-arg+0x418]`). The stub does not follow the
   `16 * index` formula — `0xc700` is a fixed entry, stated as
   bytes, not forced into the index scheme.

## What this means for a consume-stamped block

For a block exactly as #236 stamped it (`[block+0x10]` dword
`0x100`, `[block+0x60] = 0x200`, `[block+0x68] = 0`,
`[block+0xb0] = 0`, flag bytes `+0x14`/`+0x24` zero):

- `[block+0x68] == 0` selects the queue path; the `[block+0x60]`
  value is never read on this path.
- `[block+0x12]` goes from `0x00` (third byte of the `0x100`
  dword) to `1` — the next flag byte after the `0x01` at
  `+0x11` that gated this call.
- The block is linked into the `+0x1080` list and the anchor is
  updated to it; the function returns. No size classification,
  no bitmap write, no tail call happens for such a block.

So #237's question is answered: this function **queues** the
counted block. It does not consume (free) it, and it does not
transform its contents beyond the single flag byte.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d8790..0x63d88c4`); `int3` padding
  `0x63d88c4..0x63d88d0`. Static analysis only; the binary was
  never executed.
- 4 exhibits, 292 bytes, 82 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `hd_entry` | `0x63d8790..0x63d87f8` | 104 | 33 | Entry, flag `:= 1`, queue splice, anchor store, ret |
| `hd_size` | `0x63d8800..0x63d8879` | 121 | 30 | `0x200` test, size call, index, entry probe call |
| `hd_tail` | `0x63d8879..0x63d88a8` | 47 | 15 | Bitmap set, pops, tail jump |
| `hd_over` | `0x63d88b0..0x63d88c4` | 20 | 4 | Overflow stub |

- The `nopl` gaps (`0x63d87f8..0x63d8800`,
  `0x63d88a8..0x63d88b0`) are padding, not claimed.
- Census: direct `E8` call sites to `0x63d8790`: 2. Direct `E9` jump
  sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63d8790`: 0 of 60,723 entries.
  E8: `0x63d9232` (FDE `0x63d9070..0x63d9337`, unclaimed
  neighbour; its tail tests `[block+0x11]`, calls this function,
  then tests `[block+0x13]` and calls `0x63d88d0` — the same
  flag-test pattern as #237's tail, cited only),
  `0x63d966a` (block register FDE, #237; called when
  `[block+0x11] != 0`).
  Internal calls within the FDE: 2 (`0x63e8bf0`, `0x63b9680`).
  Internal jump targets: all lie inside
  `0x63d8790..0x63d88c4` except the tail jump to `0x63b99d0`.
  Single `ret` at `0x63d87f7`.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#237 (checked against the merged tree's 161 exhibit
  ranges and the #235/#236/#237 worktree records) and no other
  contributor's topic, addresses, or tables. The gate, the
  driver, the single-shot caller, the block register, the size
  helper, the entry probe, and the tail-call target are cited
  by address, not claimed here.

## Corrections to earlier packets

- **#237 confirmed and completed.** This FDE is the flag-gated
  handoff the register calls at `0x63d966a` whenever
  `[block+0x11]` is nonzero. Refined: a second caller exists at
  `0x63d9232` (FDE `0x63d9070..0x63d9337`), so the register is
  not the only caller.
- **#236 confirmed and completed.** A consume-stamped block
  takes this function's queue path; the gate's `+0xe0`/`+0xe8`
  bookkeeping stays gate-side, and this function only flags and
  queues the block.
- **#235 confirmed.** The gate's paths reach this function only
  indirectly, through the block register.
- **#234 confirmed.** The driver's gate-block path runs gate,
  then register, then this handoff whenever `[block+0x11]` is
  nonzero.
- **#233 confirmed.** The loop caller is not involved with this
  function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the block register.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- The identities and semantics of `0x63e8bf0` (size mapping),
  `0x63b9680` (entry probe: what a nonzero return means), and
  `0x63b99d0` (tail-call target receiving `(entry, block)`).
- What the `first-arg+0x400` bitmap counts in domain terms, and
  what the `+0x1080`-anchored list is drained by — no reader of
  the queued blocks is decoded here.
- Why a block with `[block+0x68] == 0x200` returns without
  queueing, and which writers produce such blocks.
- Whether the `+0x1080` anchor here is the same slot #230's
  class-64 fallback value named — same offset, but the objects
  are not proven identical.
- What the second caller FDE `0x63d9070..0x63d9337` is, and why
  it shares the register tail's flag-test pattern.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#239)

Decode `0x63b99d0` end to end: what it does with the
(size-class entry, block) pair it receives by tail jump from
this function, and whether it links, stores, or further
classifies the block — this decides what happens to
nonzero-`[block+0x68]` blocks after classification.

## Verification

- `tools/node115_lu_handoff.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, single `ret`, key stores and call rel32s, tail-jump
  target, full census, neighbour disjointness, MANIFEST coverage
  (13 entries).
- `tests/test_node115_lu_handoff.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7167 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
