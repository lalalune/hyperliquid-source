# RE-001: the node #115 lu class insert — key, count, spine rotation

## Question

Packet #238's next question: what does `0x63b99d0` do with the
(size-class entry, block) pair it receives by tail jump from the
block handoff, and whether it links, stores, or further
classifies the block — this decides what happens to
nonzero-`[block+0x68]` blocks after classification.

## Answer

`0x63b99d0` (single FDE `0x63b99d0..0x63b9d0c`, 828 bytes,
`endbr64` entry, two `ret` sites at `0x63b9a4c` and `0x63b9cd7`,
zero `call` instructions, zero tail jumps of its own) **inserts**
the block into the entry's chain and then runs a **bounded
rotation pass** along that chain. It does not classify anything
further: the entry arrives pre-classified from the handoff's size
path, and this function never calls the size mapper, the allocator,
or any other helper.

In short:

- The block's `+0x28`/`+0x30`/`+0x38` links are zeroed first.
- If the entry's head is null, the block becomes the head and the
  function returns, leaving the count word untouched.
- Otherwise the block's key (`[block+8]`, the consume-stamped
  counter from #236) is compared against the head's key:
  - block key **smaller** than head key → the block displaces the
    head: `[block+0x38] := head`, `[head+0x28] := block`,
    `[entry] := block`, `[entry+8] := 0`, return.
  - block key **greater or equal** → the block is inserted right
    after the head in the `+0x28`/`+0x30` chain, `[entry+8] += 1`,
    and — only if the new count exceeds 1 — a rotation pass runs.
- The pass performs exactly `tzcnt(count before this insert)`
  adjacent-pair steps (or fewer, if the chain ends first). Each
  step compares one adjacent pair on the `+0x30` chain and rotates
  it so the larger-key node stays on the spine and the smaller
  becomes its `+0x38` child.

## Entry contract

- `rdi` = 16-byte size-class entry: `[entry]` = head pointer,
  `[entry+8]` = count word. These are exactly the entries #238's
  size path computes (`first-arg + 16*index`) and probes with
  `0x63b9680` before tail-jumping here.
- `rsi` = block pointer: the gate's stamped block (via #237's
  register and #238's handoff).
- No return value is established by these bytes: on the empty-head
  path `rax` is zeroed, on the other paths it ends as the last
  walk node, and no caller is shown to read it (the only caller
  reaches this function by tail jump).

## Block links, as used here

Three pointer fields per node, all zeroed on entry:

- `+0x28` = back link (parent / predecessor: the node written
  here is the head during the pass, and the previous node after
  a swap).
- `+0x30` = forward link (the chain the pass walks: head's
  `+0x30` always tracks the current walk node).
- `+0x38` = side link (the smaller node of a rotated pair is
  tucked here under the winner).

The block's other stamped fields are never read here:
`[block+0x00]` (cursor), `[block+0x10]` (the `0x100` dword),
`[block+0x60]`/`[block+0x68]` (size-class fields), and the
`+0x50`/`+0x58` list links from #237's register tail are all
untouched by this FDE.

## Empty head

If `[entry] == 0`:

- `[entry] := block`, and the function returns through the shared
  epilogue. The count word is **not** incremented on this path —
  one of the reasons it is not a plain element count (see
  Unresolved).

## Key comparison and dispatch

With head non-null, `edx` is set to the sign of
`[block+8] - [head+8]` (`-1`, `0`, `+1` via `setb`/`sbb`):

- `edx == -1` (block key smaller) → the min-displacement path
  (`tl_min` exhibit): `[block+0x38] := head`,
  `[head+0x28] := block`, `[entry] := block`,
  `[entry+8] := 0`, return. The old head is not unlinked or
  freed; it hangs off the new head's `+0x38`.
- `edx >= 0` (block key greater or equal) → the insert path
  (`tl_insert` exhibit):
  - `[block+0x28] := head`
  - `[block+0x30] := [head+0x30]` (the old successor)
  - `[head+0x30] := block`
  - if the old successor exists, `[old-successor+0x28] := block`
  - `[entry+8] += 1`
  - if the new count is `<= 1`, return; otherwise enter the
    rotation pass.

Equal keys therefore insert after the head; only strictly smaller
keys displace it.

## The rotation pass

Setup (`tl_loop` exhibit): `rbp := count - 1`
(the count before this insert), `r11 := tzcnt(rbp)`,
`ebx := r11` (the step budget). If the budget is `0` (count
before was odd — including `1`, the second insert) the function
returns immediately. The walk starts at the newly inserted block
(`rax := block`), with `r8 := head+0x28` and `rsi := head`.

Each step, with `cur` = walk node and `next := [cur+0x30]`:

1. Both nodes' `+0x28`/`+0x30` are cleared first.
2. Their keys are compared (`[cur+8]` vs `[next+8]`).
3. One of two mirror-image rewires runs (the `tl_step` exhibit
   shows the non-swap form; the swap forms at `0x63b9c30`,
   `0x63b9c90`, `0x63b9ce0` mirror it):
   - **Non-swap** (`next_key >= cur_key`, a left rotation):
     `[cur+0x28] := next`, `[cur+0x30] := [next+0x38]`,
     `[next+0x38] := cur`, `[next+0x30] := next-next`,
     `[next+0x28] := head`, `[head+0x30] := next`,
     and if next-next exists, `[next-next+0x28] := next`.
     The walk node becomes `next`.
   - **Swap** (`next_key < cur_key`, a right rotation):
     `[next+0x28] := cur`, `[next+0x30] := [cur+0x38]`,
     `[cur+0x38] := next`, `[cur+0x30] := next-next`,
     `[cur+0x28] := head`, `[head+0x30] := cur`,
     and if next-next exists, `[next-next+0x28] := cur`.
     The walk node stays `cur`.
4. The step count increments; the pass ends when it reaches the
   budget, or earlier if the chain ends (`next == 0` at a step
   boundary, or the walk node itself is null).

Net local effect of every step, stated exactly: the **larger-key**
node of the pair remains on the `+0x30` spine (linked from
`head+0x30`, pointing back to the head via `+0x28`), the
**smaller-key** node becomes the winner's `+0x38` child, and the
walk advances to the winner's `+0x30` (the next spine node).
The loop body is unrolled by two — an odd budget runs one
single-step prologue then two-step iterations, an even budget
runs two-step iterations directly — but the observable step
total is exactly the budget.

What the pass does **not** establish is stated under Unresolved:
`tzcnt(count)` steps cannot reorder an arbitrarily long spine,
so no claim is made that the chain ends up sorted or heap-ordered
as a whole.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b99d0..0x63b9d0c`); `int3` padding
  `0x63b99c8..0x63b99d0` (after the #231 consumer FDE, which ends
  at `0x63b99c8`) and `0x63b9d0c..0x63b9d10` (before the next
  function, which starts with `endbr64` at `0x63b9d10`). Static
  analysis only; the binary was never executed.
- 6 exhibits, 313 bytes, 88 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `tl_entry` | `0x63b99d0..0x63b99f5` | 37 | 11 | Entry, block link zeroing, head load, empty test |
| `tl_cmp` | `0x63b99f5..0x63b9a1e` | 41 | 11 | Key compare, sign dispatch |
| `tl_insert` | `0x63b9a1e..0x63b9a4d` | 47 | 16 | Count bump, insert after head, shared epilogue ret |
| `tl_min` | `0x63b9cc0..0x63b9cd8` | 24 | 8 | Min displacement, count reset, ret |
| `tl_loop` | `0x63b9a50..0x63b9a7a` | 42 | 12 | Count-1, tzcnt budget, odd/even select |
| `tl_step` | `0x63b9b10..0x63b9b8a` | 122 | 30 | Even-path step: compare, relink, advance |

- The swap forms (`0x63b9c30`, `0x63b9c90`, `0x63b9ce0`) and the
  second step of each two-step iteration are verified by the
  static verifier's whole-FDE jump-target check (every direct
  jump in the FDE lands inside it), not exhibited, to keep the
  packet at 18 files.
- Census: direct `E8` call sites to `0x63b99d0`: 0. Direct `E9`
  jump sites: 1 (`0x63d88a3`, the handoff's size-path tail jump,
  #238; confirmed by rel32). Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63b99d0`: 0 of 60,723 entries.
  Internal calls within the FDE: 0. Internal jump targets: all
  lie inside `0x63b99d0..0x63b9d0c`. Two `ret` sites:
  `0x63b9a4c` (shared epilogue) and `0x63b9cd7` (min-path
  epilogue).
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#238 (824 exhibit ranges checked across the merged tree
  and the #235–#238 worktree records) and no other contributor's
  topic, addresses, or tables. The handoff, the register, the
  gate, the driver, the allocator thunk, and the entry probe are
  cited by address, not claimed here.

## Corrections to earlier packets

- **#238 confirmed and completed.** This FDE is the tail-jump
  target of the handoff's size path (site `0x63d88a3`), and it
  is the function's **only** caller: no direct `E8` caller
  exists, so the handoff is the sole entry into this function.
- **#237 confirmed and completed.** The register's size-class
  entries are 16 bytes (head pointer + count word) and are
  exactly the entry this function receives; the register never
  calls this function directly.
- **#236 confirmed and completed.** A consume-stamped block
  (`[block+0x68] == 0`) never reaches this function — the
  handoff queues it instead. This function handles only
  nonzero-`[block+0x68]` blocks.
- **#235 confirmed.** The gate's paths reach this function only
  indirectly, through the register and the handoff.
- **#234 confirmed.** The driver's gate-block path runs gate,
  then register, then handoff, then this function for
  size-classified blocks.
- **#233 confirmed.** The loop caller is not involved with this
  function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the register and the handoff, never
  directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- The global invariant of the rotation pass: each step keeps the
  larger key on the spine, but `tzcnt(count)` steps cannot
  reorder an arbitrarily long spine, so whether the chain as a
  whole ends up sorted, heap-ordered, or under some other
  invariant is **not** proven by these bytes — no such claim is
  made here.
- The domain meaning of the `[entry+8]` count word: it is
  incremented on insert-after-head, reset to `0` on
  min-displacement, and left untouched on empty-head insert, so
  it is not a plain element count. What it counts (inserts since
  the last minimum displacement is the closest reading, but it
  is not proven) is unresolved.
- The meaning of the `+0x38` side link in domain terms (left
  child of a tree node vs. pair/overflow link): only the pointer
  writes are proven.
- Who drains these per-size-class entry chains, and what reads
  `[entry]` after this function returns — no reader is decoded
  here.
- The identity and semantics of `0x63b9680` (the entry probe
  #238's size path calls before tail-jumping here): what it
  checks in the entry, and what a nonzero return means beyond
  gating the bitmap bit in #238.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#240)

Decode `0x63b9680` end to end: what it checks in the size-class
entry it receives from the handoff's size path, what a nonzero
return means (it gates the bitmap bit at `first-arg+0x400` in
#238), and whether it reads the chains this function builds —
this decides what the entry probe validates before a block is
inserted here.

## Verification

- `tools/node115_lu_classinsert.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, two `ret` sites, zero calls, key stores, jump
  targets internal, tail-jump source, full census, neighbour
  disjointness, MANIFEST coverage (17 entries).
- `tests/test_node115_lu_classinsert.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
