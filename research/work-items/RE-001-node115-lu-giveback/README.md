# RE-001: the node #115 lu give-back — counters, removal gate, tail jump

## Summary

Packet #242's next question: what the caller FDE `0x63d8e70..0x63d906b`
does with the (first-arg, block) pair before and after calling the #242
removal entry, and what the `[block+0x13]`-gated tail jump to `0x63d84e0`
does — deciding who drives removal and what happens to a block after it
is removed.

It is a single FDE, `0x63d8e70..0x63d906b` (507 bytes, `endbr64` entry,
single `ret` at `0x63d8f98`, two internal calls, one external tail jump).
Before anything else it sets `[block+0x23] := 1` on every path, then
dispatches on `[block+0x68]` — and what it does first, on all three arms,
is **accounting, not removal**: it decrements a per-slot count by 1,
decrements a per-slot byte total by `[block+0x68]`, and adjusts a third
slot field by (`[block+0x68]` − `[block+0xb0]`), and it applies the same
three updates to a global triple at `first-arg+0x408`/`+0x410`/`+0x418`.
Only after the accounting does it test `[block+0x12]`: if set, it calls
the #242 removal entry (`0x63d8630`) with (first-arg, block); then it
tests `[block+0x13]`: if set, it pops and **tail-jumps to `0x63d84e0`**
with the same two arguments; otherwise it pops and returns. It frees
nothing itself and never writes a block key. So the answer to #242's
question is: this function is the give-back driver — it books the block
out of the counters, then hands the block to the removal entry when the
`+0x12` flag asks for it, and hands control to `0x63d84e0` when the
`+0x13` flag asks for it. The target of the tail jump is cited only;
its body is #244's question, not this packet's claim.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`, kept live across all
  paths; the size path overwrites `rdi` only as a call argument and the
  queue/zero path reads it as the table base).
- `rsi` = block pointer (saved in `rbx`): the block being given back.
- No return value is established by these bytes: every path returns
  through the pops epilogue with no value set in `rax`, and the tail
  path transfers control with the arguments still in `rdi`/`rsi`.
- Block fields, as used here: `+0x10` = byte whose negated low bits
  select a sub-slot (`(-byte) & 0x18`, i.e. 0/8/16/24); `+0x12` =
  removal-request flag (tested, never written here); `+0x13` =
  tail-request flag (tested, never written here); `+0x23` = byte set
  to 1 on entry on every path (never read here); `+0x60` = size input
  for the mapper; `+0x68` = the block's stamped value (dispatch key
  and byte total); `+0xb0` = subtrahend of the third field.

## Entry and dispatch

1. `endbr64`; pushes `rbp, rbx`; `rbp := rdi`, `rbx := rsi`;
   `sub $0x8, %rsp`.
2. `rax = [block+0x68]`; `[block+0x23] := 1` (byte), immediately,
   on every path, before the dispatch test.
3. If `rax == 0`, jump to `0x63d9020` (zero arm, step 5). If
   `rax == 0x200`, jump to `0x63d8fa0` (0x200 arm, step 6).
   Otherwise take the size arm (step 4).

## The accounting identity (all three arms)

Each arm updates a slot triple and the global triple by the same rule,
with `v = [block+0x68]` and `w = [block+0xb0]`:

- slot first qword `−= 1`; slot second qword `−= v`;
  slot `+0x10` field `+= (v − w)`.
- global `[first-arg+0x408] −= 1`; `[first-arg+0x410] −= v`;
  `[first-arg+0x418] += (v − w)`.

The arms differ only in which slot they address and, for `v == 0`,
in the vacuous `−= 0` updates, which the code simply omits:

- Size arm: slot = `first-arg + 0x420 + 48*index + ((-byte[block+0x10]) & 0x18)`,
  where `index` comes from the size mapping below; the pair update is
  done with the `paddq`/`psubq`/`movsd` shuffle (see exhibit `gb_slot`).
- 0x200 arm: slot = `first-arg + 0x1020 + ((-byte[block+0x10]) & 0x18)`,
  pair updated by adding the `.rodata` constant `(−1, −512)` — i.e.
  `−= 1` and `−= 0x200`, exactly the identity with `v = 0x200`.
- Zero arm: slot = `first-arg + 0x1050 + ((-byte[block+0x10]) & 0x18)`;
  only `[slot] −= 1`, `[slot+0x10] −= w`, `[first-arg+0x408] −= 1`,
  `[first-arg+0x418] −= w` — the `−= v` updates are omitted because
  `v == 0`. Note `0x1050 − 0x1020 = 0x30 = 48`, one slot stride past
  the 0x200 arm's base; stated as arithmetic, not as proof that the
  two bases belong to one table.

## Size arm (nonzero, non-`0x200` `[block+0x68]`)

4. `rdi = [block+0x60] << 12`; call `0x63e8bf0` (cited only — the
   same size-mapping helper #237/#238/#242 cited). If the result
   exceeds `0x7000000000000000`, take the overflow stub (`r10d =
   0x2970`, jump back into the slot computation: `0x2970 − 0x420 =
   48*199`, index 199 — verified by key bytes, not exhibited, same
   convention as #237/#238/#242). Otherwise compute the index by the
   identical scheme as #242: `bsr`, `+1` unless a power of two (via
   `cmp`/`sbb`), clamped to a minimum of 14, shift = `clamped − 3`
   except `12` when `clamped == 14`, index =
   `((result − 1) >> shift) & 3 + 4 * (clamped − 14)`.
5. Slot address and pair update as in the identity above; then the
   global triple; then fall into the tail (step 7).

## Zero arm and 0x200 arm

6. Zero arm (`0x63d9020`): slot at `+0x1050`, updates as in the
   identity with `v == 0`, then `jmp 0x63d8f7f` — straight into the
   tail's `[block+0x12]` test, with `[first-arg+0x418]` stored on the
   way in. No size computation, no removal call on this arm itself.
   0x200 arm (`0x63d8fa0`): slot at `+0x1020`, constant-vector pair
   update, global triple, `[first-arg+0x418]` stored, then `je
   0x63d8f8c` if `[block+0x12] == 0` (skip the removal call) or fall
   through to the removal call otherwise. Both arms rejoin the tail;
   neither arm frees anything.

## The tail: removal gate, then tail gate

7. `cmpb $0, 0x12(%rbx)`; `[first-arg+0x418] := rax` (the adjusted
   third global field — stored on every path that reaches here).
   If `[block+0x12] != 0`: call the #242 removal entry
   (`0x63d8630`, site `0x63d9000`, cited only) with
   `(first-arg, block)` — the entry that clears `[block+0x12]` and
   unlinks or class-removes the block. If `[block+0x12] == 0`, the
   call is skipped entirely.
8. `cmpb $0, 0x13(%rbx)`: if nonzero, pops and tail-jumps to
   `0x63d84e0` (FDE `0x63d84e0..0x63d8622`, cited only) with
   `(first-arg, block)` still in `rdi`/`rsi` — i.e. control leaves
   this function as if returning into `0x63d84e0`. If zero, pops
   and `ret` at `0x63d8f98`. The tail jump is the only exit besides
   the single `ret`. Note the asymmetry, stated rather than smoothed
   over: the removal call is gated on `+0x12`, the tail jump on
   `+0x13`, and the two flags are independent — a block can take
   either, both (removal then tail), or neither.

## What this decides

- The removal driver question is answered: this FDE drives removal
  through #242, but only when `[block+0x12]` is set — and the
  accounting runs unconditionally first, on every path, even when
  removal is skipped.
- The post-removal question is answered in form but not in content:
  after (possible) removal, a `[block+0x13]`-set block is handed to
  `0x63d84e0` by tail jump; what `0x63d84e0` does with it is not
  decoded here.
- The `+0x23 := 1` store on entry is observed on every path and read
  nowhere here; its reader is not decoded here.
- A correction to #242's framing: #242 said this FDE is "the removal
  entry's caller" — true, it is the removal entry's only caller
  (site `0x63d9000`) — but this FDE is itself called from 8 sites
  in 3 neighbouring FDEs (see census), so removal is driven from
  several places through this one give-back function, not from one.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d8e70..0x63d906b`, 507 bytes); `endbr64` entry;
  `int3` padding `0x63d8e67..0x63d8e70` (9 bytes, after the previous
  FDE, which ends at `0x63d8e67`) and `0x63d906b..0x63d9070`
  (5 bytes, before the next FDE at `0x63d9070`). Static analysis
  only; the binary was never executed.
- 6 exhibits, 387 bytes, 93 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `gb_entry` | `0x63d8e70..0x63d8e9d` | 45 | 12 | Entry, arg saves, `[block+0x68]` load, `[block+0x23] := 1`, dispatch |
| `gb_size` | `0x63d8e9d..0x63d8f05` | 104 | 25 | Size call, overflow test, index, `48*index + 0x420` |
| `gb_slot` | `0x63d8f05..0x63d8f55` | 80 | 18 | Slot pair update, slot `+0x10` adjust |
| `gb_tail` | `0x63d8f55..0x63d8f99` | 68 | 16 | Global pair, `[block+0x12]` test, `+0x418` store, `[block+0x13]` test, ret |
| `gb_call` | `0x63d8ffa..0x63d901c` | 34 | 11 | Removal call, `[block+0x13]` test, pops, tail jump |
| `gb_zero` | `0x63d9020..0x63d9058` | 56 | 11 | Zero arm: `+0x1050` slot, global low decrement, jmp to tail |

- The 0x200 arm (`0x63d8fa0..0x63d8ff8`) and the overflow stub
  (`0x63d9060..0x63d906b`) are verified by the static verifier's
  key-byte checks, not exhibited, to keep the packet at 18 files.
  The `nopl` gaps (`0x63d8f99..0x63d8fa0`, `0x63d901c..0x63d9020`,
  `0x63d9058..0x63d9060`) are padding, not claimed.
- Census: direct `E8` call sites to `0x63d8e70`: 8, all
  objdump-confirmed — `0x63b7af7`, `0x63b7c30`, `0x63b7cef`,
  `0x63b7d8b`, `0x63b7e0a` (FDE `0x63b7900..0x63b7ee6`),
  `0x63b808e`, `0x63b8296` (FDE `0x63b7ef0..0x63b8157`),
  `0x63b892f` (FDE `0x63b8820..0x63b8d85`). Direct `E9` jump
  sites: 0. Rip-relative `LEA` sites: 0. `.rela.dyn` addends
  equal to `0x63d8e70`: 0 of 60,723 entries. Internal calls
  within the FDE: 2 (`0x63e8bf0`, `0x63d8630`). Internal jump
  targets: all lie inside `0x63d8e70..0x63d906b` except the
  stated tail jump to `0x63d84e0`. Single `ret` at `0x63d8f98`.
- Disjointness: this FDE overlaps no claimed exhibit or FDE range
  from packets #183–#242 (275 unique exhibit/FDE ranges checked
  across the merged tree and the #235–#242 worktree records, 0
  overlaps) and no other contributor's topic, addresses, or
  tables. The size mapper, the removal entry, the tail target,
  the caller FDEs, the handoff, the register, the gate, the
  driver, and the allocator thunk are cited by address, not
  claimed here.

## Corrections to earlier packets

- **#242 confirmed and reframed.** Its removal entry is called
  from exactly one site, `0x63d9000` here, as #242 said — but
  #242's "removal entry's caller" framing understated the fan-in:
  this give-back FDE is itself called from 8 sites in 3 FDEs, so
  the removal path has several drivers, all funnelled through
  this function.
- **#241 confirmed.** The class remove is reached from here only
  indirectly, through the #242 removal entry, never directly.
- **#240 confirmed.** The probe's empty verdict is not re-tested
  here; this function tests the `+0x12`/`+0x13` flags instead.
- **#239 confirmed.** The class insert's chains are not touched
  here; this function only books counters and gates removal.
- **#238 confirmed and completed.** The handoff's flag
  (`[block+0x12] := 1`) is the flag tested here before the
  removal call, and the handoff's size-class entry computation
  scheme is repeated here for the slot index — but with a
  48-byte stride and a `+0x420` base, a different table from the
  handoff's 16-byte entries.
- **#237 confirmed.** The register's size-class entries are not
  the slots updated here; the slots here are a separate
  counter table.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches this function on the zero arm,
  which books it at the `+0x1050` slot — consistent with the
  handoff having queued it.
- **#235 confirmed.** The gate's paths reach this function only
  indirectly, through the register, the handoff, and the caller
  FDEs.
- **#234 confirmed.** The driver's gate-block path runs gate,
  then register, then handoff; give-back runs through this
  function, not the driver path.
- **#233 confirmed.** The loop caller is not involved with
  this function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the caller FDEs, never directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- What the tail-jump target FDE `0x63d84e0..0x63d8622` does with
  the (first-arg, block) pair — what happens to a block after
  removal. This is #244's question.
- What the 8 call sites' caller FDEs (`0x63b7900..0x63b7ee6`,
  `0x63b7ef0..0x63b8157`, `0x63b8820..0x63b8d85`) do before and
  after calling this function, and which flag (`+0x12`/`+0x13`)
  states they establish.
- Which writers set `[block+0x68] == 0x200` blocks, and why such
  blocks book at the fixed `+0x1020` slot rather than a computed
  index.
- The domain meaning of the slot triple and the global triple
  beyond the decrement pattern: the first qword behaves like a
  count, the second like a byte total, the `+0x10` field like a
  remainder — but those names are inference, not bytes.
- Who reads `[block+0x23]` after this function sets it to 1.
- Whether the `+0x1020`/`+0x1050` bases belong to the same table
  as the `+0x420` size table (the 48-byte stride arithmetic is
  suggestive, not proof).
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#244)

Decode the tail-jump target FDE `0x63d84e0..0x63d8622` end to
end: what it does with the (first-arg, block) pair it receives
by tail jump from this give-back function — deciding what
happens to a block after removal — and, if it is small, what
the three caller FDEs establish before calling this function.

## Verification

- `tools/node115_lu_giveback.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, FDE bounds, single `ret`, two call rel32s, key stores
  and dispatch bytes, 0x200 constant and slot bases, jump
  targets internal except the stated tail jump, full census,
  neighbour disjointness, MANIFEST coverage (17 entries).
- `tests/test_node115_lu_giveback.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.

## Files (18)

- `research/work-items/RE-001-node115-lu-giveback/README.md`
- `research/work-items/RE-001-node115-lu-giveback/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-giveback/records.json`
- `research/work-items/RE-001-node115-lu-giveback/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-giveback/gb_entry.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback/gb_size.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_size.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback/gb_slot.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_slot.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback/gb_tail.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_tail.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback/gb_call.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_call.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback/gb_zero.hex`
- `research/work-items/RE-001-node115-lu-giveback/gb_zero.objdump.txt`
- `tools/node115_lu_giveback.py`
- `tests/test_node115_lu_giveback.py`
