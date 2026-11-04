# RE-001-node115-lu-reregister: the node #115 lu re-register

Packet #246. Target: node #115, `artifacts/node/115/hl-node`,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
upstream main `05bc2de30` (confirmed before analysis).

## Question

Packet #245's next question: what the post-call callee FDE
`0x63d9070..0x63d9337` does with the (first-arg, block) pair it
receives from the #245 give-back drivers after they set
`[block+0x13]` — whether it reads `+0x13`, what it establishes
in return, and how it relates to the #237 register — deciding
where the flag written by the drivers is consumed.

## Answer

It is the re-register function: the exact inverse of the #243
give-back on the counters, plus a list-membership reconciler
over the #237 register's list. It clears `[block+0x23]` on
entry (undoing give-back's `+0x23 := 1`), adds the block back
into the slot triple and the global triple on all three
`[block+0x68]` arms (size, `0x200`, zero — same slot bases
`+0x420`/`+0x1020`/`+0x1050` as give-back, same index scheme,
opposite sign), and then runs a three-gate tail:

- `[block+0x11] != 0` → call the #238 handoff (`0x63d8790`)
  with (first-arg, block).
- `[block+0x13] != 0` → call `0x63d88d0` with (first-arg,
  block). **Yes, it reads `+0x13`** — the flag the #245
  drivers wrote post-give-back gates this call, and the flag
  is left set afterwards. The callee's body is cited only;
  it is #247's question.
- `[block+0x14]` then reconciles the `+0x50`/`+0x58` list
  against the `[block+0x20]` membership bit: if `+0x14` is
  set and `+0x20` is clear, insert the block (set
  `+0x20 := 1`, splice into the circular list anchored at
  `[first-arg+0x1498]`, anchor := block); if `+0x14` is
  clear and `+0x20` is set, remove the block (clear
  `+0x20 := 0`, unlink neighbours, fix the anchor, emptying
  it when the block was the only node); if desired and
  actual agree, return without touching the list.

It frees nothing, never writes a block key, and never writes
`[block+0x12]` — the removal gate is untouched here. It does
not call the #237 register (`0x63d94b0`); it performs the
register list's surgery inline, on the same anchor
(`[first-arg+0x1498]`) and the same `+0x50`/`+0x58` links.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`, kept live).
- `rsi` = block pointer (saved in `rbx`).
- No return value is established by these bytes: both `ret`
  paths return through pops epilogues with no value set in
  `rax`.
- Block fields, as used here: `+0x10` = byte whose negated
  low bits select a sub-slot (`(-byte) & 0x18`);
  `+0x11` = handoff-request flag (tested, never written
  here); `+0x13` = second-callee flag (tested, never
  written here); `+0x14` = desired-list-membership flag
  (tested, never written here); `+0x20` = actual
  list-membership bit (set on insert, cleared on remove);
  `+0x23` = byte cleared to 0 on entry on every path;
  `+0x40`/`+0x48` = the #244 post-remove list links (never
  touched here); `+0x50` = forward link of the register
  list; `+0x58` = back link of the register list;
  `+0x60` = size input for the mapper; `+0x68` = the
  block's stamped value (dispatch key and byte total);
  `+0xb0` = the other term of the third field.

## Entry and dispatch

1. `endbr64`; pushes `rbp, rbx`; `rbp := rdi`,
   `rbx := rsi`; `sub $0x8, %rsp`.
2. `rax = [block+0x68]`; `[block+0x23] := 0` (byte),
   immediately, on every path, before the dispatch test.
3. If `rax == 0`, jump to `0x63d92c0` (zero arm). If
   `rax == 0x200`, jump to `0x63d91c8` (`0x200` arm).
   Otherwise take the size arm.

## The additive identity (all three arms)

Each arm adds the block back into a slot triple and the
global triple by the same rule, with `v = [block+0x68]`
and `w = [block+0xb0]` — the exact sign-inverse of #243:

- slot first qword `+= 1`; slot second qword `+= v`;
  slot `+0x10` field `+= (w - v)`.
- global `[first-arg+0x408] += 1`; `[first-arg+0x410] += v`;
  `[first-arg+0x418] += (w - v)`.

The arms differ only in which slot they address and, for
`v == 0`, in the vacuous `+= 0` updates, which the code
simply omits:

- Size arm: slot = `first-arg + 0x420 + 48*index +
  ((-byte[block+0x10]) & 0x18)`, where `index` comes from
  the size mapping below.
- `0x200` arm: slot = `first-arg + 0x1020 +
  ((-byte[block+0x10]) & 0x18)`, pair updated by adding
  the `.rodata` constant `(1, 512)` — i.e. `+= 1` and
  `+= 0x200`, exactly the identity with `v = 0x200`, and
  the exact inverse of give-back's `(-1, -512)`.
- Zero arm: slot = `first-arg + 0x1050 +
  ((-byte[block+0x10]) & 0x18)`; only `[slot] += 1`,
  `[slot+0x10] += w`, `[first-arg+0x408] += 1`,
  `[first-arg+0x418] += w` — the `+= v` updates are omitted
  because `v == 0`.

## Size arm (nonzero, non-`0x200` `[block+0x68]`)

`rdi = [block+0x60] << 12`; call `0x63e8bf0` (cited only —
the same size-mapping helper #237/#238/#242/#243 cited).
If the result exceeds `0x7000000000000000`, take the
overflow stub (`r11d = 0x2970`, jump back into the slot
computation: `0x2970 - 0x420 = 48*199`, index 199 —
verified by key bytes, not exhibited, same convention as
#237/#238/#242/#243). Otherwise compute the index by the
identical scheme as #242: `bsr`, `+1` unless a power of
two (via `cmp`/`sbb`), clamped to a minimum of 14, shift
= `clamped - 3` except `12` when `clamped == 14`, index =
`((result - 1) >> shift) & 3 + 4 * (clamped - 14)`.

## The tail: handoff gate, second-callee gate, list reconcile

After the accounting (and the shared `[first-arg+0x418]`
store), in program order:

1. `cmpb $0, 0x11(%rbx)`: if nonzero, call the #238
   handoff (`0x63d8790`, site `0x63d9232`, cited only)
   with (first-arg, block). If zero, the call is skipped.
2. `cmpb $0, 0x13(%rbx)`: if nonzero, call `0x63d88d0`
   (site `0x63d9247`, cited only — FDE
   `0x63d88d0..0x63d8a00`) with (first-arg, block). If
   zero, the call is skipped. The flag is tested, never
   cleared, here.
3. `cmpb $0, 0x14(%rbx)` with `[block+0x20]` loaded:
   - `+0x14` set, `+0x20` clear → insert: `[block+0x20]
     := 1`; the block's `+0x50`/`+0x58` pair is first made
     self-linked, then spliced into the circular list
     anchored at `[first-arg+0x1498]` (if the anchor is
     `0`, the block simply becomes the anchor); finally
     `[first-arg+0x1498] := block`. Then `ret`.
   - `+0x14` clear, `+0x20` set → remove: `[block+0x20]
     := 0`; if the block is the anchor and self-linked,
     `[first-arg+0x1498] := 0`; if the block is the anchor
     but not self-linked, the anchor advances to
     `[block+0x50]` and the block is unlinked; if the
     block is not the anchor, the block is unlinked
     (neighbours linked to each other over `+0x50`/
     `+0x58`, block left self-linked). Then `ret`.
   - Desired and actual agree (`+0x14` set with `+0x20`
     set, or both clear) → `ret` with no list store.

## Caller context (cited only, not claimed)

Direct `E8` call sites to `0x63d9070`: 9, all
objdump- and rel32-confirmed — A `0x63b7b0e`,
`0x63b7cb7`, `0x63b7da9`, `0x63b7e6c` (FDE
`0x63b7900..0x63b7ee6`); B `0x63b8014` (FDE
`0x63b7ef0..0x63b8157`, a loop-head site: reached after
the setne/zero `+0x13` rule in the same iteration, both
on first entry and on loop-back after give-back — this
refines, but does not contradict, #245's B description);
D `0x63b83ac`, `0x63b8455` (FDE `0x63b81b0..0x63b8517`);
C `0x63b8a43`, `0x63b8c95` (FDE `0x63b8820..0x63b8d85`,
#232's, cited only). No `E9` tail jump, no rip-relative
`LEA`, and no `.rela.dyn` addend targets this FDE.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d9070..0x63d9337`, 711 bytes); `endbr64` entry;
  `int3` padding `0x63d906b..0x63d9070` (5 bytes, after
  #243's give-back, which ends at `0x63d906b`) and
  `0x63d9337..0x63d9340` (9 bytes, before the class-search
  FDE at `0x63d9340`, cited only). Static analysis only;
  the binary was never executed.
- 6 exhibits, 433 bytes, 102 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `rg_entry` | `0x63d9070..0x63d909d` | 45 | 12 | Entry, arg saves, `[block+0x68]` load, `[block+0x23] := 0`, dispatch |
| `rg_slot` | `0x63d9108..0x63d9156` | 78 | 17 | Size slot, additive updates, globals, `+0x11` test |
| `rg_200` | `0x63d91c8..0x63d9226` | 94 | 17 | `0x200` arm: `+0x1020` slot, `(1, 512)` pair add, `+0x11` test |
| `rg_tail` | `0x63d922c..0x63d9264` | 56 | 13 | Handoff call, `+0x13` call, `+0x14`/`+0x20` dispatch |
| `rg_insert` | `0x63d9264..0x63d92b7` | 83 | 22 | List insert, anchor splice, anchor `:= block`, ret |
| `rg_remove` | `0x63d9175..0x63d91c2` | 77 | 21 | List remove, anchor test, neighbour unlink, ret |

- The zero arm (`0x63d92c0..0x63d92f7`: `+0x1050` slot,
  `jmp` into the tail test), the overflow stub
  (`0x63d9320..0x63d9326`: `r11d = 0x2970`, jump into the
  slot computation), and the anchor block
  (`0x63d9300..0x63d9337`: self-link test, anchor `:= 0`,
  anchor `:= [block+0x50]`, jump into the unlink) are
  verified by the static verifier's key-byte checks, not
  exhibited, to keep the packet at 18 files.
- Census: direct `E8` call sites to `0x63d9070`: 9
  (listed above). Direct `E9` jump sites: 0.
  Rip-relative `LEA` sites: 0. `.rela.dyn` addends equal
  to `0x63d9070`: 0 of 60,723 entries. Internal calls
  within the FDE: 3 (`0x63e8bf0`, `0x63d8790`,
  `0x63d88d0`). Internal jump targets: all lie inside
  `0x63d9070..0x63d9337`. Two `ret` sites: `0x63d91c1`,
  `0x63d92b6`.
- Disjointness: this FDE overlaps no claimed range from
  packets #183–#245 and no other contributor's topic,
  addresses, or tables. The give-back drivers, the size
  mapper, the handoff, the `0x63d88d0` callee, the class
  search, the register, the gate, the driver, and the
  allocator thunk are cited by address, not claimed here.

## Corrections to earlier packets

- **#245 confirmed, with a loop-head refinement.** Its
  driver census (9 sites for the give-back fan-in, and
  this function's 9 call sites) is consistent: B's single
  `0x63d9070` site (`0x63b8014`) is a loop-head site,
  reached after the setne/zero `+0x13` rule in the same
  iteration — on first entry and on loop-back after
  give-back — so the `+0x13` this function reads was
  written just before in the same iteration, not after a
  give-back call in the same pass. No #245 address or
  site attribution changes.
- **#243 confirmed and completed in part.** Give-back's
  counter decrements are exactly inverted here, its
  `+0x23 := 1` is cleared here, and its `+0x13` tail
  gate is consumed (tested) here — but the `+0x13`
  value itself is written by the drivers, not by
  give-back.
- **#242 confirmed.** The removal entry is never called
  here; this function runs after the drivers, on the
  counters and the register list, not on the queue or
  the size-class chains.
- **#241 confirmed.** The class remove's chains are not
  touched here.
- **#240 confirmed.** The probe's empty verdict is not
  re-tested here; this function tests the `+0x11`/
  `+0x13`/`+0x14` flags instead.
- **#239 confirmed.** The class insert's chains are not
  touched here.
- **#238 confirmed and completed.** The handoff is the
  `+0x11`-gated callee here, and its size-class entry
  computation scheme is repeated here for the slot
  index — but with a 48-byte stride and a `+0x420` base,
  a different table from the handoff's 16-byte entries.
- **#237 confirmed and related.** The register's
  `+0x50`/`+0x58` list and `[first-arg+0x1498]` anchor
  are exactly the list and anchor reconciled here; the
  register itself is never called here.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches this function on the
  zero arm, which books it at the `+0x1050` slot.
- **#235 confirmed.** The gate's paths reach this
  function only indirectly, through the register, the
  handoff, and the driver FDEs.
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff; re-registration
  runs through this function, not the driver path.
- **#233 confirmed.** The loop caller is not involved
  with this function.
- **#232 confirmed.** The single-shot caller (C) is
  itself a caller of this function (sites `0x63b8a43`,
  `0x63b8c95`, cited only); this packet claims none of
  its bytes.
- **#216 confirmed.** The allocator thunk `0x636b370` is
  the gate's allocator; this function never calls it.

## Unresolved

- What the `+0x13`-gated callee FDE `0x63d88d0..0x63d8a00`
  does with the (first-arg, block) pair — whether it
  reads `+0x13` itself, and how it relates to the
  handoff and the register. This is #247's question.
- Which of the 9 call sites' FDEs establish the
  `+0x11`/`+0x14` states this function tests, beyond
  B's loop-head rule and A's post-call flag pattern
  from #245.
- The domain meaning of the slot triple and the global
  triple beyond the decrement/increment pattern: the
  first qword behaves like a count, the second like a
  byte total, the `+0x10` field like a remainder — but
  those names are inference, not bytes.
- Who reads `[block+0x23]` after give-back sets it to 1
  and this function clears it to 0, beyond this
  function's own clear.
- Whether the `+0x14` desired-membership reading holds
  on all caller paths, or only on the driver paths
  decoded here.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Next question (#247)

Decode the `+0x13`-gated callee FDE `0x63d88d0..0x63d8a00`
end to end: what it does with the (first-arg, block) pair
it receives when `+0x13` is set — whether it reads
`+0x13` itself, what it establishes in return, and how it
relates to the handoff and the register — deciding where
the drivers' flag is finally consumed.

## Verification

- `tools/node115_lu_reregister.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, FDE bounds, entry bytes, two `ret` sites, three
  call rel32s, key bytes, jump targets internal, no
  `+0x12` stores, full census, neighbour disjointness,
  MANIFEST coverage (17 entries).
- `tests/test_node115_lu_reregister.py`: 10/10 pass.
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
  it; the deviation is disclosed here, as in #245.

## Files (18)

- `research/work-items/RE-001-node115-lu-reregister/README.md`
- `research/work-items/RE-001-node115-lu-reregister/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-reregister/records.json`
- `research/work-items/RE-001-node115-lu-reregister/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-reregister/rg_entry.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-reregister/rg_slot.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_slot.objdump.txt`
- `research/work-items/RE-001-node115-lu-reregister/rg_200.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_200.objdump.txt`
- `research/work-items/RE-001-node115-lu-reregister/rg_tail.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_tail.objdump.txt`
- `research/work-items/RE-001-node115-lu-reregister/rg_insert.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_insert.objdump.txt`
- `research/work-items/RE-001-node115-lu-reregister/rg_remove.hex`
- `research/work-items/RE-001-node115-lu-reregister/rg_remove.objdump.txt`
- `tools/node115_lu_reregister.py`
- `tests/test_node115_lu_reregister.py`
