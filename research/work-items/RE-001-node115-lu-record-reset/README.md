# RE-001-node115-lu-record-reset

## Question

Packet #253's next question: what does the work function `0x63bf7f0`
do with `(tag, record)` after each successful trylock in the largest
caller FDE — deciding what that caller actually accomplishes once it
holds each lock?

## Answer

It resets the record. The work function is a 77-byte record
re-initializer: it zeroes `record+0x00..+0x40` (the helper-side
statistics `+0x00..+0x24` from #251 and the caller-side triple
`+0x28`/`+0x30`/`+0x38` from #253), leaves the mutex at `+0x40` and
the contended flag at `+0x68` untouched, and ignores its tag
argument entirely — `%rdi` is never read before being clobbered.
So the #253 sweep, once it holds each lock, zeroes that record's
counters and then (per #253's caller pattern) clears the flag and
unlocks: a lock, reset-counters, unlock sweep over every waiter
record, with lock state itself undisturbed.

## The function, in program order

FDE `0x63bf7f0..0x63bf83d` (77 bytes, `endbr64` entry, single
`ret` at `0x63bf83c`):

1. `endbr64`; `push %rbp`; `pxor %xmm0, %xmm0` (zero vector).
2. `lea 0xb9e830, %rbp` — the address of a qword in `.rodata`
   that reads 0 (cited only, not claimed).
3. `lea 0x8(%rsi), %rdi`; `push %rbx`; `rbx := rsi` (record);
   `sub $0x8, %rsp`. Note: the entry `%rdi` (the tag) is
   overwritten here without ever being read.
4. Zeroing: `movups %xmm0` to `record+0x00`, `+0x10`, `+0x20`,
   `+0x30` — 64 bytes, `record+0x00..+0x40`.
5. Two qword copies through the small helper `0x63bfbf0`
   (`mov (%rsi),%rax; mov %rax,(%rdi); ret`, cited only):
   `record+8 := [0xb9e830]` (= 0), then `record+0 := [0xb9e830]`
   (= 0). Both stores are redundant with step 4 given the
   constant is 0, but they are what the code does; the packet
   claims the bytes, not a reason for the redundancy.
6. `movq $0, 0x30(%rbx)` — last-tag slot := 0, again redundant
   with step 4's `movups` at `+0x30`.
7. `add $0x8, %rsp`; pops; `ret` at `0x63bf83c`.

Net effect: `record+0x00..+0x40 := 0`. The mutex (`+0x40`) and
the flag (`+0x68`) are outside the zeroed span and are never
written. The tag is ignored.

## What this decides

- The #253 open question is answered: once it holds each lock,
  the largest caller FDE resets that record's statistics —
  helper stats and caller triple alike — and nothing else. It
  does not consume the tag, does not touch the mutex, and does
  not clear the flag itself (the caller does that on unlock).
- The record layout from #251/#253 is confirmed as a reset
  unit: the zeroed span `+0x00..+0x40` is exactly the stats
  plus triple, stopping one byte short of the mutex.
- The copy helper `0x63bfbf0` is confirmed as a plain qword
  copy (`mov (%rsi),%rax; mov %rax,(%rdi); ret`); its use here
  with a zero `.rodata` source is why the two copy calls are
  no-ops on top of the `movups` zeroing.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame` (PC-relative sdata4
  encoding); `endbr64` entry; `int3` padding
  `0x63bf7ee..0x63bf7f0` (2 bytes, after the wait helper FDE
  ending at `0x63bf7ee`) and `0x63bf83d..0x63bf840` (3 bytes,
  before the next FDE at `0x63bf840`, cited only). Static
  analysis only; the binary was never executed.
- 4 exhibits, 77 bytes (the whole FDE), 22 strict instructions
  (strict = mnemonic-line count: address + bytes field + tab +
  mnemonic; objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `wk_entry` | `0x63bf7f0..0x63bf80c` | 28 | 8 | Entry, zero vector, zero-constant lea, tag clobber, record save |
| `wk_zero` | `0x63bf80c..0x63bf81b` | 15 | 4 | Four `movups` zeroing `record+0x00..+0x40` |
| `wk_copy` | `0x63bf81b..0x63bf82e` | 19 | 5 | Two qword copies from `0xb9e830` into `record+8`, `record+0` |
| `wk_tail` | `0x63bf82e..0x63bf83d` | 15 | 5 | Last-tag `:= 0`, epilogue, `ret` |

- Census: direct `E8` call sites to `0x63bf7f0`: 18 — all inside
  packet #253's caller FDE `0x63a5bf0..0x63a6470` (the only
  caller). Direct `E9` sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63bf7f0`: 0 of 60,723 entries.
  The 18 sites are the same 18 sites #253 lists as its work
  calls (rel32-verified here independently).
- Disjointness: the exhibits overlap no claimed range from
  packets #183–#253 (checked across the merged tree and the prior
  worktree records, deduplicated by real path with ranges
  deduplicated as a set, own slug excluded, 0 overlaps) and no
  other contributor's topic, addresses, or tables. Census and
  cited-only metadata ranges are excluded from the claimed set:
  packet #253's records cite this function by address while
  stating it is not decoded there, so counting that citation as
  a claim would falsely block the follow-up #253 itself invited.
  The wait helper, the caller FDE, the merge callers, the merge,
  the give-back, the reset, the insert, the register, the
  re-register, the size mapper, the handoff, the post-remove
  unlink, the removal entry, the class remove, the entry probe,
  the gate, the driver, and the allocator thunk are cited by
  address, not claimed here.

## Corrections to earlier packets

- **#253 confirmed and completed.** Its work function is this
  FDE: called with `(tag, record)` after each successful
  trylock, it resets the record's stats and triple, ignores
  the tag, and leaves mutex and flag alone.
- **#252 confirmed.** Its census of the caller's 18 work calls
  matches the 18 direct sites found here; no other caller exists.
- **#251 confirmed.** Its record table's stats fields are exactly
  the span this function zeroes, minus the triple #253 added.
- **#250 confirmed.** Caller B's records are reset by the same
  span shape when this sweep reaches them.
- **#249, #248, #247, #246, #243, #232 confirmed.** Nothing of
  theirs is re-claimed here.

## Unresolved

- Why the function emits redundant stores (two zero copies and
  a last-tag store on top of the `movups` zeroing) — whether the
  `.rodata` source is a placeholder for a non-zero initial value
  in another build, or compiler pattern, is not decided by these
  bytes.
- What schedules the #253 sweep (who calls the caller FDE, and
  when the reset runs) — the caller FDE's own callers are not
  surveyed here.
- Whether any other code path resets records without holding the
  lock — only this function's 18 call sites were censused.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#255)

Find the callers of the #253 sweep FDE `0x63a5bf0..0x63a6470`:
who invokes the reset sweep, and what triggers it — deciding
whether the waiter-record reset runs on a timer, on demand, or
on a lifecycle event.

## Verification

- `tools/node115_lu_record_reset.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, one `ret` site, both copy-call rel32s,
  zero-constant qword, key bytes, jump targets (none — no jumps),
  full census, neighbour disjointness, MANIFEST coverage
  (13 entries).
- `tests/test_node115_lu_record_reset.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7167 entries).
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
  it; the deviation is disclosed here, as in #245–#253.
