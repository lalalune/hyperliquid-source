# RE-001-node115-lu-wait-helper

## Question

Packet #250's next question: what does the wait helper FDE `0x63bf680`
do — what it waits on, what it returns, and how its two argument
objects (`object+0xb0` and `object+0x40` in caller B of packet #250)
relate to the two locks — deciding what the merge callers block on
when trylock fails?

## Answer

`0x63bf680(arg)` is the lu lock-wait helper: it acquires the mutex at
`arg+0x40`, first by a bounded spin (a `pause` loop gated by a global
spin limit and a contended flag), then — when spinning is disabled,
exhausted, or the flag is set — by a blocking `pthread_mutex_lock`,
with wait statistics accumulated into the argument record. It returns
with `rax` 0 (incidentally, via the stack-canary check, not as a set
result). It is a shared helper, called from many sites across the
binary — not a merge-caller private function: the two #250 caller-B
sites are two of its many direct callers.

## Entry contract

- `rdi` = pointer to a lock-waiter record (saved in `r12`, kept live).
- `rbp` = `arg+0x40`, the mutex, computed once at entry and used by
  every trylock/lock call.
- No other argument is used. One `ret` site at `0x63bf71d`; the
  canary-failure path calls `__stack_chk_fail@plt` and never returns.

## Argument record layout (as used here)

| Offset | Meaning |
|---|---|
| `+0x00` | Total waited nanoseconds, accumulated on the slow path only |
| `+0x08` | Max single wait, nanoseconds |
| `+0x10` | Blocking-path (slow) acquisition count |
| `+0x18` | Successful acquisition count (fast and slow exits) |
| `+0x20` | High-water ticket (max waiter count seen) |
| `+0x24` | Live waiter count (atomic inc on slow entry, dec after lock) |
| `+0x40` | The pthread mutex (40 bytes, `+0x40..+0x68`) |
| `+0x68` | Contended flag byte, set after a blocking lock, tested in the spin loop |

The two #250 caller-B argument objects fit this layout exactly: the
first-lock record at `object+0xb0` has its mutex at `object+0xf0`
and its flag at `object+0x118` (the wait flag #250 reported); the
second-lock record at `object+0x40` has its mutex at `object+0x80`
and its flag at `object+0xa8`. Caller B clears both flags on its
success exit — this function itself never clears the flag.

## Fast path: bounded spin

1. `endbr64`; pushes `r14, r13, r12, rbp, rbx`; `r12 := rdi`,
   `rbp := rdi+0x40`; stack canary saved.
2. If the `.bss` word at `0x6511730` equals 1, skip spinning
   entirely and go to the slow path. (The word is runtime-filled;
   its value is not read from the file, and no purpose beyond this
   test is claimed.)
3. Spin loop (`rbx` = spin count, starting at 0): load the `.data`
   qword at `0x64ffc98`; continue while it equals -1 or is greater
   than the spin count, otherwise go to the slow path. Each cycle:
   `pause`; if `[arg+0x68]` is nonzero, recheck the limit without
   trylocking; else `pthread_mutex_trylock` on `arg+0x40`. On
   success: `[arg+0x18] += 1`, canary check, `ret`.
4. The `.data` limit reads as a spin bound (unlimited when -1); the
   exact bound value is runtime state and is not claimed.

## Slow path: ticket, blocking lock, time accounting

1. `r13 := rsp`, `r14 := rsp+8`, `ebx := 1`.
2. Call the now-nanoseconds helper `0x63bfcf0` (cited only,
   `CLOCK_MONOTONIC`): `[rsp] :=` start time in nanoseconds.
3. Copy `[rsp]` to `[rsp+8]` (the deadline slot, initially the start
   time).
4. `lock xadd %ebx, [arg+0x24]`: `ebx` becomes the old waiter
   count, the count increments; then `ebx += 1`, so `ebx` is the
   new waiter's ticket number.
5. `pthread_mutex_trylock` on `arg+0x40`: on success, `lock sub
   $0x1, [arg+0x24]` and jump to the success exit (step 8).
6. On failure: `pthread_mutex_lock` (blocking) on `arg+0x40`;
   `[arg+0x68] := 1`; `lock sub $0x1, [arg+0x24]`; call the
   max-now helper `0x63bfa70` (cited only, reached through the
   `.data.rel.ro` GOT slot at `0x64df1e8`) on `[rsp+8]`, which
   stores `max(now, start)` there.
7. Accounting, via the small qword helpers (cited only):
   `[rsp+0x10] := [rsp+8]`; `[rsp+0x10] -= [rsp]` (elapsed =
   end − start); `[arg+0x10] += 1`; `[arg] += [rsp+0x10]`
   (total waited); compare `[arg+0x08]` with elapsed — if the
   stored max is smaller, `[arg+0x08] := elapsed`; if
   `[arg+0x20] < ebx`, `[arg+0x20] := ebx` (high-water ticket).
8. Success exit: `[arg+0x18] += 1`, canary check, pops, `ret`
   at `0x63bf71d`.

## What this decides

- The #250 open question is answered: when trylock fails, the merge
  callers block in this helper — first spinning (bounded by the
  global limit, deferred while the contended flag is set), then
  taking the mutex blocking, with the wait charged to the two
  waiter records embedded in the caller-B object.
- The wait flags #250 reported (`+0x118`, `+0xa8` on the caller-B
  object) are this helper's contended flag at record `+0x68`: set
  by the helper after a blocking acquisition, cleared by caller B's
  exit, never cleared here.
- The helper is shared infrastructure, not merge-specific: its
  direct callers span the binary (see Census). Any packet that
  touches a trylock failure path may meet it again.
- The record's statistic fields are proved by the stores, but their
  domain names (total/max wait, counts, ticket) are readings of the
  update pattern, not bytes — the bytes prove which offsets move
  and in which direction.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63bf680..0x63bf7ee`, 366 bytes); `endbr64` entry;
  `int3` padding `0x63bf677..0x63bf680` (9 bytes, after the
  preceding FDE ending at `0x63bf677`) and `0x63bf7ee..0x63bf7f0`
  (2 bytes, before the next FDE at `0x63bf7f0`, cited only).
  Static analysis only; the binary was never executed.
- 5 exhibits, 329 bytes, 84 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `wt_entry` | `0x63bf680..0x63bf6b7` | 55 | 16 | Entry, arg save, mutex lea, canary, spin-disable test |
| `wt_spin` | `0x63bf6b9..0x63bf6fd` | 68 | 18 | Spin loop, limit test, pause, flag test, trylock, success bump |
| `wt_slow` | `0x63bf720..0x63bf77d` | 93 | 22 | Deadline, copy, ticket xadd, trylock, blocking lock, flag set, waiter dec, GOT lea |
| `wt_acct` | `0x63bf77d..0x63bf7d0` | 83 | 21 | Max-now call, copies, elapsed subtract, slow-count bump, total add, compare, max store, ticket high-water |
| `wt_exit` | `0x63bf7d0..0x63bf7ee` | 30 | 7 | Waiter decrement + success jump, negative-compare copy path, stack-check failure call |

- The gaps (`0x63bf6b7..0x63bf6b9` jmp, `0x63bf6fd..0x63bf720`
  canary check + epilogue + ret) are verified by the static
  verifier's key-byte checks, not exhibited.
- Census: direct `E8` call sites to `0x63bf680`: 474
  (objdump-mnemonic confirmed, all rel32-verified), including the
  two #250 caller-B sites `0x63b92e3` and `0x63b92fb`. Direct `E9`
  jump sites: 0. Rip-relative `LEA` sites: 0. `.rela.dyn`
  addends equal to `0x63bf680`: 0 of 60,723 entries.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#250 (952 unique exhibit/FDE ranges checked across
  the merged tree and the prior worktree records, deduplicated by
  real path with ranges deduplicated as a set, own slug excluded,
  0 overlaps) and no other contributor's topic, addresses, or
  tables. The merge callers, the merge, the give-back, the reset,
  the insert, the register, the re-register, the size mapper, the
  handoff, the post-remove unlink, the removal entry, the class
  remove, the entry probe, the gate, the driver, and the allocator
  thunk are cited by address, not claimed here.

## Corrections to earlier packets

- **#250 confirmed and completed.** Its wait helper is this FDE:
  the calls at `0x63b92e3` and `0x63b92fb` land here, the two
  argument objects are waiter records whose mutexes are the two
  locks, and the wait flags are this helper's `+0x68` contended
  flag. Caller B's flag clears on exit are consistent with the
  helper never clearing the flag itself.
- **#249 confirmed.** The merge's callers block here, not in the
  merge; the merge itself never waits.
- **#248 confirmed.** The reset's span is not touched here.
- **#247 confirmed.** The insert's slot table, bitmap, and anchor
  are untouched here.
- **#246 confirmed.** Its counter region is the kind of state the
  merge accumulates, but no counter value is set here — only wait
  statistics on the argument record.
- **#243 confirmed.** The give-back is not re-claimed here.
- **#242, #241, #240, #239, #238, #236, #235, #234, #233, #232,
  #216 confirmed.** Nothing of theirs is re-claimed here.

## Unresolved

- What clears the contended flag besides caller B's exit — whether
  other callers clear it, or it is cleared on unlock paths elsewhere,
  is not decided here.
- The runtime values of the spin-disable word (`.bss`) and the spin
  limit (`.data`): the tests that gate them are proved, the values
  are not read from the file.
- The domain meaning of the ticket beyond the waiter-count pattern:
  whether tickets order waiters (a queue discipline) or only count
  them is not proved by these bytes.
- What the small qword helpers (`0x63bfbf0`, `0x63bfc00`,
  `0x63bfc20`, `0x63bfc40`, `0x63bfcf0`, `0x63bfa70`) are beyond
  their proved operations — they are cited only, not decoded as
  packets.
- Who calls this helper at its other 472 sites, and whether
  any caller passes a record whose mutex is not at `+0x40`, is not
  surveyed here.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#252)

Survey the other direct callers of this helper: which call sites
pass waiter records with a different layout or purpose than caller
B's two records — deciding whether this helper serves one lock
family or many.

## Verification

- `tools/node115_lu_wait_helper.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, one `ret` site, all internal call
  rel32s, GOT-indirect target, key bytes, jump targets internal,
  full census, neighbour disjointness, MANIFEST coverage
  (15 entries).
- `tests/test_node115_lu_wait_helper.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7169 entries).
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
  it; the deviation is disclosed here, as in #245–#250.

## Files (16)

- `research/work-items/RE-001-node115-lu-wait-helper/README.md`
- `research/work-items/RE-001-node115-lu-wait-helper/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-wait-helper/records.json`
- `research/work-items/RE-001-node115-lu-wait-helper/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_entry.hex`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_spin.hex`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_spin.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_slow.hex`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_slow.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_acct.hex`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_acct.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_exit.hex`
- `research/work-items/RE-001-node115-lu-wait-helper/wt_exit.objdump.txt`
- `tools/node115_lu_wait_helper.py`
- `tests/test_node115_lu_wait_helper.py`
