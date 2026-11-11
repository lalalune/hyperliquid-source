# RE-001-node115-lu-merge-callers

## Question

Packet #249's open question: which object pair do the context merge's two
callers merge — and what else do the callers do around the call? The
originally assigned #250 topic (the neighbour FDE `0x63d8e70..0x63d906b`
after the merge) turned out to be packet #243's give-back itself (PR
#2713), a full duplicate, so no packet was built on it. This packet
instead decodes the merge's two caller FDEs, which #249 cited only and
which were verified unclaimed.

## Answer

Caller A (`0x63b9180..0x63b91d2`, 82 bytes) is a pure pass-through
wrapper: it calls the merge with its own `(dst, src)` unchanged, then
adds `src+0xc60`/`+0xc70` into `dst+0xc60`/`+0xc70`, so the full add on
its path is `+0x0..+0xc80` (400 qwords). Caller B
(`0x63b91e0..0x63b930c`, 300 bytes) is a locked merge: it takes two
trylocks on the object, bumps acquisition/distinct counters and last-tag
slots for each, then calls the merge with `(dst = third arg,
src = object+0x560)`, adds `object+0x1628`/`+0x1638` into
`dst+0xc60`/`+0xc70`, clears its wait flags, and releases both locks —
exiting by a tail jump to the unlock PLT, with no `ret` in its body.
So the merged pairs are: A merges its own arguments; B merges the
object's `+0x560` region into a caller-supplied destination, under two
locks, with the tail pair coming from a different object region
(`+0x1628`) than the merge source.

## Entry contracts

Caller A:

- `rdi` = destination object (saved in `rbx`, kept live; unchanged at
  the merge call).
- `rsi` = source object (saved in `rbp`, kept live; unchanged at the
  merge call).
- No other argument is read. Single `ret` at `0x63b91d1`; no return
  value is established.

Caller B:

- `rdi` = tag value (saved in `r12`; compared against the last-tag
  slots, never dereferenced).
- `rsi` = object (saved in `rbx`, kept live).
- `rdx` = destination object (saved in `rbp`; becomes the merge's
  first argument).
- No `ret`: the exit path pops and tail-jumps to the unlock PLT.

## Caller A, in program order

1. `endbr64`; `push %rbp`; `rbp := rsi`; `push %rbx`; `rbx := rdi`;
   `sub $0x8, %rsp`.
2. `call 0x63d8b20` (site `0x63b9190`, the #249 merge) with the
   caller's own `(rdi, rsi)` — neither register is modified before
   the call.
3. Tail adds: `xmm2 := [src+0xc70]`, `xmm1 := [src+0xc60]`,
   `xmm0 := [dst+0xc70]`, `xmm3 := [dst+0xc60]`,
   `paddq`, `movups` back to `dst+0xc60`/`dst+0xc70`.
4. `add $0x8, %rsp`; pops; `ret` at `0x63b91d1`.

## Caller B, in program order

1. `endbr64`; pushes `r15, r14, r13, r12, rbp, rbx`;
   `r14 := object+0xb0`, `r13 := object+0xf0`, `r12 := rdi`,
   `rdi := r13`, `rbp := rdx`, `rbx := rsi`, `sub $0x8, %rsp`.
2. First lock: `call pthread_mutex_trylock@plt` (site `0x63b920c`)
   on `object+0xf0`. On failure (`jne 0x63b92e0`): call the wait
   helper `0x63bf680` (site `0x63b92e3`) on `object+0xb0` (the entry
   value of `r14`), set `[object+0x118] := 1`, and jump back to the
   counting step — the retry skips the trylock, so after the wait the
   lock is treated as held.
3. Counting (first lock): `[object+0xe8] += 1`; if `r12 !=
   [object+0xe0]`, `[object+0xd8] += 1` and `[object+0xe0] := r12`.
4. Second lock: `r14 := object+0x80`, `r15 := object+0x40`;
   `call pthread_mutex_trylock@plt` (site `0x63b9247`) on
   `object+0x80`. On failure (`jne 0x63b92f8`): call `0x63bf680`
   (site `0x63b92fb`) on `object+0x40`, set `[object+0xa8] := 1`,
   and jump back to the second counting step.
5. Counting (second lock): `[object+0x78] += 1`; if `r12 !=
   [object+0x70]`, `[object+0x68] += 1` and `[object+0x70] := r12`.
6. Merge call: `rsi := object+0x560`, `rdi := rbp` (third arg);
   `call 0x63d8b20` (site `0x63b9272`).
7. Tail adds: `xmm2 := [object+0x1638]`, `xmm1 := [object+0x1628]`,
   `xmm0 := [dst+0xc70]`, `xmm3 := [dst+0xc60]`, `paddq`,
   `movups` back to `dst+0xc60`/`dst+0xc70`. Note the tail source
   (`object+0x1628`) is not contiguous with the merge source
   (`object+0x560..+0x11e0` for the 400-qword span): it is a
   different object region, and this packet does not claim what it
   is.
8. Exit: `[object+0xa8] := 0`; `call pthread_mutex_unlock@plt`
   (site `0x63b92b7`) on `object+0x80`; `rdi := object+0xf0`;
   `[object+0x118] := 0`; pops; tail `jmp pthread_mutex_unlock@plt`
   (site `0x63b92d4`) on `object+0xf0`. No `ret` executes on any
   path.

## What this decides

- The #249 open question is answered on both paths: A merges its own
  `(dst, src)`; B merges `object+0x560` into the third argument,
  under two locks, with the `+0xc60`/`+0xc70` tail pair taken from
  `object+0x1628`/`+0x1638` rather than from the merge source.
- The tail pattern is confirmed shared: both callers add exactly the
  `+0xc60`/`+0xc70` pair after the merge, so the architectural add is
  400 qwords on both paths, with the last 32 bytes handled inline by
  callers rather than inside the merge.
- The two locks in B are per-lock instrumented: each has an
  acquisition counter (`+0xe8` / `+0x78`), a distinct-tag counter
  (`+0xd8` / `+0x68`), a last-tag slot (`+0xe0` / `+0x70`), and a
  waited flag (`+0x118` / `+0xa8`) that is set to 1 on the wait path
  and cleared to 0 on the success exit.
- The wait helper `0x63bf680` is cited only, not decoded: its two
  argument objects (`object+0xb0` for the first lock, `object+0x40`
  for the second) are proved, but what it waits on is not claimed.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b9180..0x63b91d2`, 82 bytes, caller A;
  `pc=0x63b91e0..0x63b930c`, 300 bytes, caller B); both `endbr64`
  entries; no padding before A (the neighbour FDE
  `0x63b8fe0..0x63b9180` ends exactly at `0x63b9180`);
  `int3` padding `0x63b91d2..0x63b91e0` (14 bytes, between A and B)
  and `0x63b930c..0x63b9310` (4 bytes, before the next FDE at
  `0x63b9310`, cited only). Static analysis only; the binary was
  never executed.
- 5 exhibits, 382 bytes (the whole of both FDEs), 86 strict
  instructions (strict = mnemonic-line count: address + bytes field
  + tab + mnemonic; objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `mc_callA` | `0x63b9180..0x63b91d2` | 82 | 19 | Caller A whole FDE: entry, merge call, tail adds, ret |
| `mc_entryB` | `0x63b91e0..0x63b920c` | 44 | 14 | Caller B entry: pushes, saves, lock-target leas |
| `mc_lockB` | `0x63b920c..0x63b9268` | 92 | 19 | Caller B lock bookkeeping: two trylocks, counters, last-tag stores |
| `mc_mergeB` | `0x63b9268..0x63b92b7` | 79 | 13 | Caller B merge call, tail adds, flag clear, unlock call |
| `mc_exitB` | `0x63b92b7..0x63b930c` | 85 | 21 | Caller B exit: unlock, flag clears, pops, tail-jump unlock, wait paths |

- The `nopl` gaps in B (`0x63b92d9..0x63b92e0`,
  `0x63b92f4..0x63b92f8`) are padding, not claimed.
- Census: direct `E8` call sites to caller A: 1 — `0x63a734e`
  (objdump- and rel32-confirmed; the preceding `lea` sets `rsi` to
  `r14+0x8700`). Direct `E8` call sites to caller B: 1 —
  `0x63c0ad3` (objdump- and rel32-confirmed; the preceding `lea`
  sets `rsi` to `rdi+0xf3b0`, `rdi` to `r15`). Direct `E9` jump
  sites to either caller: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to either caller: 0 of 60,723 entries.
  Internal calls within B: 5 (`pthread_mutex_trylock@plt` twice,
  `0x63bf680` twice, `pthread_mutex_unlock@plt` once) plus the
  tail-jump unlock. Internal jump targets in B: all lie inside
  `0x63b91e0..0x63b930c` except the tail jump to the unlock PLT.
  Caller A has one internal call (the merge) and no jumps.
- Disjointness: both FDEs overlap no claimed range from packets
  #183–#249 (1212 unique exhibit/FDE ranges checked across the
  merged tree and the prior worktree records, deduplicated by path
  string with ranges deduplicated as a set, 0 overlaps) and no other
  contributor's topic, addresses, or tables. The merge, the
  give-back, the reset, the insert, the register, the re-register,
  the size mapper, the handoff, the post-remove unlink, the removal
  entry, the class remove, the entry probe, the gate, the driver,
  and the allocator thunk are cited by address, not claimed here.
  The only records mention near these addresses is #234's text
  citation of the different neighbour FDE `0x63b8fe0..0x63b9180`,
  which ends where caller A begins; no byte of it is claimed here.

## Corrections to earlier packets

- **#249 confirmed and completed.** Its two merge callers are these
  FDEs: caller A passes its own arguments through (site
  `0x63b9190`), caller B passes `(dst = third arg,
  src = object+0x560)` (site `0x63b9272`); both add the
  `+0xc60`/`+0xc70` tail pair, and B's tail source
  (`object+0x1628`/`+0x1638`) is a different object region than
  its merge source.
- **#248 confirmed.** The reset's span is not touched here; these
  callers only read the object fields listed above and add into a
  destination.
- **#247 confirmed.** The insert's slot table, bitmap, and anchor
  are untouched here.
- **#246 confirmed.** Its global triple and counter region are the
  kind of state the merge accumulates, but no counter value is set
  here — only added, under B's locks.
- **#243 confirmed.** The give-back is not re-claimed here; the
  originally assigned #250 topic was its FDE, which is why this
  packet decodes the merge callers instead.
- **#234 confirmed.** Its driver FDE and the neighbouring FDE
  `0x63b8fe0..0x63b9180` are untouched here; caller A begins
  exactly where that neighbour ends.
- **#242, #241, #240, #239, #238, #236, #235, #233, #232, #216
  confirmed.** Nothing of theirs is re-claimed here.

## Unresolved

- What the wait helper `0x63bf680` waits on, and what its argument
  objects (`object+0xb0`, `object+0x40`) are — the helper itself is
  not decoded here.
- What the tail source region `object+0x1628`/`+0x1638` is, and
  whether it belongs to the same logical structure as the merge
  source `object+0x560`.
- The domain roles of the two locks (which lock guards what), and of
  the tag value `rdi` in caller B, beyond the counter/last-tag
  pattern proved here.
- Who calls caller A (site `0x63a734e`) and caller B (site
  `0x63c0ad3`) in the live call graph — the enclosing FDEs are not
  decoded here.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#251)

Decode the wait helper FDE `0x63bf680` end to end: what it waits on,
what it returns, and how its two argument objects (`object+0xb0` and
`object+0x40` in caller B) relate to the two locks — deciding what the
merge callers block on when trylock fails.

## Verification

- `tools/node115_lu_merge_callers.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, ret site (A) / no-ret (B), tail-jump
  rel32, all internal call rel32s, key bytes, jump targets
  internal, full census, neighbour disjointness, MANIFEST coverage
  (15 entries).
- `tests/test_node115_lu_merge_callers.py`: 10/10 pass.
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
  it; the deviation is disclosed here, as in #245–#249.
