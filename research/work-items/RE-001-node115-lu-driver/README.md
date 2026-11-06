# RE-001: the node #115 lu loop driver — three rounds, gate, accumulated count

## Summary

Packet #233's next question: what the driver FDE at `0x63b8d90`
does end to end — how it accumulates the loop caller's returns
across its three call sites, what its intermediate `0x63b85f0`
call does between rounds, and when it stops.

It is a single FDE, `0x63b8d90..0x63b8fd1` (577 bytes, one `ret`
at `0x63b8de7`, reached through a shared epilogue). It takes a
total count and an entry-slot pointer, drives the loop caller
(#233) in up to three rounds with remaining-count budgets, and
returns the accumulated spliced count. The rounds are not a loop:
round 1 runs under no driver-held mutex, round 2 under the
second mutex (`context+0xf0`), and round 3 under the first mutex
(`context+0x80`) after a gate call. The intermediate `0x63b85f0`
call is a go/no-go gate between rounds 2 and 3: it returns zero
to stop, nonzero to continue. So the loop caller is driven by a
staged driver that spends its budget in at most three tranches,
and the accumulated count is the total number of entries the
driver built into the entry-slot chain across those tranches.

## Arguments

- `rdi` = first-argument object (saved as `rbp`; thread-accounting
  identity, also the loop / gate / completion first argument).
- `rsi` = context object (saved as `r14`).
- `rdx` = size argument (saved as `r12`; passed to the loop calls
  and the gate call).
- `rcx` = total count (saved as `rbx`). Every round's budget is
  derived from it minus what is already accumulated.
- `r8` = entry-slot pointer (saved at the frame base). Passed as
  the loop caller's `r9` at all three call sites.
- `r9` = completion-byte pointer (saved as `r13`). Pushed as the
  loop caller's stack argument at all three call sites; the loop
  caller sets that byte to `1` on its epilogue paths.

There is no driver stack argument: the driver reads no stack
argument of its own. Its frame locals are the flag byte at
`rsp+0x37` (its own byte, passed as the loop caller's `rcx` at
all three sites), the canary at `rsp+0x38`, and saved
mutex/helper pointers for the contention paths.

## Guard and return-0 path

Entry is `endbr64` followed by pushes and `sub $0x48, %rsp`.
The accumulator `r15` starts at `0`. The single guard is
`cmp %rdx, 0x15f8(%rsi)` with `jae` to the main path: if
`[context+0x15f8] < size`, the function returns `0` immediately
through the shared epilogue (canary check, pops, `ret`). This is
the same guard shape as #232's single-shot caller
(`[context+0x15f8] < rdx`), here returning a count of `0`
rather than a NULL pointer.

## Round 1: no driver-held mutex

The flag byte is initialised to `0`; the flag-byte pointer is
saved on the stack. The first loop call at `0x63b8e1a` passes
(first-arg, context, size, flag-byte-ptr, count = total,
entry-slot, completion-byte-ptr). After the call:

- `r15 := return` (accumulated = first round's spliced count).
- If `return == total`, jump to the epilogue: return `total`.
- If the flag byte is nonzero (the loop caller set it on a
  NULL-item or predicate-divert early exit), jump to the
  epilogue: return the partial accumulated count.

No mutex is held on this path, and neither contention flag
(`[context+0x118]`, `[context+0xa8]`) is touched.

## Round 2: second mutex, remaining budget

The driver takes the second mutex, `context+0xf0`, with
`pthread_mutex_trylock`. On failure the contention helper
`0x63bf680(context+0xb0)` runs (note: helper argument =
mutex − `0x40`, the same pattern as the first mutex's
`context+0x40` for `context+0x80`), `[context+0x118] := 1`
marks contention, and control rejoins the post-lock code (see
"Contention semantics" below). Second-mutex thread accounting
follows: `[context+0xe8]++`, and on first-argument change
`[context+0xd8]++` with `[context+0xe0] := first-arg`.

The second loop call at `0x63b8e95` passes count =
`total − accumulated` (`sub %r15, %r8`). After the call:

- `r15 += return`.
- If `accumulated == total`, go to the early-exit path: clear
  `[context+0x118]`, unlock `context+0xf0`, return accumulated.
- If the flag byte is nonzero, take the same early-exit path.

## Gate: the intermediate 0x63b85f0 call

If round 2 neither completed the total nor set the flag, the
driver calls `0x63b85f0(first-arg, [context+0x38], size,
flag-byte-ptr)` at `0x63b8ec2` — cited by address only, not
decoded here. Its return decides the next step:

- Zero: take the early-exit path (clear `[context+0x118]`,
  unlock `context+0xf0`, return accumulated).
- Nonzero: continue to round 3.

The gate takes the `context+0x38` object as its second argument
(the same object #232's wake path calls virtually through
`*0x128`), the size, and the flag-byte pointer. What it checks
is not settled by these bytes; its position — after round 2's
accumulation and before any round-3 work — makes it a
go/no-go gate on spending a third tranche, not a per-item test.

## Round 3: first mutex, completion call, final tranche

The driver takes the first mutex, `context+0x80`, with
`pthread_mutex_trylock`. On failure the contention helper
`0x63bf680(context+0x40)` runs, `[context+0xa8] := 1` marks
contention, and control rejoins the post-lock code.
First-mutex thread accounting follows: `[context+0x78]++`,
and on first-argument change `[context+0x68]++` with
`[context+0x70] := first-arg` — the same accounting group the
loop caller itself maintains.

Then, with the remaining budget (`rbx := total − accumulated`)
already computed:

- `0x63d94b0(record)` at `0x63b8f1a`, where record =
  `context+0x140` — a completion helper, cited only. Note this
  target is 16 bytes past #232/#233's `0x63d94a0`; it is a
  distinct call target as observed, not identified with that
  helper (see Unresolved).
- `[context+0xa8] := 0` (contention flag cleared).
- Unlock `context+0x80`.
- The third loop call at `0x63b8f4d` passes count =
  `total − accumulated` and the same other arguments.
- `[context+0x118] := 0` (second-mutex contention flag cleared).
- `r15 += return`; unlock `context+0xf0`; return accumulated.

Round 3 has no post-call check: unlike rounds 1 and 2, the
driver does not test the total or the flag byte after the third
call. The third round always ends the function.

## Epilogue and return contract

Every path funnels through `0x63b8dc2`: canary check (failure
goes to `__stack_chk_fail`), `mov %r15, %rax`, pops, single
`ret` at `0x63b8de7`. The return value is the accumulated
spliced count across the rounds actually run:

- `== total` on full completion (any round reaching the total).
- Partial on flag-byte exits (rounds 1 and 2), on a zero gate
  return (after round 2), and on round 3's unconditional end.
- `0` on the entry-guard failure.

So what the accumulated count means to the driver's caller is
the total number of entries the driver built into the
entry-slot chain: each loop round splices its built entries
after the chain head (#233), and the driver sums the spliced
counts. A partial return is not an error code — it is the
count of entries actually built before the driver stopped.

## Contention semantics

On either `pthread_mutex_trylock` failure, the contention path
calls `0x63bf680(mutex − 0x40)`, sets the matching contention
flag byte (`[context+0x118]` for `+0xf0`,
`[context+0xa8]` for `+0x80`), and jumps directly back to the
post-lock code (`0x63b8e56` for the second mutex,
`0x63b8efc` for the first). No second `trylock` instruction
appears on either contention path: the helper call is treated
as delivering the lock, not as a prelude to retrying the
trylock in this FDE. The same shape appears in #233's loop
caller (contention block `0x63b84f0..0x63b84ff` jumps to
`0x63b8212`, the post-lock code), so #232/#233's "retried"
wording is refined here to helper-then-rejoin: whether the
helper itself spins until it holds the lock is the helper's
business, not a second trylock in these FDEs.

One observed quirk, stated not explained: the first-mutex
contention path reloads the saved gate return into `rsi`
before rejoining the post-lock code, but the rejoined path does
not consume `rsi` before reassigning it for the third call.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032
  bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis; the
  binary is byte-identical to the `8fd8db6` base — same git
  blob SHA and size — so the target hash is unchanged).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b8d90..0x63b8fd1`); the following bytes
  `0x63b8fd1..0x63b8fe0` are `int3` padding and the next
  function starts with `endbr64` at `0x63b8fe0`. Static
  analysis only; the binary was never executed.
- 6 exhibits, 410 bytes, 106 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `dr_entry` | `0x63b8d90..0x63b8df0` | 96 | 28 | Entry, guard, shared epilogue |
| `dr_call1` | `0x63b8df0..0x63b8e31` | 65 | 20 | First loop call, done/flag checks |
| `dr_lock2` | `0x63b8e31..0x63b8e76` | 69 | 12 | Second mutex, accounting |
| `dr_call2` | `0x63b8e76..0x63b8eb3` | 61 | 17 | Second call, accumulate, checks |
| `dr_gate` | `0x63b8eb3..0x63b8ed0` | 29 | 7 | Gate call, zero test |
| `dr_call3` | `0x63b8f10..0x63b8f6a` | 90 | 22 | Completion call, third call, return path |

- Census: direct `E8` call sites to `0x63b8d90`: 0. Direct `E9`
  jump sites: 0. Rip-relative `LEA` sites: 1 — `0x63b90ea`,
  in FDE `0x63b8fe0..0x63b9180`, loading the driver address
  into `rcx` immediately before loading the single-shot
  caller's address (`0x63b8820`) into `rsi` at `0x63b90f5`:
  the neighbouring function passes both FDEs as callback
  arguments (cited, not claimed). `.rela.dyn` addends equal
  to `0x63b8d90`: 0 of 60,723 entries. Internal calls within
  the FDE: 13 (3 loop calls, 2 trylocks, 3 unlocks, 1 gate,
  1 completion, 2 contention, 1 stack-check). Internal jump
  targets: all 10 distinct targets lie inside
  `0x63b8d90..0x63b8fd1`.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#233 and no other contributor's topic, addresses, or
  tables — checked against all 182 records files in the new
  tree (193 ranges, zero overlaps) plus #232's FDE
  (`0x63b8820..0x63b8d85`) and #233's FDE
  (`0x63b81b0..0x63b8517`), which sit adjacent but disjoint.
  The loop caller, the gate, the completion helper, the
  contention helper, and the neighbouring callback function are
  cited by address, not claimed here.

## Corrections to earlier packets

- **#233 confirmed and completed.** Its "next question" is
  answered here: the driver is this FDE; its three call sites
  (`0x63b8e1a`, `0x63b8e95`, `0x63b8f4d`) pass remaining
  budgets — the first call's remaining equals the total
  because the accumulator starts at `0` — and the driver
  accumulates the spliced counts and returns the total. No
  correction to #233's bytes or counts.
- **#230 confirmed.** Its driver-site notes match: three loop
  calls in FDE `0x63b8d90..0x63b8fd1`, accumulating returns
  until the total is reached or the flag byte is set — with
  the gate-zero stop and the unconditional third-round end now
  added as further stop conditions.
- **#232/#233 refined, not contradicted.** Their "contention
  helper runs and the lock is retried" wording is refined to
  helper-then-rejoin: in this FDE (and, observed, in #233's
  contention block) the helper call is followed by a direct
  jump to the post-lock code, with no second trylock
  instruction. The lock-acquisition outcome is unchanged;
  only the mechanism description is corrected.
- **#232 confirmed.** Its second-phase shape (second mutex
  `context+0xf0`, loop calls, first-mutex completion work)
  recurs here as the driver's round 2 / round 3 structure,
  with different budgets: #232's second phase calls with count
  `1` then `1 − first return`; this driver calls with the
  remaining total each round.

## Unresolved

- The identity and semantics of the gate `0x63b85f0`: what it
  checks in `(first-arg, [context+0x38], size, flag-byte-ptr)`
  and why a zero return stops the driver after round 2.
- Whether `0x63d94b0` is a distinct helper or an alternate
  entry into the `0x63d94a0` completion helper's region: it is
  a distinct call target 16 bytes past `0x63d94a0`, cited as
  observed, not identified.
- The identity of the neighbouring function
  (`0x63b8fe0..0x63b9180`) that passes the driver and the
  single-shot caller as callbacks, and what it does with the
  driver's accumulated-count return.
- The purpose of the saved gate return being reloaded into
  `rsi` on the first-mutex contention path when the rejoined
  path does not consume it.
- Whether the `+0x50`/`+0x58` in-use list or any other
  structure observes the entry-slot chain order the rounds
  build, or only the slot head matters.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#235)

Decode the gate `0x63b85f0` end to end: what it checks in
`(first-arg, [context+0x38], size, flag-byte-ptr)`, why a zero
return stops the driver after round 2, and whether it can set
the flag byte itself — this decides what stands between the
driver's second and third tranches. The neighbouring callback
function (`0x63b8fe0..0x63b9180`) and its use of the driver's
accumulated-count return are the following question, not this
packet's claim.

## Verification

- `tools/node115_lu_driver.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, single `ret`, key call rel32s, guard/accumulate/
  remaining/gate/contention/return stores, all branch targets
  internal, full census, neighbour disjointness, MANIFEST
  coverage (17 entries).
- `tests/test_node115_lu_driver.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression. The
  packet itself adds no tracked catalogue input (its files are
  untracked, and the check reads tracked files only).
- Full `make test`: the new base carries 584 test files, up from
  77 on the old base. A full run reached [157/584] with 0
  failures before a VM restart terminated it mid-run (the log
  ends `Terminated`, with no final tally); the run was not
  resumed, since a full 584-file run takes hours at this scale.
  This packet's own file did not run inside that interrupted
  run and passes 10/10 standalone.
