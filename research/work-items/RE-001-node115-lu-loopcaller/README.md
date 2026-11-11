# RE-001: the node #115 lu loop caller — count-bounded class-minimum consumption, splice, count return

## Summary

Packet #232's next question: what the loop caller at `0x63b81b0`
does end to end — how it iterates items, whether each iteration
consumes one class minimum the same way as the single-shot caller,
and what its count argument and entry slot do.

It is a single FDE, `0x63b81b0..0x63b8517` (871 bytes, one `ret`
at `0x63b84d4`). Each iteration consumes exactly one class minimum
with the same sequence as the single-shot caller in #232 — fetch,
class search, take, stamp, value compute, entry build,
predicate/wake handling, give-back — and then additionally splices
the built entry into the chain rooted at the entry-slot argument.
The loop runs until the spliced count reaches the count argument,
and returns that spliced count. So the single-shot consumption in
#232 is a separate FDE duplicating this loop's body once, not the
loop's body inline: the loop adds count-bounded repetition,
per-iteration splicing, and a spliced-count return.

## Arguments

- `rdi` = first-argument object (saved; thread-accounting identity,
  also the fetch / predicate / completion first argument).
- `rsi` = context object (`rbx`).
- `rdx` = size argument (`r13`, passed to the class search and the
  value compute).
- `rcx` = early-stop flag-byte pointer. Set to `1` when the fetch
  returns NULL or when the predicate diverts an iteration; never
  set on the class-search-NULL path or on full completion.
- `r8` = iteration count bound (saved at `rsp+0x30`). The loop
  exits when the spliced counter `rbp` equals it; `0` returns `0`
  immediately (after lock acquisition and release).
- `r9` = entry-slot pointer (saved at `rsp+0x20`). Each built entry
  is spliced into the chain rooted at `[slot]`.
- Stack argument = completion-byte pointer (saved at `rsp+0x48`).
  Set to `1` on every epilogue path.

## Prologue and lock

Entry is `push %r15; push %r14; push %r13; push %r12; push %rbp;
push %rbx; sub $0x68, %rsp` — notably, the FDE starts with pushes,
not `endbr64` (see the #230 correction below). It takes the
`context+0x80` mutex with `pthread_mutex_trylock`; on failure the
contention helper `0x63bf680(context+0x40)` runs and the lock is
retried, with `[context+0xa8] := 1` marking contention. Thread
accounting follows: `[context+0x78]++`, and on first-argument
change `[context+0x68]++` with `[context+0x70]` updated. The
counter `rbp` starts at `0`; `r12 = context+0x140` is the record
for the class search.

## One iteration, in order

Loop head at `0x63b8250` (identical in shape to #232's main path):

1. **Fetch.** `r15 = 0x63b5840(first-arg, context+0x128)`; the
   returned 16-byte pair is saved at `rsp+0x10`. NULL diverts to
   the flag-set path (step 8).
2. **Class search.** `r14 = 0x63d9340(record, size)` (#230,
   cited only). NULL diverts to the release path (step 8) after
   `0x63b59e0(first-arg, context+0x128, item)`.
3. **Take.** `0x63d8e70(record, r14)` (cited only): the node
   leaves the class's free accounting.
4. **Stamp.** If `[r14+0x68] == 0`, the counter at
   `[context+0x15e0]` is consumed: `[r14+8] := old counter`,
   counter++.
5. **Value and build.** `r9 = 0x63ba680(r14, size)` (cited only);
   a new live entry is written at `r15` with the same field
   construction as #232 (`[r15]` rebuilt from page bits, low 12
   bits of `[r15+0x10]`, `[context+0x15e8]`, size, constant
   `0xe806000` under mask `0xffffeffff0000fff`;
   `[r15+8] := r9`; `[r15+0x20] := [r14+8]` (the stamp);
   `[r15+0x50] := 0`; `[r15+0x18] := r14`).
6. **Predicate and wake.** `0x63ae2b0(first-arg,
   [context+0x15f0], r15)` (cited only) returning nonzero diverts
   to the predicate path: `0x63bb330` call, give-back, release,
   flag set, epilogue — the iteration is neither spliced nor
   counted. Otherwise the wake-flag block runs exactly as in #232
   (`[r14+0x20]` high bytes, `[r14+0x68]` vs `[r14+0xb0]` into
   `[r14+0x13]`, size check against `[context+0x1600]`,
   `[r14+0x10] == 0` gating the virtual call `*0x128([context+0x38])`
   with output to `[r14+0x18]` and `[r14+0x14] := 1`, cleared
   again when `[r14+0x68] == 0`).
7. **Give-back and splice.** `0x63d9070(record, r14)` (cited
   only) re-registers the node. Then the splice block — the one
   step #232's single-shot path skips — runs unconditionally:
   the saved fetch pair is written to `[r15+0x28]`; if
   `[slot] == 0`, `[slot] := r15`; otherwise the new entry is
   inserted into the chain after the current head (head itself
   unchanged: `[head+0x30] := new`, `[new+0x28] := head`,
   `[new+0x30] := [pair-high+0x28]`,
   `[[pair-high+0x28]+0x28] := new`), and `[slot]` is rewritten
   with the (unchanged) head. `rbp++`; if `rbp != count`, loop.
8. **Early exits.** NULL item: flag byte `:= 1`, epilogue.
   Class-search NULL: release, epilogue (flag byte untouched).
   Predicate divert: give-back, release, flag byte `:= 1`,
   epilogue. In all three, the return value is the spliced count
   so far (iterations that were spliced, not iterations
   attempted).

## Epilogue and return

`0x63b7900(first-arg, context, 0)` then `0x63d94a0(record)`;
if the latter returns zero, `0x63b76b0(context)` runs first.
Either way the stack completion byte `:= 1`,
`[context+0xa8] := 0`, the mutex is unlocked, and the function
returns `rbp` — the spliced-iteration count (`== count` on full
completion). Loop-exit path restores `rbp := count` before the
epilogue, so the two agree.

## The count and the entry slot, answered

- The count argument is a splice budget, not an item budget: the
  loop counts only iterations that reach the splice. A predicate
  divert consumes a class minimum (take + give-back) without
  counting it, and a NULL fetch or NULL class search ends the
  loop early with a partial count.
- The entry slot is the accumulation point: the loop's built
  entries are chained through it, head-first (first entry becomes
  head; later entries insert after the head). This is exactly the
  slot #232's second phase passes (its stack slot) and the slot
  #232's single-shot path leaves untouched (guard `0`).
- The return contract is what makes the drivers work: #232's
  second phase calls with count `1`, then with count
  `1 - first return` (call sites `0x63b8baf`, `0x63b8c59`,
  cited by address), and the driver FDE at `0x63b8d90`
  accumulates returns across three call sites until the total is
  reached or the flag byte is set (sites `0x63b8e1a`,
  `0x63b8e95`, `0x63b8f4d`, cited by address).

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Loop caller `0x63b81b0`: 5 direct E8, 0 E9,
0 LEA, 0 GOT. E8: `0x63b8baf` and `0x63b8c59` (single-shot caller
FDE, #232 — first with count 1, second with count `1 - first
return`), `0x63b8e1a`, `0x63b8e95`, `0x63b8f4d` (driver FDE
`0x63b8d90..0x63b8fd1` — accumulating driver, cited by address
only, not decoded here).

## Corrections to earlier packets

- **#230 corrected.** Its first class-search caller's enclosing
  FDE is this FDE (`0x63b81b0..0x63b8517`), not
  `0x63b8160..0x63b81ab`: that range is the preceding tiny
  wrapper function (`endbr64`, one call to `0x63b7ef0`, `ret`),
  which cannot contain site `0x63b827f`. The site's argument
  setup (`r12` record, `r13` size, NULL test) matches #230's
  note exactly — only the FDE range was wrong. The likely cause:
  this FDE's entry has no `endbr64`, so a scan for the nearest
  preceding `endbr64` lands on the wrapper instead.
- **#232 confirmed and completed.** Its second-phase delegation
  targets this FDE, and the single-shot consumption is a separate
  FDE duplicating this loop's body once (same fetch, search,
  take, stamp, value, build, predicate, wake, give-back) minus
  the splice and the count return.
- **#231 confirmed.** The consumer's merged minimum is what each
  loop iteration takes and re-registers; the loop is the general
  form of that consumption.
- No bytes claimed by packets #183–#232 are re-claimed. All
  exhibits lie strictly inside the loop-caller FDE; the fetch,
  class search, take, value, predicate, wake, give-back, release,
  completion, contention, and fallback helpers, the single-shot
  caller, and the driver FDE are cited by address only.

## Unresolved, stated not inferred

The identity and semantics of the fetched item (`0x63b5840`) and
the value computed by `0x63ba680`; the wake predicate
(`0x63ae2b0`) and the virtual `*0x128` call's role in setting
node `+0x14`/`+0x18`; the completion-byte protocol and the
`0x63d94a0`/`0x63b76b0` pair's return contract; why this FDE's
entry has no `endbr64` while its neighbours do, and whether that
affects indirect-call reachability; whether the entry-slot chain
order (head unchanged, new entries inserted after the head) is
observable to later passes, or only the slot head matters; the
driver FDE `0x63b8d90..0x63b8fd1`'s purpose beyond accumulating
loop returns.

## Next question

Decode the driver FDE `0x63b8d90..0x63b8fd1` end to end: how it
accumulates the loop caller's returns across its three call sites,
what its intermediate `0x63b85f0` call does between rounds, and
when it stops — this decides what the loop caller is driven by and
what the accumulated count means to its caller.

## Verification

- Static verifier `tools/node115_lu_loopcaller.py`: exit 0
  (6 excerpts, 475 bytes, 114 strict mnemonics, census 5 E8
  sites, MANIFEST 17/17).
- Unit tests `tests/test_node115_lu_loopcaller.py`: 10/10.
- `make verify`: exit 0 (29 manifests, 473 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 10/10.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#232 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.
