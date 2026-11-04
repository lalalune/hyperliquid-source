# RE-001: the node #115 lu class-minimum consumer — take, stamp, re-register, return

## Question

Packet #231's next question: what does the class-search caller do with
the merged chain's minimum node — and does the returned node leave the
class's slot, or stay linked there?

## Answer

The single-shot class-search caller, FDE `0x63b8820..0x63b8d85`
(1381 bytes, single `ret` at `0x63b889f`), consumes the minimum: it
takes it out of the class's free accounting, stamps it, builds a new
live entry around it, re-registers it in the record's in-use
accounting, and returns the new entry. The node is **not freed**,
**not dropped**, and **not unlinked from its chain by this caller**
(no store to `[slot]` or to the `+0x28`/`+0x30`/`+0x38` chain appears
in the main path) — but it **does leave the class's free slot** in
the accounting sense: the take helper decrements the free counts and
the give-back helper increments the in-use counts, with the node's
size moving into the in-use totals.

## Main path, in order

Arguments: `rdi` = first-argument object (`r12`), `rsi` = context
object (`rbx`), `rdx` = size argument (`r13`), `rcx` = bound,
`r8b` = flag, plus a stack-argument completion-byte pointer.

1. **Guards (exhibit `cm_entry`).** Return NULL (`0`) immediately
   if `rcx > 0x1000`, if `r8b != 0`, or if
   `[context+0x15f8] < rdx`. Otherwise proceed.
2. **Lock.** `pthread_mutex_trylock(context+0x80)`; on failure the
   contention helper `0x63bf680(context+0x40)` runs and the lock is
   retried. Thread accounting follows: `[context+0x78]++`, and
   `[context+0x70]`/`[context+0x68]` update when the first argument
   changes.
3. **Fetch (exhibit `cm_fetch`).** `r15 = 0x63b5840(r12,
   context+0x128)`; the returned pair is saved on the stack. A NULL
   item diverts to the second phase with a flag set (see below).
4. **Class search (exhibit `cm_fetch`).** `rbp = context+0x140`;
   `r14 = 0x63d9340(rbp, r13)` — packet #230's helper, cited only.
   A NULL return diverts to the release path (`0x63b59e0`) and then
   the second phase.
5. **Take (exhibit `cm_take`).** `0x63d8e70(rbp, r14)` — cited only.
   From its bytes: it sets `node+0x23 := 1` and decrements the
   class's slot-entry counts and the record totals (the free side).
   This is the moment the node leaves the free slot.
6. **Stamp (exhibit `cm_take`).** If `[r14+0x68] == 0`, the counter
   at `[context+0x15e0]` is consumed: `[r14+8] := old counter`,
   counter++. (When `[r14+0x68] != 0` the stamp is skipped.)
   Then `r9 = 0x63ba680(r14, r13)` — value compute, cited only.
7. **Build (exhibit `cm_build`).** A new live entry is written at
   `r15`: `[r15]` is rebuilt from the old word's page bits, the
   low 12 bits of `[r15+0x10]`, `[context+0x15e8]`, `r13`, and the
   constant `0xe806000` (with the `0xffffeffff0000fff` mask);
   `[r15+8] := r9`; `[r15+0x10]` keeps its low 12 bits;
   `[r15+0x20] := [r14+8]` (the stamp);
   `[r15+0x50] := 0`; `[r15+0x18] := r14` — the new entry points
   back at the consumed node.
8. **Predicate (cited).** `0x63ae2b0(r12, [context+0x15f0], r15)`
   returning nonzero diverts to the `0x63b8c78` path (which calls
   `0x63bb330`, then the give-back helper, then `0x63b59e0`, sets
   the second-phase flag, and continues at the second phase).
   A zero result continues below.
9. **Wake flags (cited).** If `0x20(r14)` has any high byte set,
   `[r14+0x13] := 0` and control jumps to step 10. Otherwise
   `[r14+0x68]` vs `[r14+0xb0]` sets `[r14+0x13]`, a size check
   against `[context+0x1600]` and a `[r14+0x10] == 0` check gate a
   virtual call `*0x128([context+0x38])` with `(stack slot, 1)`,
   whose output becomes `[r14+0x18]` with `[r14+0x14] := 1`;
   if `[r14+0x68] == 0` then `[r14+0x14] := 0`.
10. **Give-back (exhibit `cm_give`).** `0x63d9070(rbp, r14)` —
    cited only. From its bytes: it clears `node+0x23 := 0`,
    increments the class's slot-entry counts and the record totals
    (the in-use side; net over the take/give-back pair, the node's
    size moves into entry field 1 and record `+0x410`), and
    conditionally moves the node in the `+0x50`/`+0x58`
    doubly-linked list rooted at `[record+0x1498]`:
    `+0x14 != 0` with `+0x20 == 0` inserts at the head;
    `+0x14 == 0` with `+0x20 != 0` splices out (with a head-removal
    case that empties the list or promotes the successor).
11. **Splice guard (exhibit `cm_give`).** The saved item pair is
    written to `[r15+0x28]`, and the splice block that follows is
    guarded by the stack local at `[rsp+0x48]`, which this
    single-shot path initialised to `0` and never set before the
    test — so the splice is skipped here. (The loop caller A, by
    contrast, passes a live entry slot.)
12. **Return (exhibit `cm_ret`).** `[rsp+0x48] := r15`; the
    completion helpers `0x63b7900` and `0x63d94a0(rbp)` run; the
    caller's completion byte is set from their results; the mutex
    is unlocked; then either the second phase runs (below) or
    control reaches `mov 0x48(%rsp),%rax; jmp` to the epilogue —
    **the function returns the new entry `r15`**, which embeds the
    consumed minimum node at `+0x18`.

## Second phase (cited, not decoded)

When the second-phase flag is clear, the caller takes a second
mutex (`context+0xf0`), calls the loop caller `0x63b81b0` twice
(first with count 1, then with count `1 - first-return`), and
finally returns the same entry. The loop caller's interface —
its count argument, its entry slot, and its return contract — is
the next question, not a claim of this packet.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Caller `0x63b8820`: 0 direct E8, 0 E9, 1 LEA,
0 GOT. LEA: `0x63b90f5` (a neighbouring function loads this FDE's
address into `rsi` alongside other function pointers — a callback
reference, cited only). The caller has no direct callers.

## Exhibits

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `cm_entry` | `0x63b8820..0x63b8874` | 84 | 20 | Entry, guards, lock setup |
| `cm_fetch` | `0x63b88de..0x63b8923` | 69 | 16 | Item fetch, class-search call, NULL tests |
| `cm_take` | `0x63b8929..0x63b895c` | 51 | 12 | Take call, stamp, value compute |
| `cm_build` | `0x63b895c..0x63b89c0` | 100 | 22 | New-entry field writes, node embed |
| `cm_give` | `0x63b8a3d..0x63b8a5a` | 29 | 7 | Give-back call, pair write, splice guard |
| `cm_ret` | `0x63b8ad0..0x63b8ada` | 10 | 2 | Return-value load, epilogue jump |

6 exhibits, 343 bytes, 79 strict instructions (strict =
mnemonic-line count: address + bytes field + tab + mnemonic;
objdump byte-continuation lines excluded).

## Corrections to earlier packets

- **#231 confirmed and completed.** The consumer's returned
  minimum node is what this caller takes, stamps, embeds, and
  re-registers. The consumer's `[slot] := minimum` write is not
  undone here: no store to `[slot]` or to the chain pointers
  appears in this caller's main path.
- **#230 confirmed.** This caller is the second class-search
  caller (call site `0x63b8918`, record `rbx+0x140`, size arg
  `r13`); its NULL test on the return matches #230's note. The
  returned minimum is consumed here, not merely observed.
- **#224 confirmed.** The slot second-word convention recurs as
  the entry's `+0x50 := 0` preparation and the consumer's entry
  write.

## Unresolved, stated not inferred

- The identity and semantics of the fetched item (`0x63b5840`)
  and the value computed by `0x63ba680`.
- The wake predicate (`0x63ae2b0`) and the virtual `*0x128`
  call's role in setting `node+0x14`/`+0x18`.
- The completion-byte protocol (stack argument) and the
  `0x63d94a0`/`0x63b76b0` pair's return contract.
- The second-phase delegation to loop caller A: its count
  argument, entry slot, and when it returns 1.
- Whether the `+0x50`/`+0x58` list at `record+0x1498` is the
  in-use list, and what the `+0x14`/`+0x20` flag pair means
  outside this path.
- The purpose of the skipped splice block (guard local
  initialised to 0 in this single-shot path).

## Next question

Decode the loop caller `0x63b81b0` end to end: how it iterates
items, whether each iteration consumes one class minimum the same
way, and what its count argument and entry slot do — this decides
whether the single-shot consumption here is the loop's body or a
separate path.
