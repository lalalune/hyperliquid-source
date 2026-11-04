# RE-001 node-115 lu workers — modes select call, skip, or top-up; the ref passes through untouched

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base upstream main `8fd8db6`. Static analysis only; no node execution.
Coordinate system: `.text` file offset = VA − 0x1000.

This packet answers packet #208's explicitly stated next question:
decode the inner route's two workers `0x63c19a0` / `0x63c1930` end
to end — what do modes 0, 1, and 2 − bss byte select, and what do
they do with the seg+0x29b0 reference passed through untouched by
the inner route?

## Shared calling convention (both workers)

`(thread, ref, C, arg4, arg5, mode)` = `(rdi, rsi, rdx, rcx, r8,
r9d)`, where ref is always seg+0x29b0 and C is always a record C
(seg+0x10ec8 or seg+0x115c0 — the two C's #206 found). Both workers
take the same sum from arg5 before anything else:

```
sum = [arg5+0x2618] + [arg5+0x4bd0]
```

via two calls to the 12-byte field loader `0x63b0510`
(`mov 0x25a8(%rdi),%rax; ret`) with `arg5+0x70` and `arg5+0x2628`.
Neither worker dereferences ref itself: ref is passed on as arg2
to the shared callee `0x63c1030` in every call both workers make.
The one thing the workers do with ref is nothing — that is the
answer to the second half of the question: ref is a pass-through
token for the callee, and the workers' own logic runs on C
(arg3) and arg5.

## WorkerB `0x63c1930..0x63c199d` (109B): unconditional forwarder

WorkerB ignores C entirely (no C read) and always calls the shared
callee once:

```
0x63c1030(thread, ref, C, arg4, arg5, mode, 0, sum)
```

with mode forwarded as the 6th argument (`movzbl %r15b,%r9d`).
Both observed callers pass mode 1 (inner branch `0x635fc71`,
FDE `0x6360ed0` site `0x63610a4`). WorkerB has no return
contract: both callers discard eax (inner proceeds to unlock;
`0x6360ed0` proceeds to unlock).

## WorkerA `0x63c19a0..0x63c1af4` (340B): three regimes, then modes

WorkerA first branches on `[C+0x78]` (#204's batch in-count label):

- `[C+0x78] < 0`: return 0, no calls at all.
- `[C+0x78] == 0`: skip the compute step, call
  `0x63c1030(thread, ref, C, arg4, arg5, 0, 0, sum)` once, return 0.
- `[C+0x78] > 0`: the compute path. It stamps a CLOCK_BOOTTIME
  nanosecond timestamp (`0x63bfcf0`, `clock_gettime(6)`) into a
  stack slot, then calls the compute callee
  `0x63a9750(C, &timestamp, sum)` and keeps its low byte `al`.
  WorkerA's own return value is that byte in every compute-path
  exit (directly, or zero-extended after the callee call).

On the compute path, mode (r9d) selects:

- **Mode 0**: capacity check only. If `[C+0xa0] >= sum`, return
  without calling. Else call
  `0x63c1030(thread, ref, C, arg4, arg5, 0, [C+0xa0],
  sum − [C+0xa0])` — a top-up of exactly the shortfall — then
  return `al`.
- **Mode 1**: return `al` without calling, unconditionally.
- **Mode 2**: like mode 0, but additionally gated on `al`: if
  `al == 0`, return without calling; else the same capacity
  check and top-up call.

Mode values observed at the four workerA call sites: inner route
`0x635fbd8` (0 when its 6th argument is nonzero, else
`2 − [.bss 0x6711ab8]` — one call site serving both via a
jump-back at `0x635fc88`), FDE `0x6360ed0` site `0x6360f7c`
(`2 − [.bss 0x6711ab8]`), FDE `0x6361170` site `0x63611ef`
(literal 0), FDE `0x63c1b00` site `0x63c1bfc` (its own r8
argument passed through, value not fixed in that FDE). No
observed caller passes literal 1; mode 1 arises when
`[.bss 0x6711ab8] == 1` (2 − 1). The byte is runtime-populated,
so the live mode cannot be fixed from the file alone; a byte
above 2 would make mode negative, which workerA treats like
mode 1 (not 0, not 2 → return).

## The shared callee's entry gate (characterised only)

`0x63c1030` (callee_gate.hex) is decoded only at its entry,
which is what makes the workers' calls meaningful:

- If `[C+0x70] != 0`, it returns immediately (no-op).
- Else if arg8 (the amount) == 0, it returns immediately.
- Else it sets `[C+0x70] = 1` and proceeds — a claim latch: the
  first non-empty call per C runs, later calls are no-ops.
- It then unlocks C's mutex (`pthread_mutex_unlock(C+0x40)`) —
  the lock the workers' callers hold — before its own work,
  which starts from `[ref+0xe408]` (seg+0x10db8) via `0x636b340`.

So workerA's capacity logic and the callee's latch compose:
workerA tops up only the shortfall, and the callee runs only the
first non-empty top-up per C. The rest of `0x63c1030` (including
what mode selects inside it, and what `0x63b2630` does with
arg7) is not decoded here.

## Census (whole `.text`, byte scan + per-site disassembly check; `.rela.dyn` for GOT)

- WorkerA `0x63c19a0`: 4 direct E8 (`0x635fbd8`, `0x6360f7c`,
  `0x63611ef`, `0x63c1bfc`), 0 E9, 0 LEA, 0 GOT.
- WorkerB `0x63c1930`: 2 direct E8 (`0x635fc71`, `0x63610a4`),
  0 E9, 0 LEA, 0 GOT.
- FDE bounds from `.eh_frame`: workerA `0x63c19a0..0x63c1af4`
  (340B), workerB `0x63c1930..0x63c199d` (109B).

## Exhibits (5, 196 bytes, 63 strict mnemonics)

- `wB_head.hex` — workerB `0x63c1930..0x63c195f` (47B, 16): arg
  saves, mode save, first field-load call.
- `wA_gate.hex` — workerA `0x63c19cf..0x63c19f2` (35B, 8):
  `[C+0x78]` load, signed gate, timestamp-call setup.
- `wA_mode.hex` — workerA `0x63c1a1c..0x63c1a32` (22B, 6): mode
  restore, mode-1 exit, `[C+0xa0]` capacity compare.
- `wA_call.hex` — workerA `0x63c1a6e..0x63c1a8e` (32B, 11):
  remainder, mode 0, top-up call to `0x63c1030`.
- `callee_gate.hex` — shared callee `0x63c1030..0x63c106c`
  (60B, 22 strict + 1 byte-continuation line): C+0x70 latch,
  arg8 gate, latch set. (callee_gate.objdump.txt has 23 lines.)

Claims not covered by a shipped excerpt (field loader body,
mode-2 computation, mode-0 jump-back, stack7 test, workerB mode
forward, workerB/==0-path call shapes, callee unlock) are covered
by exact key-byte checks in the verifier and tests, and are
marked address-cited in EVIDENCE.md.

## Corrections to earlier packets

None that change a verdict. #206 confirmed in full: stack7
selects workerB mode 1 vs workerA; workerA mode is 0 (6th
argument nonzero) or 2 − bss byte (6th argument zero); ref
passes through the inner route untouched; C is seg+0x10ec8 or
seg+0x115c0. #206's worker census (A 4 / B 2 sites) is
reproduced exactly by an independent byte scan. #204's C layout
is extended by one field use: +0xa0 is workerA's capacity /
already-credited amount, and +0x78 gates workerA's regime; the
+0x78 < 0 arm's meaning is unresolved (a count label does not
explain a negative arm — stated, not relabelled).

## Unresolved (stated, not inferred)

Full decodes of `0x63a9750` (compute callee: GOT predicate
selects C+0x98 vs C+0x88 for `0x63bfc00`; index clamped at 199
with a C+0xb0 table — beyond that, open), `0x63c1030` past its
entry gate (mode's role inside, `0x63b2630`'s use of arg7),
the semantic labels of arg4/arg5 beyond their roles above, the
identity of the object behind arg5's +0x2618/+0x4bd0 fields,
the FDE `0x6360ed0` workerB site's arg3/arg4/arg5 values (path-
dependent, restored from that FDE's saved slots), the FDE
`0x63c1b00` workerA site's pass-through mode value, all `.bss`
contents, and the purpose of `[C+0x70]` beyond the latch.

## Next question

Decode the shared callee `0x63c1030` past its entry gate: what
does it do with (thread, ref, C, arg4, arg5, mode, base,
amount), what does mode select inside it, and what does
`0x63b2630` do with the base? Behind it, still open: the
compute callee `0x63a9750` in full, the C-0x80 divisor source,
the entry+8 condvar waiters, the two runtime method pointees
([seg+0x29d0] / [seg+0x11cf0] writers), the drain helper
`0x51e8720`, the field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0` and unwind
callee `0x1680cab`.
