# RE-001 node-115 lu callee — the shared callee past its gate: mode arms the repurpose path, base gates the block selector

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base upstream main `8fd8db6`. Static analysis only; no node execution.
Coordinate system: `.text` file offset = VA − 0x1000.

This packet answers packet #209's explicitly stated next question:
decode the shared callee `0x63c1030` past its entry gate — what
does it do with (thread, ref, C, arg4, arg5, mode, base, amount),
what does mode select inside it, and what does `0x63b2630` do
with the base?

## Signature and frame

FDE `0x63c1030..0x63c1360` (816B). SysV arguments:

```
(thread, ref, C, arg4, arg5, mode, base, amount)
 = (rdi,   rsi, rdx, rcx,  r8,   r9d,  stack arg7, stack arg8)
```

`#209`'s entry gate stands as claimed: `[C+0x70]` latch, amount
at stack arg8 (`0x88(%rsp)` in the callee frame), base at stack
arg7 (`0x80(%rsp)`). Past the gate the callee saves: ref → rbp,
thread → rbx, arg5 → r12, mode → r15d, arg4 → `0x8(%rsp)`,
C → `0x10(%rsp)`, mutex `C+0x40` → `0x20(%rsp)`. It clears
`[C+0x68]`, then unlocks `C+0x40` (`pthread_mutex_unlock@plt` at
`0x63c1090`) before its own work — the same unlock-before-work
shape `#205`/`#206` showed for the central pool.

`arg4` is a pointer to a three-field statistics record, written
only at the end with atomic adds (see "Exit accounting" below).
`arg5` is the block-source record: it carries the same
lock-header layout as C through `+0x70` (mutex `+0x40`,
counters `+0x28`/`+0x30`/`+0x38`, flag `+0x68`), plus its own
chain fields at `+0x2610` (head), `+0x4bc8` (fallback),
`+0x4be0` (kind), `+0x4be8` (flag byte).

## Phase 1: the acquisition loop

The callee calls the pool accessor `0x636b340([ref+0xe408])`
once, then loops (`loop_call` exhibit):

```
block = 0x63b2630(thread, ref, pool, arg5, base)   # 0x63c10bd
if block == NULL: goto tail (see below)
link block into the circular doubly-linked list at +0x40/+0x48
  (fresh block self-links first: [block+0x40] = [block+0x48] = block)
pages += [block+0x10] >> 12
if pages < amount: loop again
```

The list head is r13 (NULL until the first block); the
accumulator is r14. The loop exits by amount reached
(`0x63c111c` / `0x63c1233`) or by selector NULL
(`0x63c10cb` → `0x63c1278`): NULL with pages != 0 still runs
phase 2 with the partial list; NULL with pages == 0 skips
phase 2 and the statistics entirely and goes straight to the
exit protocol. Whether sub-page blocks (size < 0x1000, zero
pages each) occur is not established from this FDE, so the
orphan-list edge that branch implies is stated, not claimed
as a defect.

## Mode's one role inside the callee

Mode is used exactly once (`callee_mode` exhibit). After the
second pool call (`0x63c112e`), the callee computes a flag r11:

```
r11 = 0
if mode == 0: r11 = ([ref+0xec88] != 0)
```

`mode != 0` leaves r11 = 0 without even loading the field.
r11 is saved to `0x2c(%rsp)` and gates exactly one thing in
phase 2 (below). Mode is dead after this point: the mode-0
arm overwrites r15 with the field value, and the walk resets
r15 as its own page accumulator. So mode selects nothing else
inside the callee — no branch on mode in the loop, the walk,
or the exit. Consequences for the known callers:

- WorkerB (mode forwarded, observed 1) → r11 = 0 always:
  every node takes the release path.
- WorkerA mode-0 top-up calls → r11 = ([ref+0xec88] != 0):
  the repurpose path is available only when that field is set.
- WorkerA mode-2 calls → r11 = 0: release path only, same as
  mode 1 inside the callee (workerA's mode-2 gating on `al`
  happens in workerA, before the call).

## Phase 2: the walk — release, or repurpose

The walk visits every acquired node once, unlinking each from
the circular list as it goes (the last node, self-linked, needs
no unlink). Per node it counts one node and adds
`[node+0x10] >> 12` pages. Then, per node, exactly one of two
paths runs:

**Release path** — taken when `[arg5+0x4be0] != 1`, or when
the r11 flag is 0, or when the repurpose probe below returns
nonzero:

```
0x63b3080(thread, ref, pool, node, [node+0x10] & ~0xfff)
```

The fifth argument is the page-aligned size, computed in the
walk (`and $0xfffffffffffff000`). Released bytes accumulate
in r12 (pages, shifted back to bytes at the end).

**Repurpose path** — taken only when `[arg5+0x4be0] == 1`
AND r11 != 0 AND the probe returns 0:

```
0x63b3c00(thread, pool, node, 0)          # probe; 0 = proceed
0x63b3b00(thread, ref, pool, ref+0x4c28, node)
```

Repurposed nodes skip the release call and contribute nothing
to r12. The internals of `0x63b3080`, `0x63b3c00`, and
`0x63b3b00` are not decoded here; only their argument shapes
and the selection logic are claimed.

Note the shared kind field: `[arg5+0x4be0]` is compared
against 1 here and against 2 inside the selector (below) —
same field, two thresholds, two different decisions.

## Exit accounting and exit protocol

On walk completion (`callee_stats` exhibit), with arg4's
record in r13:

```
lock addq $1, 0x0(arg4)        # one callee run
lock add %rdx, 0x8(arg4)       # rdx = node count
lock add %r14, 0x10(arg4)      # r14 = total pages
lock sub %r12, 0x38([ref+0xf310])   # r12 = released bytes
```

The empty-list path (`0x63c1356`) runs the same update with
zeros. Then the exit protocol (`callee_tail` exhibit):
try to re-acquire `C+0x40` (`pthread_mutex_trylock@plt` at
`0x63c128f`). On success it bumps `C+0x38`, tracks the owner
thread (`C+0x30`, changed-count `C+0x28`), clears the latch
`[C+0x70] = 0`, and returns. On trylock failure it calls the
wait helper `0x63bf680` (the same helper the selector uses on
its own trylock failure), sets `[C+0x68] = 1`, and then
proceeds down the same success path — so the latch is cleared
only after the mutex is actually re-held. `#209` described the
gate's set side; the clear side and the contention flag are
new here.

## The selector `0x63b2630` and the base

FDE `0x63b2630..0x63b2850` (544B). Its arguments are
`(thread, ref, pool, arg5, base)` = `(rdi, rsi, rdx, rcx, r8)`.
It locks arg5's mutex with the same trylock-or-wait protocol
(`pthread_mutex_trylock@plt` at `0x63b266e`, wait helper
`0x63bf680`, `[arg5+0x68]` flag, `+0x38`/`+0x30`/`+0x28`
bookkeeping), then:

```
head = [arg5+0x2610]; if head == NULL: head = [arg5+0x4bc8]
if head == NULL: return NULL
loop:
  sum = [arg5+0x2618] + [arg5+0x4bd0]   # two 0x63b0510 loads
  if base >= sum: return NULL           # base_gate exhibit
  if 0x63b0780(arg5+0x70, head) is bypassed by
     [arg5+0x4be8] == 0 or head flag bit 0x10000 set:
       goto take
  (flag byte != 0 and bit clear):
    0x63b1b60(thread, ref, pool, arg5, head, &flag)
    if flag != 0: 0x63b0560(arg5+0x70, result); loop again
  take:
    if [arg5+0x4be0] > 2: 0x63ae980(thread, head)
      (+ gated global page-counter decrement at 0x67121d8)
    else: 0x63adb50(thread, [ref+0xe410], head, 0)
    unlock arg5+0x40; return head
```

So the base is a threshold, not a pointer or a count to
consume: it is compared against the recomputed sum, and
`base >= sum` yields NULL with no block offered. Base is
never passed to any deeper callee — the only use of the
saved base (`0x18(%rsp)`) is that one comparison. The
composition with the workers is exact: workerB passes base 0
(blocks offered while sum > 0); workerA's mode-0 call passes
base `[C+0xa0]` (blocks offered only while the
already-credited amount is below the target sum); workerA's
`== 0` call passes base 0. Because the selector recomputes
sum on every call, a shrinking sum can turn later calls NULL
mid-loop — one way the callee's partial-acquisition path
arises (the other is chain exhaustion: both head pointers
NULL).

The retry loop re-reads `[arg5+0x2610]` after `0x63b0560`,
so progress requires that helper to advance the head (or
shrink sum below base); `0x63b0560`'s internals are not
decoded here, so the mechanism is stated as a requirement,
not a finding.

The selector has a second, independent caller outside the
callee: FDE `0x63c1c60..0x63c1cc5` loops
`0x63b2630(thread, ref, pool, ref+0x9818, 0)` until NULL,
passing each returned block to `0x63b2c40`. Base 0 there
means the gate never closes while sum > 0 — the selector is
a reusable next-block iterator, not callee-private.
`0x63b2c40` is not decoded here.

## Census (whole `.text`, byte scan + per-site disassembly check; `.rela.dyn` for GOT)

- Callee `0x63c1030`: 3 direct E8, 0 E9, 0 LEA, 0 GOT —
  workerB `0x63c1989`, workerA mode-0 `0x63c1a89`,
  workerA `== 0` path `0x63c1ae1`. No other callers.
- Selector `0x63b2630`: 2 direct E8, 0/0/0 — callee loop
  `0x63c10bd`, drain loop `0x63c1cad`.
- `.rela.dyn` (60,723 entries) has no addend equal to either
  target, so no GOT-mediated callers exist.

## Corrections and extensions to earlier packets

- `#209` confirmed in full: workerB's call shape (mode
  forwarded, base 0, amount sum), workerA's mode-0 shape
  (mode 0, base `[C+0xa0]`, amount shortfall) and `== 0`
  shape (mode 0, base 0, amount sum), the callee entry gate
  (latch, amount arg8, unlock, `[ref+0xe408]` via
  `0x636b340`), and the worker census it cited.
- `#209` extended: the gate's clear side — latch
  `[C+0x70] = 0` at exit, only after re-holding the mutex;
  contention sets `[C+0x68] = 1`. And arg5 shares C's
  lock-header layout through `+0x70` (mutex, counters,
  flag), with its own chain/kind fields beyond.
- `#204`'s C layout is otherwise untouched; no earlier
  verdict changes.

## Unresolved (stated, not inferred)

- Internals of `0x63b3080` (release), `0x63b3c00` (probe),
  `0x63b3b00` (repurpose), `0x63b0780`, `0x63b0560`,
  `0x63b1b60`, `0x63adb50`, `0x63ae980`, `0x636b340`
  (pool accessor), and `0x63b2c40` (drain-loop consumer).
- The `[ref+0xec88]` flag's writer and meaning; the
  `[ref+0xf310]` object's identity; the arg4 statistics
  record's consumer.
- Whether sub-page blocks occur (the NULL + zero-pages
  skip-walk edge); the `0x63b0560` retry mechanism.
- Still open behind this packet: the compute callee
  `0x63a9750` in full, the C−0x80 divisor source, the
  entry+8 condvar waiters, the two runtime method pointees
  ([seg+0x29d0] / [seg+0x11cf0] writers), the drain helper
  `0x51e8720`, the field-drop callees `0x5a50a10` /
  `0x5a4d200`, and #200's delegates `0x51f3e20` /
  `0x57ec1b0` and unwind callee `0x1680cab`.

## Next question

Decode the release function `0x63b3080` end to end: what
does it do with (thread, ref, pool, node, page-aligned size),
and what happens to the node afterwards — is it freed,
recycled, or handed on? Behind it, still open: the
repurpose pair `0x63b3c00` / `0x63b3b00`, the selector's
`0x63b1b60` and `0x63b0560`, the compute callee `0x63a9750`,
and the items listed above.
