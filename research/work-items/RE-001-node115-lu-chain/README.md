# RE-001-node115-lu-chain: the node #115 chain helper

This packet answers packet #212's explicitly stated next question:
decode the chain helper `0x63b1b60` end to end: what does it do
with (thread, ref, pool, dest, node, &flag), what does it return,
and what does the flag byte select?

## Answer in one line

The helper walks a chain: it repeatedly asks `0x63ae260` for the
next node, runs `0x63b0780` and the `0x63b1810` byte test on it,
joins (`0x63adb50` + `0x63b0560`) when the test says so, and
otherwise either advances or exits — returning the latest node
and writing *flag = 1 only when the caller must keep chaining,
*flag = 0 when the chain is done. It never frees a node and
never manufactures a NULL.

## What it shows

1. **Signature and entry.** FDE `0x63b1b60..0x63b1d5a`
   (506B), single `ret` at `0x63b1d35`: (thread, ref, pool,
   dest, node, &flag) = (rdi, rsi, rdx, rcx, r8, r9).
   Prologue saves thread (r13), ref (r12), dest (rbx),
   dest+`0x70` (r14), current node (rbp), pool
   ([rsp+`0x8`]), and the flag pointer ([rsp+`0x18`]).
   A second, local flag byte lives at [rsp+`0x17`];
   it is not the out-parameter.

2. **The loop head.** Each iteration calls
   `0x63ae260(thread, [ref+0xe410], cur, 0, kind, 1)`
   where kind = [dest+`0x4be0`]. On NULL it falls to
   the retry block (item 5). On a node it runs
   `0x63b0780(dest+0x70, nxt)`, then the byte test
   `0x63b1810(thread, ref, pool, cur, nxt)`.

3. **Test nonzero: join, then retry.** When the test
   returns nonzero, the helper runs the join pair
   `0x63adb50(thread, [ref+0xe410], nxt, kind)` and
   `0x63b0560(dest+0x70, nxt)` — or dest+`0x2628`
   when node[0] bit 16 (`0x10000`) is set (cmove) —
   then falls to the retry block. The join pair is
   #212's join path, seen here a second time with
   the same argument shapes.

4. **Test zero: flag out, or second next call.**
   When the test returns zero and dest+`0x4be8` != 0,
   the helper writes *flag = 1 and returns cur
   (early exit A). When dest+`0x4be8` == 0, it calls
   `0x63ae260` again with the sixth argument 0
   instead of 1: on NULL it loops back to the head,
   on a node it sets the local flag byte to 1 and
   enters the mid block.

5. **Retry block.** `0x63ae260(thread, [ref+0xe410],
   cur, 0, kind, 0)`: on NULL it exits (item 7),
   on a node it sets the local flag byte to 0 and
   enters the mid block. The head call passes 1 as
   the sixth argument; both retry calls pass 0.
   What that bit selects inside `0x63ae260` is not
   decoded here.

6. **Mid block.** `0x63b0780(dest+0x70, nx)`, then
   the byte test with its node arguments swapped:
   `0x63b1810(thread, ref, pool, nx, cur)`. On
   nonzero it joins (same pair as item 3), then
   loops to the head if the local flag is nonzero
   and exits if it is zero — so the local flag
   records which retry produced this node (1 = the
   test-zero path, 0 = the NULL/join path). On zero
   with dest+`0x4be8` != 0 it writes *flag = 1 and
   returns nx (early exit B). On zero with
   dest+`0x4be8` == 0 it advances cur = nx and
   loops to the head.

7. **Exit and return value.** If dest+`0x4be8` != 0
   the helper writes *flag = 0, then returns cur.
   Every return value is a node pointer the helper
   already held: cur (the input node, or the last
   advanced node) or, on early exit B, the newest
   next-node result — every next-node result it
   returns was tested non-NULL, so the helper
   never manufactures a NULL.

8. **What the flag selects.** All three *flag writes
   are gated on dest+`0x4be8` != 0; when it is 0
   the out-parameter is never dereferenced — which
   composes with #212's single-call observation
   (hand-on passes r9 = 0 there). *flag = 1 means
   "keep chaining with the returned node" (#212's
   loop repeats while the flag is nonzero; the
   selector caller likewise tests its flag byte
   after return, `jne 0x63b27e0`); *flag = 0 means
   "chain done, proceed downstream". The flag is
   set to 1 exactly on the two test-zero early
   exits, and to 0 exactly on the normal exit.

9. **Census (whole `.text`, byte scan + per-site
   disassembly check; `.rela.dyn` for GOT).**
   Chain helper `0x63b1b60`: 3 direct E8, 0 E9,
   0 LEA, 0 GOT. E8: `0x63b2734` (selector FDE
   `0x63b2630`, #210's selector — it passes a
   stack flag byte and tests it after return),
   `0x63b3974` (hand-on loop call, #212),
   `0x63b3a1a` (hand-on single call, #212).
   `.rela.dyn` (60,723 entries) has no addend
   equal to the target. The caller FDEs are cited
   as census sites only and are not decoded here.

## Corrections to earlier packets

None that change a verdict. #212 confirmed in full:
both hand-on call sites target this helper, the
flag out-parameter convention, and the
dest+`0x4be8` gate. #212 extended once: the
flag-write gating explains why hand-on's
single-call path can pass r9 = 0. #210's selector
is a third caller (new census fact, not a
correction — #210's census counted the selector's
own callers, not its callees). #210's, #209's,
and #204's shapes are otherwise untouched.

## Unresolved, stated not inferred

Internals of `0x63ae260` (including what its sixth
argument 1-vs-0 selects and when it returns NULL),
`0x63b0780`, `0x63b1810` (including why its node
arguments swap between the head and mid calls),
the join calls `0x63adb50` / `0x63b0560` in full,
the probes `0x63c1c40` in full, the predicate
`0x63b2e60` in full, the ordered-insert
`0x63aa7d0` in full, the repurpose pair
`0x63b3c00` / `0x63b3b00`, the compute callee
`0x63a9750` in full, the C-`0x80` divisor source,
the entry+8 condvar waiters, the two runtime
method pointees ([seg+`0x29d0`] / [seg+`0x11cf0`]
writers), the drain helper `0x51e8720`, the
field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0`
and unwind callee `0x1680cab`.

## Next question

Decode the `0x63ae260` next-node call end to end:
what does it do with (thread, [ref+`0xe410`], node,
0, kind, 1-or-0), what does it return, when does
it return NULL, and what does its sixth argument
select? Behind it, still open: the `0x63b1810`
byte test in full, the `0x63b0780` call in full,
the join calls `0x63adb50` / `0x63b0560` in full,
the probes `0x63c1c40` in full, the predicate
`0x63b2e60` in full, the ordered-insert
`0x63aa7d0` in full, the repurpose pair
`0x63b3c00` / `0x63b3b00`, the compute callee
`0x63a9750` in full, the C-`0x80` divisor source,
the entry+8 condvar waiters, the two runtime
method pointees ([seg+`0x29d0`] / [seg+`0x11cf0`]
writers), the drain helper `0x51e8720`, the
field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0`
and unwind callee `0x1680cab`.
