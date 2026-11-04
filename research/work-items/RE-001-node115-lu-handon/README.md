# RE-001-node115-lu-handon: the node #115 hand-on destination

This packet answers packet #211's explicitly stated next question:
decode the hand-on destination `0x63b38d0` end to end: what does it
do with (thread, ref, pool, ref+`0x9818`, node), and on which path
does it re-enter release?

## Answer in one line

Hand-on locks the dest record, chains `0x63b1b60` until its flag
clears, then either runs the join path (`0x63adb50` +
`0x63b0560`, unlock, return) or — only when the chained result
is big enough and both `0x63c1c40` probes pass — unlocks,
re-enters release, accounts, and returns. It never frees the node.

## What it shows

1. **Signature and entry.** FDE `0x63b38d0..0x63b3af1`
   (545B): (thread, ref, pool, dest, node) = (rdi, rsi, rdx,
   rcx, r8), where dest is ref+`0x9818`. Provenance is
   release's tail jump (`0x63b3111`, #211's rel_tail
   excerpt): rdi = thread, rsi = ref, rdx = pool,
   rcx = ref+`0x9818`, r8 = node. The prologue saves
   thread (rbp), ref (r12), pool (r13), dest (rbx),
   node (r15), and dest+`0x40` (r14, the mutex argument),
   with a stack canary.

2. **Lock protocol.** `pthread_mutex_trylock(dest+0x40)`;
   on failure it calls the wait helper `0x63bf680(dest)`,
   sets dest+`0x68` = 1, and proceeds. Then dest+`0x38`
   += 1 always; when the owner slot dest+`0x30` differs
   from thread, dest+`0x28` += 1 and dest+`0x30` = thread.
   This is the same lock-header layout as #204/#210
   (mutex +`0x40`, changed-count +`0x28`, owner +`0x30`,
   bump +`0x38`, contention flag +`0x68`).

3. **Three gates before the chain.** Node[0] bit 16
   (`0x10000`) set skips straight to the join path (and
   later selects dest+`0x2628` for `0x63b0560`).
   Dest+`0x4be8` == 0 runs a single `0x63b1b60` call
   with r9 = 0, then the join path. Otherwise, if
   [node+`0x10`] & ~`0xfff` <= `0x3fff`, the join path
   runs directly with no chain call at all.

4. **The chain.** Otherwise hand-on loops
   `0x63b1b60(thread, ref, pool, dest, node, &flag)`,
   where &flag is a stack byte at rsp+`0x17` (the
   callee's out-parameter) and each iteration passes
   the previous result as the node argument. The loop
   repeats while the flag byte is nonzero; the final
   return value becomes the node for everything
   downstream. `0x63b1b60` is not decoded here.

5. **Threshold and probes.** If page-aligned
   [result+`0x10`] >= [ref+`0xe510`], hand-on calls
   `0x63c1c40(ref, 1)` and then `0x63c1c40(ref, 2)`;
   either returning -1 falls back to the join path.
   Both probes must return something other than -1
   (their other values are discarded) for the re-entry
   path. `0x63c1c40` is not decoded here.

6. **Join path.** `0x63adb50(thread, [ref+0xe410],
   node, [dest+0x4be0])`, then `0x63b0560(dest+0x70,
   node)` — or dest+`0x2628` when node[0] bit 16 is
   set (cmovne). Then dest+`0x68` = 0, a stack-canary
   check, and a tail jump to `pthread_mutex_unlock`
   (the unlock's return value is hand-on's return).
   This path performs no [ref+`0xf310`] accounting.

7. **Re-entry path.** Dest+`0x68` = 0, then
   `pthread_mutex_unlock(dest+0x40)` as a plain call
   (unlock before the work, as in #210's callee), then
   release `0x63b3080(thread, ref, pool, node)` at
   `0x63b3a92` — the re-entry call #211's census
   recorded. Argument r8 is not reset before this
   call; it is stale but dead inside release per #211,
   so no value is claimed for it. After release
   returns, hand-on accounts on [ref+`0xf310`]:
   `lock addq $1` at +`0x8`, `lock add`
   [node+`0x10`] >> 12 at +`0x10`, `lock sub`
   [node+`0x10`] & ~`0xfff` at +`0x38`, then `ret`
   (rax is the zeroed canary check). So a
   release → hand-on → release cycle exists, with
   exactly one accounting update per re-entry.

8. **Census (whole `.text`, byte scan + per-site
   disassembly check; `.rela.dyn` for GOT).**
   Hand-on `0x63b38d0`: 6 direct E8, 2 E9, 0 LEA,
   0 GOT. E8: `0x63b4aa1` (FDE `0x63b46e0`),
   `0x63b5186`, `0x63b51a5`, `0x63b545d`,
   `0x63b54d8` (all in FDE `0x63b4b50`),
   `0x63c1f15` (FDE `0x63c1cd0`). E9:
   `0x63b3111` (release's tail jump, #211) and
   `0x63b3b13` (inside the 24B shim FDE
   `0x63b3b00..0x63b3b18`, which clears node[0]
   bit 15 and page-aligns node+8 before tail-jumping
   to hand-on with registers unchanged).
   `.rela.dyn` (60,723 entries) has no addend equal
   to the target. The caller FDEs are cited as
   census sites only and are not decoded here.

## Corrections to earlier packets

None that change a verdict. #211 confirmed in full:
the release tail-jump site `0x63b3111` and its
register setup, the hand-on FDE bounds (545B), the
re-entry call site `0x63b3a92`, and the dest+`0x40`
lock with counters characterisation. #211 extended
twice: the dest is ref+`0x9818` (not just "dest"),
and the re-entry path's accounting shape is now
explicit ([ref+`0xf310`]+`0x8`/+`0x10`/+`0x38`,
with no +`0x0` run count on that object, unlike
#210's arg4 record). Disambiguation, not a
correction: hand-on's chain helper `0x63b1b60`
(6 arguments, flag out-parameter) is NOT #210's
selector `0x63b2630` (5 arguments, base threshold)
— different functions, different call sites.
#210's and #209's shapes and #204's C layout are
otherwise untouched.

## Unresolved, stated not inferred

Internals of `0x63b1b60`, `0x63adb50`, `0x63b0560`,
and `0x63c1c40`; what the [ref+`0xe510`]
threshold represents; the identity of the
[ref+`0xf310`] accounting object; the roles of
the six E8 caller FDEs (`0x63b46e0`, `0x63b4b50`,
`0x63c1cd0`); and every item still open from
#211's list (predicate `0x63b2e60`, ordered-insert
`0x63aa7d0`, repurpose pair `0x63b3c00` /
`0x63b3b00`, compute callee `0x63a9750`,
C-`0x80` divisor source, entry+8 condvar waiters,
runtime method pointees, drain helper `0x51e8720`,
field-drop callees, #200's delegates and unwind
callee). Of #210's selector items, `0x63b1b60` is
now this packet's chain helper (next question)
and `0x63b0560` is the join-path second call
(seen, not decoded).

## Next question

Decode the chain helper `0x63b1b60` end to end:
what does it do with (thread, ref, pool, dest, node,
&flag), what does it return, and what does the flag
byte select? Behind it, still open: the join calls
`0x63adb50` / `0x63b0560` in full, the probes
`0x63c1c40` in full, the predicate `0x63b2e60`
in full, the ordered-insert `0x63aa7d0` in full,
the repurpose pair `0x63b3c00` / `0x63b3b00`,
the compute callee `0x63a9750` in full, the
C-`0x80` divisor source, the entry+8 condvar
waiters, the two runtime method pointees
([seg+`0x29d0`] / [seg+`0x11cf0`] writers), the
drain helper `0x51e8720`, the field-drop callees
`0x5a50a10` / `0x5a4d200`, and #200's delegates
`0x51f3e20` / `0x57ec1b0` and unwind callee
`0x1680cab`.
