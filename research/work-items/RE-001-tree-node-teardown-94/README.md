# RE-001: node #94 tree-node teardown 0x514c1c0

## Bounded question

What does the 861-byte function at 0x514c1c0 in node #94 destroy, in
what order, and which callers use it?

## Answer

It is a post-order teardown of a list of 0x48-byte tree nodes. Each
node carries a next-sibling link, a first-child link, and one string
member:

- node size: 0x48 (every node delete passes size 0x48);
- next sibling: field at +0x10;
- first child: field at +0x18;
- string member at +0x28: pointer at +0x28, length at +0x30 (never
  read by this function), union at +0x38 (heap capacity, or the
  16-byte SSO buffer itself).

Destroying one node means: if the string pointer at +0x28 differs
from the node's own +0x38 address (heap arm), sized-delete the buffer
with size capacity + 1 (the heap buffer plus its terminator); if it
equals +0x38 (SSO arm), no buffer delete. Then sized-delete the node
itself with size 0x48. Every delete goes through the same PLT stub,
`_ZdlPvm` at 0x5660440 (GOT slot 0x5778f48, R_X86_64_JUMP_SLOT).

The traversal is `destroy_list`: for each node in the +0x10 sibling
chain, destroy the whole +0x18 child list first (each child with its
own subtree), then destroy the node, then move to the next sibling.
A null head destroys nothing and returns immediately. The first-child
descent is unrolled 7 links deep (ancestor slots: stack +0x10, r14,
r15, rbx, rbp, r12, r13); deeper levels go through the self-call at
0x514c264, so traversal depth is unbounded, not 7. The compiler's
unrolling is why the same destroy pattern repeats at every level:
each unwind block destroys its level's node, then continues with that
node's +0x10 sibling, or unwinds one more level when the chain ends.

## Callers (complete census, full .text direct-call byte scan)

| site | consumer | setup observed |
| --- | --- | --- |
| 0x514c537 | wrapper 0x514c520..0x514c57f (whole function in `wrapper.objdump.txt`) | Wrapper list teardown: head = [container+0x10]; per node, call teardown on [node+0x18], destroy the node with the same string/node pattern, then node = [node+0x10]. The wrapper never destroys its own container argument. |
| 0x5150dec | enclosing function 0x5150bb0..0x5150e4e (whole function in `cleanup-caller.objdump.txt`) | Exception-cleanup path: immediately after a `__cxa_end_catch` call, rdi = [r14+0x10]; the teardown runs on the unwind path before the stack-canary check and `_Unwind_Resume`. |

The third call site found by the scan, 0x514c264, is the function's
own self-call and is not an external caller. No tail jumps to this
function were found.

## Distinction from neighbouring teardown work

The preceding FDE is the double formatter 0x514c050 (a different,
unrelated function), and the following FDE is the wrapper 0x514c520
itself, included here only as a consumer. Other teardown binds in the
0x514b region (0x514bd40, 0x514be80, 0x514bee0, 0x514bf60, 0x514bfe0)
are different FDEs with different shapes; this item claims only
0x514c1c0, its self-recursion, its delete callee, and its two
consumers above.

## Observations, inferences, unknowns

Observations are the records in `records.json` and the verbatim
excerpts. Inferences: the +0x28 member is a libstdc++ string because
the destroy pattern (pointer vs own +0x10 buffer, capacity + 1 sized
delete) matches that layout exactly, and the +0x10/+0x18 links form a
first-child/next-sibling tree because children are destroyed before
their node and siblings are walked in chain order. Unknowns: the
owning component and source-level type name, what the tree represents,
stored string lengths (never read here), and capacity-overflow
behaviour (not observed). This function has no `endbr64` (it opens
with `push %r15`); the `endbr64` in the wrapper excerpt is a genuine
instruction of the wrapper function, not a placeholder. The `nopw` /
`nopl` bytes are genuine alignment padding emitted by the compiler.
Instruction-level detail lives only in the raw excerpt files, exactly
as objdump emitted them; `records.json` carries semantic records, not
a per-instruction list.

## Verification

`python3 verify.py` checks the target digest, the function carve SHA,
the 3-byte int3 padding, every call target re-derived from the raw
rel32 encodings, the full caller census by byte scan, the three FDE
lines, the GOT relocation, the excerpt lines against a fresh objdump
run, and the MANIFEST.sha256 hashes. It prints ALL CHECKS PASSED on
success. `export_excerpts.py` regenerates the excerpt files.
