# RE-001: map node #115 recursive tree teardown 0x5f53f50 with its sole external caller

## Bounded question

What does the recursive teardown function at 0x5f53f50 delete, in what
order, and who calls it? This packet pins the whole function end to
end — not a lone-window fragment: the 457-byte recursive tree
teardown, its nine operator-delete sites, its self-call, and its sole
census-confirmed external caller, which makes the behavior observable
end to end. It closes the by-contract use of 0x5f53f50 in
RE-001-element-reset-115 (#2232), which called this function once per
linked-list node without reading its internals.

## Windows

- Recursive teardown: 0x5f53f50..0x5f54119 (457 bytes), FDE at
  .eh_frame offset 0x35c744, length 0x48, CIE 0 (no LSDA). The window
  ends at the `ret` at 0x5f54118; the `int3` padding at 0x5f54119 and
  the next function at 0x5f54120 are excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpt was produced

From the repository root:

```
objdump -d --start-address=0x5f53f50 --stop-address=0x5f54119 work/hl-node-115.bin
```

The excerpt file is that output verbatim, whole-function. This
function has no `endbr64` at its entry (it starts with `push %r15`);
every mnemonic in the excerpt is genuine objdump output from the
target binary, not a placeholder, and verify.py checks sampled
instructions byte-for-byte against a fresh objdump run and the raw
binary. Instruction-level detail lives only in the verbatim excerpt;
records.json carries semantic records, not a per-instruction list.

## Semantics (literal)

The function takes one argument, a chain-head pointer (rdi), and
returns void. A null head returns at once (the entry test jumps
straight to the epilogue). No stack canary is used (no %fs reference
appears in-window) and no rip-relative reference appears in-window.
The only PLT call in-window is operator delete.

Node layout (each node is 0x30 bytes; no other field is read):

- +0x10: next sibling (the chain link)
- +0x18: first child (head of the child chain)

Behavior, stated as the recursion the binary implements:

```
teardown(chain):
    node = chain
    while node is not null:
        child = node + 0x18          # read before any delete
        next = node + 0x10           # read before any delete
        teardown(child)              # whole child chain first
        operator_delete(node, 0x30)  # then the node itself
        node = next
```

So the delete order is depth-first: children before parents,
siblings in chain order. A null child chain is a no-op, because the
entry null check covers the recursive call too (the call passes a
child pointer that may itself be null). The next and child pointers
are always read before the node is deleted, so the walk survives
deletion.

Implementation shape (unrolling, same observable order): instead of
calling itself at every level, the binary walks the first-child chain
iteratively through eight levels — the head, then the +0x18 chain
nodes held in the stack slot, r14, r15, rbx, r12, rbp, rdx and r13 —
and makes a true recursive self-call only for deeper chains (the
call at 0x5f53fe1 passes r13 + 0x18). Each unwind level then deletes
its node and follows that node's +0x10 siblings with the same
child-first rule, so the observable delete order is identical to the
direct recursive formulation above. The Python model implements the
recursive formulation.

Delete sites (nine calls to _ZdlPvm@plt at 0x63f0d80, each with
esi = 0x30, one per unwind level): 0x5f53ff2, 0x5f5400d, 0x5f54028,
0x5f5404d, 0x5f5406b, 0x5f54091, 0x5f540b4, 0x5f540d4, 0x5f540f6.
The only other direct call in-window is the self-call at 0x5f53fe1
(e8 6a ff ff ff).

Sole external caller (census-confirmed): the element reset 0x5f54ee0
mapped by #2232, call site 0x5f54f8e (e8 bd ef ff ff), passing a list
node's +0x18 child chain as the argument and deleting the list node
itself after the call returns. The whole-file census finds exactly
two direct calls to 0x5f53f50 (the self-call and the reset call), no
tail jumps, no 8-byte occurrences of the address in .text, no
8-byte occurrence anywhere in the file, and no RELATIVE relocation
addend equal to the address — so no vtable or data reference to this
function was found.

## Worked delete order

For a chain A -> B (siblings via +0x10), where A has child chain
C -> D (siblings) and C has child E (no children, no next), the
delete order is: E, C, D, A, B. The model test pins exactly this
order, plus a ten-level first-child chain (deeper than the binary's
eight-level unrolling) to show the recursion and the unrolling agree.

## Unknowns (explicitly not claimed)

- Node type names are unknown: the binary carries no usable symbol
  for this function (objdump labels it with a reused library stub
  name), so the packet names it only by address.
- Fields +0x00..+0x0f and +0x20..+0x2f are never read by this
  function, so nothing is claimed about them.
- The census rules out direct calls, tail jumps, .text qwords,
  whole-file qwords and RELATIVE addends; it does not rule out a
  caller that computes the address arithmetically.
