# RE-001: map node #115 list teardown 0x5d59780 with its per-node string dispose and sole caller

Bounded question: what does node #115 routine 0x5d59780 (FDE
0x5d59780..0x5d59825, 165 bytes) do to the holder in rdi, end to end?

## Answer

It is a list teardown followed by a buffer clear, not a destructor:
it drains a linked list, disposing one string per node, then zeroes
and conditionally frees the holder's buffer — but it never frees the
holder itself, and it performs no canary check. It pushes r12/rbp/rbx
and reserves no stack.

Phase 1 — linked-list drain. The list head is at holder+0x10; a null
head skips straight to phase 2. Each node is 0x38 bytes: the next
pointer at node+0x00 is loaded before the node is disposed, so the
walk survives each free. Per node, in order:

1. String dispose: pointer at node+0x08, capacity at node+0x18.
   Short-form rule — when the pointer equals node+0x18 (the address
   of its capacity slot), nothing is freed; otherwise a sized delete
   of (pointer, capacity + 1) through the _ZdlPvm PLT at 0x63f0d80.
2. Node free: a sized delete of (node, 0x38) through the same PLT.

Nodes are freed head to tail; the string is always disposed before
its node.

Phase 2 — buffer clear and exit. The qword at holder+0x08 is the
count of 8-byte entries: memset(holder+0x00, 0, count * 8) through
the memset PLT at 0x63f0a90, then holder+0x10 (the drained list head)
and holder+0x18 are zeroed. The buffer exit then compares the begin
pointer against holder+0x30: when they are equal the routine returns
plainly, otherwise it tail-jumps to the sized-delete PLT freeing
(begin, count * 8). The begin (+0x00) and count (+0x08) slots are not
cleared. Reading holder+0x30 as an inline-storage base is an
inference; the pinned fact is the comparison itself and the exact
free size.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 1 direct call + 0 tail jumps across 1 caller FDE
(see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data. The
sole caller passes rbx+0x618 in rdi (lea immediately before the call
site at 0x5d84c57); what that caller does with the holder before or
after the call is not claimed here.

Relation to neighbouring work: distinct from the adjacent routine
0x5d596f0, which shares this tail but drains a plain linked list
with no per-node string dispose; distinct from the record-loop
teardowns 0x5d593f0 and 0x5d591d0, which walk fixed-stride arrays
rather than a linked list; and distinct from the object teardown
0x5d56f50, which disposes member vectors rather than a list plus a
buffer.

## Evidence notes

The raw excerpts in this packet are verbatim objdump output, kept
whole-function; the objdump command that produced each file is
recorded in export_excerpts.py. Instruction text such as `endbr64`
at the routine entry is a genuine instruction present in the target
binary, not a placeholder. The packet JSON holds semantic records
only, not a per-instruction list.

## Unknowns (not claimed)

- What the list nodes and the buffer entries hold beyond their
  pointer/capacity and count shapes; they are recorded as observed
  pairs and counts only.
- What holder+0x30 contains beyond being the buffer-exit comparison
  address; the inline-storage reading is an inference.
- What the sole caller function does with the holder before or after
  this call; only the call site and its FDE are recorded.
- Behaviour on a malformed list (a cycle, or a next pointer that is
  not a valid node); the model requires a terminating list.
- Behaviour when the buffer begin is null with a nonzero count;
  the model requires a valid buffer range for count * 8 bytes.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-list-string-teardown-59780-115/verify.py
    python3 research/work-items/RE-001-list-string-teardown-59780-115/census.py

The checker binds the binary SHA-256 to provenance/artifacts.json,
regenerates every excerpt byte-for-byte from fresh objdump runs,
checks every main.txt line against the raw binary, re-runs the
caller census, and invokes the model tests in
tests/test_list_string_teardown_59780_115.py.
