# RE-001: node #115 recursive list-tree teardown 0x5d4c8d0

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 201-byte
routine at 0x5d4c8d0 do to the list it is given, end to end? It is a
complete behavior, not a lone-window fragment: a recursive post-order
teardown of a list of 0x30-byte nodes, each node carrying a next pointer
and a child-list head, with all four of its direct call sites in the
binary documented. It is the callee the 0x5d516f0 visited-element
teardown routine calls once per list node (open PR #2384); this packet
pins the callee's own semantics, which #2384 explicitly left unclaimed.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the routine window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpt in main.txt and the verbatim site excerpts; the JSON in this
packet holds semantic records only. The objdump command that produced
the excerpts is recorded in export_excerpts.py, which regenerates
them byte-for-byte.

## Semantics, stated literally

The routine takes one list head in rdi and returns void. It reads
exactly two qwords per node: +0x10 (next sibling) and +0x18
(child-list head). It writes nothing itself: every effect is a call
to operator delete (PLT 0x63f0d80, `_ZdlPvm`) with (node, 0x30).

Destruction order: walk the +0x10 chain in order. For each node,
first destroy the whole list at its +0x18 in the same post-order
(each element of that list: its own child list first, then itself,
then its +0x10 successor), then delete the node itself, then move
to the node's +0x10 successor. The successor is loaded before the
delete, so the chain survives the free. A null head returns at once
with no delete.

Worked order: a head A with next B and child list C -> D (D having
child E) deletes C, then E, then D, then A, then B. A chain nested
ten deep deletes innermost first and outermost last; the binary
inlines the loop for the first eight +0x18 levels and recurses into
itself (site 0x5d4c961, passing the eighth-level node's child-list
head) past that depth, then unwinds one level at a time, deleting
each level's node and processing its +0x10 successor before moving
up. The recursion is an implementation detail of the same rule.

NOT claimed: caller semantics beyond the four sites' argument setup
and immediate surroundings; what r12 denotes in the landing pad;
what [rbx+0x20d0] denotes in the large function; any field of a
node beyond +0x10 and +0x18; any meaning for the node contents
beyond the two pointers.

## Call sites (all four, whole-file census)

* 0x5d4c961 (self, recursive): rdi = qword at [r13+0x18], the
  child-list head of the eighth-level node. After the call returns,
  the eighth-level node itself is deleted and its +0x10 successor
  is processed as the new eighth level, unwinding one level at a
  time.
* 0x5d4cb76 (landing pad in 0x5d4caa0..0x5d4cb94): rdi = r12,
  between `__cxa_begin_catch` and `__cxa_rethrow` — the teardown
  runs while an exception is being rethrown. Excerpted in
  site-landing.txt.
* 0x5d518cc (loop in the 0x5d516f0 visited-element teardown, open
  PR #2384): rdi = qword at [rbx+0x18] of the current list node;
  after the call the caller deletes that node with (node, 0x30)
  and follows its +0x10 pointer. Excerpted in site-teardown.txt.
* 0x5d81617 (straight-line in 0x5d80440..0x5d81813): rdi = qword
  at [rbx+0x20d0], following a delete of the vector at
  [rbx+0x2108] and a call to 0x5d593f0 on rbx+0x20f0. Excerpted in
  site-large.txt.

Distinct from open PR #2235 (recursive tree teardown 0x5f53f50):
a different routine at a different address with its own caller;
no address overlap.

## Assumptions, stated explicitly

Each node is 0x30 bytes; only +0x10 and +0x18 are read. A null
head deletes nothing. A missing node, a missing field, a cycle,
or a node deleted twice is not silently modelled — the model
raises instead.
