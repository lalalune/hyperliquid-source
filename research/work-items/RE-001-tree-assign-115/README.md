# RE-001: map node #115 tree assign 0x5d4ea90 with its node-reuse rebuilder 0x5d4e6a0

## Bounded question

Open PR #2409 mapped the 0x60-byte tree teardown at `0x5d4cfd0`,
its deep copy at `0x5d4d050`, and the string builder at `0x5d4a6a0`
they share — but none pinned what happens when one tree container
is assigned from another. What does the assign routine at
`0x5d4ea90` (FDE `0x5d4ea90..0x5d4ec32`, 426 bytes) do end to end,
together with the rebuilder at `0x5d4e6a0` (FDE
`0x5d4e6a0..0x5d4ea62`, 962 bytes) it calls? It detaches the old
destination tree into a two-slot pool, rebuilds the source tree
into the destination reusing pool nodes while they last and
allocating fresh nodes after they run out, then destroys whatever
pool nodes remain.

## Node and container layout

Node layout is open PR #2409's, referenced not re-claimed: a
0x60-byte node with tag at +0x00, link at +0x08, next sibling at
+0x10, first child at +0x18, string A at +0x20/+0x28/+0x30, and
string B at +0x40/+0x48/+0x50. A string field is a
pointer/size/capacity-or-inline triple: inline exactly when its
stored pointer equals the address of its own capacity/inline slot
(+X+0x10); a heap string is freed as `delete(ptr, capacity + 1)`;
sizes are never read. The builder `0x5d4a6a0` (open PR #2409)
stores at most 15 bytes inline, else in a fresh heap buffer.

The container embeds a header node at dst+0x08: dst+0x10 is the
root, dst+0x18 is the last node of the root's +0x10 walk, dst+0x20
is the last node of the root's +0x18 walk, dst+0x28 is the node
count. A fresh root's link is the header address; an empty tree
has root 0 and +0x18/+0x20 both equal to the header address.

## Answer, stated literally

### Step 1: self-assign and detach (assign)

When dst and src are the same container, the routine returns with
no effect at all. Otherwise it detaches the old destination tree
into a stack pool pair: pool[0] is the old root, pool[1] is the
old +0x20 node's +0x10 successor when that successor exists, else
the old +0x20 node itself. The old root's link is cleared, and the
destination is reset to empty (root 0, +0x18/+0x20 = header
address, count 0). When the old root is 0 the pool pair is (0, 0)
and the destination is reset the same way.

### Step 2: rebuild (rebuilder, called at site 0x5d4eb1e)

When the source root exists, the rebuilder rebuilds it with link
= the header address and the pool above, and the assign then sets
dst+0x10 to the rebuilt root, dst+0x18 to the last node of the
rebuilt root's +0x10 walk, dst+0x20 to the last node of its +0x18
walk, and dst+0x28 to the source count. When the source root is 0
the destination stays empty and the routine goes straight to step 3.

The rebuilder `(src, link, pool)` returns one new root:

* Take: one pool node is taken by the pop below, or a fresh
  0x60-byte node is allocated when the pool is empty. A reused
  node's old strings are disposed (string B first, then string A)
  and both strings are rebuilt from the source node (string A
  first, then string B). The tag is copied, link is the link
  argument, and next and child start as 0.
* Child: the source's child subtree is rebuilt recursively and
  stored at the new node's +0x18.
* Siblings: each source sibling is rebuilt the same way — its link
  is the previous rebuilt sibling, the previous sibling's +0x10 is
  the new node — and its child subtree is rebuilt recursively.

The pop, identical in the head path and the sibling path: head =
pool[1]; when head is 0 there is no node to take. Otherwise nxt =
head's link and pool[1] = nxt. When nxt is 0, pool[0] is cleared
(the pool is empty). When nxt's +0x18 child is head, the take
splices: nxt's child is cleared; when nxt's next exists, pool[1]
walks from that next node down its +0x18 child chain to the
deepest node, and then to that deepest node's +0x10 successor when
one exists. Otherwise (nxt's child is not head) nxt's +0x10 is
cleared. The taken node is head in every case.

### Step 3: leftover destruction (assign)

Whatever pool nodes remain are destroyed starting from pool[0]:
per node, the +0x18 child subtree is torn down first with the
`0x5d4cfd0` teardown (open PR #2409, referenced not re-claimed),
then string B, then string A, then the node is deleted with size
`0x60`, advancing to the +0x10 successor loaded before the node's
own deletes. When pool[0] is 0 nothing is destroyed.

### Observed consequence: orphaned nodes

A simple-case pop clears the new pool head's +0x10 link, and a
splice-case pop clears the spliced node's +0x18 link. A node
reachable only through a cleared link is then neither reused nor
destroyed: it is orphaned by the binary's own cuts. Concretely,
when the pool entry node has a later sibling in its chain, that
later sibling (and any subtree under it) is orphaned as soon as
the first pop runs — the worked example in the model tests is an
old root with three children, where the third child is orphaned
while the first two children and the root are reused or destroyed.
The model reproduces this exactly as the branch code dictates; it
is a property of the target's assign, not a modeling choice, and
it is recorded here rather than smoothed over.

## What is NOT claimed

What the trees, nodes, tags, and strings denote; the `_M_create`
internals behind a heap string build (the model records a heap
string's capacity as its length, so its delete size is length +
1); caller semantics beyond the call-site addresses; the teardown
and builder semantics themselves (open PR #2409, referenced not
re-claimed); behavior on cyclic structures (the model raises on a
repeated node in the teardown path instead of looping forever).
The four assign call sites are recorded site-only: two inside the
`0x5d56320..0x5d56f45` routine and two inside the
`0x5d80440..0x5d81813` routine.

## Evidence

All extracted from the digest-verified node #115 work binary
(SHA-256 `a6e2897c…5301`, `work/hl-node-115.bin` hashes exactly;
full digest in `records.json` and `verify.py`). Whole-function
verbatim excerpts `rebuilder.txt` and `assign.txt` (the
disassembly text is exactly as objdump emits it: instruction
mnemonics such as `endbr64` are genuine instructions present in
the target binary, not placeholders); `frames.txt` with the FDE
lines for both routines, the teardown, and both assign-caller
functions; `relocations.txt` (empty: no RELATIVE addend mentions
either routine); `callers.tsv` with every direct call site and its
smallest enclosing FDE; `verify.py` + `export_excerpts.py` +
`census.py` in this packet; `MANIFEST.sha256`. The model is
`tools/tree_assign_115.py`, tested by
`tests/test_tree_assign_115.py` (256 checks: copy-shape fidelity,
slot/count results, disjoint reuse/destroy with no double
destroy, the worked orphan case, the no-orphan exact-once case,
heap/inline dispose sizes, self-assign, empty sides, and 60
random chained assigns).

## Census

Whole-file scan, reproduced by the packet's `census.py` and
re-run inside `verify.py`: rebuilder exactly 3 direct calls (two
self-recursions at `0x5d4e768` and `0x5d4e851`, one from the
assign at `0x5d4eb1e`), assign exactly 4 direct calls
(`0x5d56a7f`, `0x5d56a93`, `0x5d80c27`, `0x5d80c3b`), 0 tail
jumps, 0 stored qwords, 0 RELATIVE addends for either routine.
