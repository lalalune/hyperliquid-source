# RE-001: node #115 recursive list-tree copy 0x5d4caa0

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 244-byte
routine at 0x5d4caa0 do to the list it is given, end to end? It is a
complete behavior, not a lone-window fragment: a recursive deep copy
of a list of 0x30-byte nodes, each node carrying a next pointer and a
child-list head, with all three of its direct call sites in the
binary documented and both of its trailing exception landing pads
stated literally. It is the mirror of the list-tree teardown pinned
by open PR #2386 (0x5d4c8d0): where that routine destroys such a
list-tree, this routine builds one — and its landing pad calls the
teardown to destroy a partial copy when construction throws.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` instructions at the heads of the landing pads are
genuine instructions present in the target binary, not placeholders.
Instruction-level detail lives only in the whole-function verbatim
excerpt in main.txt and the verbatim site excerpt; the JSON in this
packet holds semantic records only. The objdump command that produced
the excerpts is recorded in export_excerpts.py, which regenerates
them byte-for-byte.

## Semantics, stated literally

The routine takes a source list head in rdi and a link value in rsi,
and returns the head copy in rax. Each node is 0x30 bytes. For every
copied node it allocates one fresh node with operator new, size
0x30 (PLT 0x63f0dd0, `_Znwm`), and copies exactly two things from
the source node: the dword at +0x00 and the 16 tail bytes at
+0x20..+0x2f. It sets the copy's +0x10 and +0x18 to 0 at allocation,
then fills them in as the walk proceeds. It never reads the source
node's +0x08 field, and it never reads or writes the +0x04..+0x07
bytes, which stay uninitialized in each fresh copy.

Copy order: copy the head node first; then copy its whole child
list; then walk the source +0x10 chain in order, copying each
sibling and its child list before moving on. Allocation order for
a head A with next B and child list C -> D (D having child E) is
therefore A, C, D, E, B.

The +0x08 previous-link rule: the head copy's +0x08 is the
routine's incoming rsi, verbatim. A sibling copy's +0x08 is the
previous copy. A child-list head copy's +0x08 is the copy of the
parent node (the head copy for the first level, the sibling copy
for deeper levels). The +0x10 next rule: each sibling copy is
stored at the previous copy's +0x10 as the walk advances, so the
last copy's +0x10 stays 0. The +0x18 child rule: a copy's +0x18
is the recursive copy of the source node's +0x18 list, or stays 0
when that list is null. A sibling copy is linked to its previous
copy before its own child list is copied.

The routine assumes a non-null source head: its first instructions
dereference the source node, so a null head is not a handled case
(the only observed caller guards it before calling; see below).
The model raises for a null head rather than modelling a call the
binary never makes.

## Exception landing pads (trailing blocks, stated literally)

Two landing pads follow the routine's `ret` inside the same FDE
(0x5d4caa0..0x5d4cb94). The first, at 0x5d4cb67, moves the
exception object into rdi, calls `__cxa_begin_catch`, moves the
partial head copy in r12 into rdi, calls the list-tree teardown
0x5d4c8d0 (open PR #2386), and calls `__cxa_rethrow`. In other
words: an exception during construction tears down the partial
copy built so far and rethrows. Each nested copy invocation has
the same pad, so a failure deep in a child list tears down the
inner partial copy first, then the outer partial copy, innermost
first — the model reproduces exactly that order. The second pad,
at 0x5d4cb80, moves the exception object into rbx, calls
`__cxa_end_catch`, moves rbx into rdi, and calls `_Unwind_Resume`.
Which try region each pad guards is NOT claimed; the pads are
stated as trailing blocks only.

## Call sites (all three, whole-file census)

* 0x5d4caef (self, recursive): rdi = the qword at [rbx+0x18],
  the head node's child-list head; rsi = r12, the head copy; the
  result is stored at [r12+0x18].
* 0x5d4cb47 (self, recursive): rdi = the qword at [rbp+0x18],
  the sibling's child-list head; rsi = rbx, the sibling copy; the
  result is stored at [rbx+0x18].
* 0x5d80ee3 (in 0x5d80440..0x5d81813, the same large function that
  calls the teardown at 0x5d81617 in open PR #2386): rdi = the
  qword at [rbp+0x20d0], the source list head; rsi = rbx+0x20c8.
  Before the call the caller stores 0 at [rbx+0x20d0] and
  [rbx+0x20e8], stores rbx+0x20c8 at [rbx+0x20d8] and [rbx+0x20e0],
  stores 0 as a dword at [rbx+0x20c8], and stores r13 at
  [rbx+0x20b0]. The call is skipped entirely when rdi is zero
  (the test at 0x5d80ede jumps to 0x5d80f38). After the call the
  caller walks the copy's +0x10 chain to its last node and stores
  it at [rbx+0x20d8], walks the copy's +0x18 chain from the head
  copy to its last node and stores it at [rbx+0x20e0], stores the
  head copy at [rbx+0x20d0], and stores the qword at [rbp+0x20e8]
  at [rbx+0x20e8]. Excerpted in site-large.txt.

Distinct from open PR #2386 (recursive list-tree teardown
0x5d4c8d0): that routine destroys a list-tree; this routine
builds one. The windows are adjacent but disjoint, and no claim
here re-states #2386's semantics beyond the landing pad's call to
it. Distinct from open PR #2384 (visited-element teardown
0x5d516f0) and #2383 (element-visit-and-reset 0x5f6eac0): callers
of the teardown, not of this routine. No open PR title or code
search hit for 0x5d4caa0.

NOT claimed: caller semantics beyond the 0x5d80ee3 site's argument
setup, guard, and post-call walks; what the rbx/rbp objects or
their +0x20b0/+0x20c8/+0x20d0/+0x20d8/+0x20e0/+0x20e8 fields denote;
which try region each landing pad guards; any meaning for the node
fields beyond the copy rules; any behavior for a null source head;
the +0x04..+0x07 contents of any copy.

## Verification

The packet's verify.py checks: the work binary digest against the
provenance entry; MANIFEST.sha256 against every packet file;
excerpt regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw binary;
three extra spot instructions byte-for-byte against a fresh
objdump run and the raw binary (0x5d4caef, 0x5d4cb47, 0x5d80ee3);
the FDE ranges for the routine and the large caller against a
fresh frame dump; census consistency (callers.tsv against a fresh
whole-file scan: exactly 3 direct calls, 0 tail jumps, 0 stored
qwords, 0 RELATIVE addends); the semantic records; and the model
tests in tests/test_list_tree_copy_115.py, which exercise the
full copy structure, the allocation order, the site walks, the
structural guards, and the allocation-failure teardown order.

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs, and no Ghidra/Java, so the model layer is Python and
the evidence is objdump/readelf output against the digest-verified
local binary. No full node build or binary-equivalence claim is
made.
