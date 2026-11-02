# RE-001: bind node #94 tree-node teardown 0x514cd00 with its container wrapper and exception-cleanup consumer

Task ID: RE-001. Bounded question: given a sibling list of 0x68-byte
nodes, each carrying two strings and a first-child link, what does the
774-byte function at 0x514cd00 destroy, in what order, and what does it
free for each node? Answer: it destroys the whole list in post-order --
for each node, the whole +0x18 child list first, then the node itself
(both strings, then a 0x68 sized delete), then the +0x10 sibling. A null
head frees nothing. Two consumers are bound with it: the 0x514d010
container wrapper, which destroys the list at [container+0x10] through
this function, and the exception-cleanup call at 0x5150b34 in
0x5150870..0x5150baf, which destroys the list at [r14+0x10] after
__cxa_end_catch.

This is a different node type from the RE-001 0x48-byte tree-node
teardown at 0x514c1c0 (different FDE, different size, two strings
instead of one, different link offsets): that item is not redone here,
and neither is the 0x514c580 level-report item whose following FDE this
window is.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Window function: 0x514cd00..0x514d006, 774 bytes, FDE at .eh_frame
  +0x0029aa7c (length 0x4c), 10 int3 padding bytes to the next FDE at
  0x514d010.
- This function has no endbr64 at its entry (it starts with a null test
  on rdi) and no stack canary; the wrapper at 0x514d010 starts with
  endbr64, and the nopl/nopw bytes inside the functions are alignment
  padding -- all verbatim from the target. Instruction-level detail
  lives only in the raw excerpt files below; records.json carries
  semantic records, not a per-instruction list.
- Node layout: sibling +0x10, first child +0x18, string 1 at +0x28
  (pointer +0x28, length +0x30, capacity/SSO +0x38), string 2 at +0x48
  (pointer +0x48, length +0x50, capacity/SSO +0x58), total size 0x68.
  Fields +0x00 and +0x08 are never read by this function.
- PLT: _ZdlPvm@plt 0x5660440 (GOT 0x5778f48),
  _M_dispose@plt 0x5660470 (GOT 0x5778f60).

## Observations (read from the bytes)

- Entry: test rdi, rdi; je 0x514d005 (a bare ret -- the null-head
  path). Otherwise rbp = head, and the loop at 0x514cd1a takes
  r12 = [rbp+0x18]; a null child jumps straight to the head-finalize
  block at 0x514cfa4.
- Descent: the +0x18 chain is unrolled six links deep (r12, then the
  stack slots and rbx/r14/r13/r15/rcx), and the self-call at
  0x514cd9c recurses on the next +0x18 link for deeper chains. The
  unwind blocks (0x514ce34, 0x514ce70, 0x514cea3, 0x514cec...,
  0x514cf24, 0x514cf5e) each dispose one chain node and follow its
  +0x10 sibling before continuing up, so the observable order is the
  plain destroy_list recursion in tools/foundation_tree_teardown_68.py.
- Per node, in order: string 2 is disposed first (via _M_dispose in
  most blocks; the head-finalize block at 0x514cfa4 and the wrapper
  inline the same test: pointer != own +0x58, then sized-delete
  capacity + 1), then string 1 (via _M_dispose in some blocks, inlined
  in others: pointer != own +0x38, then sized-delete capacity + 1),
  then the node itself is sized-deleted with size 0x68. An SSO string
  (pointer equal to its own union address) deletes no buffer.
- Wrapper 0x514d010..0x514d087 (FDE 0x0029aacc, length 0x24, no
  padding): rbx = [rdi+0x10]; a null head returns immediately. Per
  node it calls 0x514cd00 on [rbx+0x18] at 0x514d027, then disposes
  the node's two strings with the same pointer-vs-union test and
  capacity + 1 rule, deletes the node with size 0x68, and advances
  via the saved [rbx+0x10]. Observable effect: destroy_list of the
  [container+0x10] list.
- Cleanup consumer: in 0x5150870..0x5150baf (FDE 0x00634310, length
  0x50), after __cxa_end_catch@plt at 0x5150b2b, the code calls
  0x514cd00 on [r14+0x10] at 0x5150b34, then checks the stack canary
  and unwinds. Only that call site is claimed; the enclosing
  function's wider semantics are not.
- Caller census (full binary scans, re-derived, not trusted from any
  index): direct e8 callers of 0x514cd00 are exactly the self-call
  0x514cd9c, the wrapper 0x514d027 and the cleanup call 0x5150b34.
  The full .text e9 tail-jump scan found no tail jump to it, and the
  whole-file qword-pointer scan found no vtable reference to it.

## Model and tests

- tools/foundation_tree_teardown_68.py models destroy_list,
  dispose_node and the wrapper effect.
- tests/test_foundation_tree_teardown_68.py covers: null head, a
  single SSO node, a single heap node (both strings, capacity + 1
  sizes), child-before-parent order, sibling order, a mixed
  child-plus-sibling tree, a chain deeper than the six-link unrolling
  (depth 10), the wrapper equivalence, the cleanup call's argument,
  packet verification, excerpt regeneration, and corruption controls.

## Unknowns (kept separate from observations)

- The source-level type names of the node, its strings and its
  container.
- The meaning of the unread node fields at +0x00 and +0x08.
- Whether any consumer reaches the window through a path other than
  a direct e8 call (none was found in the full scans above).
