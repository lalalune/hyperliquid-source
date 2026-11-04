# RE-001: member-tree teardown routine 0x5d573f0 (node #115)

## Bounded question

What does the routine at `0x5d573f0` destroy, in what order, and
through which code is it reached? In particular: what are the fields
of the node it destroys, how does it walk the child and sibling
links, what happens at depths beyond the compiler's unrolled descent,
and why do two different string-disposal idioms appear in one routine?

## Answer (established semantics)

The routine `0x5d573f0` is a whole 837-byte routine (FDE
`0x5d573f0..0x5d57735`), not a lone-window fragment: it is a
post-order teardown of a tree of 0x58-byte nodes. It takes a tree
root in `rdi`, saves `r15`, `r14`, `r13`, `r12`, `rbp` and `rbx`,
reserves `0x38` stack bytes, has no stack canary and no plain
return other than the single `ret` at `0x5d57734`. A null root
returns immediately with nothing destroyed. The disassembly
excerpts in this packet are verbatim objdump output: opcodes such
as `endbr64` are genuine instructions present in the target binary,
not placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d573f0 --stop-address=0x5d57735 work/hl-node-115.bin
objdump -d --start-address=0x5d7b424 --stop-address=0x5d7b611 work/hl-node-115.bin
objdump -d --start-address=0x5d7b620 --stop-address=0x5d7d442 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

## Node layout (0x58-byte nodes, offsets pinned, kinds not pinned)

- `+0x10`: next sibling — followed after the node itself is
  destroyed.
- `+0x18`: first child — its whole subtree is destroyed before the
  node itself.
- `+0x20`: a libstdc++ string (data pointer at `+0x20`, size at
  `+0x28`, capacity / inline buffer at `+0x30`).
- `+0x40`: a member object of size `0x18`, passed by address to
  `0x5d35c30` (call-shape only; that callee's internals are not
  pinned here).

This node type is distinct from the two neighbouring teardown
routines: RE-001-node-tree-teardown-55aa0-115 destroys 0x38-byte
nodes with a refcounted payload at `+0x30` and no string, and
RE-001-deep-tree-teardown-55d50-115 destroys 0x50-byte nodes with a
string at `+0x20` and a refcounted payload at `+0x48` released
through `0x5d350c0`. Here the nodes are 0x58 bytes, the string is
at `+0x20`, and the second member is the `0x5d35c30` call on
`+0x40`, made unconditionally for every node.

## Per-node teardown, in order

For each node, in order:

1. Call `0x5d35c30` with the node's `+0x40` member address
   (call-shape only, unconditional — no null check precedes it).
2. Dispose the `+0x20` string, with the idiom depending on the
   node's level inside its invocation frame (see below).
3. Sized-delete the node itself with size `0x58` through the
   `_ZdlPvm` PLT at `0x63f0d80`.

The routine writes nothing back to any node: a destroyed node's
fields are never cleared, and no field of a surviving node is
touched. The next-sibling pointer (`+0x10`) is always read before
the node is freed, so the sibling chain survives each free.

## The two string-disposal idioms and the frame boundary

The nine inline levels of one invocation use two idioms for the
same `+0x20` string field:

- Levels 0–4 (root, and the first four descent levels): the manual
  short-form check — if `[node+0x20]` equals the inline-buffer
  address `node+0x30`, nothing is freed; otherwise the heap buffer
  is sized-deleted with `_ZdlPvm([node+0x20], [node+0x30] + 1)`.
- Levels 5–8 (the deeper inline levels): the string is disposed by
  the `_M_dispose` PLT at `0x63f0db0` with `rdi = node+0x20`.

The idiom is a function of the level *inside one invocation*, not
of absolute tree depth: the self-recursion restarts the frame, so
a node at absolute depth 9 (the recursion root) is disposed with
the manual idiom again, a node at absolute depth 14 with the
`_M_dispose` idiom again, and so on. The model in
`tools/member_tree_teardown_573f0_115.py` encodes exactly this
rule (level-in-frame = absolute depth mod 9; manual when it is
0–4, `_M_dispose` when it is 5–8) and its tests pin the
depth-9 reset. No reason for the compiler's idiom split is claimed;
only the observed boundary is pinned.

## Traversal order: post-order over the whole structure

For each node in the `+0x10` chain starting at the root, the
routine destroys that node's `+0x18` subtree first, then tears the
node down, then moves to the next `+0x10` node and repeats. The
compiler unrolled the first levels of the `+0x18` descent inline —
the descent blocks chain through registers — and the single
self-recursive call at `0x5d57489` extends the descent past the
unrolled depth: it recurses on the `+0x18` child of the deepest
unrolled node, and after it returns that node itself is torn down
and its `+0x10` chain is followed. The observable free order is
the post-order above regardless of unrolling: children before
parents, siblings in chain order, a parent before its own next
sibling.

The unrolled levels, with their holding registers and dispose
blocks, are:

| level | holder | child link read | dispose block | string idiom |
| --- | --- | --- | --- | --- |
| root | `rsp+0x20` | root `+0x18` | `0x5d576c5` | manual |
| 1 | `rsp+0x18` | level-1 `+0x18` | `0x5d57664` | manual |
| 2 | `r12` | level-2 `+0x18` | `0x5d5761e` | manual |
| 3 | `r13` | level-3 `+0x18` | `0x5d5759b` | manual |
| 4 | `rbx` | level-4 `+0x18` | `0x5d57521` | manual |
| 5 | `rbp` | level-5 `+0x18` | `0x5d57568` | `_M_dispose` |
| 6 | `r14` | level-6 `+0x18` | `0x5d575e0` | `_M_dispose` |
| 7 | `r15` | level-7 `+0x18` | `0x5d574d9` | `_M_dispose` |
| 8 | `r8` | level-8 `+0x18` | `0x5d57493` (after the recursion returns) | `_M_dispose` |

If a level's child link is null, control jumps straight to that
level's parent's dispose block (for example, a null level-1 child
jumps to the root dispose at `0x5d576c5`; a null level-8 child
jumps to the level-7 dispose at `0x5d574d9`). When the level-8
child is non-null, the routine calls itself at `0x5d57489` with
that child as the new root, so trees deeper than nine levels are
handled by recursion, not by the unrolled code. Each dispose
block, after freeing its node, follows that node's `+0x10` link:
a non-null next sibling restarts the descent at that level (for
example, a level-8 sibling re-enters at `0x5d57480`, a level-7
sibling re-enters at `0x5d57477`).

The routine keeps no visited set, so the post-order claim rests
on the recorded assumption that the `+0x18`/`+0x10` links form a
tree; a cyclic graph would not terminate in the binary either, so
the model raises instead of looping.

## Consumers

Two external direct callers (see callers.tsv), both passing the
tree root in `rdi` from their stack slot at `rsp+0xf0`, plus the
internal self-recursion site at `0x5d57489`. No tail jumps, no
stored qwords, no RELATIVE relocations — the routine is reached
only by code, never by data.

## Assumptions (not pinned claims)

- The `+0x18`/`+0x10` links form a tree (see above).
- The source-level names and kinds of the node, its `+0x40`
  member and the tree itself are not pinned; only field offsets
  and the transition rules are.
- The `0x5d35c30` callee is used call-shape only; its allocation
  behaviour is not modelled.
- The string size field at `+0x28` is never read by this routine;
  only the pointer at `+0x20` and the capacity at `+0x30` decide
  disposal in the manual idiom.
