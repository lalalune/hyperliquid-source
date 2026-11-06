# RE-001: map node #115 recursive node-tree teardown 0x5d55aa0

Bounded question: what does the 684-byte routine at 0x5d55aa0 do
end to end — what structure does it destroy, in what order, and
what exactly happens to each node?

## Answer, end to end

Arguments: rdi = root node. A null root returns immediately with
nothing destroyed. The routine has no landing pads in its FDE
range (cie=00000000) and no stack canary.

### 1. Node layout (0x38-byte nodes)

- +0x10: next link — the next sibling, followed after the node
  itself is destroyed.
- +0x18: down link — the first child; the subtree rooted here is
  destroyed before the node itself.
- +0x30: refcounted payload pointer, released through the shared
  helper 0x5d350c0 when non-null and skipped when null.

### 2. Per-node teardown, identical in every teardown block

For each node, in order:

1. Release [node +0x30] through 0x5d350c0 when non-null; the
   release is skipped entirely when the payload is null.
2. Sized-delete the node itself with size 0x38 via _ZdlPvm,
   unconditionally — even when the payload was null.

The routine writes nothing back to any node: a destroyed node's
fields are never cleared, and no field of a surviving node is
touched.

### 3. Traversal order: post-order over the whole structure

For each node in the +0x10 chain starting at the root, the routine
destroys that node's +0x18 subtree first, then tears the node
down, then moves to the next +0x10 node and repeats. The compiler
unrolled the first levels of the +0x18 descent inline — the
descent blocks chain through registers — and the single
self-recursive call at 0x5d55b40 extends the descent past the
unrolled depth: it recurses on the +0x18 child of the deepest
unrolled node, and after it returns that node itself is torn down
and its +0x10 chain is followed. The observable free order is the
post-order above regardless of unrolling: children before parents,
siblings in chain order, a parent before its own next sibling.

The routine keeps no visited set, so the post-order claim rests on
the recorded assumption that the +0x18/+0x10 links form a tree
(each node reached exactly once); shared nodes would be destroyed
twice, and the excerpt shows no guard against that.

## Consumers

Four external direct calls plus the self-recursive call
(exhaustive executable-LOAD-segment E8/E9 scan with objdump
confirmation, reproduced by census.py and re-run inside verify.py).
No tail jumps, no stored references — the routine is reached only
by code, never by data:

- 0x5d55b40: the self-recursive call inside the routine itself.
- 0x5d6c30f in FDE 0x5d6bdf0..0x5d6c395, rdi = [rbp +0x1240].
- 0x5d84aa9 in FDE 0x5d8479c..0x5d85475, rdi = [rbx +0x1240];
  the site follows a __cxa_rethrow call in a cleanup fragment of
  that teardown function.
- 0x5d87d35 and 0x5d8847d, both in FDE 0x5d878f0..0x5d887b0,
  rdi = [rbx +0x1240] in both cases.

All four external callers pass the same holder +0x1240 field as
the root argument, so the destroyed structure is the tree owned
by that holder field. The release helper 0x5d350c0's own callers
are not censused here; only its release contract (established in
the RE-001 three-release packet) is used.

## Unknowns (recorded, not filled in)

- The source names of the node type and its holder type.
- What the holder +0x1240 field's object kind is beyond its layout
  role as the tree root.
- Whether the +0x30 payload type differs across nodes; only its
  release contract is pinned here.

## Evidence and method

- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json (artifacts/node/115/hl-node).
- main.txt is the whole-function objdump excerpt for
  0x5d55aa0..0x5d55d4c, verbatim except the header normalized to
  the bare binary name. Detail at the single-step level lives
  only in that excerpt; records.json above carries semantic
  records, not a per-step list. The mnemonics in the excerpt are
  genuine instructions present in the target binary, not
  placeholders.
- frames.txt holds the routine's FDE line plus the FDE lines of
  the release helper and the three distinct caller functions.
- verify.py re-checks the digest, the manifest, byte-for-byte
  excerpt regeneration, every excerpt line against the
  raw binary, every FDE line, the census, the stored-reference
  census, the semantic records and the model tests.
- Run the packet checker from the repository root:
  `python3 research/work-items/RE-001-node-tree-teardown-55aa0-115/verify.py`
- Generate the excerpt with:
  `python3 research/work-items/RE-001-node-tree-teardown-55aa0-115/export_excerpts.py`
