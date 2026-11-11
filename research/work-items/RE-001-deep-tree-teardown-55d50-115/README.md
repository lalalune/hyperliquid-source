# RE-001: deep tree teardown routine 0x5d55d50 (node #115)

## Bounded question

What does the routine at `0x5d55d50` dispose, in what order, and which
code reaches it? In particular: what are the fields of the node it
destroys, how does it walk the child and sibling links, and what happens
at depths beyond the compiler's unrolled descent?

## Answer (established semantics)

The routine is a post-order teardown of a tree of 0x50-byte nodes.
Each node has:

- `+0x10`: next sibling (followed after the node itself is destroyed),
- `+0x18`: first child (its whole subtree is destroyed before the node),
- `+0x20`: a libstdc++ string (pointer at `+0x20`, length at `+0x28`,
  allocated-capacity / inline buffer at `+0x30`),
- `+0x48`: a refcounted pointer, released through the shared helper
  `0x5d350c0` when non-null (the helper is pinned whole in the
  RE-001 three-release packet; only its call shape is used here).

Disposing one node, in order, is:

1. Release `[node+0x48]` through the helper `0x5d350c0` when non-null;
   a null field is skipped, with no call.
2. Dispose the `+0x20` string: if `[node+0x20]` equals the inline-buffer
   address `node+0x30`, the string is stored inline and nothing is
   freed; otherwise the heap buffer is sized-deleted with
   `_ZdlPvm([node+0x20], [node+0x30] + 1)` — the capacity at `+0x30`
   (which shares storage with the inline buffer) plus one.
3. Sized-delete the node itself with `_ZdlPvm(node, 0x50)`.

The routine writes nothing back to any node: disposal is destructive
and final. A null root returns immediately with no work.

## The unrolled descent and the self-recursion

The compiler unrolls the first eight descent levels, then calls itself
for anything deeper. The levels, with their holding registers and their
dispose blocks, are:

| level | holder | child link read | dispose block |
| --- | --- | --- | --- |
| root | `rsp+0x10` | root `+0x18` | `0x5d560be` |
| A | `rsp+0x08` | A `+0x18` | `0x5d56035` |
| B | `r14` | B `+0x18` | `0x5d55fef` |
| C | `r15` | C `+0x18` | `0x5d55f5a` |
| D | `rbx` | D `+0x18` | `0x5d55e50` |
| E | `rbp` | E `+0x18` | `0x5d55f10` |
| F | `r12` | F `+0x18` | `0x5d55fa0` |
| G | `r13` | G `+0x18` | `0x5d55eb8` |
| H | `rdx` / `(rsp)` | H `+0x18` | `0x5d55df1` (after the recursion returns) |

If a level's child link is null, control jumps straight to that level's
parent's dispose block (for example, a null A jumps to the root dispose
at `0x5d560be`; a null H jumps to the G dispose at `0x5d55eb8`).
When H is non-null, the routine calls itself at `0x5d55dec` with the
argument `[H+0x18]` — the subtree below H — so trees deeper than nine
levels are handled by recursion, not by the unrolled code. The
nine-level unrolling is therefore an implementation detail: the
observable order is the same recursive post-order at every depth.

Each dispose block first saves its node's `+0x10` next link (in a
register or on the stack slot `(rsp)` for G and H). After the node is
deleted, a non-null saved next link re-enters that level's descent
with the sibling as the new node at that level; a null next link falls
through to the parent level's dispose block. The root level is the
same, except a null root next link returns (`0x5d5609d`).

So the observable order is: a node's whole child subtree, then the
node, then the node's next sibling subtree — children before parents,
siblings in chain order, a parent before its own next sibling.

The nine dispose blocks contribute nine helper calls, nine string
heap-delete sites, and twelve node-delete sites: one node-delete site
after each string delete, plus three extra inline-only node-delete
sites for H (`0x5d55ea8`), A (`0x5d560b4`) and the root (`0x5d56093`),
whose string-skip jumps land on a separate delete instead of falling
through to the shared one. The function has no stack canary and no
landing-pad fragments in its FDE range; its only return is at
`0x5d560ab`.

## Consumers

Exactly 3 direct calls, 0 tail jumps, 0 stored references
(executable-LOAD E8/E9 scan with objdump confirmation, reproduced by
`census.py` and re-run inside `verify.py`):

| site | kind | caller FDE |
| --- | --- | --- |
| 0x5d55dec | call (self-recursion) | 0x5d55d50..0x5d56114 |
| 0x5d6992d | call | 0x5d69926..0x5d699fe |
| 0x5d6a510 | call | 0x5d69a00..0x5d6a6d9 |

Both external callers pass their argument from a stack slot at
`rbp-0x960`; their surrounding code is not pinned here. The routine
is reached only by code, never by data.

## Relation to neighbouring packets

This routine is the string-carrying counterpart of the RE-001
node-tree teardown at `0x5d55aa0` (PR #2676): same `+0x18` child /
`+0x10` sibling shape and the same shared release helper, but a
larger 0x50-byte node, an extra libstdc++ string field at `+0x20`,
and a nine-level unrolled descent with self-recursion instead of a
single unrolled descent. It is not a copy of that packet: the node
layout, the string disposal, and the recursion depth handling are
all different, and each is pinned from this routine's own bytes.

## Unknowns (not filled in)

- Class and field source names; what the tree nodes represent.
- What the `+0x48` refcounted targets are, beyond the helper contract.
- The callers' argument values beyond the shared `rbp-0x960` slot.
- Whether shared nodes (reachable from two parents) occur in practice;
  the code keeps no visited set, so the post-order claim rests on the
  recorded tree assumption — a shared node would be destroyed twice,
  exactly as in the `0x5d55aa0` teardown.

## Evidence

- `main.txt`: whole-function verbatim objdump excerpt. Regenerate with:
  `objdump -d --start-address=0x5d55d50 --stop-address=0x5d56114 work/hl-node-115.bin`
  The header is normalized to the bare binary name only.
- `frames.txt`: the FDE lines for the routine, the release helper, and
  the two external caller functions.
- `callers.tsv`: the 3 confirmed call sites with their caller FDEs.
- `relocations.txt`: empty — no stored reference to the routine.
- `records.json`: semantic records only (node layout, disposal order,
  unrolled levels, caller domains, unknowns). No per-step token list.
- `verify.py`: packet checker (digest, provenance, manifest, excerpt
  regeneration byte-for-byte, excerpt bytes vs the raw binary, FDE
  lines, census, relocations, records shape, model spot checks, full
  test module).
- `census.py`, `export_excerpts.py`: the scripts that produced the
  census and the excerpts, committed in the packet.

## Artifact binding

Node #115 binary `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
as listed in `provenance/artifacts.json`.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. All evidence
above is static objdump/readelf analysis of the materialized binary
plus a Python model of the established semantics. No Rust
reconstruction is claimed.
