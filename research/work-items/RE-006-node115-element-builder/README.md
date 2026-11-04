# RE-006 node 115: the element builder behind the sibling-search node

## Scope

PR #2561 pinned the join helper and proved that none of the bodies in
the consumption window — the sibling search `0x35bf460`, its fallback
`0x4556410`, the join callee `0x36a0d80`, its four callers, and all 63
search-caller FDEs — writes the eight element fields the callee reads
(+0x40, +0x58, +0x60, +0x78, +0x80, +0x88, +0x90, +0x98 of the 0xb0-byte
element at `node + position * 0xb0`). Those fields are incoming,
written by an element builder before the window. This packet follows
the discriminator the predecessor prescribed: trace the allocation
and insertion paths of the sibling-search node layout outward from
its handle constructors, and census every store into a new element.

Static analysis only, against node 115
(sha256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
No artifact code was executed.

## Short answer

The builder machinery never writes any of the eight fields
individually. Across the 19 pinned builder bodies — 3 insert
wrappers, 3 insert/split giants, 6 flat-to-tree build initialisers,
3 bulk-build giants, and 4 insert-or-assign drivers, 5,506 decoded
instructions in total — there is **no store at any of the eight
displacements through a non-stack address**, and every
element-derived store (base or index register data-dependent on an
`imul $0xb0`/`imul $0xb8` address product) is the displacement-0
head-qword store (21 sites, all in the six giants).

Elements enter a node only as wholesale copies of an already-built
element image:

- 22 whole-element memcpys of 0xb0 bytes through GOT slot
  `0x64df508` (`memcpy@GLIBC_2.14`),
- 51 tail memcpys of 0xa8 bytes (element bytes +8..+0xb0), each
  paired with a head-qword register store,
- 15 whole-element memmove shifts through GOT slot `0x64df568`
  (`memmove@GLIBC_2.2.5`) during in-node insertion shifts.

The image itself is caller-supplied: the four drivers receive the
element as an argument and only forward it (to the wrappers, and so
into the giants) or copy it wholesale with 0xb0 memcpys of their own.
**The original per-field writer is whoever fills that 0xb0-byte
element buffer above the drivers.** The drivers' direct E8 callers
are censused as the boundary (13 sites in 11 FDEs) and deliberately
not traced — one more level up, per the lane brief.

## The builder window

The layout recurs in three clone families; each body below is
pinned by digest, the 13 small bodies additionally by every decoded
instruction row. Call edges are binary-wide E8 facts.

| role | bodies | callers (E8, binary-wide) |
| --- | --- | --- |
| insert wrapper (305 B) | `0x26daaf0`, `0x370e210`, `0x51f0d50` | exactly the drivers: wrap_a ← caller_a; wrap_b ← caller_b1 + caller_b2; wrap_c ← caller_c |
| insert/split giant (3,418 B) | `0x1ca5420`, `0x34e4910`, `0x4c693b0` | exactly its own wrapper (1 site each) |
| build initialiser (403–425 B) | `0x23a4e90`, `0x23b3680`, `0x3885190`, `0x3896840`, `0x5169d90`, `0x516a760` | — (entry points of the bulk-build path) |
| bulk-build giant (2,328 B) | `0x1cff190`, `0x3578e50`, `0x4cba750` | exactly its family's two initialisers (2 sites each) |
| insert-or-assign driver (164–1,242 B) | `0x2dc3900`, `0x3ce15b0`, `0x3f1a150`, `0x4dd2ca0` | the boundary census below |

No pinned body calls the sibling search (the search's 99 E8 sites
sit in none of the pinned FDEs); the drivers carry inlined copies of
the descent instead.

## Allocation

Every fresh node in the window is allocated through GOT slot
`0x64df480` (R_X86_64_RELATIVE → body `0x6355830`, the shared
allocator) with a constant size, 27 sites in total:

- 0x7f8 bytes for a leaf node — 15 sites (3 wrappers, 1 per
  insert/split giant (3), 1 per bulk-build giant (3), 6
  initialisers' first nodes): 11 elements × 0xb0,
  11 keys × 8, parent pointer at +0x790, child index at +0x7f0,
  count at +0x7f2, 12 edge slots from +0x7f8;
- 0x858 bytes for an internal node — 12 sites (the split/root-split
  paths of the six giants).

Every fresh node is initialised the same way: a zero qword store to
the parent pointer (+0x790) and a zero word store to the count
(+0x7f2), 27 sites each. Freed nodes go through GOT slot `0x64df4a0`
(R_X86_64_RELATIVE → `0x635de30`, sized deallocation).

## The insertion census

Per body, the extractor classifies every memory-destination store
and every call through the memcpy/memmove/allocator slots
(`records.json`, key `insertion_census`, carries the full site
lists). Totals over the 19 bodies:

| measure | count |
| --- | --- |
| decoded instructions | 5,506 |
| stores at the 8 field displacements, non-stack base | **0** |
| element-derived stores at a field displacement | **0** |
| element-derived stores at any other displacement | **0** |
| head-qword stores (displacement 0, element-derived) | 21 |
| whole-element memcpys (0xb0) | 22 |
| tail memcpys (0xa8) | 51 |
| whole-element memmove shifts (element-derived dest) | 15 |
| other copy-slot calls (key/edge shifts, staging, block moves) | 54 |
| node-field stores (+0x790/+0x798/+0x7a0/+0x7f0/+0x7f2/+0x7f8…) | 285 |
| node initialisation zero stores (+0x790 and +0x7f2) | 54 |

The wrappers are the leaf fast path: allocate 0x7f8, zero
parent/count, store the key at keys[0], and copy the element in with
one 0xb0 memcpy from the wrapper's element argument — itself the
driver's element argument, forwarded unchanged. In the giants, an
insertion is a key memmove, an element memmove shift, and the same
0xb0 memcpy; a split promotes the median element as head-qword store
plus 0xa8 tail memcpy, in both directions (node → stack staging
buffer → parent node). The bulk-build giants consume flat 0xb8-byte
records (key at +0, element at +8) and place each element with the
same head-plus-tail pattern. The drivers stage the element argument
into a stack record `{key, element}` with a 0xb0 memcpy, or, on a
search hit, swap it into the found element slot with two 0xb0
memcpys (out-copy, then in-copy). None of them computes a field.

## Boundary

The drivers' direct E8 callers, censused and not traced:

- caller_a `0x2dc3900` ← 1 site in FDE `0x2c62590`;
- caller_b1 `0x3ce15b0` ← 10 sites in 8 FDEs, including three of
  the four join-consumer FDEs pinned by PR #2558 (`0x2a89500`,
  `0x55a07e0`, `0x55a12e0`) — the consumers update elements through
  the same driver after reading them;
- caller_b2 `0x3f1a150` ← 1 site in FDE `0x36a1330`;
- caller_c `0x4dd2ca0` ← 1 site in FDE `0x55defd0`.

Whoever writes the eight fields does so while filling the 0xb0-byte
element buffer these callers hand to the drivers. That is the next
open question; it is one level above this packet's window.

## Files

- `records.json` — authenticated findings (extractor output).
- `frames.txt` — the readelf FDE lines for the 21 pinned bodies
  plus the sibling search and the join callee.
- `*_full_body_*_objdump.txt` — full intel-syntax disassembly
  exports of all 21 pinned bodies (each ≤ 3,418 bytes).
- `MANIFEST.sha256` — hashes of the packet files.
- Extractor: `tools/element_builder_static.py`; tests:
  `tests/test_element_builder_static.py`.
