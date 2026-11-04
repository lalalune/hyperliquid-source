# RE-001: map node #115 object destructor 0x5d5e5d0

## Bounded question

Open PR #2409 mapped the 0x60-byte tree teardown at `0x5d4cfd0`
and recorded its call sites, and open PR #2415 mapped a
different object destructor (`0x5d50170`) that inlines the
per-node teardown loop — but neither pinned this destructor.
What does the routine at `0x5d5e5d0` (FDE
`0x5d5e5d0..0x5d5e852`, 642 bytes) destroy end to end? It
destroys a whole object: three string fields, two tree lists
through the teardown, then fifteen more string fields.

## Answer, stated literally

The routine takes one object pointer in `rdi` and returns void.
It writes nothing itself and never deletes the object itself.
Every effect is an operator delete (PLT `0x63f0d80`) or a call
to the `0x5d4cfd0` teardown, whose own semantics are pinned by
open PR #2409 and are referenced here, not re-claimed.

### Order of destruction

1. Three string fields, in this order: +0x3b8, +0x398, +0x368.
2. The tree list at obj+0x318, by calling the teardown
   (site `0x5d5e648`).
3. The tree list at obj+0x2e8, by calling the teardown
   (site `0x5d5e654`). A null list head is passed to the
   teardown unchanged, which frees nothing for it (per #2409).
4. Fifteen string fields, in descending offset order:
   +0x2b8, +0x298, +0x278, +0x258, +0x238, +0x218, +0x1f8,
   +0x1d8, +0x1b8, +0x198, +0x178, +0x158, +0x40, +0x20, +0x00.

### String fields

Each field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. The field is
inline exactly when its stored pointer equals the address of
its own capacity/inline slot (+X+0x10); in that case nothing
is freed. Otherwise the heap buffer is freed as
`delete(ptr, capacity + 1)`. The last field (+0x00) reaches
the delete PLT by a tail jump (`0x5d5e846`); the effect is
identical to the other fields' calls.

### Tree lists (0x60-byte nodes, per #2409)

Node layout: tag dword at +0x00 (never read by the teardown),
link at +0x08 (never read by the teardown), next sibling at
+0x10, child-list head at +0x18, string A at +0x20 (pointer
+0x20, size +0x28, capacity-or-inline +0x30), string B at
+0x40 (pointer +0x40, size +0x48, capacity-or-inline +0x50).
The teardown's own destroy order (child subtree, string B,
string A, node delete 0x60, then the +0x10 successor) is
#2409's claim, referenced here; this packet only pins that
this routine hands it the +0x318 and +0x2e8 list heads, in
that order, between the two string groups.

### Call sites of this routine (census)

Whole-file census, reproduced by the packet's census.py and
re-run inside verify.py: the destructor has exactly 12 direct
calls, 0 tail jumps, 0 stored qwords, and 0 R_X86_64_RELATIVE
addends. All 12 sites are recorded by address and enclosing
FDE range in callers.tsv only; no caller semantics are
claimed for any of them. The first call site (`0x5d802e7`)
sits in `0x5d7fc80..0x5d8043e`, the same consumer function
#2409 excerpted for the tree copy — again recorded as a
site only.

## NOT claimed

- What the object, its trees, its nodes, or its strings
  denote.
- Caller semantics beyond the recorded site addresses.
- The teardown callee's own semantics (open PR #2409).
- Behavior on cyclic or dangling trees: the model raises,
  while the binary dereferences unchecked. The binary's
  string-size fields are never read by the deletes (only the
  capacity fields are, for the +1 sizes).

## Evidence and environment

All extracted from the digest-verified node #115 work binary
(SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
`work/hl-node-115.bin`, bound to
`provenance/artifacts.json`). The packet holds the semantic
records.json only — no per-instruction mnemonic list;
instruction-level detail lives only in the whole-function
verbatim excerpt main.txt, exactly as objdump emitted it
(mnemonics such as `endbr64` are genuine instructions
present in the target binary, not placeholders). The packet
additionally carries its own runnable verify.py, census.py,
and export_excerpts.py. Environment limits, stated honestly:
this VM has no cargo/rustc, no git-lfs, and no Ghidra/Java;
everything here was derived from objdump/readelf output on
the materialized #115 binary plus the Python model and its
tests, which verify.py re-runs.
