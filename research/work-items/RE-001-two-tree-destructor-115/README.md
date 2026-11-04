# RE-001: map node #115 two-tree object destructor 0x5d50170

## Bounded question

Open PR #2409 mapped the 0x60-byte tree teardown at `0x5d4cfd0`,
its copy, and their shared string builder, and recorded the
teardown's 23 call sites — but it did not pin any of the
teardown's callers. What does one of those callers do end to
end? The caller at `0x5d50170` (FDE `0x5d50170..0x5d503f5`,
645 bytes) destroys a whole object: two tree lists plus twelve
string fields. This packet pins that destructor, its exact
field order, and its delete sequence.

## Answer, stated literally

The routine takes one object pointer in `rdi` and returns void.
It writes nothing itself and never deletes the object itself.
Every effect is an operator delete (PLT `0x63f0d80`) or a call
to the `0x5d4cfd0` teardown, whose own semantics are pinned by
open PR #2409 and are referenced here, not re-claimed.

### Order of destruction

1. The tree list at obj+0x288.
2. The tree list at obj+0x258.
3. Twelve string fields, in descending offset order:
   +0x228, +0x208, +0x1e8, +0x1c8, +0x1a8, +0x188, +0x168,
   +0x148, +0x128, +0x108, +0xe8, +0xc8.

### Tree lists (0x60-byte nodes, per #2409)

Node layout: tag dword at +0x00 (never read here), link at
+0x08 (never read here), next sibling at +0x10, child-list
head at +0x18, string A at +0x20 (pointer +0x20, size +0x28,
capacity-or-inline +0x30), string B at +0x40 (pointer +0x40,
size +0x48, capacity-or-inline +0x50).

Per list, the routine walks the +0x10 chain in order. Per
node, in this order:

1. Call the teardown on the node's +0x18 child-list head
   (sites `0x5d5018b` for the +0x288 list, `0x5d501f0` for
   the +0x258 list). A null child head is still passed to the
   teardown, which frees nothing for it.
2. Dispose string B: delete unless its pointer equals
   `&node+0x50`, with size `qword at +0x50 + 1`.
3. Dispose string A: delete unless its pointer equals
   `&node+0x30`, with size `qword at +0x30 + 1`.
4. Delete the node itself with size `0x60`.
5. Advance to the +0x10 successor, which was loaded before
   the node's own deletes, so the chain survives the free.

A null list head skips that list entirely. Worked order for a
list whose head A has child chain C -> D (D having child E)
and sibling B: C, E, D, A, B — children before their node,
siblings after it. The two lists are destroyed by the same
inlined sequence; the routine does not call itself.

### String fields

Each field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. The field is
inline exactly when its stored pointer equals the address of
its own capacity/inline slot (+X+0x10); in that case nothing
is freed. Otherwise the heap buffer is freed as
`delete(ptr, capacity + 1)`. The last field (+0xc8) reaches
the delete PLT by a tail jump (`0x5d503eb`); the effect is
identical to the other fields' calls.

### Call sites of this routine (census)

Whole-file census, reproduced by the packet's census.py and
re-run inside verify.py: the destructor has exactly 36 direct
calls and 1 tail jump (`0x5dfbcd8`), 0 stored qwords, and 0
R_X86_64_RELATIVE addends. All 37 sites are recorded by
address and enclosing FDE range in callers.tsv only; no caller
semantics are claimed for any of them. The first call site
(`0x5d802aa`) sits in `0x5d7fc80..0x5d8043e`, the same
consumer function #2409 excerpted for the tree copy — again
recorded as a site only.

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
