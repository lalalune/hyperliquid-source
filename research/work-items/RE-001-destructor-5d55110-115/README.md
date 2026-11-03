# RE-001: map node #115 object destructor 0x5d55110

## Bounded question

Open PR #2409 mapped the 0x60-byte tree teardown at `0x5d4cfd0`,
open PR #2415 mapped a two-tree destructor that walks both of its
lists inline, and open PR #2421 mapped a destructor that hands
both of its lists to the teardown — but none pinned this routine.
What does the routine at `0x5d55110` (FDE
`0x5d55110..0x5d5538d`, 637 bytes) destroy end to end? It
destroys one object with a hybrid shape: one tree list handed
whole to the teardown callee, one tree list walked inline, then
fifteen string fields in descending offset order.

## Answer, stated literally

The routine takes one object pointer in `rdi` and returns void.
It writes nothing itself and never deletes the object itself.

### Step 1: the teardown list at obj+0x2f0

At site `0x5d55122` it calls the `0x5d4cfd0` teardown with
`rdi` = the qword at obj+0x2f0, the list head. The teardown's
own semantics are pinned by open PR #2409 and are referenced
here, NOT re-claimed: per node, the child list at node+0x18
is torn down, string B then string A are disposed, the node
is deleted with size `0x60`, and the walk advances to the
+0x10 successor. A null head destroys nothing.

### Step 2: the inline list at obj+0x2c0

The routine then walks the list at obj+0x2c0 inline, with
exactly the same per-node sequence: the child list at
node+0x18 is handed to the `0x5d4cfd0` teardown (site
`0x5d55137`), string B is disposed (delete unless its
pointer equals the address of its own capacity slot at
node+0x50, size = capacity + 1), string A is disposed the
same way (pointer at node+0x20, capacity slot at node+0x30),
the node is deleted with size `0x60` (site `0x5d5517c`),
and the walk advances to the +0x10 successor loaded before
the node's own deletes (site `0x5d55186` / `0x5d55189`
loop). A null head destroys nothing. The worked order for a
head A with child chain C -> D (D having child E) and
sibling B is C, E, D, A, B — the same order open PR #2409
states for the teardown, because the inline walk applies
the same rule.

### Step 3: fifteen string fields, descending

Then, in this exact order, it disposes one string field per
offset: +0x290, +0x270, +0x250, +0x230, +0x210, +0x1f0,
+0x1d0, +0x1b0, +0x190, +0x170, +0x150, +0x130, +0x40,
+0x20, +0x00.

Each field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. The field
is inline exactly when its stored pointer equals the address
of its own capacity/inline slot (+X+0x10); in that case
nothing is freed. Otherwise the heap buffer is freed as
`delete(ptr, capacity + 1)`. The binary never reads a string
field's size for the delete; only the capacity field is
read, for the +1 sizes. The last field (+0x00) reaches the
operator delete PLT by tail jump at site `0x5d55380`,
with identical effect.

### Call sites of this routine (census)

Whole-file census, reproduced by the packet's census.py and
re-run inside verify.py: the routine has exactly 1 direct
call, 0 tail jumps, 0 stored qwords, and 0 R_X86_64_RELATIVE
addends. The single site (`0x5d562f2`) is recorded by
address and enclosing FDE range in callers.tsv only; no
caller semantics are claimed for it.

## NOT claimed

- What the object, its trees, nodes, or strings denote.
- Caller semantics beyond the recorded site address.
- The teardown callee's own semantics (open PR #2409).
- Behavior on cyclic or dangling trees: the model raises,
  while the binary would loop or dereference unchecked.
- Anything about the neighbouring routine at `0x5d56320`,
  which is a different function and is not mapped here.

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
