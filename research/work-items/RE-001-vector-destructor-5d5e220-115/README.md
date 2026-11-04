# RE-001: map node #115 vector destructor 0x5d5e220

## Bounded question

Open PR #2421 mapped the single-object destructor at `0x5d5e5d0`,
and open PR #2409 mapped the 0x60-byte tree teardown at
`0x5d4cfd0` — but neither pinned this routine. What does the
routine at `0x5d5e220` (FDE `0x5d5e220..0x5d5e5c1`, 929 bytes)
destroy end to end? It destroys a whole vector of those
objects: every element in the [begin, end) range, in order,
then the vector's storage itself.

## Answer, stated literally

The routine takes one vector pointer in `rdi` and returns void.
It writes nothing itself and never deletes the vector object
itself. The vector triple is: begin at obj+0x00, end at
obj+0x08, capacity-end at obj+0x10.

### Iteration

The loop bound is read once at entry: end = qword at obj+0x08.
The cursor starts at begin = qword at obj+0x00 and advances by
`0x3f0` per element until it equals end. An empty range
(begin == end) destroys no element but still runs the tail
below. The stride `0x3f0` is the element size: the per-element
body touches fields up to +0x3d7, so `0x3f0` covers the whole
element.

### Per-element destruction

Each element is destroyed with exactly the field sequence open
PR #2421 pins for one object (same offsets, same order); the
sequence is reproduced here because it is literally this
routine's loop body, not re-claimed as a separate result:

1. Three string fields, in this order: +0x3b8, +0x398, +0x368.
2. The tree list at element+0x318, walked inline: per node,
   the child list at node+0x18 is handed to the `0x5d4cfd0`
   teardown (sites `0x5d5e2b9` and `0x5d5e320` for the two
   lists), then string B and string A are disposed, the node
   is deleted with size `0x60`, and the walk advances to the
   +0x10 successor loaded before the node's own deletes. A
   null list head destroys nothing.
3. The tree list at element+0x2e8, by the same inline walk.
4. Fifteen string fields, in descending offset order:
   +0x2b8, +0x298, +0x278, +0x258, +0x238, +0x218, +0x1f8,
   +0x1d8, +0x1b8, +0x198, +0x178, +0x158, +0x40, +0x20, +0x00.

### String fields

Each field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. The field is
inline exactly when its stored pointer equals the address of
its own capacity/inline slot (+X+0x10); in that case nothing
is freed. Otherwise the heap buffer is freed as
`delete(ptr, capacity + 1)`. The binary never reads a string
field's size for the delete; only the capacity field is read,
for the +1 sizes.

### Tail: storage deallocation

After the loop, begin is re-read from obj+0x00. If it is null,
the routine returns with no further effect. Otherwise it
tail-jumps to the operator delete PLT (`0x63f0d80`) with
(ptr = begin, size = qword at obj+0x10 minus begin) — the
full allocation byte count from begin to capacity-end, not
the element count times `0x3f0`. So an empty-but-allocated
vector still frees its storage, and a vector whose capacity
exceeds its element count frees the whole allocation.

### Call sites of this routine (census)

Whole-file census, reproduced by the packet's census.py and
re-run inside verify.py: the routine has exactly 9 direct
calls, 0 tail jumps, 0 stored qwords, and 0 R_X86_64_RELATIVE
addends. All 9 sites are recorded by address and enclosing
FDE range in callers.tsv only; no caller semantics are
claimed for any of them. One site (`0x5d81695`) sits in
`0x5d80440..0x5d81813`, the same large function #2409 and
#2388 excerpted — again recorded as a site only.

## NOT claimed

- What the vector, its elements, their trees, nodes, or
  strings denote.
- Caller semantics beyond the recorded site addresses.
- The teardown callee's own semantics (open PR #2409) or the
  single-object destructor's own claim (open PR #2421).
- Behavior on a range whose byte length is not a multiple of
  `0x3f0`, on a null begin with a nonzero end, or on cyclic
  or dangling trees: the model raises, while the binary would
  loop, dereference, or run past the range unchecked.

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
