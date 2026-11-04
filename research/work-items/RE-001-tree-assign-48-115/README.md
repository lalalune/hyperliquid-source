# RE-001: map node #115 0x48-byte tree assign 0x5d4e140

## Bounded question

Open PR #2429 mapped the assign for the 0x60-byte two-string tree
nodes (rebuilder 0x5d4e6a0, assign 0x5d4ea90), and open PR #2409
mapped that node's teardown. A second, smaller tree node type
exists in the same binary: 0x48-byte nodes with a single string.
What does the assign at `0x5d4e140` (FDE
`0x5d4e140..0x5d4e257`, 279 bytes) do end to end, with its
rebuilder at `0x5d4de20` (FDE `0x5d4de20..0x5d4e11a`, 762 bytes)
and its leftover teardown at `0x5d4cba0` (FDE
`0x5d4cba0..0x5d4cbf9`, 89 bytes)? It is the same assign shape
as #2429, for the smaller node type: detach the old tree into a
reuse pool, rebuild the source tree from that pool, destroy what
remains.

## Answer, stated literally

The assign takes a destination container in `rdi` and a source
container in `rsi`, and returns void. A self-assign (dst is src)
returns with no effect.

### Node and container fields

Node (0x48 bytes): the tag is the dword at `+0x00`, the link the
qword at `+0x08`, the next sibling the qword at `+0x10`, the
first child the qword at `+0x18`, the string pointer the qword at
`+0x20`, the string length the qword at `+0x28`, the string
capacity/inline slot the qword at `+0x30`, and an extra qword at
`+0x40`. The bytes at `+0x38` are never read or written by any
of these three routines. A string is inline exactly when its
pointer equals its own capacity/inline slot address (`+0x30`);
a heap string is freed as delete(ptr, capacity + 1); the string
length is never used as a delete size.

Container (header embedded at dst `+0x08`): the root is the
qword at `+0x10`, the `+0x18` slot holds the last node of the
root's `+0x10` walk, the `+0x20` slot holds the last node of the
root's `+0x18` walk, and the count is the qword at `+0x28`.
A fresh root's link is the header address (`dst + 0x08`); an
empty tree has root 0 and `+0x18`/`+0x20` both equal to the
header address.

### The assign (sites in assign.txt)

1. The old tree is detached into a stack pool pair: pool[0] is
   the old root, pool[1] is the old `+0x20` node's `+0x10`
   successor when that successor exists, else the old `+0x20`
   node itself (when the old root is 0, both pool slots are 0).
   The old root's link (`+0x08`) is cleared. The destination is
   reset to empty (root 0, `+0x18`/`+0x20` = header address,
   count 0).
2. When the source root exists, the rebuilder rebuilds it (site
   `0x5d4e1ce`, link argument = the header address). Afterwards
   the destination's `+0x10` is the rebuilt root, its `+0x18`
   is the last node of the rebuilt root's `+0x10` walk, its
   `+0x20` is the last node of the rebuilt root's `+0x18`
   walk, and its `+0x28` is the source count.
3. Whatever pool nodes remain are destroyed by the teardown
   (site `0x5d4e218`), called with pool[0] as its argument.
   When the source root is empty this is the only step after
   the reset, so the old tree is destroyed whole.

### The rebuilder (sites in rebuilder.txt)

The rebuilder takes a source node in `rdi`, a link in `rsi`,
and the pool pointer in `rdx`, and returns the rebuilt node.

* A pool node is taken by the pop below, or a fresh 0x48-byte
  node is allocated when the pool is empty. A reused node's old
  string is disposed first (in the head path through the
  `_M_dispose` PLT call at site `0x5d4de70`, in the sibling
  path by inline code with the same rule: delete unless the
  pointer equals the node's own `+0x30` slot), then the string
  is rebuilt from the source node through the `0x5d4a6a0`
  builder (referenced from open PR #2409, not re-claimed):
  the destination string slot is preset to its own `+0x30`
  address, the source pointer is `rsi` and the end pointer is
  the source pointer plus the source length. The tag dword and
  the `+0x40` qword are copied from the source node, link is
  the link argument, next and child start as 0.
* The source's child subtree is rebuilt recursively (site
  `0x5d4dec7`, link = the new node) and stored at the new
  node's `+0x18`.
* Each source sibling is then rebuilt the same way: its link is
  the previous rebuilt sibling, the previous sibling's `+0x10`
  is the new node, and its child subtree is rebuilt recursively
  (site `0x5d4df77`, link = the new sibling).

### The pool pop (identical in the head and sibling paths)

head = pool[1]; when head is 0 there is no node to take.
nxt = head's link; pool[1] = nxt. When nxt is 0, pool[0] is
cleared (the pool is empty). When nxt's child is head, the take
splices: nxt's child is cleared; when nxt's next exists,
pool[1] walks from that next node down its `+0x18` child chain
to the deepest node, and then to that deepest node's `+0x10`
successor when one exists. Otherwise (nxt's child is not head)
nxt's `+0x10` is cleared. The taken node is head in every case.

### The teardown (sites in teardown.txt)

The teardown takes a node in `rdi` and returns void; a null
argument returns at once. Per node, in order: the `+0x18`
child subtree is torn down first (self-recursion site
`0x5d4cbb7`), then the string is disposed (delete unless the
pointer equals the node's own `+0x30` slot, size capacity +
1), then the node itself is deleted with size 0x48, advancing
to the `+0x10` successor loaded before the node's own deletes.
The teardown never deletes the container itself and never
frees a string's inline bytes.

### Observed consequences, recorded not smoothed over

* Orphaning: a simple-case pop clears the new pool head's
  `+0x10` link, and a splice-case pop clears the spliced
  node's `+0x18` link, so a node reachable only through a
  cleared link is neither reused nor destroyed. Worked
  example in the tests: an old root whose first child has
  siblings A -> B -> C, assigned a single-node source,
  reuses B, destroys A and the root, and orphans C.
* Splice reuse of the old root: an old root R with only child
  X, assigned a two-node source, pops X first (splice: R's
  child cleared, pool[1] becomes R) and then pops R itself as
  the second node, so both old nodes are reused and none is
  deleted.

### Census (whole-file scan, reproduced by census.py)

Assign `0x5d4e140`: exactly 2 direct calls (`0x5d52742`,
`0x5d88e47`), 0 tail jumps. Rebuilder `0x5d4de20`: exactly 3
direct calls (`0x5d4e1ce` in the assign, `0x5d4dec7` and
`0x5d4df77` self-recursions), 0 tail jumps. Teardown
`0x5d4cba0`: exactly 25 direct calls (self-recursion
`0x5d4cbb7`, the assign site `0x5d4e218`, the rebuilder
landing-pad site `0x5d4e11e`, and 22 sites in other functions
recorded site-only in callers.tsv), 0 tail jumps. No stored
qwords and no RELATIVE addends for any of the three routines.

### NOT claimed

What the trees, nodes, tags, strings, or the `+0x40` qword
denote; the `0x5d4a6a0` builder's internals beyond the
referenced behavior (model records a heap string's capacity as
its length, so its delete size is length + 1); caller semantics
beyond site addresses and caller FDE ranges; behavior on
cyclic structures (the model raises in the teardown path) or
on inconsistent headers; anything about the neighbouring
0x60-byte assign in open PR #2429 beyond the shared shape
(the node layouts differ: one string here, two there, and
different teardown callees).

### Evidence and verification

All extracted from the digest-verified #115 work binary
(SHA-256 `a6e2897c…5301`, `work/hl-node-115.bin` hashes
exactly; bound to `provenance/artifacts.json` entry
`artifacts/node/115/hl-node`). The packet's JSON holds
semantic records only; instruction-level detail lives only in
the whole-function verbatim excerpts (assign.txt,
rebuilder.txt, teardown.txt), regenerated byte-for-byte from a
fresh objdump run by export_excerpts.py and checked
byte-for-byte against the raw binary by verify.py. The
excerpts contain no placeholder tokens: they are verbatim
objdump output, and every instruction in them is re-checked
against the raw binary bytes, so a mnemonic in an excerpt is
a genuine instruction present in the target binary.
The packet additionally carries its own runnable verify
script, census script, and excerpt-export script, so the
checker behind "ALL CHECKS PASSED" is visible in the diff.

Verification: checker ALL CHECKS PASSED (digest, provenance,
manifest, excerpt regeneration byte-for-byte from a fresh
objdump run, every excerpt instruction byte-for-byte vs raw
binary, FDE ranges, census including per-site caller-function
checks against the smallest enclosing FDE, records, model
tests); 3 extra spot instructions byte-for-byte vs fresh
objdump and raw binary (`0x5d4e1ce`, `0x5d4df99`,
`0x5d4cbd5`) beyond verify.py's own 3 spots; 324 model checks
pass (empty sides, fresh build order and slots, worked
teardown order, heap dispose sizes, reuse with the orphan
case, the no-orphan two-sibling case, the splice-reuses-root
case, pop branches, self-assign, cycle guard, 60 random
chained assigns with proper-tree and shape checks).

### Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java;
the model and tests are Python only, and no claim is made
about Rust reconstruction or about running the node binary.
The pre-existing LFS-baseline test failures of the repository
are unrelated to this change.
