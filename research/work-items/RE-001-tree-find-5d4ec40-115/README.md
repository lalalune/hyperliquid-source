# RE-001: map node #115 tree find 0x5d4ec40

## Bounded question

Open PR #2409 mapped the 0x60-byte tree node's teardown, deep copy
and string builder, and open PR #2429 mapped the node-reuse assign
that rebuilds such trees, but neither pinned how a node is looked
up by key. What does the routine at `0x5d4ec40` (FDE
`0x5d4ec40..0x5d4ed33`, 243 bytes) do end to end? It is the tree
find over those same nodes, keyed by the first string field: a
lower_bound walk plus an equality recheck, so the net result is an
exact find, not a lower_bound.

## Answer, stated literally

The routine takes a tree header pointer in `rdi`, a key pointer in
`rsi` and a key length in `rdx`, and returns a node address, or
the sentinel `rdi + 0x08` when no node matches.

### Node and header fields actually read

Header: the root pointer is the qword at `rdi + 0x10`; the
not-found value is `rdi + 0x08` itself. Nothing else in the header
is read.

Node (the same 0x60-byte node open PR #2409 pins): the left child
is the qword at node `+0x10`, the right child the qword at node
`+0x18`, the key string pointer the qword at node `+0x20`, and
the key string length the qword at node `+0x28`. The tag at
`+0x00`, the link at `+0x08`, the key capacity/inline slot at
`+0x30`, and the second string at `+0x40` are never read by this
routine. The bytes at `+0x20`/`+0x28` are read as a plain
pointer/length pair; the routine never checks whether the string
is inline or heap-allocated.

### The walk (sites 0x5d4ec81..0x5d4eccb)

`candidate` starts as the sentinel and `node` starts as the root.
A null root returns the sentinel at once (site `0x5d4ec5e`).

At each node, the routine compares the node key against the search
key as strings:

1. `n = min(node length, search length)`. If `n` is nonzero, it
   calls `memcmp` on the node string and the search key over `n`
   bytes (site `0x5d4ec9b`). A nonzero result decides the step.
2. On a prefix tie (including `n == 0`), the result is the signed
   length difference `node length - search length`, saturated to
   the int32 range: a difference at or above `2**31` counts as
   positive (site `0x5d4ecaa` jumps to the candidate path), and a
   difference at or below `-2**31 - 1` counts as negative (site
   `0x5d4ecb9` jumps to the right step). Otherwise the low 32 bits
   are the result.
3. Node key < search key: step to the right child (`+0x18`,
   site `0x5d4ec78`). Node key >= search key: record the node as
   the candidate, then step to the left child (`+0x10`, site
   `0x5d4ecc4`). A null child ends the walk and control moves to
   the recheck.

This is the standard lower_bound walk: the candidate is always the
last node visited whose key is >= the search key.

### The recheck (sites 0x5d4eccd..0x5d4ed14)

If the candidate is still the sentinel, the routine returns the
sentinel. Otherwise it re-compares, this time with the opposite
orientation: `memcmp` on the search key and the candidate string
over their shorter length (site `0x5d4ecee`), then, on a prefix
tie, the signed difference `search length - candidate length`,
saturated the same way (a difference above `0x7fffffff` returns
the candidate at site `0x5d4ed04`; a difference below
`0x80000000` as signed returns the sentinel at site
`0x5d4ed0d`). If that result is negative, the sentinel is
returned (site `0x5d4ed14`); otherwise the candidate is returned.

Combined with the walk invariant that every recorded candidate
satisfies node key >= search key, the net observable result is
exact equality: the routine returns the node only when its key
equals the search key, and the sentinel otherwise. In particular
a search key that falls between two node keys returns the
sentinel, not the successor — this is a find, not a lower_bound.
The saturation branches for length differences beyond the int32
range are unreachable for any candidate the walk can record at
realistic string lengths (a candidate is >= the search key, so
the recheck's search-minus-candidate difference can only be zero
or negative there); they are recorded literally from the bytes,
and the model implements them.

### Worked example

Tree with keys `apple`, `fig`, `mango` (root `fig`, left `apple`,
right `mango`):

- Search `mango`: `fig < mango`, step right to `mango`;
  `mango >= mango`, candidate `mango`, step left to null; recheck
  equal, return the `mango` node.
- Search `melon`: `fig < melon`, step right; `mango > melon`,
  candidate `mango`, step left to null; recheck: search key
  `melon` < candidate `mango`, return the sentinel.
- Search `app`: `fig > app`, candidate `fig`, step left to
  `apple`; `apple > app` (prefix tie, longer), candidate `apple`,
  step left to null; recheck: search key `app` < candidate
  `apple`, return the sentinel.

### Callers (site-only, semantics not claimed)

Both direct call sites live in the single caller function
`0x5d88840..0x5d89173`: `0x5d88c34` and `0x5d88d3c`. What that
caller does with the returned node or sentinel is not claimed
here.

## NOT claimed

- What the tree, its nodes, or the keys denote, or what the
  caller function does with the result beyond the two recorded
  call sites.
- Behavior on cyclic trees, on dangling child pointers, or on
  keys whose stored length exceeds the bytes actually present
  (the model raises on cyclic/dangling walks instead).
- Anything about the neighbouring routines `0x5d4ed40` and
  `0x5d4f400` (different functions, not mapped here), or about
  the hash-table find in open PR #2071 (`0x5f0e660`, a different
  structure and address).

## Evidence notes

- All extracted from the digest-verified #115 work binary
  (SHA-256 `a6e2897c…5301`, `work/hl-node-115.bin` hashes
  exactly; full digest in `records.json` and
  `provenance/artifacts.json`).
- `main.txt` is the whole-function disassembly exactly as
  `objdump` emitted it, regenerated by `export_excerpts.py`;
  instruction-level detail lives only in that excerpt text.
  `records.json` holds semantic records only — no
  per-instruction mnemonic list.
- The mnemonics in the excerpt (including `endbr64`) are genuine
  instructions present in the target binary, not placeholders:
  `verify.py` checks every excerpt instruction byte-for-byte
  against the raw binary and regenerates the excerpt from a
  fresh `objdump` run.
- `frames.txt` carries the FDE lines for the routine and its
  caller function; `relocations.txt` is intentionally empty (no
  RELATIVE addend mentions this routine); `callers.tsv` records
  both call sites with their enclosing FDE range.
- The packet additionally carries its own runnable checker
  (`verify.py`) and census reproducer (`census.py`).
- Tests in `tests/test_tree_find_115.py` exercise the behavior
  end to end through the model in `tools/tree_find_115.py`
  (inputs through the walk to observable node/sentinel outputs),
  not only pinned constants.
