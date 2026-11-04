# RE-001: map node #115 0x48-byte single-string tree teardown 0x5d4d890

Task ID: RE-001. Bounded question: what does the whole routine at
0x5d4d890 in the node #115 binary do, end to end, as a complete
behavior — not a lone window?

## Evidence and binding

- Target: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching the `artifacts/node/115/hl-node` entry in
  `provenance/artifacts.json`.
- Excerpts: `main.txt` is the whole routine body, produced verbatim by
  `objdump -d --start-address=0x5d4d890 --stop-address=0x5d4dbed
  work/hl-node-115.bin` (FDE range 0x5d4d890..0x5d4dbed, 861 bytes).
  `pads.txt` is the immediately following block
  (`--start-address=0x5d4dbed --stop-address=0x5d4dc00`): int3 padding
  plus the landing-pad block, which calls the 0x60d52f0 wrapper and
  then `_Unwind_Resume`. `export_excerpts.py` regenerates both files.
- Instruction-level detail lives only in those verbatim excerpt text
  files. `records.json` holds semantic records only — no
  per-instruction mnemonic list.
- Frames: `frames.txt` carries the FDE lines for the routine, its two
  external caller functions, and the landing-pad callee wrapper.
- Census: `census.py` scans the executable LOAD segment exhaustively
  for E8/E9 sites targeting this routine and confirms each candidate
  with objdump; `callers.tsv` records the result. The routine has
  exactly 3 direct calls (its self-recursion at 0x5d4d934 and two
  external calls), 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
- Verification: `verify.py` re-checks the digest, the provenance
  entry, the manifest, excerpt regeneration byte-for-byte from a
  fresh objdump run, every excerpt instruction byte-for-byte against
  the raw binary, the FDE ranges, the empty relocation set, census
  consistency including per-site caller-function checks, the
  semantic records, and the model tests. It prints ALL CHECKS PASSED.

## Semantics

The routine destroys a sibling chain of 0x48-byte tree nodes, each
carrying one string field. A null head returns immediately and
destroys nothing. Otherwise, for each node in the +0x10 chain in
order:

1. Destroy the node's whole +0x18 child chain first. The first six
   child-chain levels are unrolled inline; deeper levels go through
   the self-recursion at 0x5d4d934, which takes the deep node's +0x18
   child-chain head and destroys the chain starting there. The
   observable order is identical either way.
2. Dispose the node's string: nothing for an inline string (the +0x28
   pointer equals the node's own +0x38 slot address); for a heap
   string, delete(pointer, capacity + 1), where capacity is read from
   the +0x38 slot. The string size slot (+0x30) is never read.
3. Delete the node itself with size 0x48.
4. Advance to the +0x10 successor, which was loaded before the
   deletes.

Net order is post-order: children before their parent, siblings in
chain order, each node exactly once on a well-formed tree.

Node fields actually read: next +0x10, child +0x18, string pointer
+0x28, string capacity/inline slot +0x38. Never read or written:
+0x00, +0x08, +0x20, +0x30.

The landing-pad block runs only on the unwind path, never on the
normal path: it calls the 0x60d52f0 wrapper (a pthread_mutex_unlock
wrapper, FDE 0x60d52f0..0x60d5385) with r15, then `_Unwind_Resume`
with rbx. The normal path acquires no lock.

## Distinctness

This node type is distinct from the 0x48-byte nodes of open PR #2453
(teardown 0x5d4cba0, whose string triple sits at +0x20/+0x28/+0x30):
here the string triple sits at +0x28/+0x30/+0x38, the delete size is
still 0x48, and the teardown is a different routine (0x5d4d890) with
its own two external call sites. It is also distinct from the
0x60-byte two-string teardown family (open PR #2409) and the 0x30-byte
teardown (open PR #2386) — different node size and layout.

## Not claimed

- What the trees, nodes, or strings denote.
- Caller semantics beyond the site addresses and caller FDE ranges
  (0x5d65d7a..0x5d65e04 and 0x5d65e10..0x5d6650b).
- The identity of any lock released by the landing-pad block, or any
  lock held on the normal path (the normal path acquires none).
- Behavior on cyclic or dangling structures, where the binary loops
  or dereferences unchecked; the model raises instead.

## Model and tests

`tools/tree_teardown_48str_115.py` models the chain teardown;
`tests/test_tree_teardown_48str_115.py` checks it (null head,
inline/heap dispose sizes including capacity + 1, sibling order,
child-before-parent, a worked mixed tree, a 10-level child chain
past the six unrolled levels, and cycle/shared-subtree guards).
