# RE-001: map node #115 0x48-byte tree teardown with a per-node destroy hook 0x5d4d560

Task ID: RE-001. Bounded question: what does the whole routine at
0x5d4d560 in the node #115 binary do, end to end, as a complete
behavior — not a lone window?

## Evidence and binding

- Target: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching the `artifacts/node/115/hl-node` entry in
  `provenance/artifacts.json`.
- Excerpts: `main.txt` is the whole routine body, produced verbatim by
  `objdump -d --start-address=0x5d4d560 --stop-address=0x5d4d883
  work/hl-node-115.bin` (FDE range 0x5d4d560..0x5d4d883, 835 bytes).
  `pads.txt` is the immediately following block
  (`--start-address=0x5d4d883 --stop-address=0x5d4d890`): int3 padding
  only; no landing-pad block follows this routine. `export_excerpts.py`
  regenerates both files.
- Instruction-level detail lives only in those verbatim excerpt text
  files. `records.json` holds semantic records only — no
  per-instruction mnemonic list.
- Frames: `frames.txt` carries the FDE lines for the routine and its two
  external caller functions.
- Census: `census.py` scans the executable LOAD segment exhaustively
  for E8/E9 sites targeting this routine and confirms each candidate
  with objdump; `callers.tsv` records the result. The routine has
  exactly 4 direct calls (its self-recursion at 0x5d4d60c and three
  external calls), 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
- Verification: `verify.py` re-checks the digest, the provenance
  entry, the manifest, excerpt regeneration byte-for-byte from a
  fresh objdump run, every excerpt instruction byte-for-byte against
  the raw binary, the FDE ranges, the empty relocation set, census
  consistency including per-site caller-function checks, the
  semantic records, and the model tests. It prints ALL CHECKS PASSED.

## Semantics

The routine destroys a sibling chain of 0x48-byte tree nodes, each
carrying a per-node destroy hook. A null head returns immediately and
destroys nothing. Otherwise, for each node in the +0x10 chain in
order:

1. Destroy the node's whole +0x18 child chain first. The first eight
   child links are unrolled inline; deeper levels go through the
   self-recursion at 0x5d4d60c, which takes the deep node's +0x18
   child-chain head and destroys the chain starting there. The
   observable order is identical either way.
2. Invoke the node's hook when it has one: the qword at +0x38 is read
   as a function pointer, and when it is non-null it is called with
   (node+0x28, node+0x28, 3) — both pointer arguments are the address
   of the node's +0x28 field, and the third argument is the constant
   3. When the +0x38 slot is null, no call is made. Note the call is
   an indirect call through the stored value itself (`call *%rax`
   after loading the slot), not a call through a vtable the slot
   points to — so the hook is data carried by the node, and the model
   takes it as a per-node parameter.
3. Delete the node itself with size 0x48.
4. Advance to the +0x10 successor, which was loaded before the hook
   call and the delete.

Net order is post-order: children before their parent, siblings in
chain order, each node exactly once on a well-formed tree, with each
node's hook invoked after its children are destroyed and before its
own delete.

Node fields actually read: next +0x10, child +0x18, hook slot +0x38.
The +0x28 field is never dereferenced as data; only its address is
passed to the hook. Never read or written: +0x00, +0x08, +0x20, +0x30,
+0x40..+0x47.

## Distinctness

This routine is distinct from the neighbouring 0x48-byte teardown in
open PR #2467 (0x5d4d890), even though both delete 0x48-byte nodes
over +0x10/+0x18 chains: #2467's nodes carry a string triple at
+0x28/+0x30/+0x38 and its routine disposes that string; here +0x38 is
a function pointer that the routine indirect-calls, and no string
dispose ever happens. It is also distinct from open PR #2453's
teardown 0x5d4cba0 (string triple at +0x20/+0x28/+0x30) and from the
0x60-byte two-string teardown family (open PR #2409). The two
external caller functions here (0x5d8479c..0x5d85475 and
0x5d878f0..0x5d887b0) are the same functions that call open PR
#2460's teardown at other sites; the routines and their call sites
do not overlap.

Correction to the prior cycle's note: the prior cycle judged this
routine as not standing alone because its callees looked like
unknown vtable slots. Re-reading the destroy blocks shows the call
is through a function pointer stored in the node itself, so the
hook's invocation contract — when it runs, with what arguments, in
what order — is fully pinned from the excerpt, and only the hook's
internals remain unclaimed. That is the same class of unknown as
"what the trees denote", which this packet leaves unclaimed.

## Not claimed

- What the trees, nodes, or hook targets denote.
- Caller semantics beyond the site addresses and caller FDE ranges
  (0x5d8479c..0x5d85475 and 0x5d878f0..0x5d887b0).
- What the per-node hook does internally, or what its constant third
  argument denotes.
- Behavior on cyclic or dangling structures, where the binary loops
  or dereferences unchecked; the model raises instead.

## Model and tests

`tools/tree_teardown_hook_115.py` models the chain teardown, with the
hook as a per-node callable receiving (member token, member token,
3); `tests/test_tree_teardown_hook_115.py` checks it (null head,
hook skipped when the slot is null, hook arguments recorded exactly,
sibling order, child-before-parent, a worked mixed tree, a
12-level child chain past the eight unrolled links, and
cycle/shared-subtree guards).
