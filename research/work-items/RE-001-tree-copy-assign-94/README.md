# RE-001: bind node #94 tree copy-assign 0x514c780 with its header fixup, teardown loop and 3 callers

Task ID: RE-001. Bounded question: what does the 358-byte function at
0x514c780 do when one tree container is assigned from another — which
header fields does it reset, what happens on self-assign and on empty
source or destination, and which callers use it? Answer: it is a complete
tree copy-assign. Self-assign is a no-op; otherwise the source tree is
deep-copied (callee 0x514b7e0, bound by RE-001-tree-deep-copy-94), the
destination header is reset from the new tree (root, leftmost via the
+0x10 spine, rightmost via the +0x18 spine, count copied from the source),
and leftover old nodes are destroyed by an erase loop (callee 0x514b690,
bound by RE-001-recursive-destructor-94).

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514c780..0x514c8e6, 358 bytes, FDE at .eh_frame+0x00633da0
  (length 0x34, CIE 0x006205d0), 10 int3 padding bytes to the next FDE
  at 0x514c8f0.
- Stack canary: fs:0x28 saved at rsp+0x18 and checked before return;
  mismatch calls __stack_chk_fail@plt (0x5660430, GOT 0x5778f40).
- The landing-pad stub at 0x514c8da (endbr64, move rax to rbx, jump to
  0x514c74e) is a genuine instruction sequence in the target binary, not
  a placeholder. The endbr64 there belongs to the landing pad, not to the
  function entry (the entry starts with register pushes). The shared
  cleanup at 0x514c74e (own FDE 0x00633dd8, 38 bytes, 12 int3 padding to
  0x514c780) erases the node in (rsp), checks the canary and calls
  _Unwind_Resume@plt (0x5660110, GOT 0x5778db0); it also serves the
  preceding function 0x514c580 and is cited here as a consumer only.

## Observations (read from the bytes)

- Arguments: rdi = destination container, rsi = source container.
  Self-assign (rdi == rsi) jumps straight to the epilogue at 0x514c87f.
- Container header, from the field accesses: root at +0x10, leftmost at
  +0x18, rightmost at +0x20, count at +0x28. When empty, root is 0 and
  both extremes point at the container + 0x8 (the header node itself);
  count is 0.
- Node layout, matching RE-001-tree-deep-copy-94: 0x30 bytes; int32 value
  word at +0x0 (copied verbatim), parent at +0x8, left child at +0x10,
  right child at +0x18, 16-byte payload at +0x20 (copied with a vector
  move by the callee).
- Pool seeding before the deep-copy call at 0x514c80e: the stack pair at
  (rsp) holds the old destination root, and (rsp+0x8) holds the old
  rightmost's left child when non-null, else the old rightmost. When the
  destination is empty, (rsp+0x8) is set to 0. The old root's parent
  (+0x8) is cleared to 0 first. The deep-copy call passes rdi = source
  root ([src+0x10]), rsi = destination + 0x8 (the header node, used as
  the new root's parent), rdx = the stack pair. The callee's pop/fixup
  sequence is transliterated in tools/foundation_tree_deep_copy.py and
  is not re-pinned here.
- After the call: leftmost is found by following +0x10 links from the new
  root to the end of the spine, rightmost by following +0x18 links; both
  are stored into the destination header together with the new root and
  the source count ([src+0x28]).
- Teardown loop (0x514c860): while the saved old-root slot (rsp) is
  non-null, erase the node's right subtree via 0x514b690, advance along
  the +0x10 link, and sized-delete the node (0x30 bytes) via
  _ZdlPvm@plt (0x5660440, GOT 0x5778f48). When the pool drains, the callee
  zeroes (rsp) and this loop is skipped; when the source is empty, the
  loop destroys the whole old tree after the header reset.
- Direct-caller census (full .text direct-e8 byte scan, no tail jumps):
  exactly 3 sites — 0x5151880 (enclosing 0x5151730..0x5151909),
  0x5151e14 and 0x515200f (both enclosing 0x5151970..0x5152201). All three
  set up the same way: rdi = <fresh object> + 0x28 (the destination
  container embedded at offset 0x28), rsi = the source container. The
  enclosing functions' wider semantics are not claimed.

## Inferences (labelled, not observations)

- The container shape (root / leftmost / rightmost / count with a header
  node at +0x8) matches an ordered tree container's header; the
  source-level type name of the tree and its owning component are not
  claimed.
- The teardown loop is read as destroying exactly the old nodes the copy
  did not reuse: taken nodes are unlinked from the old tree by the
  callee's fixups, and pool exhaustion zeroes (rsp), which skips the
  loop. The loop's own bytes (erase right, walk left, sized delete) are
  observations; the "exactly the leftovers" reading is inference.
- The three callers are read as filling an embedded tree container
  inside a freshly built object (destination at +0x28); the objects'
  identities are not claimed.

## Unknowns (not claimed)

- The deep-copy callee's exact pop order (the pool-threading fixup
  branches are recorded verbatim in copy.objdump.txt; their invariant is
  transliterated, not interpreted, in the callee's own work item).
- The LSDA action table for the landing pad is not decoded; only the
  stub-to-cleanup jump and the cleanup's own calls are claimed.
- The purpose of the callers' preceding calls (0x514ca70, 0x514cb40) is
  not claimed; only the argument setup for the copy-assign call is.

## Overlap notes (checked before building)

- The container-copy function 0x514c780 is not modelled by any existing
  work item: RE-001-tree-deep-copy-94 names it explicitly as census
  evidence only ("the caller itself is census evidence only and is not
  modelled here"), and RE-001-recursive-destructor-94 cites it only as
  the enclosing function of one destructor call site.
- Neighbours are distinct and not re-claimed: 0x514c580 (level-stats
  report, preceding function, shares the cleanup), 0x514c74e (shared
  cleanup, consumer only), 0x514b7e0 (deep copy, bound, used here),
  0x514b690 (erase, bound, used here), 0x514c8f0 (following FDE,
  unexamined).
- No open WalkCrypto PR covers 0x514c780 or a copy-assign title (checked
  against the open-PR snapshot for this cycle).

## Evidence format

- records.json holds semantic records only (function carve ranges with
  SHA-256, branch site-to-target pairs, caller records, PLT/GOT records,
  container/node layouts, pool seeding). It contains no per-instruction
  list. Instruction-level detail lives only in the raw disassembly
  excerpts, kept whole-function: window.objdump.txt (0x514c780..0x514c8f0),
  copy.objdump.txt (0x514b7e0..0x514ba10),
  erase.objdump.txt (0x514b690..0x514b6c5),
  cleanup.objdump.txt (0x514c74e..0x514c780),
  callers.objdump.txt (both enclosing functions, whole).
  Regenerate the first four with export_excerpts.py (same binutils 2.42).
- verify.py (in this packet) is the runnable checker behind
  "ALL CHECKS PASSED": target digest, function hashes, call-target
  re-derivation from rel32 bytes, caller census, excerpt regeneration,
  FDE lines, manifest hashes.

## Reproduction

```
objdump -d --start-address=0x514c780 --stop-address=0x514c8f0 work/hl-node-94.bin
objdump -d --start-address=0x514b7e0 --stop-address=0x514ba10 work/hl-node-94.bin
objdump -d --start-address=0x514b690 --stop-address=0x514b6c5 work/hl-node-94.bin
python3 research/work-items/RE-001-tree-copy-assign-94/verify.py
python3 -m unittest tests.test_foundation_tree_copy_assign -v
```
