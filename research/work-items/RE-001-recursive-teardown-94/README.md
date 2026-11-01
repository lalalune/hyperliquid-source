# RE-001: recursive chain teardown over node #94 nodes (0x514bf60)

Task ID: RE-001. Bounded question: what does the 113-byte function at
0x514bf60 in node #94 do to the node chain it is given — in what
order does it tear a node down, what does it do to the node's two
strings, and how does it reach the next node? Answer: it walks a
chain of 0x60-byte nodes; for each node it first recurses on the
child at +0x18, then disposes the string at +0x40, then the string
at +0x20, then deletes the node itself with size 0x60; the next
sibling at +0x10 is saved before any disposal, so the walk survives
disposal. A null input returns with no delete call.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514bf60..0x514bfd1, 113 bytes, FDE at .eh_frame+0x0029a7d4
  (length 0x28), 15 int3 padding bytes to the next FDE at 0x514bfe0.
- No stack canary in this function; two callee-saved registers are
  pushed and popped in balance (rbp, rbx).

## Observations (read from the bytes)

- Arguments: rdi = node pointer or null; void return. The null test
  at 0x514bf60 jumps at 0x514bf63 to the ret at 0x514bfd0, so a null
  input performs no delete call.
- Per-node order: rdi = [rbx+0x18], call 0x514bf60 (site 0x514bf77)
  recurses on the child before anything else about this node is
  touched. Then rbp = [rbx+0x10] (the next sibling, saved at
  0x514bf84), rdi = [rbx+0x40], rax = rbx+0x50; if they differ, rax =
  [rbx+0x50], rsi = rax+1, call the delete PLT stub 0x5660440 (site
  0x514bf95). Then rdi = [rbx+0x20], rax = rbx+0x30; if they differ,
  rax = [rbx+0x30], rsi = rax+1, call the delete stub (site
  0x514bfaf). Then rsi = 0x60, rdi = rbx, call the delete stub (site
  0x514bfbc). Then test rbp,rbp; jne at 0x514bfc4 to 0x514bf70,
  which moves rbp into rbx and falls through to the loop head at
  0x514bf73. The first entry reaches the loop head via the jmp at
  0x514bf6e, bypassing the mov, because rbx already holds the input.
- The loop-back target 0x514bf70 precedes the mov at 0x514bf70, so
  the sibling pointer IS reloaded into rbx on every iteration. (This
  is the loop-head reading the preceding nested-teardown item
  corrected after review: an instruction after the loop head still
  executes on every iteration when the loop-back target precedes it.)
- Delete stub: PLT 0x5660440, 16 bytes, jmp through GOT slot
  0x5778f48 (R_X86_64_JUMP_SLOT _ZdlPvm@CXXABI_1.3.9). The GOT
  slot's file bytes are the stub's own lazy-binding resolver entry
  (0x5660446), not a resolved symbol address, exactly as recorded
  in the list-teardown packet.
- Caller census: exactly 11 direct call sites and no tail jumps —
  the self site 0x514bf77 plus 0x5153bc2, 0x515410a, 0x5154183,
  0x5154354, 0x51543f0, 0x5154800, 0x5154a6b, 0x5155c1d, 0x5155ef4,
  0x5157d77. The ten external sites' enclosing functions are census
  only and are not modelled here.
- This function has no endbr64: its first instruction is the null
  test. The nopl at 0x514bfcd is genuine alignment padding before
  the null-path ret, inside the FDE range.

## Inferences (labelled, not observations)

- The node layout is read as: +0x10 next sibling, +0x18 child,
  +0x20/+0x30 one string, +0x40/+0x50 a second string. The string
  slots are read as the SSO shape (pointer, unread length,
  capacity-or-inline-buffer) because each disposal test compares the
  pointer against the inline-buffer address and the delete size is
  the buffer field + 1; the source-level type name is not claimed.
- The +0x00 and +0x08 qwords of the node are never read by this
  function; nothing is claimed about them.
- objdump's nearest-symbol annotation for this address range is
  explicitly not claimed as a symbol name; the function is
  identified by its FDE range and bytes only.

## Unknowns (not claimed)

- How the ten external callers' enclosing functions use the nodes
  they pass in; only their call sites are recorded.
- Whether the child at +0x18 is a first-child, an owned subtree
  root, or something else; the bytes only show it is torn down
  recursively before its parent node.
- The source-level type of the node and its strings is not claimed;
  the function is described by its observed layout and teardown
  behaviour only.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree claims 0x514bf60,
  and no open WalkCrypto PR covers this function. The only in-tree
  mentions of 0x514bf60 are call-site lines inside the merged
  string-move-assign packet's caller excerpts, not claims on this
  item.
- Neighbours are distinct and not re-claimed: 0x514bdf0 (string
  build-and-move, open PR #1358, preceding region), 0x514be80
  (recursive teardown with string disposal and 4 callers, open PR
  #1363 — a different function with a different caller census and
  no sibling walk), 0x514bee0 (nested teardown, open PR #1374 —
  a different function with an item list and a callee), 0x514bfe0
  (following FDE, a different function, not claimed).

## Evidence format

- records.json holds semantic records only (carve ranges with
  SHA-256, branch site-to-target pairs, call sites, the node layout,
  the caller census, the composed rule). It contains no
  per-instruction list.
- Instruction-level detail lives only in the raw objdump excerpts,
  kept whole-function: window.objdump.txt (0x514bf60..0x514bfe0,
  function plus padding), plt.objdump.txt (the 16-byte delete
  stub), callers.objdump.txt (one 5-byte call instruction per
  census site). Regenerate them with export_excerpts.py (same
  binutils 2.42).
- verify.py (in this packet) and tools/foundation_recursive_teardown.py
  (check_packet) are the runnable checkers behind "ALL CHECKS PASSED".
  verify.py's census is a byte-level .text scan for e8/e9 rel32
  targeting 0x514bf60; at build time it was cross-checked against a
  linear objdump -d sweep of the whole binary, and both methods
  agreed on exactly the 11 sites above with no tail jumps.

## Validation outcomes

- Tool versions and analysis options: GNU objdump/readelf
  (binutils 2.42); `objdump -d` with explicit start/stop addresses
  for excerpts, `readelf --debug-dump=frames-interp` for the FDE
  record, `readelf -r` for the PLT relocation. No Ghidra, REA, or
  cargo is involved; the reference revision is upstream main
  56c0ec67 at build time.
- Before/after comparison: the packet adds only new files (one
  work-item directory, one tool, one test); no existing file is
  modified, so there is no behaviour change to compare against a
  baseline beyond the new tests passing and the pre-existing suite
  staying green (see the PR body for the suite result).
- Negative controls: the tests include corruption controls on a
  packet copy (a falsified function SHA and a flipped excerpt byte
  are both caught by check_packet), an empty-input case (no
  deletes), and a capacity+1 64-bit wrap case (size 0).
- Next step: the following FDE at 0x514bfe0 is unexamined and is
  the natural next item in this address walk; the ten external
  caller sites' enclosing functions are a separate, larger item.

## Reproduction

```
objdump -d --start-address=0x514bf60 --stop-address=0x514bfe0 work/hl-node-94.bin
python3 research/work-items/RE-001-recursive-teardown-94/verify.py --binary work/hl-node-94.bin
python3 tests/test_foundation_recursive_teardown.py
```

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs, no Ghidra/Java, so `make doctor` fails and the repo-wide
`make catalogue-check` is not re-run here (its pre-existing LFS-pointer
identity failure is unrelated to this change); the checks above run
against the digest-verified work binary, not the LFS pointer.
