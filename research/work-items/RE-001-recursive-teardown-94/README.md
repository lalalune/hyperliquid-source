# RE-001: recursive teardown over node #94 (0x514be80)

Task ID: RE-001. Bounded question: what does the 89-byte function at
0x514be80 in node #94 do to the structure its argument points at?
Answer: it tears down a chain of 0x48-byte nodes — for each node it
first recursively tears down the link at node + 0x18, then disposes
the string at node + 0x20 (skipping the buffer free when the string
is inline), then deletes the node itself with size 0x48, then
advances along the link at node + 0x10 that it saved before any
free. A null input frees nothing and returns immediately.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514be80..0x514bed9, 89 bytes, FDE at .eh_frame+0x0029a778
  (length 0x28), 7 int3 padding bytes to the next FDE at 0x514bee0.
- No stack canary. Two callee-saved registers are pushed and popped
  in balance (rbp, rbx); the frame is 8 bytes of sub rsp on top.
- This function has no endbr64: its first instruction is
  `test %rdi,%rdi`. The int3 bytes after the final ret are genuine
  padding to the next FDE, not instructions.

## Observations (read from the bytes)

- Arguments: rdi = node pointer (saved in rbx before anything else
  uses rdi). Void return: no return value is set on any path.
- Null input: `test %rdi,%rdi; je 0x514bed8` returns at once; the
  function never dereferences a null argument.
- First-iteration entry: after the pushes, the code jumps directly
  to the loop body at 0x514be93, skipping the `mov %rbp,%rbx` that
  later iterations use — rbx already holds the input node.
- Recursion (site 0x514be97): rdi = [rbx + 0x18], then a call to
  this same function (0x514be80). Because the callee returns at
  once on a null link, the recursion terminates at the leaves; the
  +0x18 subtree of a node is fully torn down before the node
  itself is disposed. The recursion is a genuine self-call, not a
  tail jump (no e9 sites target this function).
- Next link saved first: rbp = [rbx + 0x10] is loaded at 0x514bea4,
  after the recursive call and before the string disposal and the
  node delete, so the walk survives the node's own delete. After
  the delete, `test %rbp,%rbp; jne 0x514be90` loops with
  rbx = rbp; a null next link falls through to the epilogue.
- String disposal: rdi = [rbx + 0x20] is the string pointer;
  rax = rbx + 0x30 is the inline-buffer address. If they are equal
  (`je 0x514beba`) nothing is freed for the string. Otherwise rax
  = [rbx + 0x30] (the capacity) and operator delete is called with
  (pointer, capacity + 1 mod 2**64) via the _ZdlPvm PLT stub
  0x5660440 (site 0x514beb5) — the +1 is the capacity-plus-terminator
  size, matching the string-destroy convention used by the
  neighbouring teardown packets.
- Node delete: rdi = rbx, esi = 0x48, call to the same _ZdlPvm PLT
  stub (site 0x514bec2). The 0x48 size is the node's size as far as
  this function is concerned; no larger containing object is
  claimed.
- Delete stub identity: PLT entry 0x5660440 jumps through GOT slot
  0x5778f48, whose .rela.plt relocation is R_X86_64_JUMP_SLOT
  _ZdlPvm@CXXABI_1.3.9. The stub identity comes from that
  relocation, not from objdump's annotation.

## Callers (full .text scan, census only)

Direct e8 call sites to 0x514be80, besides the recursive self-call:
0x5154003 (rdi = [rsp + 0x30], enclosing FDE 0x5153ffe..0x5154046),
0x5154196 (rdi = [rbx + 0x18], enclosing FDE 0x5154050..0x5154203 —
this caller passes its own +0x18 link, then disposes its own node
inline in the following instructions, which corroborates the +0x18
role without this packet claiming the caller's semantics),
0x5154209 (rdi = [rsp + 0x50], enclosing FDE 0x5154204..0x515424c),
0x51543fa (rdi = [rsp + 0x50], enclosing FDE 0x5154250..0x515442d).
No tail-jump (e9) sites target this function. The callers'
enclosing functions are not modelled here.

## Inferences and unknowns (kept separate)

- The +0x20/+0x30 pair is described as a string field because the
  test (pointer == own + 0x30) and the (capacity + 1) delete size
  are exactly the string SSO shape the neighbouring teardown
  packets pin; the bytes do not name the field, and no source-level
  type name is claimed for the node or for either link.
- The qwords at node + 0x0 and node + 0x8 are never read by this
  function, so no role is claimed for them.
- Whether the +0x18 recursion is load-bearing beyond freeing (for
  example, a nested structure versus a second list) is not claimed:
  the model records the free order exactly as the bytes do.
- Deliberately NOT folded in: the neighbouring function at
  0x514bee0 (a different teardown variant: 0x58 node size,
  different field offsets, a 0x514b690 destructor call) and the
  following FDE at 0x514bf60 — both are separate work items.
  A repo-wide grep finds no in-tree claim on 0x514be80; the
  preceding function at 0x514bdf0 (open PR #1358) ends before this
  entry and does not claim its behavior.

## Verification

- Packet verifier: `python3
  research/work-items/RE-001-recursive-teardown-94/verify.py
  --binary work/hl-node-94.bin` — target digest, function SHA,
  int3 padding, branch/call targets re-derived from raw encodings,
  caller census from a full .text scan, every excerpt line's bytes
  against the binary, the FDE line, and MANIFEST hashes.
- Tool checker: `python3 tools/foundation_recursive_teardown.py
  --binary work/hl-node-94.bin` — the same checks, wired to this
  packet.
- Tests: `python3 -m unittest
  tests.test_foundation_recursive_teardown -v` — null input, inline
  and heap nodes, capacity+1 64-bit wrap, chain order, child-before-
  parent order, interleaved child/parent chains, packet verification,
  excerpt regeneration byte-identical, and corruption controls on
  packet copies.
- Pre-submit self-check: three instructions sampled from the raw
  excerpt and verified byte-for-byte against a fresh objdump run
  (see the run record).
- Environment limits, stated honestly: `make doctor` exits 1 on this
  VM (Rust/Ghidra unavailable) and `make rea-doctor` reports the
  pinned REA package absent; repo-wide `make catalogue-check` was
  not re-run this cycle — its pre-existing LFS-pointer identity
  failure is not a regression from this change.
