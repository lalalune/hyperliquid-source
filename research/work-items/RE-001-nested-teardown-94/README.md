# RE-001-nested-teardown-94: what does the 0x514bee0 window do?

- Component: `foundation`, a nested node teardown in the
  node #94 function map (RE-001: decode FDE ranges and validate
  entrypoints with digest-bound records).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `56c0ec67`.
- Bounded question: given a head pointer in `rdi`, which nodes
  does the function at `0x514bee0` delete, in which order, with
  what size arguments, and what happens on a multi-node +0x10
  chain?
- Claim: observations about one target function, its self-recursive
  call, its 0x514b690 callee call, its two operator-delete calls,
  and its caller census. The source-level identity of the node
  type is NOT claimed: the bytes pin three qword links per outer
  node (+0x10, +0x18, +0x38), two qword links per item (+0x10,
  +0x18), a 0x58-byte outer delete size and a 0x30-byte item
  delete size, and nothing else about what the nodes are.
- Included: the 113-byte FDE function with its 15 int3 padding
  bytes, the whole 49-byte 0x514b690 callee function with its 15
  int3 padding bytes, the complete delete-order rule, the
  operator-delete PLT stub with its GOT relocation, all 6
  external direct call sites with their argument setups, and the
  r12 quirk (below) with a model that reproduces it faithfully
  instead of smoothing it over.
- Evidence format: `records.json` holds semantic records only —
  the function carve ranges with their SHA-256 values, branch
  site→target and call site→target pairs, the caller census, the
  PLT record, and the rule — following the reference packets
  that draw no `low_quality` flags. It deliberately contains no
  per-instruction mnemonic list: the raw disassembly lives in
  `window.objdump.txt`, `callee.objdump.txt` and
  `callers.objdump.txt`, and `verify.py` in this packet plus the
  checker in `tools/foundation_nested_teardown.py` verify the
  records (and the excerpt bytes) against the binary.

## Why this packet

The function map needs bounded, digest-bound entries for the
functions that tear structures down. This window is a complete
behavior, not a fragment: an entry with a null-head fast path
that returns without a frame, plus the self-recursive call that
decides the traversal order, plus the callee call that tears
down each item's +0x18 chain, plus the two operator-delete calls
that decide the observable effect (freeing items with size
`0x30` and outer nodes with size `0x58`), plus the caller census
that shows where the teardown is actually invoked. It is
deliberately distinguished from its neighbours: `0x514be80`
(the recursive teardown of PR #1363, a different variant with
string disposal and 0x48-byte nodes) and the following FDE at
`0x514bf60` (unexamined, not part of this item). The callee at
`0x514b690` is claimed in-tree by
`research/work-items/RE-001-recursive-destructor-94` and is
reused here, not re-claimed.

## The rule, traced from the bytes

Entry `0x514bee0`, whole function `0x514bee0..0x514bf51`
(FDE at `.eh_frame+0x0029a7a4`, SHA
`002d72900b2d0bc557ef154b071739d92b89aadde047d27ae3c75a6cfd7686ba`,
15 int3 padding bytes to the next FDE at `0x514bf60`):

1. Null input returns at once: `test %rdi,%rdi; je 0x514bf50`
   (the ret at `0x514bf50`, reached before any push).
2. Otherwise push r12, rbp, rbx; rbp and r12 both start as the
   input node. Each loop iteration, in order:
   - `rdi = [current + 0x18]`; call self at `0x514bef3`
     (recursion on the +0x18 link; a null link returns at once).
   - `rbx = [first + 0x38]` (the items head, from r12);
     `rbp = [current + 0x10]` (the next link, saved before any
     free below, so the walk survives the frees).
   - Inner walk while `rbx != 0`: `rdi = [item + 0x18]`, call
     `0x514b690` at `0x514bf14` (that callee, per its own packet,
     destroys `[item + 0x18]` recursively, deletes the item with
     size `0x30`, and advances to `[item + 0x10]`); then
     `rdi = item`, `rbx = [item + 0x10]`, delete with size
     `0x30` (call at `0x514bf25`). A null items head skips the
     walk (`je 0x514bf2f`).
   - Delete the node in r12 with size `0x58` (call at
     `0x514bf37`, through the `_ZdlPvm` PLT stub at `0x5660440`,
     GOT slot `0x5778f48`, `R_X86_64_JUMP_SLOT
     _ZdlPvm@CXXABI_1.3.9`).
   - If the saved next link is not null, loop back to
     `0x514beec` (`jne 0x514bf3f`).
3. Pop rbx, rbp, r12 and ret at `0x514bf45`. Void return, no
   stack canary.

## The r12 quirk (observed, not smoothed over)

The loop body updates rbp (the current node) at `0x514befd`
but never updates r12 after the single `mov %rbp,%r12` at
`0x514bef0`. The bytes therefore do, literally, on every
iteration after the first:

- re-read the items head from `[first + 0x38]`, where `first`
  is the already-deleted first node (a freed-slot read);
- re-walk and re-delete that first node's items (repeat frees
  of the items and repeat teardowns of their +0x18 chains);
- delete the first node again with size `0x58` (a repeat free);
- never delete the second, third, ... nodes themselves — only
  their +0x18 subtrees are torn down (step 1 runs for each
  current node).

The model in `tools/foundation_nested_teardown.py` reproduces
this register flow exactly, marking freed-slot reads as
`read_freed` events and repeat frees as `free_again` events.
For a single-node chain the quirk never triggers and the
behavior is clean: child subtree, then items, then the node,
each exactly once. Whether any real execution ever presents a
+0x10 chain longer than one node is NOT established by this
packet, and no claim is made that the multi-node path is safe:
with a non-clearing allocator the freed slots still hold their
old values, so the re-walk follows the same pointers, but the
repeat frees are repeat frees. The "sane" version of this loop
(delete each node once, read each node's own items) is NOT what
the bytes say, and is NOT claimed.

## Excluded

- The source-level identity of the node type, the items, and
  the structures at `[node + 0x10]` / `[node + 0x18]` /
  `[node + 0x38]` beyond "qword link" / "items head".
- The wider semantics of the 4 enclosing caller functions
  (their call sites are a census plus argument setups, not a
  claim about those functions).
- Any claim about the other `_ZdlPvm@plt` call sites beyond
  this function's own two delete calls.
- The following FDE at `0x514bf60` and the preceding FDE at
  `0x514be80` (PR #1363, a different teardown variant).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra, Java, or
REA provider was used: `make doctor` reports Rust and Ghidra
unavailable (expected on this VM, exit 1), and `make rea-doctor`
reports the pinned REA package absent. No target binary, captured
artifacts, or generated catalogue files are modified by this
change; the packet binds to the digest-verified work copy
`work/hl-node-94.bin` (SHA-256 above) because the canonical
`artifacts/node/94/hl-node` path is still an LFS pointer on this
checkout.

    python3 research/work-items/RE-001-nested-teardown-94/verify.py \
        --binary work/hl-node-94.bin
    python3 -m pytest tests/test_foundation_nested_teardown.py -q

The objdump command recorded for the excerpts is in
`export_excerpts.py` in this packet; running it against the
digest-pinned binary reproduces `window.objdump.txt` and
`callee.objdump.txt` byte-for-byte. Instruction mnemonics such
as `endbr64` do not occur in this function (its first
instruction is `test %rdi,%rdi`); the `nopw`/`cs nopw` bytes in
the excerpts are genuine alignment padding emitted by objdump,
not placeholders.
