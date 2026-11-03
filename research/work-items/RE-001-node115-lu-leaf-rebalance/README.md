# RE-001-node115-lu-leaf-rebalance

## Claim status: observation

This packet answers packet #195's (PR #2302) explicitly stated next
question: **decode the leaf op `0x4d24790` end to end — what does its
`rax == 0` flag condition mean, and what is the node `+0xe4` second
counter it writes?**

The leaf op is the B-tree node removal-and-rebalance primitive used by
the completion helper's resolver (`0x4d35b60`, called by #195's
completion helper `0x4da86a0`). It removes one key/value pair from a
node, and when the node underflows it merges or redistributes against
a sibling, cascading upward while ancestors underflow.

## The two answers

**1. The `rax == 0` flag condition means the tree height shrank by one
(root collapse).** The leaf op takes a third argument, a pointer to a
caller-owned flag byte. The completion helper zeroes that byte
(`mov byte [rsp+0x7],0` at `0x4da86b7`) and passes its address through
the resolver. The leaf op writes `1` to it at exactly one instruction
(`mov byte [rax],1` at `0x4d24efa`), on exactly one path: the upward
rebalance loop reaches a node with no parent (the root), and that
root's key count — held in `rax`, loaded at `0x4d24a6b` and
zero-extended at `0x4d24a7b` — is `0` (`test rax,rax` at `0x4d24eec`,
`jne 0x4d249fc` skips the write when nonzero). The completion helper
then gates on the flag (`cmp byte [rsp+0x7],1` at `0x4da86ea`): when
set, it promotes the old root's first child to the new root
(`[rax] = [rdi+0xe8]`, new root's parent zeroed) and frees the old
root (328 bytes via GOT `0x64df4a0`). So flag `1` ⟺ the cascade
emptied the root ⟺ the tree lost a level. The flag is *not* set when
the removed node is itself the root (single-node tree: the parent-null
exit at `0x4d248ea` never touches it) or when any ancestor keeps a
positive key count (the loop exits at `0x4d24a76` / `0x4d249fc`
without writing).

**2. The node `+0xe4` u16 is the node's 0-based index within its
parent's children array.** It is *written* by the reparenting loops
that run after every merge — single-step at `0x4d24d00` and
`0x4d24e20`, unrolled-by-4 at `0x4d24d40` and `0x4d24e60` — each
storing `[child+0xb0] = parent` and `[child+0xe4] = position` for
every moved child. It is *read* to select the merge sibling: `0`
means the node is the leftmost child, so the right sibling
(`children[1]`, at `+0xf0`) is used (entry `0x4d248f4`, loop
`0x4d24b30`); nonzero means the left sibling (`children[index-1]`,
at `+0xe0 + 8*index`) is used (entry `0x4d2486f`, loop `0x4d24aae`).
The resolver's upward walk reads it the same way (`0x4d35cb0`).

## Scope

Included:

- The full FDE `0x4d24790..0x4d24f68` (2008 bytes; body proper to the
  single `ret` at `0x4d24a46` = 695 bytes; tail = 1313 bytes; 467
  instructions: 168 body + 299 tail; 5 nops; CIE `00000000`).
- Entry removal: key shift left by one slot via memmove (GOT
  `0x64df568`) at `0x4d247f4`, value-slot shift (16-byte slots) via
  memmove at `0x4d24829`; removed key saved to `[rsp+0x60]`,
  removed value qword to `[rsp+0x58]`, removed value flag byte
  (`[slot+0x8]`) to `[rsp+0x6]`; key count decremented at
  `0x4d24832`.
- The 48-byte output struct at entry `rdi`: key, value qword, value
  flag byte, node pointer, merge-path kept-node pointer, loc levels
  field — written at `0x4d24a06..0x4d24a31`.
- The node layout (328 bytes, capacity 11 keys): value slots 16 bytes
  each at `+16*i` (`[0]` u64 value, `[8]` flag byte); parent pointer
  at `+0xb0`; u32 keys at `+0xb8 + 4*i`; child index u16 at `+0xe4`;
  key count u16 at `+0xe6`; child pointers at `+0xe8 + 8*i` (12
  slots). At 11 keys the regions tile exactly: values `[0,176)`,
  parent `[176,184)`, keys `[184,228)`, index/count `[228,232)`,
  children `[232,328)`.
- Thresholds, all pinned: rebalance iff the new count is `<= 4`
  (`cmp ax,4` at `0x4d2483e`, `0x4d24a72`, `0x4d249f6`); merge iff
  the merged size is `<= 11` — first level `old current + sibling
  < 12` (the `-1` removal and `+1` separator cancel), upward loop
  `new current + sibling + 1 < 12` — at `0x4d248bb`, `0x4d2494e`,
  `0x4d24afe`, `0x4d24b92`; otherwise redistribute.
- The upward merge core (shared by the left and right loop paths):
  separator key appended to the sibling (`0x4d24c08`), sibling
  count updated (`0x4d24bc8`), parent keys/values/children shifted
  (memmove via `0x64df568`, memcpy via `0x64df508`), children
  reparented with `+0xe4` rewritten, parent count decremented
  (`0x4d24daa`), merged-away node freed (`0x4d24a65`, GOT
  `0x64df4a0` → `0x635de30`, the same slot #195's completion free
  uses), loop repeats while ancestors stay `<= 4`.
- Callers: exactly 2 direct E8 sites, both in the resolver
  `0x4d35b60` — `0x4d35c75` (rightmost-leaf path) and `0x4d35d5b`
  (remaining-levels `== 0` leaf path). Zero GOT-indirect sites
  (no relocation addend `0x4d24790` anywhere).
- Panics: right-sibling path with a zero-key parent → `node.rs
  1360:31` via `0x4d24f62` (message at `0x9133db`, length passed
  123, leading literal "internal error: entered unreachable code:
  empty internal node"); children-memmove length mismatch →
  `node.rs 1876:5` via `0x4d24f36` (message at `0x913439`,
  "assertion failed: src.len() == dst.len()", length passed 40
  through the `len -> 2*len+1` wrapper `0x1680e60`).

Excluded:

- The merge helper `0x4ca2500` (969-byte body) and the redistribute
  helpers `0x4c93c20` (428-byte body) / `0x4c9b3b0` (796-byte body):
  only their dispatch threshold, call sites, and argument shapes are
  pinned (merge: direction flag `1` = left / `0` = right; first-level
  redistribute: `esi = 1`; upward-loop redistribute: `esi = 5 -
  current count`, consistent with borrowing up to the min-fill 5).
  Their internals are the natural next question, together with the
  grow callee `0x5155ec0` (#195's second thread, still open).
- The free wrapper `0x635de30` internals (only its call site and the
  shared GOT slot are claimed).
- Any runtime behavior. Analysis is static only; the node binary was
  never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```sh
objdump -d -M intel --start-address=0x4d24790 --stop-address=0x4d24f68 \
  artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node   # GOT slot resolutions
python3 tools/node115_lu_leaf_rebalance.py
python3 -m unittest tests.test_node115_lu_leaf_rebalance -v
```

## The leaf op, end to end

Signature `f(out: *mut [u8; 48], loc: *const Loc, flag: *mut u8)`.
`loc = {node @+0, remaining levels @+0x8 (0 = leaf, at both call
sites), key index @+0x10}`. Entry saves `rdx` (flag pointer) to
`[rsp+0x50]`, `rsi` (loc) to `r12`, `rdi` (out) to `[rsp+0x68]`.

1. **Remove.** `rbp = [loc]` (node), `r15 = [loc+0x10]` (index),
   `ebx = u16 [node+0xe6]` (old count). The key at the index is
   saved, then keys after it shift left by one slot (memmove,
   length `(old - 1 - index) * 4`); the 16-byte value slot at the
   index is saved (qword + flag byte), then value slots after it
   shift left by one (memmove, length `(old - 1 - index) * 16`).
   Count becomes `old - 1` at `0x4d24832`.
2. **Gates.** New count `> 4` → output, no rebalance (`0x4d248db`).
   No parent → output, flag untouched (`0x4d248ea`). Otherwise
   sibling selection by `+0xe4` (see above).
3. **First-level dispatch.** Combined `old current + sibling`:
   `< 12` → merge helper `0x4ca2500` (direction `1` left / `0`
   right); `>= 12` → redistribute helper (`0x4c93c20` left /
   `0x4c9b3b0` right, `esi = 1`). Either way control reaches the
   output path, which checks the parent: parent null → output;
   parent count `<= 4` → upward loop at `0x4d24a47`; else output.
4. **Upward loop.** Free the merged-away node (`0x4d24a65`). If the
   current node's count is `> 4`, exit to output. If it has no
   parent, it is the root: test its count (`0x4d24eec`) — zero
   writes flag `1` (`0x4d24efa`), nonzero exits with the flag
   untouched. Otherwise select the parent-level sibling by `+0xe4`,
   dispatch on `new current + sibling + 1 < 12` (merge core) vs
   `>= 12` (redistribute helper + exit), and repeat.
5. **Output.** The 48-byte struct (key, value, value flag byte,
   node, kept-node pointer, levels) is written to entry `rdi` at
   `0x4d24a06..0x4d24a31`, and the function returns. The resolver
   then swaps the removed leaf key/value into the internal slot
   (its own code, not claimed here).

## What this changes about #195

#195 left open "the exact meaning of [the leaf op's] `rax == 0` flag
condition" and "the node `+0xe4` second counter's role". Both are
now closed: the flag is the root-collapse signal (tree height
shrinks by one; the completion helper promotes the old root's first
child on it), and `+0xe4` is the child index in the parent, written
by every reparenting loop and read for every sibling selection.
#195's "second counter" label is superseded by "child index". The
grow callee `0x5155ec0` remains open, as do the merge/redistribute
helper internals.

## Limitations

- The merge helper and both redistribute helpers are not decoded;
  only dispatch and call shapes are pinned.
- The loc levels field (`+0x8`) is carried `+1` into the sibling
  frames; its exact downstream use inside the merge core is not
  fully traced.
- The two panic message lengths (123, and 81 after the wrapper
  transform) span packed adjacent string literals in `.rodata`; the
  packet quotes each message's leading literal and pins its
  Location, and does not claim the trailing packed bytes are part
  of one source literal.
- The freed node (`r12`) is identified as the merged-away node by
  dataflow (current node on a left merge, right sibling on a right
  merge); the free wrapper itself is not decoded.
- No runtime behavior is claimed; the node binary was never executed.

## Next question

The grow callee `0x5155ec0` (#195's second thread, still open): what
exactly does the array-to-tree conversion past length 63 build?
Second: the merge helper `0x4ca2500` and redistribute helpers
`0x4c93c20` / `0x4c9b3b0` internals — how does the merge move the
separator and children, and how does redistribute choose its borrow
count?
