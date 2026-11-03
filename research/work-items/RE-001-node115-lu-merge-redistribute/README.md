# RE-001-node115-lu-merge-redistribute

## Claim status: observation

This packet answers packet #197's (PR #2328) explicitly stated next
question, which is also packet #196's (PR #2314) second question,
still open: **the merge helper `0x4ca2500` and redistribute helpers
`0x4c93c20` / `0x4c9b3b0` internals — how does the merge move the
separator and children, and how does redistribute choose its borrow
count beyond the post-pass's `5 - count` argument?**

The answers, in one line each:

- **Merge always keeps the LEFT node and frees the RIGHT node.**
  It removes the parent separator key/value, appends the separator
  to the left node's end, appends the right node's keys/values
  after it, shifts the parent's keys/values/children left by one,
  and — for internal nodes only — appends the right node's
  children to the left node and reparents them. The direction flag
  does NOT select which node survives; it selects only the
  edge-index bound check and the edge-index remap in the output.
- **Redistribute never chooses its borrow count.** The borrow is
  purely caller-supplied (`esi`); the helper only validates it
  (current + borrow <= 11, donor - borrow >= 0) and moves exactly
  that many keys, values, and — for internal nodes — children,
  rotating the parent separator through the moved block. The
  `5 - count` figures at the call sites are the callers'
  min-fill restoration (borrow up to the min-fill 5), not the
  helper's choice.

## Scope

Included:

- The full merge FDE `0x4ca2500..0x4ca2915` (1045 bytes; body
  proper to the single `ret` at `0x4ca28c9` = 970 bytes, 213
  instructions; tail = 75 bytes, 12 instructions; 4 nops; CIE
  `00000000`).
- The full redistribute-left FDE `0x4c93c20..0x4c93f18` (760
  bytes; body proper to the single `ret` at `0x4c93ecc` = 685
  bytes, 149 instructions; tail = 75 bytes, 12 instructions; 2
  nops; CIE `00000000`).
- The full redistribute-right FDE `0x4c9b3b0..0x4c9b6ff` (847
  bytes; body proper to the single `ret` at `0x4c9b6cc` = 797
  bytes, 167 instructions; tail = 50 bytes, 8 instructions; 2
  nops; CIE `00000000`).
- The shared 56-byte frame layout, the merge output struct, both
  redistribute key/value/children move patterns, all caller
  censuses, and all panic provenances (all in
  `alloc/src/collections/btree/node.rs` — these helpers are Rust
  std's B-tree node merge/redistribute, confirmed by their panic
  messages, not a project-local reimplementation).
- Three corrections to packet #196 (see "What this changes about
  #196 and #197").

Excluded:

- The free wrapper `0x635de30` internals (only its call sites,
  GOT slot `0x64df4a0`, and size argument 232 vs 328 are claimed).
- The resolver `0x4d35b60` internals and how it consumes the leaf
  op's out48 edge index (the natural next question).
- The leaf op's upward-loop inline merge core: it performs the
  same merge steps inline (#196) but is not this packet's claimed
  body — only the extracted first-level merge helper is claimed.
- Any runtime behavior. Analysis is static only; the node binary
  was never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```sh
objdump -d -M intel --start-address=0x4ca2500 --stop-address=0x4ca2915 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4c93c20 --stop-address=0x4c93f18 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4c9b3b0 --stop-address=0x4c9b6ff \
  artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node   # GOT slot resolutions
python3 tools/node115_lu_merge_redistribute.py
python3 -m unittest tests.test_node115_lu_merge_redistribute -v
```

## The shared frame and node layout

Node (328 bytes, capacity 11 keys, #195/#196 layout): value slots
16 bytes each at `+16*i` (`[0]` u64 value, `[8]` flag byte);
parent pointer at `+0xb0`; u32 keys at `+0xb8 + 4*i`; child index
u16 at `+0xe4`; key count u16 at `+0xe6`; child pointers at
`+0xe8 + 8*i` (12 slots). Leaves are the same layout truncated
before the children array (232 bytes).

Frame (56 bytes, 7 qwords), passed by pointer to all three
helpers:

- `+0x00`: parent node.
- `+0x08`: levels + 1 (leaf op) — merge reads it only for its
  children-move gate (`>= 2` means internal).
- `+0x10`: separator index in the parent (left path: current
  index − 1; right path: 0, the current index itself; build
  post-pass: last-child index − 1).
- `+0x18`: LEFT node.
- `+0x20`: levels below the current node (0 = leaf).
- `+0x28`: RIGHT node.
- `+0x30`: levels below the current node (must agree with `+0x20`
  on leaf-vs-internal; the redistribute helpers take the
  unreachable panic when they disagree).

Left/right here are positions in the parent's children array, not
donor/recipient roles: in the merge, the left node is always kept
and the right node always freed; in redistribute-left the left
node donates to the right node; in redistribute-right the right
node donates to the left node.

## Merge, end to end

Signature `f(out: *mut [u8; 24], frame: *const Frame56,
direction: u64, edge_idx: u64)`.

- `direction` = which side the current node (and its removed
  edge) is on: `1` = current is the RIGHT node (the left-sibling
  donor path), `0` = current is the LEFT node (the
  right-sibling donor path). It does not select the survivor.
- `edge_idx` = the removed key's index within the current node
  (the leaf op's `[rsp+0x8]`).
- Guards, in order: if `direction == 1`, `edge_idx` must be `<=`
  the right node's count, else `<=` the left node's count —
  otherwise the `track_edge_idx` panic (`node.rs:1491:9`,
  "assertion failed: match track_edge_idx { LeftOrRight::Left(idx)
  => idx <= old_left_len, LeftOrRight::Right(idx) => idx <=
  right_len, }"). Then the merged count `left + right + 1` must
  be `<= 11`, otherwise the `new_left_len` panic
  (`node.rs:1414:9`, "assertion failed: new_left_len <=
  CAPACITY").
- Separator removal from the parent: the parent key at the
  separator index is saved, then parent keys after it shift left
  by one slot (memmove, `(parent_count − sep − 1) * 4` bytes)
  and parent value slots after it shift left by one (memmove,
  `(parent_count − sep − 1) * 16` bytes).
- Separator + right keys into the left node: the saved separator
  key/value are stored at the left node's old-count slot, then
  the right node's keys (memcpy, `right_count * 4`) and values
  (memcpy, `right_count * 16`) are appended after it. The left
  node's count becomes `left + right + 1`.
- Parent children: the parent child pointer at index `sep + 1`
  (the freed right node on a left merge, the freed right sibling
  on a right merge — in both cases `children[sep + 1]`) is
  removed by shifting parent children left by one from that
  index (memmove), and the parent count is decremented. The
  shifted children are reparented (parent pointer unchanged,
  child index rewritten to the new position): single-step for
  the `N mod 4` remainder, then unrolled-by-4, where `N =
  parent_count − sep − 1` — including the stale tail slot,
  which is dead once the count drops.
- Kept-node children (internal nodes only, gated on
  `frame+0x8 >= 2`): the right node's `right_count + 1`
  children are appended to the left node's children starting at
  index `left_count + 1` (memcpy, guarded by a defensive
  length check that panics at `node.rs:1876:5` on mismatch),
  then reparented to the left node with new indices:
  single-step for the `(right_count + 1) mod 4` remainder, then
  unrolled-by-4 up to the merged total.
- Free: the right node is freed via the shared free wrapper
  (GOT `0x64df4a0` → `0x635de30`) with size 232 for leaf merges
  and 328 for internal merges (`edx = 0`).
- Output (24 bytes, written to entry `rdi`, which is the leaf
  op's `[rsp+0x20]` slot): kept node (= left node), levels (=
  `frame+0x20`), and the edge index remapped into the merged
  node: `edge_idx + (direction ? left_count + 1 : 0)`. For a
  right-sibling merge the removed slot stays put; for a
  left-sibling merge it moves past the left node's keys plus
  the separator.

## Redistribute-left, end to end

Signature `f(frame: *const Frame56, borrow: u64)`. Borrows
`borrow` keys from the LEFT node into the RIGHT node (the
underfull current node).

- Guards: `right_count + borrow <= 11`, otherwise
  `node.rs:1537:13` ("assertion failed: old_right_len + count <=
  CAPACITY"); `left_count − borrow >= 0`, otherwise
  `node.rs:1538:13` ("assertion failed: old_left_len >=
  count"). Counts are updated first: left `−= borrow`, right
  `+= borrow`.
- Right keys/values shift right by `borrow` (memmove, old
  count `* 4` / `* 16` bytes).
- The left node's top `borrow − 1` keys/values (indices
  `new_left + 1 .. old_left − 1`) copy into the right node's
  front slots `0 .. borrow − 2` (memcpy; a defensive length
  check panics at `node.rs:1876:5` on mismatch).
- Separator rotation: the left node's key/value at index
  `new_left` swaps with the parent separator — the left key
  becomes the new separator, and the OLD separator lands in
  the right node's slot `borrow − 1`.
- Children (internal only, gated on both levels fields being
  nonzero and agreeing): the right node's children shift right
  by `borrow` (memmove, `(old_right + 1) * 8` bytes), the left
  node's children `new_left + 1 .. new_left + borrow` copy
  into the right node's front slots (memcpy, `borrow * 8`
  bytes), and then ALL of the right node's children are
  reparented (parent = right node, index rewritten):
  single-step for the `(new_right + 1) mod 4` remainder, then
  unrolled-by-4.
- Levels disagreement (one levels field zero, the other
  nonzero) takes the unreachable panic (`node.rs:1585:22`,
  "internal error: entered unreachable code").

## Redistribute-right, end to end

Signature `f(frame: *const Frame56, borrow: u64)`. Borrows
`borrow` keys from the RIGHT node into the LEFT node (the
underfull current node). The mirror image of redistribute-left,
with two asymmetries noted below.

- Guards: `left_count + borrow <= 11`, otherwise
  `node.rs:1600:13` ("assertion failed: old_left_len + count <=
  CAPACITY"); `right_count − borrow >= 0`, otherwise
  `node.rs:1601:13` ("assertion failed: old_right_len >=
  count"). Counts are updated first: left `+= borrow`, right
  `−= borrow`.
- Separator rotation first: the right node's key/value at
  index `borrow − 1` swaps with the parent separator — the
  right key becomes the new separator, and the OLD separator
  appends to the left node's end (slot `old_left`).
- The right node's keys/values `0 .. borrow − 2` copy into the
  left node's slots `old_left + 1 ..` (memcpy, `(borrow − 1)`
  keys / 16-byte slots).
- The right node's remaining keys/values shift left by
  `borrow` (memmove, `new_right * 4` / `* 16` bytes).
- Children (internal only, same levels gate; disagreement
  panics at `node.rs:1649:22`): the right node's children
  `0 .. borrow − 1` copy into the left node's children
  starting at `old_left + 1` (memcpy, `borrow * 8` bytes),
  then the right node's remaining children shift left by
  `borrow` (memmove, `(new_right + 1) * 8` bytes).
- Reparenting asymmetry (stated honestly): the moved children
  are reparented to the left node by an unrolled switch that
  covers at most 5 children (indices `old_left + 1 ..
  old_left + 5`, stopping early when `borrow` is reached) —
  a borrow above 5 would leave later moved children with
  stale parent/index. No call site passes borrow above 5
  (all pass 1 or `5 − count` with `count >= 0`), so the cap
  is dead in practice. The right node's remaining children
  are then reparented generally (single-step remainder, then
  unrolled-by-4), unlike redistribute-left, which reparents
  all of the current node's children because every one of
  them shifted.

## The borrow question, closed

Neither redistribute helper computes a borrow. `esi` is purely
caller-supplied, and the helper's only borrow logic is its two
guards. The three call sites choose:

- Leaf-op first level: `esi = 1` (both directions).
- Leaf-op upward loop: `esi = 5 − current_count` (both
  directions; the loop only reaches redistribute when the
  current count is `<= 4`, so the borrow is in `1..=5`).
- Build post-pass (#197): `esi = 5 − last_child_count`, and
  only redistribute-left is ever called there — the
  right-append build underfills only the rightmost path,
  whose donor is always the left sibling.

So the `5 − count` argument is the callers' min-fill
restoration (borrow up to the min-fill 5 for 11-capacity
nodes), and the helpers are pure multi-key move primitives
with a separator rotation. There is no second borrow rule
inside the helpers to find.

## Caller censuses

Direct E8 callers (full-`.text` byte scan) and GOT sites
(relocation addends):

- Merge `0x4ca2500`: exactly 1 direct caller, the leaf op's
  first-level call at `0x4d24967` (both directions funnel
  through this one site; direction is set just before it:
  `mov edx,0x1` at `0x4d248d1` on the left path,
  `xor edx,edx` at `0x4d24960` on the right path). 0 GOT
  sites. The upward loop does not call it — it inlines the
  merge core (#196).
- Redistribute-left `0x4c93c20`: exactly 3 direct callers —
  build post-pass `0x4cbdbcb` (#197), leaf-op first level
  `0x4d2497b`, leaf-op upward loop `0x4d24f12`. 0 GOT sites.
- Redistribute-right `0x4c9b3b0`: exactly 2 direct callers —
  leaf-op first level `0x4d249ac`, leaf-op upward loop
  `0x4d24f2c`. 0 GOT sites. The build never calls it.

## What this changes about #196 and #197

- #196's redistribute-left "body_bytes 428" is stale: the true
  body proper is 685 bytes including the ret (684 excluding
  it), with the single ret at `0x4c93ecc`. #196's merge (969)
  and redistribute-right (796) figures match the
  ret-exclusive convention exactly and stand.
- #196's leaf-op out48 labels are refined: `out+0x20` is
  levels, and `out+0x28` is the edge index in the resulting
  node — not "merge-path kept-node pointer" and "loc levels
  field". The register trace: after any helper path, the leaf
  op writes `out+0x18 = node`, `out+0x20 = [rsp+0x38] =
  levels`, `out+0x28 = r14 = edge index` (merge out+0x10,
  `removed + 1` after redistribute-left, `removed` after
  redistribute-right, `removed` on the no-rebalance path).
- #196's merge direction gloss is refined: direction does not
  choose the survivor — the merge always keeps the left node
  and frees the right node. Direction records which side the
  current node (and its removed edge) is on, and selects only
  the `track_edge_idx` bound and the output edge remap.
- #197's "build calls only redistribute-left in its
  post-pass" is confirmed by census, and extended: the build
  has no path to redistribute-right or merge at all.

## Limitations

- The free wrapper `0x635de30` is not decoded; only its call
  sites, GOT slot, and size argument (232 leaf / 328
  internal) are claimed.
- The redistribute-right moved-children reparent switch
  covers at most 5 children; borrow above 5 would leave
  later moved children stale. No call site passes borrow
  above 5, so this is unobserved, not a live defect.
- The merge helper's parent-children reparent loop writes
  the stale tail slot (index `parent_count − 1` after the
  shift) before the count decrement; the slot is dead once
  the count drops, so the write is harmless.
- The upward loop's inline merge core is not re-claimed
  here; #196's description of it stands, and this packet's
  merge helper is the extracted first-level version only.
- No runtime behavior is claimed; the node binary was never
  executed.

## Next question

The resolver `0x4d35b60` end to end: how does it consume the
leaf op's out48 (kept node, levels, edge index) to swap the
removed leaf key/value into the internal slot, and which of
its two leaf-op call sites (rightmost-leaf path vs
remaining-levels `== 0` leaf path) drives which completion
shape?
