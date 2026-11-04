# RE-001-node115-lu-flag-completion

## Claim status: observation

This packet answers packet #194's (PR #2278) explicitly stated next
question: **what does the flag helper `0x4dccf20` select (what makes its
out-flag 1), and what does the completion helper `0x4da86a0` do when an
l1_map entry's count hits zero — removal, notification, or recycle?**

The answers, with binary evidence for every branch:

- **The flag helper selects by key presence.** Its out-flag is 1 exactly
  when the key is present, and 0 exactly when it is absent. The caller
  (#194's gate-release operation) runs its payload — the saturating
  count decrement and the completion call — only when the flag is 1.
- **The completion helper removes.** In both of its cases it removes the
  entry and returns the removed entry's payload: the tree case unlinks
  and frees a 328-byte node, the table case memmove-shifts the array
  closed and decrements the count. There is no wake, callback, or
  notification in either path, and nothing is recycled: the node is
  freed, the array slot is compacted away.

The two helpers are the callee pair of #194's worked example: the flag
helper is called at `0x4fb530f` and the completion helper at
`0x4fb539e`, both direct calls. Neither function is claimed by any
earlier packet; #194 cited them only as undecoded callees, and this
packet cites #194 as the inviting prior.

## Scope

Included:

- The full flag helper FDE `0x4dccf20..0x4dcd300` (992 bytes) and the
  full completion helper FDE `0x4da86a0..0x4da885b` (443 bytes).
- The flag rule in all four paths (small-table hit/miss, tree hit/miss)
  and the out-struct encoding the caller consumes.
- The small-table binary search `0x57fafd0` as characterization
  (its bytes are NOT claimed): sorted 24-byte entries, bswapped u32
  key compare, circular-buffer wrap, returns 0 = present / 1 = absent
  plus a position.
- The 328-byte B-tree node layout as used by the walk, the resolver,
  and the completion helper (value slots, key array, counts, children,
  parent).
- The completion helper's two removal cases, its memmove shift, its
  count decrements, and its three panic provenances.
- Caller census for both helpers (direct calls only; neither has a GOT
  slot).

Excluded:

- The internals of the leaf op `0x4d24790` (what its `rax == 0`
  flag condition means beyond "the sole flag-byte writer"), the grow
  callee `0x5155ec0`, and the drain callees `0x5b99ef0` /
  `0x51e8720`. They are referenced by address only.
- The internals of the second flag-helper caller (`0x4fac740`, which
  chains the flag helper's out-struct into `0x4da6c80` without a flag
  check) and of the other lookup callers (`0x4fac5fa`,
  `0x4fac8d2`).
- Any runtime behavior. Analysis is static only; the node binary was
  never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```sh
objdump -d -M intel --start-address=0x4dccf20 --stop-address=0x4dcd300 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4da86a0 --stop-address=0x4da885b \
  artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node   # GOT slot resolutions
python3 tools/node115_lu_flag_completion.py
python3 -m unittest tests.test_node115_lu_flag_completion -v
```

## The flag helper: FDE 0x4dccf20, end to end

Body proper `0x4dccf20..0x4dcd2c0` (928 bytes, 234 instructions, single
`ret` at `0x4dcd2c0`); tail `0x4dcd2c0..0x4dcd300` (64 bytes, 17
instructions, unwind paths calling `_Unwind_Resume`). CIE `0039672c`
(`zPLR`), the same CIE as #192/#193/#194. Full-FDE SHA-256
`1f553432dcdfc266e8c5199fffde1e93f78ef777daaa01ba4d827e211669be72`;
body-proper SHA-256
`0755b0a92a47356d34f74014b45b7ccef69e0b37df9b7bde7392112a23719091`.

Signature: `f(out: *mut Out, table: *const Table32, key: u32)`.
The caller passes `out = rsp+0x8`, `table = P+0x18` (the 32-byte table
struct), `key = [caller_rdi+0x8]` as a dword. The out-struct is
`{flag: u64, A: u64, B: u64, C: u64, D: u64}`; the caller compares the
flag's low dword against 1 and, only on flag == 1, reads A/B/C/D.

Table struct (32 bytes; field roles inferred from the lookup's wrap
arithmetic and the threshold/reset checks): `[0]` capacity, `[0x8]`
buffer pointer, `[0x10]` head/start, `[0x18]` length.

Flow:

1. **Reset path.** If `[table] == 0x8000000000000000` (INT64_MIN
   sentinel) and `[table+0x18] < 32`, the helper drains the old
   `[table+0x8]`/`[table+0x10]` contents (`0x5b99ef0` plus a
   `0x51e8720` drain loop) and proceeds directly to the tree walk
   below — no array lookup is attempted.
2. **Array lookup.** Otherwise it calls the binary search `0x57fafd0`
   (call at `0x4dcd06c`) with `(table, &key)`. The search compares
   bswapped key dwords against the sorted 24-byte entries, handling
   the circular wrap as two runs, and returns `rax = 0` when the key
   is present and `rax = 1` when it is absent (plus a position in
   `rdx`, which the flag helper ignores).
3. **Small-table decision.** If the lookup returned 0 (present), or
   returned nonzero with `[table+0x18] <= 63` (the threshold compare
   at `0x4dcd07a`), control reaches the shared out-block: flag =
   `(lookup_result != 1)`, `A = 0`, `B = table`, `C = key`, and `D`
   is written (to the key) only on the absent path. So a present key
   yields flag 1 with the table path, and an absent key in a small
   table yields flag 0. The caller, on flag 1, takes its 24-byte
   stride table path (`entry = buffer + 24*wrapped-index + 8`,
   index derived from the key).
4. **Large-table decision.** If the lookup returned nonzero and
   `[table+0x18] > 63`, the helper copies the table to the stack,
   resets it to empty-with-capacity-8, calls the grow callee
   `0x5155ec0`, then falls into the tree walk. The walk scans a
   328-byte node per level: it reads the key count from the u16 at
   `+0xe6` (load at `0x4dcd1c4`), compares the key dword against the
   sorted u32 array at `+0xb8 + 4*i` while the key is greater,
   descends to child `i` at `+0xe8 + 8*i` when the key is smaller,
   and takes the rightmost child when the array is exhausted. The
   level budget `rsi = [table+0x10]` is decremented per descent;
   underflow ends the walk as absent. On a hit at position `i` in
   node `N`, the out-struct is `(flag = 1, A = N, B = remaining
   levels, C = i, D = &table.buffer)`, and the caller takes its
   16-byte stride path (`entry = N + 16*i`, the value slot for key
   `i`, whose first qword is the count). On exhaustion the flag is 0
   and the caller skips the payload; the trailing out fields on this
   path are path-dependent and are not pinned, since the caller does
   not read them.

The flag rule, stated once: **flag = 1 if and only if the key is
present** — small-table hit, or tree-walk hit. Every absent path
(small-table miss, tree-walk exhaustion) yields flag 0.

## The 328-byte node layout (as used, not as named)

- Value slots: 16 bytes each at `+16*i` for key position `i`
  (`i < 11`, covering `+0x0..0xb0`). The caller's entry computation
  (`node + 16*i`) and its count read/write at `[entry]` pin the count
  as the slot's first qword.
- Key array: u32 keys at `+0xb8 + 4*i`, compared bswapped.
- Second counter: u16 at `+0xe4`, written by the leaf op; its exact
  role is not established (see Limitations).
- Key count: u16 at `+0xe6`, read by the walk and the resolver.
- Children: pointers at `+0xe8 + 8*i` (12 children for up to 11 keys).
- Parent: pointer at `+0xb0`, followed upward by the resolver and
  cleared by the completion helper on unlink.
- Total: `0xb8 + 44 + 4 + 96 = 0x148 = 328` bytes, matching the
  completion helper's free size. The panic strings confirm the family:
  `alloc::collections::btree::node` (`node.rs`) and
  `alloc::collections::btree::map::entry` (`entry.rs`).

## The completion helper: FDE 0x4da86a0, end to end

Body proper `0x4da86a0..0x4da881b` (379 bytes, 102 instructions,
single `ret` at `0x4da881b`); tail `0x4da881b..0x4da885b` (64 bytes,
11 instructions, panic paths). CIE `00000000`. Full-FDE SHA-256
`338fee89876ab02fa1f9ac5f2948c35cd8a6f64fbf3283ab16796d3de1376361`;
body-proper SHA-256
`7afb93c6e32ad71cc32050e9287bb0e466dcf2aea214832d6e974c4fd2761da3`.

Signature: `f(out: *mut [u8; 24], loc: *const Loc32)`. The caller
passes `loc = {out8, out10, out18, out20}` copied from the flag
helper's out-struct (the 32 bytes at `[rsp+0x38..0x58]`), and the
helper returns the removed entry's 24 bytes: 16-byte value plus the
8-byte tail (flag byte, then the entry's `+0x11` and `+0x14` dwords,
which together reproduce the entry's `+0x10..0x18` bytes verbatim).

Case 1 — `loc[0] != 0` (tree path, the caller's node `+ 16*i` path):

- Resolve via `0x4d35b60` (call at `0x4da86c9`, flag out-pointer
  `&[rsp+0x7]` threaded through to the leaf op `0x4d24790`).
  The resolver descends `child[position]` then `child[count]`
  repeatedly to a leaf, the leaf op replaces the value slot at
  `(node, position)` with its result and returns the old payload;
  the leaf op writes 1 to the flag byte on exactly one path
  (`rax == 0` at `0x4d24eec`, store at `0x4d24efa`).
- Decrement the total count: `dec [loc[3]+0x10]` (at `0x4da86e6`).
- If the flag byte is 1: unlink the head node — `[loc[3]] =
  [head+0xe8]`, decrement `[loc[3]+0x8]`, clear
  `[new_head+0xb0]` (the parent pointer), and free the old head
  with size `0x148` (call at `0x4da872d` via GOT `0x64df4a0`,
  target `0x635de30`). If the head pointer is 0, the location-only
  panic call fires (`0x4da881c`, GOT `0x64df830`, Location
  `btree/map/entry.rs:614:42`); if the node count is 0, the
  `node.rs:618:9` assertion panic fires (see below).
- Return the resolved 24-byte payload either way.

Case 2 — `loc[0] == 0` (table path, the caller's 24-byte stride path):

- `table = loc[1]`, `index = loc[2]`, `count = [table+0x18]`. If
  `count <= index`, the `entry.rs:210:39` panic fires (message
  `occupied entry index`).
- Otherwise the entry is `buffer + 24*wrapped-index` (single wrap
  against `[table]`), and its 24 bytes are the payload.
- The gap is closed by the memmove-based shift `0x58132d0` (call at
  `0x4da87e2`, `memmove@GLIBC_2.2.5` via GOT `0x64df568`,
  24-byte stride arithmetic), then the count is decremented
  (`dec` at `0x4da87e7`, store at `0x4da87ea`).
- If the entry's flag byte (`[entry+0x10]`) is 2, the same
  `entry.rs:210:39` panic fires — after the shift and the decrement,
  in that order. Otherwise the payload is returned.

Conclusion for #194's second half: **removal, returning the removed
entry's payload**. No wake, futex, callback, or notification appears
in either path; nothing is recycled — the tree node is freed and the
table slot is compacted away with the count decremented.

## Panic provenance

- `occupied entry index` (20 bytes at `.rodata 0x9171b6`),
  Location struct `0x649cc20` → file `base/src/l1_map/entry.rs`
  (24 bytes at `0x4402cd`, via `R_X86_64_RELATIVE` addend),
  line 210, col 39. Raised by the completion table path (index out
  of range, and entry flag byte == 2 after removal).
- `assertion failed: self.height > 0` (33 bytes at `.rodata
  0x913418`), Location struct `0x649a528` → file
  `.../library/alloc/src/collections/btree/node.rs` (91 bytes at
  `0x4344f8`, via addend), line 618, col 9. Raised by the
  completion tree path when the node count is 0.
- Location-only panic call (`0x4da881c`, GOT `0x64df830` →
  `0x1680c10`) with Location struct `0x64a36d0` → file
  `.../library/alloc/src/collections/btree/map/entry.rs` (96 bytes
  at `0x430444`, via addend), line 614, col 42. Raised by the
  completion tree path when the head pointer is 0.

## Caller census

- Flag helper `0x4dccf20`: 2 direct `E8` callers
  (`0x4fb530f` — #194's gate-release operation, which checks the
  flag; `0x4fac740` — in FDE `0x4fac710`, which passes
  `(out = rsp+0x8, table = r15+0x18, key = ebp)` and chains the
  out-struct into `0x4da6c80` without a flag check), 0 GOT sites
  (no relocation addend equals the target).
- Completion helper `0x4da86a0`: 1 direct `E8` caller
  (`0x4fb539e` — #194's gate-release operation), 0 GOT sites.
- Lookup helper `0x57fafd0` (characterization only): 3 direct `E8`
  callers (`0x4dcd06c` — the flag helper itself, `0x4fac5fa`,
  `0x4fac8d2`), 0 GOT sites.

## What this changes about #194

#194 left the flag helper's selection rule mechanical ("writes a 1/0
flag to `[rsp+0x8]`") and the completion helper's effect open
("removal, notification, or recycle?"). This packet closes both:
the flag is a key-presence test (small-table binary search, or
B-tree walk past length 63), and the completion is a removal that
returns the removed payload. #194's gate-release description stands
unchanged — its payload now has a proven precondition (key present)
and a proven postcondition (entry removed, payload returned).

## Limitations

- The leaf op `0x4d24790` internals are not decoded: the exact
  meaning of its `rax == 0` flag condition is not established, only
  that it is the sole writer of the completion flag byte.
- The grow callee `0x5155ec0` internals are not decoded: it is
  called with stack copies after the table is reset to
  empty-with-capacity-8, and is described as grow/rehash from call
  shape only.
- The drain callees `0x5b99ef0` and `0x51e8720` internals are not
  decoded: described as old-contents drain from call shape only.
- Table-struct field names (capacity/head/length) are inferred from
  the lookup's wrap arithmetic and the threshold/reset checks, not
  from a named struct.
- The node `+0xe4` second u16 counter's role is not fully
  established (the walk uses `+0xe6` as the key count; the leaf op
  writes `+0xe4`).
- Tree-miss out-struct trailing fields are path-dependent and are
  not pinned; the caller only reads the flag on that path.
- No runtime behavior is claimed; the node binary was never
  executed.

## Next question

The leaf op `0x4d24790` is now the open thread: decode it end to
end — what does its `rax == 0` flag condition mean (which node
state makes the completion helper unlink and free), and what is the
node `+0xe4` second counter it writes? A second thread is the grow
callee `0x5155ec0`: what exactly does the array-to-tree conversion
past length 63 build?
