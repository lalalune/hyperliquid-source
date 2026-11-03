# RE-001-node115-lu-grow-build

## Claim status: observation

This packet answers packet #196's (PR #2314) explicitly stated first
next question: **the grow callee `0x5155ec0` (#195's second thread,
still open) — what exactly does the array-to-tree conversion past
length 63 build?**

The answer: it builds a B-tree by **right-append bulk load, not by
balanced splitting**. The grow drains the table's ring buffer into a
flat array of 24-byte entries, sorts them ascending by key, then
feeds them through a peeking iterator into a bulk builder that
appends each entry to the current rightmost leaf. When a leaf fills
(11 keys) the builder walks up past full ancestors, grows a fresh
spine of nodes, and inserts the pending entry as a separator into
the first non-full ancestor. When the stream ends, a post-pass walks
the rightmost path and redistributes keys from left siblings into
any node holding fewer than 5 keys (the min-fill for 11-capacity
nodes). The result is a B-tree whose internal nodes are 328 bytes
and whose leaves are 232 bytes — the leaf layout is the internal
layout truncated before the children array, because a leaf's
children region is never read or written by this builder.

## Scope

Included:

- The full grow FDE `0x5155ec0..0x5156053` (403 bytes; body proper
  to the single `ret` at `0x5155fdd` = 286 bytes; tail = 117 bytes;
  94 instructions; 0 nops; CIE `0039672c`).
- The full bulk-build FDE `0x4cbd730..0x4cbdcb0` (1408 bytes; body
  proper to the single `ret` at `0x4cbdbe0` = 1201 bytes; tail =
  207 bytes; 292 instructions; 5 nops; CIE `0039672c`).
- The full iterator FDE `0x4d58320..0x4d5845a` (314 bytes; two
  `ret`s at `0x4d5842e` and `0x4d58459`; 93 instructions; 1 nop; CIE
  `00000000`).
- The drain helper `0x5b9f6f0` (424 bytes; body 336; tail 88; 121
  instructions; 1 nop) and both sort paths: the insertion sort
  `0x53ef680` (188 bytes; 50 instructions; 1 nop) and the large-sort
  wrapper `0x4f3fd80` (272 bytes; 74 instructions; 0 nops).
- The caller contract: the flag helper (`0x4dccf20`, #195) calls
  grow at `0x4dcd0bd` with the pre-reset table copy when the table
  length exceeds 63, after resetting the table to empty-with-
  capacity-8; after grow it installs the tree as the table's
  tree-mode form (sentinel `0x8000000000000000` in field 0, root in
  field 8, height in field 0x10, count in field 0x18).
- Caller censuses (direct E8 only unless noted): grow has exactly 1
  direct caller (the flag helper) and 0 GOT sites; build has 2
  direct callers (grow, and FDE `0x515d170` — not decoded) and 0 GOT
  sites; the iterator has 1 direct caller (build) and 0 GOT sites;
  the drain has 1 direct caller (grow) and 0 GOT sites; the small
  sort has 3 direct callers (grow plus two undecoded FDEs); the
  large-sort wrapper has 0 direct callers and exactly 1 GOT site
  (`0x64ebae0`, used by grow).

Excluded:

- The large-sort inner `0x4f6d1e0` (1694 bytes): only the wrapper's
  buffer policy is pinned, not the inner sort's algorithm.
- The merge helper `0x4ca2500` and redistribute helpers
  `0x4c93c20` / `0x4c9b3b0` internals: only the build post-pass
  dispatch (borrow = 5 − count, left redistribute) is pinned.
  (Note: build calls only redistribute-left in its post-pass; the
  merge helper is called only from the leaf op, not from build.)
- The second build caller (FDE `0x515d170`) and the other sort
  callers: referenced by address only.
- Any runtime behavior. Analysis is static only; the node binary
  was never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.

```sh
objdump -d -M intel --start-address=0x5155ec0 --stop-address=0x5156053 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4cbd730 --stop-address=0x4cbdcb0 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4d58320 --stop-address=0x4d5845a \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x5b9f6f0 --stop-address=0x5b9f898 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x53ef680 --stop-address=0x53ef73c \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4f3fd80 --stop-address=0x4f3fe90 \
  artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node   # GOT slot resolutions
python3 tools/node115_lu_grow_build.py
python3 -m unittest tests.test_node115_lu_grow_build -v
```

## The entry, node, and tree layouts

Table entry (24 bytes, natural alignment): key u32 at `+0`, 4 pad
bytes at `+4`, value u64 at `+8`, flag u8 at `+0x10`, 7 pad bytes
at `+0x11..0x18`. The iterator copies entries verbatim in chunks
(dword + qword + dword + flag + two overlapping dwords for the
7-byte tail), and the builder reads only key (`+0`), value (`+8`),
and flag (`+0x10`) — splitting each entry into a node key and a
node value slot.

Internal node (328 bytes, #195/#196 layout): value slots 16 bytes
each at `+16*i` (`[0]` u64 value, `[8]` flag byte); parent pointer
at `+0xb0`; u32 keys at `+0xb8 + 4*i`; child index u16 at `+0xe4`;
key count u16 at `+0xe6`; child pointers at `+0xe8 + 8*i` (12
slots). Leaf node (232 bytes): the same layout truncated before
the children array — values `[0,176)`, parent `[176,184)`, keys
`[184,228)`, index/count `[228,232)`. A leaf's children region is
never touched by this builder: descents land ON the leaf and stop
(the height/chain budgets are exact), and inserts into a leaf write
only keys, values, counts, parent, and child index.

Tree out-struct (24 bytes, grow's `rdi` argument): root pointer at
`+0`, height (levels from root to leaf) at `+8`, inserted count
(unique keys) at `+0x10`. The flag helper installs it as the
table's tree-mode form: `[table] = 0x8000000000000000` (sentinel),
`[table+0x8] = root`, `[table+0x10] = height`,
`[table+0x18] = count`.

## Grow, end to end

Signature `f(out: *mut Tree24, table_copy: *const Table32)`.

1. **Drain.** The 32-byte table copy is copied to the grow's stack
   and passed to the drain helper `0x5b9f6f0`, which allocates a
   fresh buffer of exactly `length * 24` bytes and copies the ring
   buffer's entries into it verbatim: first the chunk from `head`
   to `min(head + length, capacity)`, then the wraparound remainder
   from the buffer start. Its out-struct is `{length @+0, buffer
   @+8, copied count @+0x10}`; the copied count equals the length
   when the ring is consistent. The old table buffer is freed
   (`capacity * 24` bytes) when nonempty.
2. **Empty.** If the copied count is 0, grow zeroes out `+0` (root)
   and `+0x10` (count) but leaves out `+8` (height) untouched, and
   frees the drained buffer only if the length is nonzero. (Dead
   for the flag-helper caller, whose drained count is always > 63.)
3. **Sort.** If the count is 1, sorting is skipped. For `2 <= len
   <= 20`, the insertion sort `0x53ef680` runs with start index 1;
   for `len >= 21`, the large-sort wrapper `0x4f3fd80` runs via GOT
   `0x64ebae0`. Both sort ascending by the byte-swapped key dword
   at entry `+0` — the same comparison the flag-helper walk uses
   (`bswap` on both keys), so the built tree's key order matches
   the walk's key order.
4. **Initial leaf.** Grow allocates a 232-byte leaf (parent 0,
   count 0) and builds the iterator range struct: `{begin =
   entries, cursor = entries, length, end = begin + count * 24,
   stash area, flag byte 3}`. Only the flag byte is initialized by
   grow; the stash area is filled by the iterator's first peek
   before any read.
5. **Build.** Grow calls the bulk builder `0x4cbd730` with the
   tree out-struct, the range struct, and a count out-slot. After
   the call it copies the 16-byte root+height and the count into
   its own out-struct and returns it.

## The iterator: last-wins dedup with a flag-2 terminator

Signature `f(out: *mut [u8; 24], state: *mut IterState)`. The state
is `{begin @+0, cursor @+8, length @+0x10, end @+0x18, stash
@+0x20..+0x38}`. The state byte at `+0x30` doubles as the pending
entry's flag: value 3 selects cursor mode (read fresh from the
cursor); any other value selects stash mode (read the pending
entry copied into `+0x20..+0x38` by the previous call's peek).

Each call yields one `(key, value, flag)` triple — or flag 2, the
end signal, yielded once and never inserted. The iterator always
peeks one entry ahead: when two consecutive entries have the same
key, the earlier one is dropped without output and the run
continues, so a run of equal keys collapses to its LAST entry.
That is why the tree's inserted count counts unique keys, not
drained entries.

Quirk, stated honestly: a peeked entry with flag 3 is skipped, not
yielded — because value 3 selects cursor mode, the next call reads
past the stashed flag-3 entry. Whether flag 3 occurs in real
drained streams, and what it would mean, is not established here.

## The bulk builder: right-append, spine growth, right-edge fixup

Signature `f(out: *mut Tree24, range: *const IterState, count_out:
*mut usize)`. The current node starts as the tree out-struct's
root (for grow: the fresh 232-byte leaf, height 0, so the prologue
descent — `height` levels via last-child links, mod-8 steps plus an
unrolled-8 loop — is skipped).

1. **Append.** Each yielded entry is appended to the current node
   at index `count` (key at `+0xb8 + 4*count`, value at
   `+16*count`, flag at `+16*count + 8`, count incremented), and
   the inserted count is incremented. Appending at the end is
   correct because entries arrive in ascending key order and the
   current node is always the rightmost leaf.
2. **Full node.** When the current node's count is 11, the builder
   walks up through parents while ancestors are full (count ==
   11). If it reaches a null parent, it allocates a new 328-byte
   root (first child = old root, old root's parent = new root,
   old root's child index = 0) and increments the height. It then
   builds a spine of `rbx` fresh nodes hanging off the insertion
   ancestor: the deepest node is 232 bytes (the new leaf) and the
   rest are 328 bytes, each linked as the first child of the next
   (`[node+0xe8] = previous`, `[previous+0xb0] = node`,
   `[previous+0xe4] = 0`). The pending entry is inserted into the
   ancestor at its next key position, with the spine's deepest node
   as the ancestor's new last child (`children[old_count + 1]`,
   parent and child index `old_count + 1` set). The builder then
   descends `rbx` levels via last-child links to land on the new
   leaf, and insertion resumes.
3. **Post-pass.** When the iterator signals end (flag 2), the
   builder frees the drained buffer (`length * 24` bytes) and, if
   the height is nonzero, walks the rightmost path via last-child
   links while height remains. For each last child holding fewer
   than 5 keys it calls the left redistribute helper `0x4c93c20`
   with borrow count `5 - count`, passing a state struct (node,
   height remaining, left sibling = `children[count - 1]`, last
   child). Only the rightmost path can be underfull in a
   right-append build — every other node is full at 11 — so this
   single pass restores min-fill 5 along the right edge.
4. **Panics.** A rightmost-path node with key count 0 panics
   (`node.rs:367:9`, "assertion failed: len > 0"); inserting into
   an ancestor that is still full panics (`node.rs:698:9`,
   "assertion failed: idx < CAPACITY" — defensive, since the
   walk-up guarantees a non-full ancestor); a height wraparound
   guard panics location-only (`node.rs:240:77`, practically dead).

## What this changes about #195 and #196

#195 left the grow callee as "grow/rehash from call shape only" and
#196 left it open as its first next question. It is now closed:
the conversion is a drain → sort → right-append bulk build of a
B-tree with 11-key nodes, 232-byte leaves, 328-byte internals, and
a rightmost-path redistribute fixup — not a rehash, and not a
balanced build. #196's second question (merge/redistribute
internals) remains open: this packet pins only the post-pass
dispatch, not how redistribute moves keys or chooses its borrow
beyond the `5 - count` argument.

## Limitations

- The large-sort inner `0x4f6d1e0` (1694 bytes) is not decoded;
  only the wrapper's buffer policy (temp count =
  `min(len, 333333, ceil(len/2))`, stack buffer up to 170 entries,
  heap above that, small-flag set when `len < 65`) is pinned.
- The merge helper and both redistribute helpers are not decoded;
  only dispatch and call shapes are pinned.
- The drain out-struct's length vs copied count coincide only when
  the ring is consistent; the two fields are pinned separately.
- The iterator's flag-3 stash-skip behavior is observed
  mechanically; whether flag 3 occurs in real drained streams is
  not established.
- The second build caller (FDE `0x515d170`) is not decoded; the
  packet claims the grow path only.
- No runtime behavior is claimed; the node binary was never
  executed.

## Next question

The merge helper `0x4ca2500` and redistribute helpers `0x4c93c20`
/ `0x4c9b3b0` internals (#196's second question, still open): how
does the merge move the separator and children, and how does
redistribute choose its borrow count beyond the post-pass's
`5 - count` argument?
