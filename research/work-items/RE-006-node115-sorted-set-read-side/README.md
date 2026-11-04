# RE-006 node 115 sorted-set read side (forward_2's set)

## Scope

This packet works only against the authenticated Linux x86-64 node
115 artifact:

- `artifacts/node/115/hl-node`
- SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

The forward-callee packet established forward_2 (`0x51d1b00`) as a
sorted-set insert over a B-tree layout, and the map-readback packet
then answered who reads the forward-1 map back. The remaining
question recorded there is the set side: who consumes the sorted
set's member keys on the read side, what each reader does on a hit
and on a miss, and whether the value stored as a member key is
ever read back as a value by any reader.

The layout (from the forward-callee and split-helper packets):
handle `{root at +0x0, height at +0x8, total at +0x10}`; node
`{parent at +0x0, sorted qword keys from +0x8 (at most 11),
child-index word at +0x60, count word at +0x62, child edges from
+0x68}`; leaf nodes are `0x68` bytes, internal nodes `0xc8`. In
the book record the forward-1 map sits at record `+0x0` and the
set handle at record `+0x40`: the insert callers pass a slab
lookup result `+0x40` to forward_2, and this packet shows the
remove and contains paths using the same `+0x40` handle.

## Short answer

The set has standalone readers — unlike the map, which has no
standalone get:

- `find` (`0x51d1a80`, 123 bytes) walks the layout for a key taken
  by pointer and returns `node + 0x64` on a hit, `0` on a miss.
  It exists in three byte-identical clones with seven call sites
  between them; every call site uses the result only as a null
  test and never dereferences it.
- `contains` (`0x243d260`, 169 bytes) is a boolean probe with the
  key passed by value, unique in the binary. Its only callers
  are the two consumer parents, passing the `+0x40` handle.
- `remove` (`0x51d5010`, 273 bytes) is the book cluster's
  read-modify body: its only callers are the four book remove
  consumers that also call the forward-1 map remove. Nine
  sibling remove bodies serve other clusters.

Two consumers read the set inlined. `0x23e4340` probes the set
for a record-derived key and, on a hit, does nothing but a gated
log call; on a miss it continues on the map side only.
`0x23e4c80` traverses the set in order and loads each member key
— the one place a member key is loaded as a value — but consumes
it as a lookup key into the forward-1 map: the slab slot index
always comes from the map's value slot, never from the member
itself. No reader reads a member key back as the slab index or
as any other value.

## Method

Duplicate gate first: the merged records on `main` claim none of
the owner FDEs below, and no open PR title or file list claims
them either; the RE-006 chain packets (#2416, #2427, #2441,
#2447, #2468, #2478) are cited as boundaries, not re-claimed.

Census first, trace second:

1. Walk-signature census: a raw scan of `.text` for the layout's
   three access shapes (word access at `+0x62`, scale-8 load at
   `+0x68`, scale-8 compare at `+0x8`/`+0x10`) nominates candidate
   FDEs; each candidate is objdump-decoded and must carry all
   four decoded features (count-word load, child-edge load, key
   compare, `seta`/`sbb` three-way branch). Exactly 126 FDEs
   carry the full signature.
2. Of those, the FDEs of at most 350 bytes are exactly sixteen:
   the three find clones, the contains body, two byte-identical
   cursor searches, and ten remove bodies. That is the complete
   standalone-reader set for this layout; everything larger with
   the signature is a consumer with an inlined walk or a writer.
3. Body-hash families over all FDEs: the find body hash has
   exactly three carriers (byte-identical clones), the contains
   body hash exactly one, the cursor-search body hash exactly
   two. The ten remove bodies all hash differently (separate
   codegen), so the remove family is a size-and-shape family.
4. Every E8 call site for the readers and cited callees is
   re-derived and re-validated as an instruction start inside
   its containing FDE; the `R_X86_64_RELATIVE` census is
   re-derived from `.rela.dyn`.

## Trace

1. **find `0x51d1a80`.** Root from the handle (pin `0x51d1a80`),
   height from handle `+0x8`, key value dereferenced from the
   caller's pointer (pin `0x51d1a8c`). The walk reads the count
   word at node `+0x62` (pin `0x51d1a91`), scans keys from
   `+0x10` in node-relative addressing (pin `0x51d1ab5`), and
   descends child edges at `+0x68` (pin `0x51d1ae9`) — the same
   walk as forward_2's search phase. On a hit it returns
   `node + 0x64` (pin `0x51d1af0`: `add $0x64,%rcx`), the offset
   just past the count word; on a miss or an empty handle it
   returns `0` (pin `0x51d1af8`). It contains no call and no
   store. The function makes no use of the handle total.
2. **find's call sites.** Seven sites across the three clones:
   four for `0x51d1a80` (FDEs `0x538cd30`, `0x5397b50`,
   `0x55aca20`, `0x55b2720`), two for clone `0x243ca40`, one for
   clone `0x39007b0`. At every site the instruction that consumes
   the result is `test %rax,%rax` at a pinned instruction start
   (`records.json: find_result_tests`); two of the sites probe
   successive keys in a loop until find returns null. No site
   dereferences the returned pointer, so what lives at
   `node + 0x64` is never observed through find.
3. **contains `0x243d260`.** Same walk, key passed by value in
   `rsi` (compare pin `0x243d295`). Found returns `1` in `al`
   (pin `0x243d2d0`). On a miss — including the empty handle —
   it builds a five-qword record `{handle, key, final node, 0,
   final position}` on its stack and calls `0x26d4b60` with it
   (pin `0x243d2fd`) before returning `0`; that callee is
   hash-pinned as a boundary and is not a set operation. The
   only two call sites are in the consumer parents `0x23ebea0`
   (site `0x23eeb94`) and `0x23f0a80` (site `0x23f3c25`); the
   pinned window in parent A shows the argument is a slab
   lookup result `+0x40` (lookup call pin `0x23eeb82`,
   `add $0x40` pin `0x23eeb87`) — the same handle field the
   insert and remove paths use.
4. **remove `0x51d5010`.** Same walk for a key taken by pointer
   (pins `0x51d5015`–`0x51d5079`). On a hit it records a
   `{node, height, position}` cursor on the stack and calls the
   node-remove helper `0x4d2fe70` (pin `0x51d50a8`), then
   decrements the handle total at `+0x10` (pin `0x51d50ad`); if
   the helper reports the root emptied, child 0 is promoted as
   the new root, its parent qword is zeroed, and the old root
   is freed with size `0xc8` through the allocator slot
   `0x64df4a0` (pin `0x51d50e5`; the slot relocates to
   `0x635de30`). Returns `1` when a member was removed, `0`
   when absent. Its four call sites are exactly the four book
   remove consumers (`0x58e1400`, `0x58e1f40`, `0x58e2a80`,
   `0x58e36c0`) that also call the forward-1 map remove — the
   order-removal path updates both structures. The helper
   `0x4d2fe70` is called from exactly the four remove bodies of
   this cluster family (this body and clones A–C), and the
   split helper `0x4c49f90` keeps exactly its three known
   callers (forward_2 and the two other insert bodies).
5. **consumer_a `0x23e4340`** (twin `0x23e47e0`). Called twice by
   parent `0x23ebea0`. It first probes the forward-1 map
   inlined: the length-1 fast path compares the single entry's
   key; otherwise it calls the scrambled-hash probe helper
   `0x26f5c10` (pin `0x23e43d4`). On the far side of a map miss
   it resolves a record through a second tree (`0x58`-byte
   records, function-pointer compare) and
   walks the set inlined — root and height arrive as arguments —
   for the qword at the resolved record `+0x28` (key load pin
   `0x23e46b5`; walk pins `0x23e46c2`, `0x23e46e5`, `0x23e4712`).
   On a set hit the only action is a log-style call through
   slot `0x64df9f0` (pin `0x23e475c`), reached only when the
   global flag dword at `0x64f01d8` (pin `0x23e4719`) is
   nonzero. On a set miss it calls `0x23d4140` and then
   `0x23cdb30` with the same key (pins `0x23e478d`, `0x23e47a9`,
   argument `0xb` pin `0x23e47a3`); both helpers open with the
   forward-1 map's scrambled-hash slot arithmetic (hash
   constant pins in their windows) and neither calls any
   set-family body — the tool checks their decoded direct call
   targets against the whole set family. The set probe is a
   pure membership test: the probed key is compared at every
   node and never loaded from a node.
6. **consumer_b `0x23e4c80`.** The map-readback packet's inlined
   map consumer; its set side is an in-order traversal. The
   traversal state (current node and index) is carried in
   cursor records built from its arguments and merged by the
   helper `0x22ba390` (call pin `0x23e51a9`). It descends child
   edges at `+0x68`, ascends through the parent at `+0x0` using
   the child-index word at `+0x60` (pin `0x23e5361`), bounds
   the index by the count word at `+0x62` (pins `0x23e528e`,
   `0x23e5384`), and loads each member key at
   `node + 0x8 + index * 8` (pin `0x23e542c`). Each member key
   is then used as a key for an inlined forward-1 map probe —
   the length-1 entry-key compare (pin `0x23e5444`) or the
   scrambled hash (constant pin `0x23e5503`) — the map entry's
   value supplies the slab slot index, the slab order copy is
   read under the usual bound (`book + 0x90`) and state
   (`!= 2`) checks, a numeric test is applied to the copy's
   fields, and one `0x20`-byte record per passing member is
   appended to an output vector. As the traversal ascends from
   a node it frees that node through the allocator function
   pointer loaded from slot `0x64df4a0` (load pin `0x23e4d9f`,
   call pin `0x23e537b`), with the size selected by the level
   counter (`0x68` at level 0, else `0xc8`): a consuming
   traversal. This is the only reader that loads member keys
   as values, and it spends each key as a map lookup key — the
   member is never itself used as the slab index.
7. **Other inlined walks in the book cluster.** Each insert
   caller also calls one of the four 1,093-byte book consumers
   (`0x58f5c30`, `0x58f6080`, `0x58f64d0`, `0x58f6920`) twice;
   these bodies carry the walk signature and mix an inlined
   set walk with a map `contains` call and string compares
   (walk pins in the `book_consumer_b` window: `0x58f63b2`,
   `0x58f63d5`, `0x58f6402`). Insert callers `0x5901dd0` /
   `0x5909b30` and the parent `0x23ebea0` also carry the
   signature. These bodies are hash-pinned boundaries: the
   packet claims their membership in the walk census, not a
   per-body trace.

## Read-back verdict

- Point readers compare member keys against a probe key and
  load nothing from the key array: find, contains, remove, and
  consumer_a's inlined probe.
- find's only output besides the walk is a node pointer
  (`node + 0x64`); at all seven call sites it is consumed as a
  boolean and never dereferenced.
- The single value-load of a member key (consumer_b's
  traversal) feeds a forward-1 map probe with the member as
  the key; the slab slot index is then read from the map
  entry's value slot. The stored member is never read back as
  the slab index, and no reader returns a member key to its
  caller as a value.
- The cursor searches (`0x1d65920` / `0x35bdd20`, byte-identical
  143-byte bodies in other clusters) return a four-qword cursor
  record `{root, node, position, height}`-shaped result to
  their callers — a search variant, not a member-value read;
  they are hash-pinned boundaries, not owners of this packet.

## Negative results

- No standalone get returning a member value exists for this
  layout: the complete ≤350-byte reader census is find,
  contains, the cursor searches, and the remove bodies.
- No owner has a relocation slot: find, contains, remove,
  consumer_a, and consumer_b are reached only by direct calls
  (owner addends are absent from the `R_X86_64_RELATIVE`
  census). The allocator slot `0x64df4a0` used by remove and
  consumer_b relocates to `0x635de30`.
- consumer_a's set hit performs no slab read and no insert;
  its set miss performs no set operation at all (both miss
  helpers are map-side only, verified by decoded call target).
- find never reads the handle total, and contains never
  returns anything but 0/1: neither can serve as a member-value
  readback.

## Boundaries

Hash-pinned, one level deep: the two find clones, the two
cursor searches, consumer_a's twin, the three remove clones of
this cluster and the six remove bodies of other clusters, the
node-remove helper `0x4d2fe70`, forward_2 and the split helper
(cited from #2447/#2468), the map readers from #2478
(`0x4ef4010`, `0x4e37a10`, `0x4eeed90`), the two consumer
parents, consumer_b's caller, the two miss helpers, contains'
miss callee `0x26d4b60`, the cursor-state helper `0x22ba390`,
the map probe helper `0x26f5c10`, the four book consumers, and
forward_2's two non-book callers. Decoded windows are retained
for parent A's contains call site, both miss helpers' hash
heads, and book consumer B's set walk.

## Reproduction

```sh
python3 tools/sorted_set_read_side_static.py \
  artifacts/node/115/hl-node \
  research/work-items/RE-006-node115-sorted-set-read-side
python3 -m unittest tests/test_sorted_set_read_side_static.py
sha256sum -c research/work-items/RE-006-node115-sorted-set-read-side/MANIFEST.sha256
```
