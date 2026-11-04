# RE-015: node 115 map owner of the flag-group chain

```text
Task: RE-015
Function: 0x15a3b90 (handle census, phase-2 window, drain window), with the map insert 0x156d840, its delegate 0x1495230 and the collect helper 0x153ba90 as co-owners
Topic: who owns the sorted-node map the chain stores into — the root handle's provenance, and where the stored values are read back, copied, or freed
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 out-buffer-owner packet (#2469)
traced the chain's delivered 24-byte header into a value of
the large consumer `0x15a3b90`'s sorted-node map — on a hit
into the found entry, on a miss into the value record of a
call to the map insert `0x156d840` — and left the map itself
open: who owns the map, where its root handle comes from,
and what happens to the stored values afterwards. This
packet answers both ends.

The answer, in three stages:

1. **Provenance (large consumer `0x15a3b90`, traced
   here).** The map handle is a 24-byte header in the
   consumer's own frame: root pointer at `[rsp+0x178]`,
   tree height at `[rsp+0x180]`, element count at
   `[rsp+0x188]`. The consumer's complete handle census is
   16 accesses. At the head of every field-loop iteration
   the consumer itself zeroes the root (`0x15a3d24`) and
   the count (`0x15a3d30`); the height word has **no store
   anywhere in the body** — it is written only through the
   handle pointer by the insert family, and the walks use
   it as their descent countdown. No handle word arrives
   from a caller argument or a field: the consumer's only
   direct caller in the binary, the wrapper FDE at
   `0x15a6510` (call site `0x15a6556`, hash-pinned
   boundary), passes an out scratch in `rdi`, its own
   record pointer in `rsi`, and a scalar in `edx` — no map
   state. The map is born empty inside the consumer, once
   per field iteration.

2. **Writes through the handle (map insert `0x156d840`
   and its delegate `0x1495230`, traced here).** On a
   miss, each flag segment builds a record whose first
   word is the handle's address (`lea` at `0x15a417c` /
   `0x15a4456`) and calls the insert — the insert's only
   two direct call sites in the binary. The insert
   branches on the record's second word. For the empty
   tree it allocates a `0x120`-byte node through the alloc
   slot (`0x64df480` → `0x6355830`), zeroes its first
   child and its count word (`+0x112`), writes the node as
   the root **through the handle pointer** (`0x156d8cb`),
   zeroes the height word through the same pointer
   (`0x156d8cf`), and stores the first entry: key byte at
   node `+0x114`, the 24-byte triple at
   `node-0x10 + index*0x18`. For an existing node it calls
   the delegate — the delegate's only direct call site in
   the binary (`0x156d88b`) — which stores the triple into
   the node after shifting trailing key bytes and entries
   through the `memmove` slot (`0x64df568`), moving stored
   triples verbatim. On a root split the delegate reloads
   the record pointer (`0x1495c8e`), allocates a
   `0x180`-byte node, makes the old root its first child,
   and writes the new root (`0x1495cf3`) and the
   incremented height (`0x1495cf7`) through the handle
   pointer. Both insert paths join at the common exit,
   which increments the element count through the pointer
   (`0x156d91b`). The node layout is: first child `+0x0`,
   count word `+0x112`, key bytes `+0x114` (the consumer's
   walks address key *i* as `[node + (i-1) + 0x115]`),
   children from `+0x120`, at most 11 entries per node.

3. **Readback and lifetime (traced here).** A stored
   value is read back in exactly three places. (a) The
   segments' own walks, on a hit, replace the entry's
   triple and free the replaced buffer under the
   0/sentinel guard — the out-buffer-owner packet's
   subject, cited not re-traced. (b) A phase-2 probe walk
   (`0x15a453c`–`0x15a45e0`) descends the map by the key
   bytes at `[rsp+0x1e0..]` and, at the found entry,
   loads **only the capacity word**, comparing it against
   the sentinel `0x8000000000000000` (`0x15a45e0`); the
   stored pointer and length words are never loaded in
   this window, and neither branch copies or frees
   anything — both build descriptor records from
   `.rodata` strings. (c) The per-iteration drain on the
   field loop's back-edge (`jne 0x15a3cf0` at
   `0x15a5746`): the consumer builds two iterator records
   from the handle triple (`{0, root, height}` at
   `0x15a5523`–`0x15a5544`) and calls the collect helper
   `0x153ba90` (at `0x15a5580`), which reads count words
   (`+0x112`, loads at `0x153bb67`, compare at
   `0x153bc8e`) and descends child pointers (`+0x120`)
   across the tree; its teardown arm frees the nodes
   through the dealloc slot (`0x64df4a0` → `0x635de30`;
   calls at `0x153bc35` and `0x153bde6`, size `0x120` for
   a leaf, `0x180` for an internal node). The consumer
   then walks the collected vector of 24-byte elements
   (base at `[rsp+0x90]`, count at `[rsp+0xa0]`) and frees
   each element's buffer through the dealloc slot (call
   at `0x15a55ca`) unless the checked word is 0 or the
   sentinel — the only free of stored buffers in the
   traced code besides the hit-path replacement free. The
   collect helper contains no `0x18`-stride entry copy: it
   never copies a stored triple. Inside the delegate, all
   six dealloc-slot calls (`0x1495ed2`, `0x1495f3f`,
   `0x1495f4f`, `0x1495f9d`, `0x1495fd3`, `0x1495fee`) sit
   after the normal return (`ret` at `0x1495d9a`), in
   panic and unwind landing pads freeing the delegate's
   own in-flight allocations — no stored entry is freed
   in the insert family's normal flow. The consumer's
   tail region repeats the drain for the unwind path
   (handle loads at `0x15a63d1`–`0x15a63ec`, collect calls
   at `0x15a6459` and `0x15a64b5`).

## Boundary

The sole caller wrapper `0x15a6510` (356 bytes) and the
second-structure helper `0x1542870` (322 bytes) are
hash-pinned boundaries; the wrapper's consumer call site
is re-pinned. The format consumer `0x141e3a0` and the
derived-byte callee `0x15ae430` are hash-pinned as cited
boundaries from the sibling packets (#2408, #2396). The
instance scope of the layout claims is established by the
direct-call census, not by a binary-wide offset census:
the node layout is a generic family with over a hundred
monomorphised sibling instantiations sharing the
`+0x112`/`+0x120` offsets for other key/value types, so
offset hits elsewhere in the binary are other instances,
not readers of this map.

## Traced result

Composing the chain end to end: the map is a local,
per-iteration structure of the large consumer. It is
initialised empty by the consumer itself at each field
iteration; it grows only through the insert family
writing through the handle pointer the consumer lends
it; its stored values are probed once by capacity word
only, and at the end of the iteration the whole map is
drained — buffers freed by the consumer under the
0/sentinel guard, nodes freed by the collect helper —
before the loop head zeroes the handle for the next
field. Ownership never leaves the consumer's frame.

Next question: the phase-2 probe's two branches build
descriptor records from `.rodata` strings and the
consumer's argument block and hand them to `0x474d890`
and to a call through slot `0x64e1458` — what consumes
those records, and does the sentinel/non-sentinel branch
change what is emitted?

Reproduce from the repository root:

```bash
python3 -B tools/map_owner_static.py
python3 -m unittest tests.test_map_owner_static -v
```

Map ownership for the RE-015 flag-group chain's instance
only: the large consumer 0x15a3b90 (its complete
16-access handle census, its segment walks, the phase-2
probe walk, and the drain region on the field loop's
back-edge), the map insert 0x156d840, its general
delegate 0x1495230, and the collect helper 0x153ba90
where the consumer drives it. The node layout is a
generic family: over a hundred monomorphised sibling
instantiations share the +0x112/+0x120 offsets for other
key and value types, and no binary-wide reader census
for the layout is claimed — instance scope is
established by the direct-call census (the insert is
called only from the large consumer, the delegate only
from the insert). The drain region's later record
processing (including the second stack structure at
[rsp+0x1b8] and the helper 0x149e5b0), the phase-2
probe's record consumers (0x474d890 and the call through
slot 0x64e1458), the allocator/deallocator targets
behind slots 0x64df480/0x64df4a0, and the collect
helper's 61 call sites in other instantiations are NOT
traced. No captured code executed, no runtime value,
indirect-call recovery beyond the pinned slot bindings,
#94 correspondence, or reconstruction gate is claimed.
