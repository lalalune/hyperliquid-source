# RE-001: stats-snapshot insert 0x606ef50 with its caller, wrapper and two node types (node #115)

## Bounded question

What does the routine at `0x606ef50` build from a source iterator, how
does its caller at `0x5d4cc80` create and hand off the snapshot node, and
what do the two node types (vtables `0x64d2c28` / `0x64d2c90`) differ in?

## Answer

The caller builds a 0x70-byte snapshot node holding an embedded
`std::map<std::string, u64>` at `+0x28`, a flag byte at `+0x60` and a
back-pointer to the source object at `+0x68`. The byte at source
`+0x4c9` selects the node type: 0 builds type A (vtable `0x64d2c28`)
and initializes it through the locked lookup `0x5d52660`; nonzero
builds type B (vtable `0x64d2c90`) and fills the map through the
insert `0x606ef50`. The insert drives the source object's iterator
protocol (produce at vtable slot `0x198`, seek `0x28`, has-current
`0x10`, current key `0x48`, current value `0x50`, advance `0x38`,
release `0x8`), parses each entry's `#`-delimited key, skips exactly
the `__persistent_stats_format_version__` entry, decimal-parses the
value into the map value, and finally REPLACES the node's map with
the freshly built one. The wrapper `0x606f920` is type B's slot 3:
it calls the insert with `1 + *(node+0x8)` as the bound. The
corresponding type-A slot 3 (`0x606c6b0`) calls the node initializer
with the same arguments instead.

## The caller 0x5d4cc80 (490 bytes)

Arguments: `rdi` owner, `rsi` source object, `rdx` lower key bound,
`rcx` upper key bound, `r8` snapshot slot (pointer to a node
pointer). Returns the owner.

1. `r8 == 0`: builds a Status through the shared builder `0x61cf670`
   with code 4 (InvalidArgument) and the format at `0x960ee0`
   (32 bytes): `stats_iterator not preallocated.` The second view is
   `{ptr 0x4376fd, len 0}` and contributes nothing. The caller then
   jumps to the common epilogue (canary check, return owner).
2. Otherwise it allocates a 0x70-byte node and initializes it. The
   two paths differ only in the vtable, in `+0x08` and in the fill
   step:

   | field | flag-0 path (type A) | flag-nonzero path (type B) |
   |---|---|---|
   | `+0x00` | vtable `0x64d2c38` | vtable `0x64d2ca0` |
   | `+0x08` | not written (fresh allocation) | 0 |
   | `+0x10` | caller's `rdx` | caller's `rdx` |
   | `+0x18` | caller's `rcx` | caller's `rcx` |
   | `+0x28..+0x48` | empty map header (color 0, parent 0, left/right `&+0x28`, count 0) | same |
   | `+0x50` (u32), `+0x54` (u16), `+0x58` (ptr) | 0 | 0 |
   | `+0x60` | 1, then overwritten by the lookup result | 1 |
   | `+0x68` | caller's `rsi` | caller's `rsi` |
   | fill step | `0x606c680` (node init) | `0x606ef50` (insert) |

3. Then the handoff: `old = *slot; *slot = new`; when `old` is
   non-null the old node's deleting destructor (vtable slot 1) runs
   on it. The owner's vtable slot 7 (`0x38`) is called with
   `(owner, node)` — for both node types that slot copies the node's
   `+0x50/+0x54/+0x58` header into the owner (see below). The
   caller returns the owner.

The caller itself has no direct callers: it reaches the binary
through four `{slot address, 8, function}` registration triples
(slot addresses `0x64c97c8`, `0x64cb540`, `0x64cba20`, `0x64cc020`;
stored qwords at file offsets `0x104ab8`, `0x1090c0`, `0x109f30`,
`0x10b0a0`).

## The node (112 bytes) and its two vtables

Vtable A lives at `0x64d2c28` (the object stores `0x64d2c38`);
vtable B at `0x64d2c90` (the object stores `0x64d2ca0`). Each has
8 function slots (slot 0 is the destructor, the object stores
`vtable + 0x10`):

| slot | A (`0x64d2c28`) | B (`0x64d2c90`) | meaning |
|---|---|---|---|
| 0 | `0x606c5e0` | `0x606e250` | destructor (see below) |
| 1 | `0x606c660` | `0x606e2d0` | deleting destructor: slot 0, then `operator delete(node, 0x70)` |
| 2 | `0x606c180` | `0x606ddf0` | flag getter: `(u8)node+0x60` |
| 3 | `0x606c6b0` | `0x606f920` (the wrapper) | refresh: A calls `node_init(node, 1+*(node+0x8), *(node+0x18))`; B tail-jumps to `insert(node, 1+*(node+0x8), *(node+0x18))` |
| 4 | `0x606c190` | `0x606de00` | count getter: `*(node+0x8)` |
| 5 | `0x606c170` | `0x606c170` (shared) | returns -1 |
| 6 | `0x606c1a0` | `0x606de10` | returns `&node+0x20` |
| 7 | `0x606c1e0` | `0x606de50` | header copy (identical twins, see below) |

Destructor (both types, 119 bytes each): reset the object's vtable
to its own, free `+0x58` with array-delete when non-null, then walk
the embedded map's tree from the parent at `+0x30`: for each 0x48-byte
entry free the key string when it is heap-allocated and free the
entry. Type A disposes keys with `0x606c280`; type B with
`0x606def0`. The two tree-free routines are the same recursive
routine instantiated twice (861 bytes each; the only differing
instruction is the self-recursive call target) and are safe no-ops
on a null root.

Slot 7 (both types, 152 bytes each, identical): copy the node's
header into the destination: `dst u32@0 = src u32@0x50`,
`dst u16@4 = src u16@0x54`, `dst ptr@8 = strdup(src ptr@0x58)` via
`0x61cf610` (the old destination pointer is freed first; a null
source pointer leaves the destination pointer null). Returns the
destination. In the caller-built flow the source fields are all
zero, so this resets the owner's header.

## The insert 0x606ef50 (2511 bytes)

Arguments: `rdi` node, `rsi` bound, `rdx` upper bound. In order:

1. `node+0x68 == 0`: set `node+0x60 = 0` and return. Nothing else
   happens.
2. Initialize a 0x90-byte state struct on the stack with
   `0x60b21f0`: all zero except `+0x2c = 0x101`, `+0x78 = -1`,
   `+0x84 = 4`, `+0x88 = 0x100`. The second argument is never read.
3. Read the bound with the getter `0x5d532d0` (`*(source+0xac0)`).
4. Call the source's vtable slot `0x198` with
   `(source, &state, *(source+0xac0))`; the result is the iterator.
5. Format `max(node+0x8, bound)` with `%010d` (format at `0x444749`)
   into an 11-byte buffer and pass that view to the iterator's slot
   `0x28` (the seek key).
6. Slot `0x10` (has-current): false here clears `node+0x60`, releases
   the iterator (slot `0x8`) and returns WITHOUT touching the map.
7. Otherwise read the current key view (slot `0x48`), parse it with
   the delimited-key parser `0x606eb60` (bound = the insert bound),
   and store the parsed sequence into `node+0x8`. When
   `node+0x8 < bound` the flag is cleared, the iterator released and
   the routine returns without touching the map. Otherwise set
   `node+0x60 = 1` and build an empty local map header on the stack.
8. Loop head: slot `0x10`; false ends the loop and goes to the merge.
   Otherwise read the current key view (slot `0x48`) and parse it
   again with `0x606eb60`; the parsed suffix is moved into the
   saved-key slot (`rsp+0xb8`, a `std::string`: ptr `+0xb8`, len
   `+0xc0`, inline buffer `+0xc8`).
9. Version-key gate: when the saved key is exactly the 35-byte
   `__persistent_stats_format_version__` (memcmp over
   `min(35, len)` equal AND `len == 35`), advance via slot `0x38`
   and continue. Any other key — including a longer key that merely
   starts with the version key — proceeds to insertion.
10. Read the value view (slot `0x50`), copy it into a fresh string
    with the hex helper's flag-0 path (`0x61c7e30`, plain copy), and
    decimal-parse it with `0x61d1540` (whitespace, optional sign,
    `K`/`M`/`G`/`T` suffix shifts; throws on no digits or overflow)
    into the sequence.
11. Lower-bound walk over the local map plus the helper `0x5d6c600`:
    an exact duplicate key is dropped (the first occurrence wins;
    the freshly allocated node is freed). Otherwise allocate a
    0x48-byte map node: key string at `+0x20` (SSO inline at `+0x30`
    when `len <= 15`, heap via `_M_create` when longer, NUL at
    `+0x30+len`), value `u64` = the sequence at `+0x40`. Insert with
    `_Rb_tree_insert_and_rebalance` at the position the helper
    returned and increment the count.
12. Advance via slot `0x38` and repeat from step 8.

Merge (when the iterator is exhausted): the node's map is REPLACED
by the local map and the old tree is freed with the node's type
tree-free routine. Three cases: node map empty — adopt the local
tree (no free); local map empty — move the node tree into the local
header, zero the node map, free the tree (the snapshot becomes
empty); both non-empty — swap the two headers and free the old node
tree. The iterator is released (slot `0x8`) on every merge path.

The key comparison everywhere is `0x5d498c0`: `memcmp` on the common
prefix, else the length difference clamped to the int32 range
(`> 0x7fffffff` stays `0x7fffffff`, `< -0x80000000` stays
`-0x80000000`).

## The node initializer 0x606c680 and the locked lookup 0x5d52660

`0x606c680` (37 bytes): when `node+0x68` is non-null, call
`0x5d52660(node+0x68, lower, &node+0x8, &node+0x20)` and store the
returned bool in `node+0x60`; when it is null, store 0.

`0x5d52660` (261 bytes) takes `(source, lower, upper, out1, out2)`:
when either out pointer is null it returns 0 without locking.
Otherwise it acquires the instrumented lock `0x606ca40` on
`source+0x988` and walks the tree rooted at `source+0xcb0`
(sentinel `&source+0xca8`; nodes carry key `+0x20`, left `+0x10`,
right `+0x18`, map `+0x28`) for the first node with key in
`[lower, upper)`. On a hit it writes the key into `*out1`, deep-copies
that node's map into `*out2` with the map copy `0x5d4e140`
(dst map at `dst+0x08` := src map at `src+0x00`, old dst tree cleared
first), unlocks with `0x60d52f0` and returns 1. On a miss it unlocks
and returns 0, writing nothing.

## The version keys and their initializer

Two `{ptr, len}` records live in BSS and are built once by the
static initializer `0x606f950` (registered in `.init_array` at
`0x63f3990`, stored qword at file offset `0x7468`) from literals via
the string constructor `0x5f204e0`:

- `0x65061c0`: `__persistent_stats_format_version__` (35 bytes,
  literal at `0x95c460`) — the key the insert skips.
- `0x65061a0`: `__persistent_stats_compatible_version__` (39 bytes,
  literal at `0x96ae00`) — built by the same initializer; the
  insert, its sibling `0x606e3a0` and the routine at `0x5e61ad0`
  read the format-version record, and the sibling also reads the
  compatible-version record elsewhere (not mapped here).

## Re-shipped helpers

- `key_parse.txt`: the delimited-key parser `0x606eb60`, byte-identical
  from merged PR #2592.
- `parse_u64.txt`: the decimal parser `0x61d1540`, byte-identical from
  PR #3196.
- `hex_helper.txt`: the hex/copy helper `0x61c7e30`, byte-identical from
  PR #3221.
- `status_builder.txt`: the Status builder `0x61cf670`, byte-identical
  from PR #3221.
- `strdup.txt`: the strdup helper `0x61cf610`, byte-identical from
  PR #3221.

The instrumented acquire `0x606ca40` is mapped end to end in its own
merged packet and is only referenced here as the lock the lookup
takes; the unlock wrapper `0x60d52f0` is likewise referenced, not
re-claimed.

## Verification

`verify.py` checks the work binary digest against the provenance
entry, the manifest, excerpt regeneration byte-for-byte from fresh
objdump runs (re-shipped excerpts by pinned SHA-256), every excerpt
instruction byte-for-byte against the raw binary, spot instructions,
the FDE ranges in `frames.txt` against a fresh frame dump, the
relocation set (30 lines: the two node vtables plus every RELATIVE
record naming a pinned routine), the literals, the census
reproduction (33 pinned routines; `callers.tsv` holds 1525 rows),
the semantic records (re-derived from the excerpts: the vtable slot
tables, the wrapper/slot-3 tail jumps, the `%010d` site, the
version-key gate, the state-init stores, the slot-7 copy sites),
and the model tests in `tests/test_stats_snapshot_insert_115.py`.

## Not claimed

- The concrete dynamic type behind the source object's vtable slots
  (produce `0x198`, seek `0x28`, has-current `0x10`, current key
  `0x48`, current value `0x50`, advance `0x38`, release `0x8`).
- What the slot-`0x50` value view contains beyond its pinned use
  (copied into a string and decimal-parsed into the map value).
- The owner object's identity and its slot-`0x38` dispatch beyond
  the slot-7 copy the caller performs.
- What the flag byte at source `+0x4c9` means beyond selecting node
  type A (0) versus B (nonzero).
- Who fills node `+0x50/+0x54/+0x58` in flows other than this one
  (they are zero in the caller-built node, so slot 7 resets the
  owner header here).
- The other three vtables whose slots hold the caller `0x5d4cc80`
  (slots `0x64cb540`, `0x64cba20`, `0x64cc020`).
- Behaviour on a null owner or a null source pointer (the caller
  reads source `+0x4c9` unconditionally).
- The sibling routine `0x606e3a0`, which shares the bound getter
  and the version-key table (not mapped here).
- Whether the slot-`0x50` decimal parse can throw inside the insert
  loop (the parser throws `invalid_argument`/`out_of_range` on
  malformed input; no handler is pinned in the insert).

The mnemonics in the excerpts (`endbr64` included) are genuine
instructions present in the target binary, not placeholders.
