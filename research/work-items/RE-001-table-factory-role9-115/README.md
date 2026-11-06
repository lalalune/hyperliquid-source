# RE-001: node #115 BlockBasedTableFactory role-9 cache reservation manager

Task: RE-001. Bounded question: in the BlockBasedTableFactory
copy `0x60db710`, after the deterministic prefix (PR #3254) and
the record-vector registration (PR #3257), how is the role map
at factory+0xa8 populated from the source, which role does the
tail look up, and what shared holder does it build at
factory+0x118/+0x120 when the looked-up entry is still 0?

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`work/hl-node-115.bin`, verified against
`provenance/artifacts.json`). All addresses below are node #115
virtual addresses; all excerpts are whole-function verbatim
objdump output. The mnemonics in the excerpts (`endbr64`
included) are genuine instructions present in the target binary,
not placeholders.

## What this pins (complete behaviour, not a fragment)

1. **The factory object.** `0x60db710` copies a 0x260-byte
   `rocksdb::BlockBasedTableFactory` (vtable `0x64d39b8`,
   typeinfo name `N7rocksdb22BlockBasedTableFactoryE` at
   `0x9787a0`). The allocator wrapper `0x60dbd80` (59 bytes)
   allocates the 0x260 bytes and calls the copy directly; it
   has three callers of its own (`0x5d356f5`, `0x6081a8d`,
   `0x6081bac`). The copy itself has three callers
   (`0x60b4197` inside the options default-init main
   `0x60b3fb0`, the wrapper `0x60dbda0`, `0x61a54b4`).
2. **The role map is populated by a deep copy.** The map at
   factory+0xa8 is a `std::map<int, int>`: 0x28-byte nodes
   (color +0x00, parent +0x08, left +0x10, right +0x18, key
   i32 +0x20, value i32 +0x24), header at +0xa8 (color
   +0xa8, root +0xb0, leftmost +0xb8, rightmost +0xc0, count
   +0xc8). The copy calls `0x60d7fb0` (libstdc++
   `_Rb_tree::_M_copy`, 210 bytes) with the source root
   (source+0x90) and the destination header, which
   recursively clones the tree: same entries, same colors,
   same shape, independent nodes (each new node is a fresh
   0x28-byte allocation copying the 8-byte key+value pair
   at +0x20). The destination header is then wired by
   walking to the leftmost (down +0x10) and rightmost (down
   +0x18) nodes and taking the count from source+0xa8.
   The clone has exactly three calls: two self-recursions
   and the table_init call — it is used only by this copy.
3. **The tail looks up role 9.** After the copy, the tail
   runs `map::at(9)` over the copied tree: a lower_bound
   walk comparing each node's key +0x20 with 8 (key > 8
   goes left, recording the candidate; otherwise goes
   right). The landed node must have key <= 9, i.e. exactly
   9, else `std::out_of_range("map::at")` is thrown (the
   literal is pinned at `0x4408a7`; an empty map throws
   too, since the root is null). The same enumerator value
   9 appears as the template argument of the impl type
   built below (`CacheReservationManagerImpl<CacheEntryRole::9>`).
4. **Two gates, then the build.** The build runs only when
   (a) the factory's shared_ptr at +0x58 is non-null
   (`cmpq $0x0,0x58(%rbx)`) and (b) the role-9 value is 0
   (`mov 0x24(%rax),%eax; test`). The mapped int is used as
   a presence flag: 0 means no manager built for this role
   yet; nonzero skips the build. The lookup runs first, so
   a missing role-9 entry throws even when +0x58 is null.
5. **The holder build (0x60dbac0).** Three allocations:
   - O78, 0x78 bytes: a `_Sp_counted_ptr_inplace` control
     block (vtable `0x64d3a80`) holding the 0x68-byte
     `CacheReservationManagerImpl<CacheEntryRole::9>` object
     in place at +0x10, built by `0x5db8800` (111 bytes)
     from a copy of the factory's +0x58 shared_ptr (stored
     at impl+0x18, its control addref'd), flag byte 0 at
     impl+0x28, the rest zeroed. The impl ctor has exactly
     one caller: this path. The impl derives from
     `enable_shared_from_this`: its weak_ptr at impl+0x08 /
     +0x10 is set to {&impl, O78}, raising O78's weak count
     from 1 to 2 (use stays 1).
   - O50, 0x50 bytes: a
     `rocksdb::ConcurrentCacheReservationManager` object
     (vtable `0x64c9a50`), zeroed except for the shared_ptr
     to the impl at +0x40 (ptr &impl) / +0x48 (control
     O78). The manager is also `enable_shared_from_this`:
     its weak_ptr at +0x08/+0x10 is set to {&O50, O18},
     raising O18's weak count from 1 to 2 (use stays 1).
   - O18, 0x18 bytes: a `_Sp_counted_ptr` control block
     (vtable `0x64c9c70`) with `_M_ptr` O50 at +0x10.
   The factory's +0x118/+0x120 shared_ptr is installed as
   {O50, O18}; a previous holder, if any, is released
   first. Both control blocks start with the refcount pair
   {use=1, weak=1} loaded as one 8-byte constant
   (`0x100000001`) from `.rodata` at `0x459b20`. Neither
   use count is incremented during the build: O78's use=1
   is taken over by the manager's shared_ptr, and O18's
   use=1 by the factory holder. The factory's +0x58 control
   gains exactly one use reference (the impl's copy:
   pre-call addref, ctor addref, post-call temp release).
6. **The release helper.** `0x5d350c0` (133 bytes, 1273
   direct calls, 25 tail jumps) models shared release:
   when the refcount pair at +0x08 is exactly {1,1} it
   sets both counts to 0 and calls vtable slot 2 (dispose)
   then slot 3 (delete). Otherwise it decrements the use
   count; when the old use count was 1 it runs the destroy
   dispatch `0x5d35070` (76 bytes, 654 calls, 36 jumps),
   which calls slot 2, decrements the weak count, and calls
   slot 3 when the old weak count was 1. The release helper
   jumps to the destroy dispatch across FDE boundaries
   (`jmp 5d35070` at `0x5d35140`).

## Correction to PR #3254

PR #3254's README said the table-copy tail's tree "is
populated by the 0x6099ce0 call". PR #3257 already corrected
that the push-back appends one record to the record vector
at +0x08, not to the tree. This packet pins the actual
population mechanism: the tree at dest+0xa8 is a deep copy
of the source tree rooted at source+0x90, made by
`0x60d7fb0` (`_Rb_tree::_M_copy`).

## Evidence

Packet `research/work-items/RE-001-table-factory-role9-115/`
(semantic `records.json` only; 6 whole-function verbatim
excerpts — `table_init.txt` and `wrapper.txt` re-shipped
byte-identical from PR #3254, SHA-256 `d496a0e3…` and
`bef8338f…`; `frames.txt` with all 6 FDEs; `callers.tsv`
with 22956 rows; `relocations.txt` with 81 RELATIVE records
— the five vtable groups plus the five typeinfo name
pointers; `verify.py` + `export_excerpts.py` + `census.py`
in packet; `MANIFEST.sha256`) plus
`tools/table_factory_role9_115.py` and
`tests/test_table_factory_role9_115.py`.

The five vtables are identified by their typeinfo names,
recovered through the RELATIVE records (the file's
`.data.rel.ro` holds zeros where the relocations apply, so
the vtable slots are reconstructed from `.rela.dyn`): the
typeinfo pointer at vptr-0x08 names a typeinfo object whose
name pointer at ti+0x08 names a `.rodata` string, demangled
with `c++filt _ZTI<name>`. The typeinfo names are
`rocksdb::BlockBasedTableFactory`,
`rocksdb::ConcurrentCacheReservationManager`,
`rocksdb::CacheReservationManagerImpl<(rocksdb::CacheEntryRole)9>`,
`std::_Sp_counted_ptr<rocksdb::ConcurrentCacheReservationManager*, (__gnu_cxx::_Lock_policy)2>`,
and
`std::_Sp_counted_ptr_inplace<rocksdb::CacheReservationManagerImpl<(rocksdb::CacheEntryRole)9>, std::allocator<void>, (__gnu_cxx::_Lock_policy)2>`.

## Verification

Checker ALL CHECKS PASSED (digest, provenance, manifest,
excerpt regeneration byte-for-byte from fresh objdump runs,
all excerpt lines byte-for-byte vs the raw binary, 3 spot
instructions plus 3 further random instructions byte-for-byte
vs fresh objdump and raw binary, FDE ranges, relocation set
(81 records), literals (map::at, the refcount constant, all
five typeinfo names), census reproduction, semantic records
re-derived from the excerpts, model tests); 97 model-test
checks pass (run directly, pytest is not installed on this
VM).

## Unknowns (recorded, not claimed)

- The pointee type of the factory's +0x58 shared_ptr
  (copied into the impl at +0x18) is not pinned here; it is
  set by the factory constructor or a setter outside this
  packet.
- Which code inserts role entries into a source factory's
  role map (the source side of the population) is not pinned
  here.
- The enumerator name for CacheEntryRole value 9 is not
  recovered; only the value 9 is pinned (lookup constant +
  template argument).
- The data-address entries inside the five vtable groups
  (e.g. `0x64d3990`, `0x64c9930`, `0x96db60`) are recorded
  as installed addends but not classified as functions or
  secondary-vtable headers.
- The old-value release paths inside the weak_ptr
  initializations (`0x60dbc84`, `0x60dbc46`) are present in
  the excerpts but not taken for a fresh construction, since
  the ctors zero those fields.
