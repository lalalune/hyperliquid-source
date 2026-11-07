# RE-001: pin node #115's ObjectLibrary registry end-to-end

Task: RE-001. Bounded question: how does node #115's
`rocksdb::ObjectLibrary` registry work end-to-end — the Default
getter, the registry count, the unordered-map find-or-insert with
its rehash and vector-insert, the three registration entry points
(insert / default-init / register), the control-block teardown,
the PatternEntry vtable and its matcher, and the FactoryEntry
node vtables?

Bound to node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

## What this pins

The registry object (`rocksdb::ObjectLibrary`, 0x80 bytes):
mutex +0x00..+0x28, `std::unordered_map` at +0x28 (buckets +0x28,
bucket_count +0x30 = 1, before_begin +0x38 = 0, element_count
+0x40 = 0, max_load_factor +0x48 = 1.0f, next_resize +0x50 = 0,
single_bucket +0x58 = 0), name `std::string` at +0x60 =
`"default"` (SSO, 7 chars).

- **Default getter `0x61f8b60`**: function-local-static singleton.
  Guard byte `0x6509108`, holder at `0x6509110` (16 bytes: object
  ptr, control-block ptr); `__cxa_guard_acquire`/`release`;
  allocates a 0x10-byte holder and a 0x90-byte make_shared block;
  control-block vtable `0x64d00f0`, packed counts `0x100000001`
  from the global at `0x459b20`. 17 direct call sites.
- **Count `0x61f8700`**: locks the mutex; `*out` = number of
  distinct map keys; return = total registered entries. 8 call
  sites.
- **Find-or-insert `0x5fd1da0`**: `_Hash_bytes(key, len,
  0xc70f6907)`; bucket = hash % bucket_count; chain walk compares
  stored hash, then key length, then `memcmp`; on a miss allocates
  a 0x48-byte node, rehashes via `0x5fd1c60` when the policy
  demands, links the node, returns `&node+0x28` (the value
  vector). 22 call sites. The cold FDE `0x5fd1ffa..0x5fd20c4`
  is the exception landing pad (destroys the partially built
  node, the key string and the `std::function` at rsp+0x40, then
  `_Unwind_Resume`); it is shipped as its own excerpt.
- **Rehash `0x5fd1c60`**: fresh bucket array, re-link every node
  by hash % new_count, free the old array unless it was the
  single bucket. Only called from find-or-insert.
- **Vector-insert `0x5fd17c0`**: `std::vector<T*>::insert` for
  8-byte elements; growth doubling; moves the value OUT of the
  source slot (the source is zeroed). 22 call sites.
- **Insert `0x5fd24c0`**: builds a 0x30-byte FactoryEntry node
  (vtable A `0x64cde68`) and a 0x70-byte PatternEntry; locks;
  find-or-insert under the key `"Environment"`; appends the
  node. Called twice, both from register.
- **Default-init `0x5fd20d0`**: same construction inline (node
  vtable B `0x64cde98`); pattern `"TimeEmulatedSystemClock"`,
  map key `"SystemClock"`; calls count. Taken by address from
  the create host `0x5fd46c0..0x5fd4c2e` as a `pthread_once`
  initializer (guard `0x6504b68`), so it runs exactly once.
- **Register `0x5fd27c0`**: calls the getter, registers
  `"MockEnv"` then `"CompositeEnv"` through insert, then calls
  count. Taken by address from two hosts as a `pthread_once`
  initializer (shared guard `0x6504bb8`), so it runs exactly
  once. No direct callers.

## The "Environment" answer (open unknown from PR #3948)

`insert()` hardcodes the map key `"Environment"` (literal at
`0x44a397`). ALL entries registered through `insert()` live
under the single map key `"Environment"`; the per-entry pattern
strings (`"MockEnv"`, `"CompositeEnv"`, `"SystemClock"`,
`"SliceTransform"`, ...) are stored in the PatternEntry objects,
not as map keys. `default-init` is the exception: it uses the
map key `"SystemClock"` (`0x438369`). After default-init +
register, the map has 2 keys and count returns 3 total entries
with `*out` = 2.

## Control block and destruction

The `_Sp_counted_ptr_inplace<ObjectLibrary>` control-block
vtable `0x64d00f0` has 5 slots: D1 `0x5fefc70` (ret), D0
`0x5fefd00` (delete 0x90), `_M_dispose` `0x5ff7900` (destroys
the name string, the map via `0x5ff7820`, frees the bucket
array unless single), `_M_destroy` `0x5fefd50` (delete 0x90),
`_M_get_deleter` `0x5feff70` (returns `this+0x10` only for the
`_Sp_make_shared_tag` typeinfo, GOT `0x64ecdc8` -> `0x96cb48`).
Map destroy `0x5ff7820` walks the node chain, calls each
value-vector element's vtable slot 1 (FactoryEntry-node D0),
frees the vector buffer, destroys the key string, deletes the
0x48-byte node.

## PatternEntry and the matcher

PatternEntry (0x70 bytes): vtable, `std::string` pattern +0x08,
pattern-length copy +0x28, `std::vector<std::string>` +0x30,
flag byte +0x48 (=1), pointer +0x50 (=0), `std::vector<0x28-byte>`
+0x58 (elements: string at +0x00, mode at +0x20). Its vtable
`0x64d8ed0` has exactly 4 slots: D2 `0x5ff2030`, D0 `0x5ff2150`,
Matches `0x61f8670`, pattern accessor `0x61f8120`.

The matcher `0x61f8670` tries the pattern itself through
str-match `0x61f8430`, then each +0x30 string. Str-match: an
empty +0x58 vector means exact match only (the +0x48 flag is
NOT checked); equal lengths with a non-empty vector means exact
match with the flag required; otherwise the query must start
with the pattern and every +0x58 element must match in sequence
through elem-match `0x61f8280`. Modes: 2 = the element string
must occur AT pos; 0/1 = `std::string::find` from pos+1; 3 =
find with an all-digits gap (after an optional `-`); 4 = find
with a dotted-digits gap (at most one `.`, at least one digit).
The mode governing element i+1 (and the tail after the last
element) is stored in element i's +0x20 field; element 0 is
governed by the initial mode 2. The tail: mode 2 requires the
position to reach the end of the query; modes 3/4 require the
remainder to be digits / dotted digits; any other mode accepts.

## FactoryEntry nodes

Node (0x30 bytes): vtable, PatternEntry*, `std::function`
(functor 16B, manager +0x20, invoker +0x28). Two node vtables
sit contiguously in `.data.rel.ro`: FactoryEntry\<Env\>
`0x64cde68` (used by insert) and FactoryEntry\<SystemClock\>
`0x64cde98` (used by default-init), each with D2, D0, and two
forwarders to the entry's vtable slots 2 (Matches) and 3
(accessor). The `_Sp_counted_ptr<Env*>` control-block vtable
`0x64cdec8` follows them (D1 `0x5fcc6a0`, D0 `0x5fcc830`
delete 0x18, dispose/destroy/get-deleter cited only).

## Vtable boundary finding

The qwords that follow PatternEntry's 4 slots (offset-to-top 0
at `0x64d8ef0`, typeinfo at `0x64d8ef8`) are the header of the
NEXT vtable, the `_Sp_counted_ptr_inplace<ObjectRegistry>`
control-block vtable at `0x64d8f00` (5 slots: D1 `0x61f8130`,
D0 `0x61f8140` delete 0xd0, `_M_dispose` `0x61f8760`, `_M_destroy`
`0x61f8170` delete 0xd0, `_M_get_deleter` `0x61f8180`). Its
dispose destroys a 0xc0-byte ObjectRegistry, a different class
from ObjectLibrary; it is recorded here as the boundary and is
a follow-up work item, not part of this packet.

## Evidence

- `records.json`: semantic records only (layouts, vtable maps,
  caller counts, relocation rows, literals, open unknowns). No
  per-instruction mnemonic list.
- `*.objdump.txt`: verbatim whole-function excerpts, one file
  per window, produced by
  `objdump -d --start-address=0x<start> --stop-address=0x<stop> work/hl-node-115.bin`
  (relative binary path). `endbr64` and the other mnemonics in
  these files are genuine instructions present in the target
  binary, not placeholders.
- `frames.txt`: the FDE ranges for the 31 windows (including
  the cold landing-pad FDE).
- `callers.tsv`: every direct call, tail jump and lea reference
  to the 30 pinned routines, from a full-binary census
  (`census.py`).
- `relocations.txt`: the 31 R_X86_64_RELATIVE records in the
  vtable ranges and the `_Sp_make_shared_tag` GOT slot.
- `census.py`, `export_excerpts.py`, `gen_records.py`,
  `verify.py`: the scripts that produced and check the packet.
- `tools/objectlibrary_registry_115.py` +
  `tests/test_objectlibrary_registry_115.py`: the Python model
  (23 tests) exercising the behaviour end-to-end: Default ->
  register -> default-init -> count (keys=2, total=3) ->
  find-or-insert hit/miss + rehash -> vector-insert growth ->
  matcher modes -> dispose/destroy order.

Run `python3 research/work-items/RE-001-objectlibrary-registry-115/verify.py`
from the repository root; it prints ALL CHECKS PASSED.

## Open unknowns

- The ObjectRegistry class (0xc0-byte object; control-block
  vtable `0x64d8f00`, dispose `0x61f8760`, recursive destroy
  `0x61f81d0`, string-dispose `0x61f814e`) is a different class;
  its functions are cited as the vtable boundary, not excerpted.
  Follow-up work item.
- The `_Sp_counted_ptr<Env*>` dispose `0x5fcc790`, destroy
  `0x5fcc840` and get-deleter `0x5fcc7b0` are cited from
  RELATIVE records, not excerpted.
- The mode field's lagged semantics is recorded as observed;
  whether the source attaches the mode to the following segment
  is not established.
- The two register hosts and the default-init host are
  identified by FDE range only; their names are not established.
- The find-or-insert cold FDE shares code with another frame;
  recorded as observed.
- The registry's read-only find path (`0x61c9d70`) does not call
  find-or-insert in the census; its exact lookup shape is not
  pinned here.
- The exact `_Prime_rehash_policy` prime selection is modelled
  from the libstdc++ policy as observed in find-or-insert's
  `_M_need_rehash` call; the rehash function itself is pinned
  exactly.
- The hash is libstdc++ `_Hash_bytes` with seed `0xc70f6907`;
  the model substitutes a deterministic stand-in hash and pins
  placement/lookup, not hash values.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make doctor` fails on missing providers and `make verify` /
`make catalogue-check` fail because `artifacts/node/115/hl-node`
is a Git LFS pointer here. The packet binds to the materialized
`work/hl-node-115.bin` instead (SHA-256 above, matching
`provenance/artifacts.json`). The repo gates were not run on
this VM; the packet's own `verify.py` (digest, manifest,
excerpt regeneration byte-for-byte, spots, frames,
relocations, literals, census reproduction, records and model
tests) passes here.
