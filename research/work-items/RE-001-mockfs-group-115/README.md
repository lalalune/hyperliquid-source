# RE-001: pin node #115 the "supports_direct_io" option group registered by MockFileSystem

Task: RE-001 (RocksDB options reconstruction).
Work item: `RE-001-mockfs-group-115`.

## Bounded question

Which option group does the MockFileSystem ctor `0x6028a60`
register — name, base, map — what does the map hold, and who
constructs it? This pins the single RegisterOptions site `0x6028b3a`,
which #4372's census lists as "not individually analysed", and the
contents of its map `0x65058e0`, which open PR #4528 recorded only as
a lead ("still unanalysed") and left as an open unknown ("which host
registers the `0x65058e0` group").

## Answer (read from the binary)

### The element

One element is a `Configurable::RegisterOptions` group record, 0x30
bytes (`#3257` pinned the helper and the layout; this packet pins the
MockFileSystem registration):

| offset | field |
| --- | --- |
| `+0x00` | `std::string name`, data pointer (SSO: points at `+0x10`) |
| `+0x08` | `std::string name`, size |
| `+0x10` | `std::string name`, SSO buffer (16 bytes, `+0x10..+0x20`) |
| `+0x20` | options-base pointer |
| `+0x28` | `OptionTypeInfo` map pointer |

`RegisterOptions` (`0x6099ce0`, FDE `0x6099ce0..0x6099e34`,
`rocksdb::Configurable::RegisterOptions(const std::string&, void*,
const std::unordered_map<std::string, OptionTypeInfo>*)` per the
`docs/PROGRESS.md` vendor census) appends the record to the vector at
`object+0x08` (begin `+0x08`, end `+0x10`, capacity-end `+0x18`).
When `end == capacity-end` it calls the growth helper `0x6099790`
(capacity 1 for an empty vector, else `min(2*size, MAX_SIZE)`,
`#3257`).

### The host

`0x6028a60..0x6028ba4` is
`rocksdb::MockFileSystem::MockFileSystem(const
std::shared_ptr<SystemClock>&, bool)` (vendor census in
`docs/PROGRESS.md`, 285/324 bytes). The object is 0x98 bytes:

| offset | field |
| --- | --- |
| `+0x00` | vtable → `0x64d1a08` (MockFileSystem; typeinfo `N7rocksdb14MockFileSystemE` at `0x64d1210`, name string at `0x974450`; 61 slots, all FDE starts, read from `.rela.dyn` — see below) |
| `+0x08`/`+0x10`/`+0x18` | group vector triple, zeroed by the base ctor `0x5fe7080` |
| `+0x20` | `std::mutex` (40 bytes, `+0x20..+0x48`), initialized by `0x60d50c0` (`pthread_mutex_init`) |
| `+0x48` | 8 bytes, not touched by the ctor or the dtor — recorded as unaccounted, not claimed as a field |
| `+0x50` | `std::map` (40-byte `_Rb_tree_header`: color 0 at `+0x50`, parent 0 at `+0x58`, left = right = header at `+0x60`/`+0x68`, node count 0 at `+0x70`) |
| `+0x78` | `std::shared_ptr<SystemClock>` (`{ptr +0x78, control +0x80}`), copied from the ctor's second argument |
| `+0x88` | raw `SystemClock*`, the same pointer as `+0x78` |
| `+0x90` | `bool` supports_direct_io, from the ctor's third argument |

The base ctor `0x5fe7080` runs first (call `0x6028a8a`): it stores
the base vtable `0x64cf008` (`lea 0x64ceff8` + `0x10`) and zeroes
the vector triple. The host then stores the MockFileSystem vtable
`0x64d1a08` (`lea 0x64d19f8` at `0x6028a8f` + `0x10`, store at
`0x6028a9d`).

The mutex at `+0x20` is initialized by `0x60d50c0` (call
`0x6028aaa`, FDE `0x60d50c0..0x60d5157`, which calls
`pthread_mutex_init`). The byte the host loads from `0x97877c` into
`esi` at `0x6028aa7` is dead: the callee zeroes `esi` first (`xor
%esi,%esi` at `0x60d50c5`), so the byte (`0x00`, the tail of a
`.rodata` table just before the `N7rocksdb12Table...` typeinfo
string) is not consumed.

The map at `+0x50` is an empty `std::map`: the ctor stores match
`_Rb_tree_header::_M_reset` exactly — color 0 (`movl $0` at
`0x6028ab3`), parent 0 (`movq $0` at `0x6028ac2`), left = right =
`&header` (`object+0x50`, stored at `0x6028aba`/`0x6028abe`),
node count 0 (`movq $0` at `0x6028aca`). Per the dtor, it maps
string keys to pointers to 0x98-byte refcounted file objects
(mutex at value `+0x28`, refcount at value `+0x50`, strings at
value `+0x08`/`+0x58`); tree nodes are 0x48 bytes. The value
object's C++ type name is not pinned here.

The clock at `+0x78` is copied from the ctor's second argument
(`rsi`, `r12`): `movdqu (%r12),%xmm0` at `0x6028ad2`, `movups
%xmm0,0x78(%rbx)` at `0x6028adf`, and the refcount bump on
`control+0x08` at `0x6028af9` (or the `lock addl` path at
`0x6028b78`). The raw pointer at `+0x88` is the same pointer again
(`movq %xmm1,0x88(%rbx)` at `0x6028b24`).

The bool at `+0x90` is the ctor's third argument (`edx`, `ebp =
edx` at entry, `mov %bpl,0x90(%rbx)` at `0x6028afd`).

The host's exception cleanup (FDE `0x6028a0e..0x6028a5d`, reached
from the landing pads at `0x6028b8c`/`0x6028b98`) corroborates the
layout: it erases the map (`0x6027720` on the root at `object+0x58`),
destroys the mutex at `object+0x20` (`0x60d5170`), releases the
clock (`0x5d350c0` on `object+0x80`) and tail-calls the base dtor
`0x5fe70b0`.

### The registration

Exactly one call, at `0x6028b3a`: `(rdi=object, rsi=stack string at
0x00(%rsp), rdx=object+0x90, rcx=0x65058e0)`.

- **Name ""** (empty): the string struct at `(%rsp)` is `{ptr
  0x10(%rsp), size 0}` — `rbp = lea 0x10(%rsp)` at `0x6028b07`,
  stored as the name pointer at `(%rsp)` at `0x6028b20`; size `0`
  at `0x8(%rsp)` at `0x6028b2c`; NUL at `0x10(%rsp)` at
  `0x6028b35`. 0 chars is within the 15-char SSO limit, so the
  element name is SSO-backed, no heap allocation.
- **Base `object+0x90`** (`lea` at `0x6028b0f` into `rdx`) — the
  supports_direct_io `bool` member itself. The entry's field
  offset is 0, so the option addresses the member directly.
- **Map `0x65058e0`** (`lea` at `0x6028b16`).

The vector starts empty (zeroed by the base ctor), so the growth
path runs once and capacity becomes 1. Resulting vector: 1 element,
capacity 1 — `[{"", object+0x90, 0x65058e0}]`.

### The map's contents

Exactly one entry. The static initializer `0x6029d10..0x602a25d`
(`__static_initialization_and_destruction_0v`) builds it, in its
third block:

| field | value |
| --- | --- |
| key | `"supports_direct_io"` — built from the `.rodata` literal `0x44657e` via the string ctor `0x60261f0` at `0x602a09d` into `-0x1f0(%rbp)`; 18 chars exceeds the 15-char SSO limit, so the key string is heap-backed |
| pack | `0x0` at record `+0xa8` (`movq $0x0` at `0x602a12f`) → type 0, verification 0 |
| type | bool (type 0 = bool per the verified type pattern in merged `RE-001-optiontypeinfo-mismatches-115`: "type 0 = bool (all-zero +0xa8)"), corroborated by the group base being the bool member at `object+0x90` |
| flags | `0x0` at record `+0xb0` (`movl $0x0` at `0x602a13a`) |
| offset | 0 (no offset store anywhere in the value build) |
| callbacks | none (no function-pointer stores and no `0x5e32920` call in this block) |

The record at `-0x1d0(%rbp)` (0xb8 bytes) is built by immediate
zero stores only — the record builder `0x5e32920` runs in the two
sibling blocks, never in this one — and the pair ctor `0x5d400f0`
(`std::pair<const std::string, OptionTypeInfo>` ctor, vendor census
888/903) at `0x602a167` copies it verbatim into the pair at
`-0x110(%rbp)`. The pair is inserted by `0x5d405b0`
(unordered-map insert, vendor census 2348/2434) at `0x602a19a`;
temps are destroyed by the `OptionTypeInfo` dtor `0x5d3f950`
(vendor census 131/131, 100%), and the map dtor `0x5d3f820` is
registered via `__cxa_atexit` at `0x602a1d4..0x602a1f3` — this
block ends in a tail jump to `__cxa_atexit`, unlike the two
sibling blocks which call it. The trailing 4 bytes of the record
(`+0xb4..+0xb8`) are not zeroed by this block; they are stack-slot
residue from the previous block's record and are padding after the
flags field, not a field.

Single-entry proof: the map has exactly two binary-wide lea sites
— `0x6028b16` (host, RegisterOptions arg) and `0x602a17b` (this
initializer, insert arg) — and the initializer performs exactly
one insert into it.

The same initializer also inserts `"time_elapse_only_sleep"` into
`0x6505960` (insert `0x6029e6b`) and `"mock_sleep"` into
`0x6505920` (insert `0x6029fff`); both are pinned by open PR #4528,
cited here as context, not re-derived. #4528 recorded this third
insert only as a lead and left the host unanalysed — this packet
resolves that open unknown. The initializer is installed in
`.init_array` through a RELATIVE reloc addend `0x602e4c0` at
`0x63f3918`; the 9-byte stub `0x602e4c0` (`endbr64; jmp 0x6029d10`)
tail-jumps into it, so it runs at load time; it has no direct `E8`
caller anywhere (pinned by #4528).

### The creators

The host has exactly two direct `E8` callers.

**Invoker `0x5fe58b0..0x5fe590c`** — the `_Function_handler
_M_invoke` for a `RegisterBuiltinFileSystems` lambda (E3 variant,
vendor census 78/92 bytes). It allocates 0x98 bytes via operator
new (call `0x5fe58c2`), takes the clock from
`SystemClock::Default()` `0x5fe2680` (call `0x5fe58ca`),
constructs the MockFileSystem with bool=true (`mov $0x1,%edx` at
`0x5fe58d2`, call `0x6028a60` at `0x5fe58da`), and stores the new
object into the out slot (`*rbp`, where `rbp = *rdx`), releasing
any previous object via its vtable slot 1 (`call *0x8(%rax)` at
`0x5fe58ef`). It has no direct `E8` caller binary-wide — it is
reachable only through the `std::function` vtable, like the
ChrootFileSystem creator in #4565. The name under which it is
registered in the ObjectLibrary is an open unknown.

**`MockEnv::Create` `0x6028d80..0x6028e80`** —
`rocksdb::MockEnv::Create(Env*, const
std::shared_ptr<SystemClock>&)` (vendor census 208/256 bytes). It
allocates 0xa8 bytes via operator new (call `0x6028dab`): a
make_shared-style control block (vtable `0x64d1c70`, `lea
0x64d1c60` at `0x6028dca` + `0x10`, store at `0x6028dd8`;
counts `(1,1)` from GOT `0x459b20` at `0x6028dc6`) plus the
0x98-byte MockFileSystem at `+0x10`, constructed with the caller's
clock and bool=true (call `0x6028a60` at `0x6028ddb`). It then
allocates a 0x60-byte MockEnv (call `0x6028de5`) and constructs it
via `0x60289f0` (call `0x6028e12`), which calls the
CompositeEnvWrapper ctor `0x5fd7360` (#4379) and stores the MockEnv
vtable `0x64d1398`, and returns the MockEnv. Its sole `E8` caller
is `0x602982a` in `MockEnv::Create(Env*)` `0x60297a0..0x60298f7`
(vendor census 298/343), which builds an EmulatedSystemClock via
`0x6029390` and forwards it as the clock.

### The dtor

`0x6028bb0..0x6028cea` is
`rocksdb::MockFileSystem::~MockFileSystem()` (vendor census
262/314 bytes). It stores the MockFileSystem vtable (`lea
0x64d19f8` at `0x6028bb4` + `0x10`, store at `0x6028bd2`); walks
the files map from `_M_left` (`0x6028bce`), and for each value
locks its mutex (`0x60d5230`), decrements the refcount at
value `+0x50`, destroys the value only when the count reaches 0
(unlock `0x60d52f0`, dispose the strings at value `+0x58`/`+0x08`,
destroy the mutex `0x60d5170`, delete 0x98 bytes); erases the tree
nodes via the `_M_erase` helper `0x6027720` (right-subtree
recursion at `0x6028c93`, node delete 0x48 bytes); releases the
clock shared_ptr (`0x5d350c0` on `object+0x80` at `0x6028c80`);
destroys the mutex at `object+0x20` (`0x60d5170` at `0x6028cd5`);
and tail-calls the base dtor `0x5fe70b0` (`jmp` at `0x6028ce5`).
It is vtable slot 0; slot 1 is `0x6028cf0`.

### The vtable

Address point `0x64d1a08` (base `0x64d19f8`: offset-to-top 0, no
reloc; typeinfo pointer at `0x64d1a00` is a RELATIVE reloc to the
typeinfo object `0x64d1210`, whose `+0` reloc is type 1 to
`_ZTVN10__cxxabiv120__si_class_type_infoE + 16` and whose `+8`
reloc points at the name string `N7rocksdb14MockFileSystemE` at
`0x974450`). 61 slots (`0x64d1a08..0x64d1be8`), each a RELATIVE
reloc whose target is an FDE start — the file bytes there are
zero, so the slots are read from `.rela.dyn` (full table in
`vtables.tsv`). Slot 0 is the dtor `0x6028bb0`; slot 5 is
`0x6028eb0` (a MockFileSystem virtual; it calls
`SystemClock::Default` at `0x6028f00` — cited, not pinned); slots
2..4 and 6..13 hold the 11 base-class function addresses that
#4487 lists as the shared addresses of the FilterPolicy vtables,
in the same order.

### Lea censuses

The map `0x65058e0` → `0x6028b16` (host), `0x602a17b`
(initializer). The vtable base `0x64d19f8` → `0x6028a8f` (host),
`0x6028bb4` (dtor). The key literal `0x44657e` →
`0x602a093` (initializer, sole site). The sibling maps:
`0x6505960` → `0x602942b` (EmulatedSystemClock ctor), `0x6029e50`
(initializer); `0x6505920` → `0x6029471` (ctor), `0x6029fe0`
(initializer) — matching #4528.

## Evidence

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

| File | Contents |
| --- | --- |
| `fn-6028a60-mock-filesystem-ctor.objdump.txt` | Whole-function objdump of the host ctor |
| `fn-6029d10-static-initializer.objdump.txt` | Whole-function objdump of the static initializer that fills map 0x65058e0 (and the two sibling maps, #4528) |
| `fn-5fe58b0-mockfs-creator-invoke.objdump.txt` | Whole-function objdump of the RegisterBuiltinFileSystems invoker |
| `fn-6028bb0-mockfs-dtor.objdump.txt` | Whole-function objdump of the dtor |
| `fn-6028d80-mockenv-create.objdump.txt` | Whole-function objdump of MockEnv::Create |
| `callers.tsv` | All 37 direct call sites of 0x6099ce0 with enclosing FDE (matches #3257, #4372, #4551 and #4565 exactly) |
| `literals.tsv` | The supports_direct_io map and key, the vtable base and the MockFileSystem typeinfo string, and the two sibling maps, with lea sites |
| `frames.txt` | FDE ranges for the cited functions |
| `vtables.tsv` | The 61 MockFileSystem vtable slots from .rela.dyn, each target an FDE start |
| `records.json` | Semantic records only: host, helper, registration, resulting vector, map contents, creators, dtor, vtable, censuses, open unknowns |
| `export_excerpts.py` | Generates the five excerpts (objdump commands recorded here) |
| `census.py` | Regenerates callers.tsv / literals.tsv / frames.txt / vtables.tsv |
| `gen_records.py` | Builds records.json from the census, with cross-checks |
| `verify.py` | Runs every check below; prints ALL CHECKS PASSED |

Excerpt commands (run from the repo root):

```sh
objdump -d --start-address=0x6028a60 --stop-address=0x6028ba4 work/hl-node-115.bin
objdump -d --start-address=0x6029d10 --stop-address=0x602a25d work/hl-node-115.bin
objdump -d --start-address=0x5fe58b0 --stop-address=0x5fe590c work/hl-node-115.bin
objdump -d --start-address=0x6028bb0 --stop-address=0x6028cea work/hl-node-115.bin
objdump -d --start-address=0x6028d80 --stop-address=0x6028e80 work/hl-node-115.bin
```

The mnemonics in the excerpts (`endbr64`, `movdqu`, `movups`, …)
are genuine instructions present in the target binary, reproduced
verbatim by objdump, not placeholders. The group name is empty
(`""`), so there is no `.rodata` name literal for it; the map key
`"supports_direct_io"` is an 18-char `.rodata` literal at
`0x44657e`. The vtable slots are read from `.rela.dyn` RELATIVE
relocations because the file bytes at the vtable are zero — the
relocations carry the values (the same method the RE-002 vtable
packets use).

Section map used (readelf -S): `.text` vaddr 0x1419300, file offset
0x1418300 (offset = vaddr − 0x1000); `.rodata` offset == vaddr;
`.data.rel.ro` offset = vaddr − 0x2000; `.rela.dyn` at file offset
0x6be8, 24-byte entries.

## Verification

```sh
python3 research/work-items/RE-001-mockfs-group-115/verify.py
python3 -m pytest tests/test_mockfs_group_115.py -q
```

`verify.py` checks: the artifact digest against
`provenance/artifacts.json`; every MANIFEST hash; byte-for-byte
regeneration of all five excerpts; the FDE ranges against the unwind
tables; the cited instructions against the raw binary bytes; the
37-site RegisterOptions census reproduced by byte-scan and matched
against `callers.tsv`; the lea censuses for the map, the key literal,
the vtable base and the two sibling maps; the direct-E8 caller
censuses for the host, MockEnv::Create and the invoker; the 61
vtable slots reproduced from `.rela.dyn` and matched against
`vtables.tsv`; the literals; the semantic-only records and the full
64-char digest; and the model tests. The model
`tools/mockfs_group_115.py` reproduces the one-element vector
(empty-name group, base `+0x90`, capacity 1) and the single map
entry (type 0 = bool, verification 0, flags 0) and is covered by 13
tests in `tests/test_mockfs_group_115.py`.

## Open unknowns

- The keys and fields of the other RegisterOptions call sites
  (listed in `callers.tsv`, not individually analysed).
- The name under which the invoker `0x5fe58b0` is registered in the
  ObjectLibrary (RegisterBuiltinFileSystems registers several
  FileSystem creators; this one's key is not pinned here).
- The C++ type name of the files-map value object (0x98 bytes:
  mutex `+0x28`, refcount `+0x50`, strings `+0x08`/`+0x58`,
  0x20 bytes at `+0x78..+0x98` untouched by the dtor).
- The 8 bytes at `object+0x48` (between the mutex and the files
  map), untouched by the ctor and the dtor.
- The internals of the MockFileSystem virtual at slot 5
  (`0x6028eb0`) and the other per-class vtable slots; cited by
  address only.
- The identity of `0x5fcf430`, called by `MockEnv::Create(Env*)`
  `0x60297a0` before the EmulatedSystemClock construction; cited
  only.
- Which code reads the group name at runtime (the map serializer
  `0x6097630` and apply loop `0x609c8c0` read only `element+0x20` /
  `+0x28`, per #4372).

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify test catalogue-check` could not be run here; the packet's own
`verify.py` and the model tests were run instead. The binary used is
the materialized `work/hl-node-115.bin` whose SHA-256 matches
`provenance/artifacts.json`.
