# RE-001: pin node #115 the "chroot_dir" option group registered by ChrootFileSystem

Task: RE-001 (RocksDB options reconstruction).
Work item: `RE-001-chrootfs-group-115`.

## Bounded question

Which option group does the ChrootFileSystem ctor `0x5feeab0`
register — name, base, map — what does the map hold, and who
constructs it? This pins the single RegisterOptions site `0x5feeb6a`,
which #4372's census lists as "not individually analysed", and the
contents of its map `0x6505240`, never recorded before.

## Answer (read from the binary)

### The element

One element is a `Configurable::RegisterOptions` group record, 0x30
bytes (`#3257` pinned the helper and the layout; this packet pins the
ChrootFileSystem registration):

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

`0x5feeab0..0x5feec0d` is
`rocksdb::ChrootFileSystem::ChrootFileSystem(const
std::shared_ptr<FileSystem>&, const std::string&)` (vendor census in
`docs/PROGRESS.md`, 316/349 bytes). The object is 0x50 bytes:

| offset | field |
| --- | --- |
| `+0x00` | vtable → `0x64cf478` (ChrootFileSystem; typeinfo `N7rocksdb16ChrootFileSystemE` at `0x64cf450`; 63 slots pinned by `RE-002-node115-rocksdb-fs-chroot-vtable`) |
| `+0x08`/`+0x10`/`+0x18` | group vector triple, zeroed by the base ctor `0x5fe7080` |
| `+0x20` | wrapped `std::shared_ptr<FileSystem>` (`{ptr +0x20, control +0x28}`), copied from the ctor's second argument by the FileSystemWrapper ctor `0x5fe7210` |
| `+0x30` | `std::string` chroot path (data pointer `+0x30`, size `+0x38`, SSO buffer `+0x40..+0x50`) |

The base chain runs first: the host calls `0x60072b0` (`0x5feead8`),
which calls the FileSystemWrapper ctor `0x5fe7210` (`0x60072b8`,
pinned by open PR #4398 — it zeroes the vector via `0x5fe7080`,
stores its vtable `0x64cf200`, copies the shared_ptr, and registers
its own empty-name group for base `object+0x20` with map `0x65051e0`,
call `0x5fe7292`, cited here not re-pinned), then stores vtable
`0x64d05a8` (`lea 0x64d0598` + `0x10`). The host then stores the
ChrootFileSystem vtable `0x64cf478` (`lea 0x64cf468` at `0x5feeadd`
+ `0x10`, store at `0x5feeaf8`). The class identity of the
intermediate ctor `0x60072b0` is an open unknown.

The dir string is copied from the ctor's third argument (`rdx`,
`rbp = rdx` at entry): size > 15 takes the heap path (`_M_create`
into `object+0x30`, `memcpy`), size == 1 stores one byte at
`object+0x40`, otherwise `memcpy` into `object+0x40` with the size at
`object+0x38` (`object+0x30` is first set to `object+0x40`, the SSO
pointer).

### The registration

Exactly one call, at `0x5feeb6a`: `(rdi=object, rsi=stack string at
0x10(%rsp), rdx=object+0x30, rcx=0x6505240)`.

- **Name "chroot_dir"** (10 chars): built on the stack, not from a
  `.rodata` literal — `movabs "chroot_d"` (`0x645f746f6f726863`) to
  `0x20(%rsp)` (`0x5feeb41`), `mov $0x7269` (`"ir"`) to `0x28(%rsp)`
  (`0x5feeb57`), NUL to `0x2a(%rsp)` (`0x5feeb65`); size `0xa` at
  `0x18(%rsp)`; the string struct at `0x10(%rsp)` is `{ptr
  0x20(%rsp), size 10}`. 10 chars is within the 15-char SSO limit,
  so the element name is SSO-backed, no heap allocation.
- **Base `object+0x30`** (`lea` at `0x5feeac0` into `r12`, passed as
  `rdx` at `0x5feeb25`) — the chroot-dir `std::string` member itself.
  The entry's field offset is 0, so the option addresses the member
  directly.
- **Map `0x6505240`** (`lea` at `0x5feeb46`).

The vector already holds the base's empty-name group (size 1,
capacity 1), so the growth path runs and capacity becomes 2.
Resulting vector: 2 elements, capacity 2 —
`[{"", object+0x20, 0x65051e0}, {"chroot_dir", object+0x30,
0x6505240}]`.

### The map's contents

Exactly one entry. The static initializer `0x5fef080..0x5fef25f`
(`__static_initialization_and_destruction_0v`, vendor census 432/479
bytes) builds it:

| field | value |
| --- | --- |
| key | `"chroot_dir"` — built identically on the stack (`movabs "chroot_d"` to `-0x1d0(%rbp)`, `"ir"` to `-0x1c8(%rbp)`, size `0xa`; key string struct at `-0x1e0(%rbp)`) |
| pack | `0x9` at record `+0xa8` (`movq $0x9` at `0x5fef19f`) → type 9, verification 0 |
| type | string (type 9 = string per the verified type pattern in merged `RE-001-optiontypeinfo-mismatches-115`) |
| flags | `0x0` at record `+0xb0` (`movl $0x0` at `0x5fef1aa`) |
| offset | 0 (no offset store anywhere in the value build) |
| callbacks | none (both `std::function` pairs are zero; no GOT loads in the value build) |

The pair is built by `0x5d400f0` (`std::pair<const std::string,
OptionTypeInfo>` ctor, vendor census 888/903) at `0x5fef1b4` and
inserted by `0x5d405b0` (unordered-map insert, vendor census
2348/2434) at `0x5fef1e6`; temps are destroyed by the
`OptionTypeInfo` dtor `0x5d3f950` (vendor census 131/131, 100%), and
the map dtor `0x5d3f820` is registered via `__cxa_atexit` at
`0x5fef220..0x5fef23d`. Single-entry proof: the map has exactly two
binary-wide lea sites — `0x5feeb46` (host, RegisterOptions arg) and
`0x5fef1ca` (this initializer, insert arg) — and the initializer
performs exactly one insert.

### The creator

The host's sole direct E8 caller is `0x5fe78cc`, inside
`0x5fe7870..0x5fe79ab` — the `_Function_handler _M_invoke` for a
`RegisterBuiltinFileSystems` lambda (E3 variant, vendor census
293/315 bytes). It allocates 0x50 bytes via operator new, constructs
the ChrootFileSystem with a null wrapped FileSystem (shared_ptr at
`(%rsp)`, both qwords zero) and an empty dir string (`{ptr
0x20(%rsp), size 0}` at `0x10(%rsp)`), stores the new object into the
out slot (`*rbp`), releasing any previous object via its vtable slot
1; the null control pointer skips the refcount fixup. The creator
builds defaults — the chroot dir is set after construction through
the `"chroot_dir"` option this packet pins; that is what the option
group is for. The name under which this creator is registered in the
ObjectLibrary is an open unknown.

### Lea censuses

The map `0x6505240` → `0x5feeb46` (host), `0x5fef1ca`
(initializer). The vtable base `0x64cf468` → `0x5feeadd` (host),
`0x5feec1d` (dtor `0x5feec10`, `ChrootFileSystem::~ChrootFileSystem`
per the vtable packet), `0x5feecfd` (`0x5feecf0`, cited only).

## Evidence

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

| File | Contents |
| --- | --- |
| `fn-5feeab0-chroot-filesystem-ctor.objdump.txt` | Whole-function objdump of the host ctor (vtable store first used by the RE-002 vtable packet) |
| `fn-5fef080-static-initializer.objdump.txt` | Whole-function objdump of the static initializer that fills map 0x6505240 |
| `fn-5fe7870-chroot-creator-invoke.objdump.txt` | Whole-function objdump of the sole caller, the RegisterBuiltinFileSystems creator |
| `callers.tsv` | All 37 direct call sites of 0x6099ce0 with enclosing FDE (matches #3257, #4372 and #4551 exactly) |
| `literals.tsv` | The chroot_dir map, the vtable base, and the ChrootFileSystem typeinfo string, with lea sites |
| `frames.txt` | FDE ranges for the cited functions |
| `records.json` | Semantic records only: host, helper, registration, resulting vector, map contents, creator, census, open unknowns |
| `export_excerpts.py` | Generates the three excerpts (objdump commands recorded here) |
| `census.py` | Regenerates callers.tsv / literals.tsv / frames.txt |
| `gen_records.py` | Builds records.json from the census, with cross-checks |
| `verify.py` | Runs every check below; prints ALL CHECKS PASSED |

Excerpt commands (run from the repo root):

```sh
objdump -d --start-address=0x5feeab0 --stop-address=0x5feec0d work/hl-node-115.bin
objdump -d --start-address=0x5fef080 --stop-address=0x5fef25f work/hl-node-115.bin
objdump -d --start-address=0x5fe7870 --stop-address=0x5fe79ab work/hl-node-115.bin
```

The mnemonics in the excerpts (`endbr64`, `movdqa`, `movups`, …) are
genuine instructions present in the target binary, reproduced
verbatim by objdump, not placeholders. The group name "chroot_dir"
is built from immediates (`movabs` + `mov $0x7269`), not from a
`.rodata` literal — that is why there is no `.rodata` name literal
for it, and why the spot-bytes checks cover the two immediates
directly.

Section map used (readelf -S): `.text` vaddr 0x1419300, file offset
0x1418300 (offset = vaddr − 0x1000); `.rodata` offset == vaddr.

## Verification

```sh
python3 research/work-items/RE-001-chrootfs-group-115/verify.py
python3 -m pytest tests/test_chrootfs_group_115.py -q
```

`verify.py` checks: the artifact digest against
`provenance/artifacts.json`; every MANIFEST hash; byte-for-byte
regeneration of all three excerpts; the FDE ranges against the unwind
tables; 45 cited instructions against the raw binary bytes; the
37-site RegisterOptions census reproduced by byte-scan and matched
against `callers.tsv`; the lea censuses for the map and the vtable
base; the typeinfo literal; the host's sole E8 caller; the
semantic-only records and the full 64-char digest; and the model
tests. The model `tools/chrootfs_group_115.py` reproduces the
two-element vector (base empty-name group + "chroot_dir", SSO name,
growth 1→2) and the single map entry (type 9 = string, verification
0, flags 0) and is covered by 11 tests in
`tests/test_chrootfs_group_115.py`.

## Open unknowns

- The keys and fields of the other RegisterOptions call sites
  (listed in `callers.tsv`, not individually analysed).
- The class identity of the intermediate ctor `0x60072b0` (calls the
  FileSystemWrapper ctor `0x5fe7210`, then stores vtable `0x64d05a8`).
- The name under which the creator `0x5fe7870` is registered in the
  ObjectLibrary.
- The internals of `0x5feecf0` (third lea site of the ChrootFileSystem
  vtable base); cited only.
- The entry count of the base group's map `0x65051e0` (pinned as a
  registration by #4398; its contents are not re-derived here).
- Which code reads the group name at runtime (the map serializer
  `0x6097630` and apply loop `0x609c8c0` read only `element+0x20` /
  `+0x28`, per #4372).

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify test catalogue-check` could not be run here; the packet's own
`verify.py` and the model tests were run instead. The binary used is
the materialized `work/hl-node-115.bin` whose SHA-256 matches
`provenance/artifacts.json`.
