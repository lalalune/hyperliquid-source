# RE-002: node #115 FileChecksumGenCrc32cFactory deleting destructor

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32cFactory::~FileChecksumGenCrc32cFactory()`
deleting destructor (D0Ev) at `0x61cd400` (FDE `0x61cd400..0x61cd48b`),
vtable slot 1 of `FileChecksumGenCrc32cFactory` (address point
`0x64d79b0`; the vtable itself was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-factory-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE and the body hash are
  observations. There is no vendor-census attribution for this address,
  stated as an unknown in `records.json`; the body hash is recorded
  from the binary and matches the `target_body_sha256` the merged
  factory-vtable packet records for slot 1. The C++ symbol attribution
  rests on that vtable slot and on the sibling complete destructor
  below.
- Scope included: the destructor body, the vector member it tears
  down, and the sized object delete. Excluded: callers of the
  destructor, the complete destructor at `0x61cd370` (sibling, compared
  but not modelled here), what the trailing `0x10` bytes of each
  vector element hold, and any claim about when the node destroys
  factories.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61cd400 --stop-address=0x61cd48b work/hl-node-115.bin
(cd research/work-items/re-002-node115-file-checksum-factory-dtor-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`~FileChecksumGenCrc32cFactory(this: *mut FileChecksumGenCrc32cFactory)`.
The deleting destructor: it resets the vptr, destroys the vector
member at `+0x8`, frees the vector buffer, and then frees the `0x20`
-byte factory object itself with a sized `operator delete`.

### Destructor body (observed)

The whole function is 139 bytes (`file_checksum_factory_dtor115.hex`,
`file_checksum_factory_dtor115.objdump.txt`):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61cd400` | `f3 0f 1e fa` | `endbr64` |
| `0x61cd404` | `48 8d 05 15 60 30 00` | `lea 0x306015(%rip),%rax` — resolves to `0x64d3420` |
| `0x61cd40b` | `41 54` | `push %r12` |
| `0x61cd40d` | `49 89 fc` | `mov %rdi,%r12` — save `this` |
| `0x61cd410` | `55` | `push %rbp` |
| `0x61cd411` | `53` | `push %rbx` |
| `0x61cd412` | `48 8b 6f 10` | `mov 0x10(%rdi),%rbp` — `rbp` = vector finish |
| `0x61cd416` | `48 83 c0 10` | `add $0x10,%rax` — `rax` = `0x64d3430` |
| `0x61cd41a` | `48 8b 5f 08` | `mov 0x8(%rdi),%rbx` — `rbx` = vector start |
| `0x61cd41e` | `48 89 07` | `mov %rax,(%rdi)` — vptr = `0x64d3430` |
| `0x61cd421` | `48 39 dd` | `cmp %rbx,%rbp` — finish against start |
| `0x61cd424` | `74 31` | `je 0x61cd457` — empty vector: skip the element loop |
| `0x61cd426` | `66 2e 0f 1f 84 00 00 00 00 00` | `cs nopw` (alignment padding) |
| `0x61cd430` | `48 8b 3b` | `mov (%rbx),%rdi` — element string `_M_p` |
| `0x61cd433` | `48 8d 43 10` | `lea 0x10(%rbx),%rax` — `&_M_buf` |
| `0x61cd437` | `48 39 c7` | `cmp %rax,%rdi` |
| `0x61cd43a` | `74 44` | `je 0x61cd480` — SSO string: skip the delete |
| `0x61cd43c` | `48 8b 43 10` | `mov 0x10(%rbx),%rax` — `_M_capacity` |
| `0x61cd440` | `48 83 c3 30` | `add $0x30,%rbx` — next element |
| `0x61cd444` | `48 8d 70 01` | `lea 0x1(%rax),%rsi` — `capacity + 1` |
| `0x61cd448` | `e8 33 39 22 00` | `call _ZdlPvm@plt` — `operator delete(ptr, capacity + 1)` |
| `0x61cd44d` | `48 39 eb` | `cmp %rbp,%rbx` |
| `0x61cd450` | `75 de` | `jne 0x61cd430` |
| `0x61cd452` | `49 8b 5c 24 08` | `mov 0x8(%r12),%rbx` — vector start again |
| `0x61cd457` | `48 85 db` | `test %rbx,%rbx` |
| `0x61cd45a` | `74 10` | `je 0x61cd46c` — no buffer: skip the buffer free |
| `0x61cd45c` | `49 8b 74 24 18` | `mov 0x18(%r12),%rsi` — end of storage |
| `0x61cd461` | `48 89 df` | `mov %rbx,%rdi` — buffer start |
| `0x61cd464` | `48 29 de` | `sub %rbx,%rsi` — byte size |
| `0x61cd467` | `e8 14 39 22 00` | `call _ZdlPvm@plt` — `operator delete(buffer, size)` |
| `0x61cd46c` | `5b` | `pop %rbx` |
| `0x61cd46d` | `4c 89 e7` | `mov %r12,%rdi` — `this` |
| `0x61cd470` | `5d` | `pop %rbp` |
| `0x61cd471` | `be 20 00 00 00` | `mov $0x20,%esi` — object size `0x20` |
| `0x61cd476` | `41 5c` | `pop %r12` |
| `0x61cd478` | `e9 03 39 22 00` | `jmp _ZdlPvm@plt` — `operator delete(this, 0x20)` |
| `0x61cd47d` | `0f 1f 00` | `nopl` (padding) |
| `0x61cd480` | `48 83 c3 30` | `add $0x30,%rbx` — SSO path: next element |
| `0x61cd484` | `48 39 dd` | `cmp %rbx,%rbp` |
| `0x61cd487` | `75 a7` | `jne 0x61cd430` |
| `0x61cd489` | `eb c7` | `jmp 0x61cd452` |

The `lea` target `0x64d3420` plus `0x10` is the base-class vtable
address point `0x64d3430`, which the merged packets
`research/work-items/RE-001-delegate-vtable-115/` and
`research/work-items/RE-001-skiplist-rep-factory-115/` attribute to
the `rocksdb::Configurable` vtable. The vector member is begin
`+0x8`, finish `+0x10`, end of storage `+0x18`; each element is
`0x30` bytes and starts with a `std::string` (ptr `+0x0`, length
`+0x8`, SSO buffer / capacity `+0x10`), destroyed with the same
`_M_dispose` shape as the generator destructor at `0x61cd490`. The
buffer free uses the full capacity size (`end_of_storage - start`),
and the object itself is freed with the sized delete `0x20` — the
same size the singleton getter at `0x61cd600` (PR #5423) allocates
the factory with (`operator new(0x20)`).

### Corroboration (observed)

- The complete destructor at `0x61cd370` (vtable slot 0, FDE
  `0x61cd370..0x61cd3f5`, body SHA-256
  `2faae890cd037e81473b17f5c104872ddccd276d8236463ad1d4c1257c99d3da`)
  implements the same teardown. A direct byte comparison of the two
  bodies shows they are identical from offset 0 to 102 except the
  four rip-relative displacement bytes at offsets 7, 59, 73 and 91;
  the endings differ from offset 103: D1 frees the vector buffer
  with a tail call and returns, while D0 calls the buffer free and
  then tail-calls the sized object delete. D1 is a sibling, not
  modelled here.
- The singleton getter at `0x61cd600` (PR #5423) allocates the
  factory with `operator new(0x20)` and registers this destructor
  (`0x61cd400`) with `__cxa_atexit` — the delete size `0x20` here
  matches that allocation size.

## Check values

- Body SHA-256 `a3eed2dad9689a25bd3a12e4b2194adf74866726c52c19e00ca2c1049374d2ca`
  over the 139 bytes `f30f1efa488d051560300041544989fc5553488b6f104883c010488b5f084889074839dd7431662e0f1f840000000000488b3b488d43104839c77444488b43104883c330488d7001e8333922004839eb75de498b5c24084885db7410498b7424184889df4829dee8143922005b4c89e75dbe20000000415ce9033922000f1f004883c3304839dd75a7ebc7`.
- vptr installed: `0x64d3430` (the `rocksdb::Configurable` vtable address point).
- Empty vector (`begin == finish`, `begin == 0`): no element loop, no buffer free, `operator delete(this, 0x20)`.
- Non-empty vector: each element's string disposed (`operator delete(ptr, capacity + 1)` unless SSO), buffer freed with size `end_of_storage - begin`, then `operator delete(this, 0x20)`.
