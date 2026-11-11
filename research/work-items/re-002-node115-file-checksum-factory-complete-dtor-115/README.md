# RE-002: node #115 FileChecksumGenCrc32cFactory complete destructor

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32cFactory::~FileChecksumGenCrc32cFactory()`
complete destructor (D1Ev) at `0x61cd370` (FDE `0x61cd370..0x61cd3f5`),
vtable slot 0 of `FileChecksumGenCrc32cFactory` (address point
`0x64d79b0`; the vtable itself was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-factory-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE and the body hash are
  observations. There is no vendor-census attribution for this address,
  stated as an unknown in `records.json`; the body hash is recorded
  from the binary and matches the `target_body_sha256` the merged
  factory-vtable packet records for slot 0. The C++ symbol attribution
  rests on that vtable slot and on the sibling deleting destructor
  below.
- Scope included: the destructor body, the vector member it tears
  down, and the tail-called buffer free. Excluded: callers of the
  destructor, the deleting destructor at `0x61cd400` (sibling, compared
  but not modelled here), what the trailing `0x10` bytes of each
  vector element hold, and any claim about when the node destroys
  factories.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61cd370 --stop-address=0x61cd3f5 work/hl-node-115.bin
(cd research/work-items/re-002-node115-file-checksum-factory-complete-dtor-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`~FileChecksumGenCrc32cFactory(this: *mut FileChecksumGenCrc32cFactory)`.
The complete destructor: it resets the vptr, destroys the vector
member at `+0x8`, frees the vector buffer, and returns — it does not
free the `0x20`-byte factory object itself; that is the deleting
destructor's job.

### Destructor body (observed)

The whole function is 133 bytes (`file_checksum_factory_complete_dtor115.hex`,
`file_checksum_factory_complete_dtor115.objdump.txt`):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61cd370` | `f3 0f 1e fa` | `endbr64` |
| `0x61cd374` | `48 8d 05 a5 60 30 00` | `lea 0x3060a5(%rip),%rax — resolves to 0x64d3420` |
| `0x61cd37b` | `41 54` | `push %r12` |
| `0x61cd37d` | `49 89 fc` | `mov %rdi,%r12 — save `this`` |
| `0x61cd380` | `55` | `push %rbp` |
| `0x61cd381` | `53` | `push %rbx` |
| `0x61cd382` | `48 8b 6f 10` | `mov 0x10(%rdi),%rbp — `rbp` = vector finish` |
| `0x61cd386` | `48 83 c0 10` | `add $0x10,%rax — `rax` = `0x64d3430`` |
| `0x61cd38a` | `48 8b 5f 08` | `mov 0x8(%rdi),%rbx — `rbx` = vector start` |
| `0x61cd38e` | `48 89 07` | `mov %rax,(%rdi) — vptr = `0x64d3430`` |
| `0x61cd391` | `48 39 dd` | `cmp %rbx,%rbp — finish against start` |
| `0x61cd394` | `74 31` | `je 0x61cd3c7 — empty vector: skip the element loop` |
| `0x61cd396` | `66 2e 0f 1f 84 00 00 00 00 00` | `cs nopw (alignment padding)` |
| `0x61cd3a0` | `48 8b 3b` | `mov (%rbx),%rdi — element string `_M_p`` |
| `0x61cd3a3` | `48 8d 43 10` | `lea 0x10(%rbx),%rax — `&_M_buf`` |
| `0x61cd3a7` | `48 39 c7` | `cmp %rax,%rdi` |
| `0x61cd3aa` | `74 34` | `je 0x61cd3e0 — SSO string: skip the delete` |
| `0x61cd3ac` | `48 8b 43 10` | `mov 0x10(%rbx),%rax — `_M_capacity`` |
| `0x61cd3b0` | `48 83 c3 30` | `add $0x30,%rbx — next element` |
| `0x61cd3b4` | `48 8d 70 01` | `lea 0x1(%rax),%rsi — `capacity + 1`` |
| `0x61cd3b8` | `e8 c3 39 22 00` | `call _ZdlPvm@plt — `operator delete(ptr, capacity + 1)`` |
| `0x61cd3bd` | `48 39 eb` | `cmp %rbp,%rbx` |
| `0x61cd3c0` | `75 de` | `jne 0x61cd3a0` |
| `0x61cd3c2` | `49 8b 5c 24 08` | `mov 0x8(%r12),%rbx — vector start again` |
| `0x61cd3c7` | `48 85 db` | `test %rbx,%rbx` |
| `0x61cd3ca` | `74 24` | `je 0x61cd3f0 — no buffer: skip the buffer free` |
| `0x61cd3cc` | `49 8b 74 24 18` | `mov 0x18(%r12),%rsi — end of storage` |
| `0x61cd3d1` | `48 89 df` | `mov %rbx,%rdi — buffer start` |
| `0x61cd3d4` | `48 29 de` | `sub %rbx,%rsi — byte size` |
| `0x61cd3d7` | `5b` | `pop %rbx` |
| `0x61cd3d8` | `5d` | `pop %rbp` |
| `0x61cd3d9` | `41 5c` | `pop %r12` |
| `0x61cd3db` | `e9 a0 39 22 00` | `jmp _ZdlPvm@plt — tail-call `operator delete(buffer, size)`; returns straight to the caller` |
| `0x61cd3e0` | `48 83 c3 30` | `add $0x30,%rbx — SSO path: next element` |
| `0x61cd3e4` | `48 39 dd` | `cmp %rbx,%rbp` |
| `0x61cd3e7` | `75 b7` | `jne 0x61cd3a0` |
| `0x61cd3e9` | `eb d7` | `jmp 0x61cd3c2` |
| `0x61cd3eb` | `0f 1f 44 00 00` | `nopl (padding)` |
| `0x61cd3f0` | `5b` | `pop %rbx` |
| `0x61cd3f1` | `5d` | `pop %rbp` |
| `0x61cd3f2` | `41 5c` | `pop %r12` |
| `0x61cd3f4` | `c3` | `ret` |

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
and it is a tail call, so the delete returns straight to this
function's caller. When the vector is empty and the buffer pointer
is null, the function pops the saved registers and returns.

### Corroboration (observed)

- The deleting destructor at `0x61cd400` (vtable slot 1, FDE
  `0x61cd400..0x61cd48b`, body SHA-256
  `a3eed2dad9689a25bd3a12e4b2194adf74866726c52c19e00ca2c1049374d2ca`,
  PR #5434) implements the same teardown and then frees the object
  with a sized `operator delete(this, 0x20)`. A direct byte
  comparison of the two bodies shows they are identical from offset
  0 to 102 except the four rip-relative displacement bytes at
  offsets 7, 59, 73 and 91; the endings differ from offset 103: D1
  frees the vector buffer with a tail call and returns, while D0
  calls the buffer free and then tail-calls the sized object delete.
  D0 is a sibling, not modelled here.
- The singleton getter at `0x61cd600` (PR #5423) allocates the
  factory with `operator new(0x20)` and registers the deleting
  destructor (`0x61cd400`) with `__cxa_atexit` — this complete
  destructor frees no object memory, consistent with its role.

## Check values

- Body SHA-256 `2faae890cd037e81473b17f5c104872ddccd276d8236463ad1d4c1257c99d3da`
  over the 133 bytes `f30f1efa488d05a560300041544989fc5553488b6f104883c010488b5f084889074839dd7431662e0f1f840000000000488b3b488d43104839c77434488b43104883c330488d7001e8c33922004839eb75de498b5c24084885db7424498b7424184889df4829de5b5d415ce9a03922004883c3304839dd75b7ebd70f1f4400005b5d415cc3`.
- vptr installed: `0x64d3430` (the `rocksdb::Configurable` vtable address point).
- Empty vector (`begin == finish`, `begin == 0`): no element loop, no buffer free, plain `ret`.
- Non-empty vector: each element's string disposed (`operator delete(ptr, capacity + 1)` unless SSO), buffer freed with size `end_of_storage - begin` via a tail call, object itself not freed.
