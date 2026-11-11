# RE-002: node #115 FileChecksumGenCrc32c deleting destructor

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32c::~FileChecksumGenCrc32c()`
deleting destructor (D0Ev) at `0x61cd4d0` (FDE `0x61cd4d0..0x61cd50e`),
vtable slot 1 of `FileChecksumGenCrc32c` (address point `0x64d7970`;
the vtable itself was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE and the body hash are
  observations. The C++ symbol attribution rests on vendor-census
  record `node115-vendor-61cd4d0` (librocksdb-sys 0.11.0+8.1.1:
  `_ZN7rocksdb21FileChecksumGenCrc32cD0Ev`), whose
  `target_body_sha256` matches the bytes hashed from the node binary,
  and on the merged vtable packet, which records this address at slot
  1.
- Scope included: the destructor body, the `checksum_` string it
  destroys, and the sized object delete. Excluded: callers of the
  destructor, the complete destructor at `0x61cd490` (sibling,
  compared but not modelled here), and any claim about when the node
  destroys generators.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61cd4d0 --stop-address=0x61cd50e work/hl-node-115.bin
(cd research/work-items/re-002-node115-file-checksum-gen-deleting-dtor-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`~FileChecksumGenCrc32c(this: *mut FileChecksumGenCrc32c)`.
The deleting destructor: it resets the vptr, destroys the `checksum_`
string at `+0x10`, and then frees the `0x30`-byte generator object
itself with a sized `operator delete`.

### Destructor body (observed)

The whole function is 62 bytes (`file_checksum_gen_deleting_dtor115.hex`,
`file_checksum_gen_deleting_dtor115.objdump.txt`):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61cd4d0` | `f3 0f 1e fa` | `endbr64` |
| `0x61cd4d4` | `48 8d 05 85 a4 30 00` | `lea 0x30a485(%rip),%rax — resolves to 0x64d7960` |
| `0x61cd4db` | `53` | `push %rbx` |
| `0x61cd4dc` | `48 89 fb` | `mov %rdi,%rbx — save `this`` |
| `0x61cd4df` | `48 83 c0 10` | `add $0x10,%rax — `rax` = `0x64d7970`` |
| `0x61cd4e3` | `48 89 07` | `mov %rax,(%rdi) — vptr = `0x64d7970`` |
| `0x61cd4e6` | `48 8b 7f 10` | `mov 0x10(%rdi),%rdi — `checksum_._M_p`` |
| `0x61cd4ea` | `48 8d 43 20` | `lea 0x20(%rbx),%rax — `&_M_buf` (`this+0x20`)` |
| `0x61cd4ee` | `48 39 c7` | `cmp %rax,%rdi` |
| `0x61cd4f1` | `74 0d` | `je 0x61cd500 — SSO string: skip the delete` |
| `0x61cd4f3` | `48 8b 43 20` | `mov 0x20(%rbx),%rax — `_M_capacity`` |
| `0x61cd4f7` | `48 8d 70 01` | `lea 0x1(%rax),%rsi — `capacity + 1`` |
| `0x61cd4fb` | `e8 80 38 22 00` | `call _ZdlPvm@plt — `operator delete(ptr, capacity + 1)`` |
| `0x61cd500` | `48 89 df` | `mov %rbx,%rdi — `this`` |
| `0x61cd503` | `be 30 00 00 00` | `mov $0x30,%esi — object size `0x30`` |
| `0x61cd508` | `5b` | `pop %rbx` |
| `0x61cd509` | `e9 72 38 22 00` | `jmp _ZdlPvm@plt — tail-call `operator delete(this, 0x30)`` |

The `lea` target `0x64d7960` plus `0x10` is the `FileChecksumGenCrc32c`
vtable address point `0x64d7970`, which the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`
reconstructs. The `checksum_` string is pointer `+0x10`, length
`+0x18`, SSO buffer / capacity `+0x20` (per the Finalize packet at
`0x61cd1c0`); it is destroyed with the `_M_dispose` shape — the heap
buffer is freed with `operator delete(ptr, capacity + 1)` only when
`_M_p` differs from `&_M_buf`, and an SSO string costs no call. The
object itself is freed with the sized delete `0x30` — the same size
the factory at `0x61cd2e0` (PR #5419) allocates a generator with
(`operator new(0x30)`).

### Corroboration (observed)

- The complete destructor at `0x61cd490` (vtable slot 0, FDE
  `0x61cd490..0x61cd4c1`, body SHA-256 `9437dc313e16…`, PR #5433)
  implements the same string dispose and then returns without
  freeing the object. This deleting destructor shares the identical
  `_M_dispose` prologue and then tail-calls the sized object delete.
  D1 is a sibling, not modelled here.
- The factory at `0x61cd2e0` (PR #5419) creates a generator with
  `operator new(0x30)` — the delete size `0x30` here matches that
  allocation size.

## Check values

- Body SHA-256 `854bf0cf1ab2f505ed2d32e23e1ccd3f4a46d94e60327ae16f1aef9729bb1b95`
  over the 62 bytes `f30f1efa488d0585a43000534889fb4883c010488907488b7f10488d43204839c7740d488b4320488d7001e8803822004889dfbe300000005be972382200`.
- vptr installed: `0x64d7970` (the `FileChecksumGenCrc32c` vtable address point).
- SSO `checksum_` (`_M_p == &_M_buf`): no string free, `operator delete(this, 0x30)`.
- Heap `checksum_`: `operator delete(_M_p, _M_capacity + 1)`, then `operator delete(this, 0x30)`.
