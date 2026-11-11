# RE-002: node #115 FileChecksumGenCrc32c destructor

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32c::~FileChecksumGenCrc32c()` complete-object
destructor (D1Ev) at `0x61cd490` (FDE `0x61cd490..0x61cd4c1`), vtable slot 0
of `FileChecksumGenCrc32c` (address point `0x64d7970`; the vtable itself
was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE and the census body hash are
  observations. The C++ symbol attribution is the vendor-census record
  `node115-vendor-61cd490` (librocksdb-sys 0.11.0+8.1.1:
  `_ZN7rocksdb21FileChecksumGenCrc32cD1Ev`), whose
  `target_body_sha256` matches the bytes hashed from the node binary.
- Scope included: the destructor body and the `checksum_` string it
  destroys. Excluded: callers of the destructor, the deleting
  destructor at `0x61cd4d0` (sibling, not modelled here), and any claim
  about when the node destroys generators.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61cd490 --stop-address=0x61cd4c1 work/hl-node-115.bin
(cd research/work-items/re-002-node115-file-checksum-gen-dtor-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`~FileChecksumGenCrc32c(this: *mut FileChecksumGenCrc32c)`. The
complete-object destructor: it resets the vptr, destroys the
`checksum_` string member, and returns. It does not free the object
itself — that is the deleting destructor's job (sibling at `0x61cd4d0`).

### Destructor body (observed)

The whole function is 49 bytes (`file_checksum_gen_dtor115.hex`,
`file_checksum_gen_dtor115.objdump.txt`):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61cd490` | `f3 0f 1e fa` | `endbr64` |
| `0x61cd494` | `48 8d 05 c5 a4 30 00` | `lea 0x30a4c5(%rip),%rax` — resolves to `0x64d7960` |
| `0x61cd49b` | `48 8d 57 20` | `lea 0x20(%rdi),%rdx` — `rdx` = `&checksum_._M_buf` |
| `0x61cd49f` | `48 83 c0 10` | `add $0x10,%rax` — `rax` = `0x64d7970` |
| `0x61cd4a3` | `48 89 07` | `mov %rax,(%rdi)` — vptr = `0x64d7970` |
| `0x61cd4a6` | `48 8b 47 10` | `mov 0x10(%rdi),%rax` — `rax` = `checksum_._M_p` |
| `0x61cd4aa` | `48 39 d0` | `cmp %rdx,%rax` — `_M_p` against `&_M_buf` |
| `0x61cd4ad` | `74 11` | `je 0x61cd4c0` — SSO string: nothing to free, `ret` |
| `0x61cd4af` | `48 8b 77 20` | `mov 0x20(%rdi),%rsi` — `rsi` = `checksum_._M_capacity` |
| `0x61cd4b3` | `48 89 c7` | `mov %rax,%rdi` — heap pointer |
| `0x61cd4b6` | `48 83 c6 01` | `add $0x1,%rsi` — `capacity + 1` |
| `0x61cd4ba` | `e9 c1 38 22 00` | `jmp _ZdlPvm@plt` — `operator delete(ptr, capacity + 1)` |
| `0x61cd4bf` | `90` | `nop` (padding) |
| `0x61cd4c0` | `c3` | `ret` |

The `lea` target `0x64d7960` plus `0x10` is the `FileChecksumGenCrc32c`
vtable address point `0x64d7970` — the same address point the merged
vtable packet records for slot 0. The string at `+0x10` is `checksum_`
(ptr `+0x10`, length `+0x18`, SSO buffer / capacity `+0x20`); the
dispose sequence is the standard `std::string::_M_dispose` shape:
free the heap buffer only when the data pointer differs from the
in-object SSO buffer, with the sized-delete size `capacity + 1`.

### Corroboration (observed)

- The factory `CreateFileChecksumGenerator` at `0x61cd2e0` (PR #5419)
  initialises a fresh generator with `checksum_` empty (length 0, SSO),
  so a freshly created generator's destructor takes the `ret` path.
- `Finalize` at `0x61cd1c0` (PR #5416) appends to `checksum_`; once the
  string grows past 15 bytes it leaves SSO, so a used generator's
  destructor takes the `operator delete` path.
- The deleting destructor at `0x61cd4d0` (vtable slot 1, FDE
  `0x61cd4d0..0x61cd50e`) repeats this dispose sequence and then frees
  the `0x30`-byte object with `operator delete(this, 0x30)` — sibling,
  not modelled here.

## Check values

- Body SHA-256 `9437dc313e16bef7dc211d2ced3ef033f7715da95b6136b4ab3a797966890f99`
  over the 49 bytes `f30f1efa488d05c5a43000488d57204883c010488907488b47104839d07411488b77204889c74883c601e9c138220090c3`.
- vptr installed: `0x64d7970` (the `FileChecksumGenCrc32c` vtable address point).
- SSO checksum (length <= 15): no free, `ret`.
- Heap checksum (length >= 16): `operator delete(_M_p, _M_capacity + 1)`.
