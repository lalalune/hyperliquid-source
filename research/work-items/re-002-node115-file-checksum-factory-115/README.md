# RE-002: node #115 FileChecksumGenCrc32cFactory CreateFileChecksumGenerator

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32cFactory::CreateFileChecksumGenerator`
method at `0x61cd2e0` (FDE `0x61cd2e0..0x61cd36f`), as attributed by
the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`; also
recorded in `research/byte-windows.json`). It is vtable slot 19 of
`FileChecksumGenCrc32cFactory` (address point `0x64d79b0`; the factory
vtable itself was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-factory-vtable/`,
which records this function as a slot only — this packet reconstructs
its behavior).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the name gate, the
  allocation call and the initialisation stores are observations. The
  C++ symbol attribution comes from the vendor census. The object-field
  names (`crc_`, `checksum_`) and the context-field name (requested
  checksum name) are inferences from the disassembly. The empty-name
  interpretation is an open unknown (see below).
- Scope included: the CreateFileChecksumGenerator body, the name gate,
  the allocation and the initialised object layout. Excluded: callers
  of the factory, and the `GetFileChecksumGenCrc32cFactory` singleton
  getter at `0x61cd600` (noted next candidate).

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/file_checksum_factory115.py --verify
python3 tools/file_checksum_factory115.py --out research/work-items/re-002-node115-file-checksum-factory-115
python3 -m unittest tests.test_file_checksum_factory115
(cd research/work-items/re-002-node115-file-checksum-factory-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`create(out: *mut FileChecksumGenCrc32c*, context: *const FileChecksumGenContext) -> *mut FileChecksumGenCrc32c`,
observed register use: `rdi` = hidden out-pointer, `rdx` = context,
returns `rdi`. The requested name is the std::string at context+0x20
(data pointer +0x20, length +0x28, SSO buffer +0x30). The function
stores the new generator pointer, or null, at `[rdi]`.

### Name gate (observed)

| Requested name | Result |
| --- | --- |
| empty (length 0) | creates — the `je` at `0x61cd2ef` jumps straight to the allocation, skipping the byte compare |
| exactly `FileChecksumCrc32c` (length 0x12) | creates |
| any other length or any differing byte | stores null and returns |

The 18-byte compare is two 8-byte xor/or steps against the movabs
immediates `FileChec` (`0x63656843656c6946`) and `ksumCrc3`
(`0x336372436d75736b`), then a 2-byte compare against `2c`
(`cmpw $0x6332` at `0x61cd32c`).

### Creation (observed)

| Window | Range | Content |
| --- | --- | --- |
| gate_load | `0x61cd2e0..0x61cd2f1` | `endbr64`, `push rbx`, load name length from `0x28(%rdx)`, save `rdi`, `test`, `je` to allocation |
| gate_length | `0x61cd2f1..0x61cd2f7` | `cmp $0x12,%rax`; `je` to the byte compare |
| null_return | `0x61cd2f7..0x61cd308` | store null at `[rdi]`, `pop rbx`, `ret` (plus padding) |
| name_compare | `0x61cd308..0x61cd334` | the two movabs immediates, xor/or, `jne` to null return, `cmpw $0x6332`, `jne` to null return |
| create_alloc | `0x61cd334..0x61cd33e` | `mov $0x30,%edi`; `call operator new` (PLT `0x63f0dd0`) |
| create_init | `0x61cd33e..0x61cd36f` | `lea` vtable base `0x64d7960`, `add $0x10` → address point `0x64d7970`; store vptr, zero length at +0x18, NUL at +0x20, SSO pointer at +0x10, zero crc at +0x8; store the pointer at `[rdi]`; return `rdi` |

### Object layout (observed)

| Offset | Field | Evidence |
| --- | --- | --- |
| `+0x0` | vptr | `0x64d7970`, the FileChecksumGenCrc32c vtable address point the Finalize packet pins |
| `+0x8` | `crc_` (u32) | zeroed here; Update reads it as the extend seed and stores the result back |
| `+0x10` | `checksum_` (std::string) | pointer set to object+0x20 (SSO), length 0 at +0x18, NUL first byte at +0x20 |

The object is `0x30` bytes. The function has no stack canary and
makes no other call.

## Unknowns

- Empty-name acceptance: observed — an empty requested name creates a
  generator. Whether that is the caller treating an empty name as "use
  the default" or the factory's own rule is not determined from this
  packet.
- Callers of `CreateFileChecksumGenerator`: no caller census was run
  for this packet.
- `GetFileChecksumGenCrc32cFactory` at `0x61cd600`: not modelled here;
  noted next candidate.
