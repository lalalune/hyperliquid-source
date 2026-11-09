# RE-002: node #115 FileChecksumGenCrc32c GetChecksum

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32c::GetChecksum` method at `0x61cd510` (FDE
`0x61cd510..0x61cd5c4`), as attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, id
`node115-vendor-61cd510`, whose `target_body_sha256` matches the body
hash in `result.json`; also recorded in `research/byte-windows.json`).
It is vtable slot 4 of `FileChecksumGenCrc32c` (address point
`0x64d7970`; the vtable itself was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the copy branches,
  the `_M_create`/`memcpy` calls and the return-pointer ABI are
  observations. The C++ symbol attribution comes from the vendor census
  plus the vtable slot. The object-field names (`crc_`, `checksum_`)
  are inferences from the disassembly. The identical-body twin is an
  explicit unknown, stated below.
- Scope included: the GetChecksum body, the object layout it implies,
  the sibling methods that produce the string it returns (Update,
  Finalize, the factory), and the 2400-case model cross-check.
  Excluded: callers of GetChecksum, and any claim about which files
  the node checksums with this generator.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/file_checksum_get_checksum115.py --verify
python3 tools/file_checksum_get_checksum115.py --out research/work-items/re-002-node115-file-checksum-get-checksum-115
python3 -m unittest tests.test_file_checksum_get_checksum115
(cd research/work-items/re-002-node115-file-checksum-get-checksum-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`get_checksum(this: *const FileChecksumGenCrc32c) -> std::string`
(by value). Observed register use: `rdi` = hidden return-storage
pointer, `rsi` = this; `rax` returns the storage pointer. It copies
the `std::string` member at `this+0x10` (`checksum_`) into the
return storage and returns it.

### Why the return is by value (observed)

- `mov %rdi,(%rbx)` stores `rdi+0x10` into the storage object. If
  `rdi` were `this`, that store would overwrite the vptr at `+0x0`.
- The length and pointer are read from `[rsi+0x18]` and `[rsi+0x10]`,
  i.e. the string member at `this+0x10` (length at `+0x18`, pointer
  at `+0x10`), not from a caller-supplied out-pointer.
- The function returns the storage pointer in `rax`
  (`mov %rbx,%rax` at `0x61cd572`).

The out-pointer `void GetChecksum(std::string*)` form is therefore
ruled out by the bytes: it would read the caller's length and
overwrite the vptr. This matches the census label, which cites a
by-value getter (`Transaction::GetName`) as the identical-body twin.

### Object layout (observed)

| Offset | Field | Evidence |
| --- | --- | --- |
| `+0x0` | vptr | D1/D0 store the generator vtable address point `0x64d7970` here |
| `+0x8` | `crc_` (u32) | Update reads it as the extend seed and stores the result back; the factory zeroes it |
| `+0x10` | `checksum_` (std::string) | GetChecksum copies it; length at `+0x18`, SSO buffer/capacity at `+0x20` |

The object is `0x30` bytes (`operator new(0x30)` in the factory at
`0x61cd2e0`): vptr + crc + padding + the 32-byte std::string. The
factory initialises the string with pointer `object+0x20` (SSO),
length 0 and a NUL first byte, and zeroes `crc_`.

### GetChecksum body (observed)

| Window | Range | Content |
| --- | --- | --- |
| prologue_canary | `0x61cd510..0x61cd537` | `endbr64`, pushes, `rdi+0x10` setup, stack-canary load/store |
| copy_setup | `0x61cd537..0x61cd548` | store SSO pointer, load source ptr/length, `cmp $0xf,%rbp` |
| len_one_path | `0x61cd548..0x61cd57a` | length 1: copy one byte, store length, NUL, canary check, `ret` |
| align_nop | `0x61cd57a..0x61cd580` | 6-byte alignment nop |
| len_zero_path | `0x61cd580..0x61cd590` | length 0: skip the copy, store length 0 and NUL |
| heap_alloc_path | `0x61cd590..0x61cd5ab` | length > 15: `_M_create` (PLT `0x63f0e10`), store heap pointer/capacity |
| memcpy_epilogue | `0x61cd5ab..0x61cd5bf` | `memcpy` (PLT `0x63f0a60`), restore length, store it, NUL, jump to epilogue |
| stack_fail_path | `0x61cd5bf..0x61cd5c4` | `call __stack_chk_fail` (PLT `0x63f0d70`) |

The SSO threshold is `cmp $0xf,%rbp` at `0x61cd542`: lengths 0..15
stay in the SSO buffer at `out+0x10`; lengths above 15 call
`_M_create` with the capacity slot on the stack and old capacity 0,
then `memcpy` the bytes. Every path stores the length at `out+0x8`
and a NUL terminator after the last byte.

### Sibling slots (inferences, not modelled here)

- Slot 2, Update (`0x61cd1a0`): `crc_` is the raw CRC32C extend
  accumulator (PR #5387).
- Slot 3, Finalize (`0x61cd1c0`, PR #5416): appends the big-endian
  form of the accumulated CRC32C word to the string at `+0x10`.
- Slot 5, Name (`0x61cd020`, FDE `0x61cd020..0x61cd02c`): returns the
  pointer at `0x43336e`, the string `FileChecksumCrc32c`. The factory
  at `0x61cd2e0` creates a generator exactly when the context name is
  that same 18-byte string, which corroborates the name.

### Identical-body twin (unknown, recorded honestly)

The vendor census records this address as one of 2 identical bodies
(e.g. `Transaction::GetName`). The name attribution for this instance
rests on vtable slot 4 of `FileChecksumGenCrc32c` and on the copy of
the string at `+0x10`, not on a unique body. Which other call sites
share this exact body was not traced.

## Check values

- `copy(b"") = b""` (length 0, empty string).
- `copy(b"a") = b"a"` (length 1, single-byte path).
- `copy(bytes(range(15))) = bytes(range(15))` (longest SSO copy).
- `copy(bytes(range(16))) = bytes(range(16))` (shortest heap copy).
- `copy(b"\xe3\x06\x92\x83") = b"\xe3\x06\x92\x83"` (the Finalize
  output round-trips unchanged).
- `copy(b"FileChecksumCrc32c") = b"FileChecksumCrc32c"` (the 18-byte
  generator name, heap path).
- End to end: `extend(0, b"123456789") = 0xe3069283`, Finalize appends
  `b"\xe3\x06\x92\x83"`, and GetChecksum returns those same 4 bytes.

## Cases

2400 deterministic cases (structured source contents including the
empty string, the 15/16-byte SSO boundary, the Finalize output and
the 18-byte generator name; boundary lengths 0..1024; then random
sources). Model vs independent reference (explicit length-branch
transliteration vs plain byte copy), 0 mismatches. The full run is
summarised in `result.json` by its aggregate digest; the first 64
rows are in `cases.tsv`.
