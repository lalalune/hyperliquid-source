# RE-002: node #115 FileChecksumGenCrc32c Finalize

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32c::Finalize` method at `0x61cd1c0` (FDE
`0x61cd1c0..0x61cd23f`), as attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`; also
recorded in `research/byte-windows.json`). It is vtable slot 3 of
`FileChecksumGenCrc32c` (address point `0x64d7970`; the vtable itself
was reconstructed in the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the `bswap`, the
  length guard and the append call are observations. The C++ symbol
  attribution comes from the vendor census. The object-field names
  (`crc_`, `checksum_`) are inferences from the disassembly. The
  sibling-method identities (Update, GetChecksum, Name) are inferences
  from their vtable slots and bodies, stated as such.
- Scope included: the Finalize body, the object layout it implies, the
  Update method that produces the accumulated word, and the 2400-case
  model cross-check. Excluded: callers of Finalize, the Reset question
  (see unknowns), and any claim about which files the node checksums
  with this generator.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/file_checksum_finalize115.py --verify
python3 tools/file_checksum_finalize115.py --out research/work-items/re-002-node115-file-checksum-finalize-115
python3 -m unittest tests.test_file_checksum_finalize115
(cd research/work-items/re-002-node115-file-checksum-finalize-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`finalize(this: *mut FileChecksumGenCrc32c) -> ()`, observed register
use: `rdi` = this, no return value. It appends 4 bytes to the string
member and returns.

### Object layout (observed)

| Offset | Field | Evidence |
| --- | --- | --- |
| `+0x0` | vptr | D1/D0 store the generator vtable address point `0x64d7970` here |
| `+0x8` | `crc_` (u32) | Update reads it as the extend seed and stores the result back; the factory zeroes it |
| `+0x10` | `checksum_` (std::string) | Finalize appends to it; length at `+0x18`, SSO buffer/capacity at `+0x20` |

The object is `0x30` bytes (`operator new(0x30)` in the factory at
`0x61cd2e0`): vptr + crc + padding + the 32-byte std::string. The
factory initialises the string with pointer `object+0x20` (SSO),
length 0 and a NUL first byte, and zeroes `crc_`.

### Finalize body (observed)

| Window | Range | Content |
| --- | --- | --- |
| prologue_canary | `0x61cd1c0..0x61cd1d6` | `endbr64`, `sub rsp,0x18`, stack-canary load/store |
| load_bswap | `0x61cd1d6..0x61cd1df` | `mov eax,[rdi+0x8]`; `bswap eax`; store to stack |
| length_guard | `0x61cd1df..0x61cd1f3` | `movabs rax,0x3fffffffffffffff`; `sub rax,[rdi+0x18]`; `cmp rax,0x3`; `jbe` to the throw path |
| append_call | `0x61cd1f3..0x61cd209` | `lea rcx,[rdi+0x10]`; `lea rsi,[rsp+0x4]`; `mov edx,0x4`; `call _M_append` (PLT `0x63f0f40`) |
| canary_check_ret | `0x61cd209..0x61cd21e` | canary check, `add rsp,0x18`, `ret` |
| length_error_path | `0x61cd21e..0x61cd23a` | canary check, `call __throw_length_error` (PLT `0x63f0de0`) |
| stack_fail_path | `0x61cd23a..0x61cd23f` | `call __stack_chk_fail` (PLT `0x63f0d70`) |

The appended bytes are the big-endian form of the accumulated CRC32C
word: `bswap` reverses the four bytes, and `_M_append` copies them in
memory order. This is **not** the little-endian `PutFixed32` used
elsewhere in RocksDB.

### No Mask/Unmask

There is no rotate and no add of `0xa282ead8` anywhere in the body.
Unlike `ComputeBuiltinChecksum` (`0x616bca0`, PR #5413), whose CRC32C
arm applies `Mask` inline (`ror $0xf` + add), Finalize does not Mask or
Unmask the accumulator: the checksum string holds the raw CRC32C,
byte-swapped only.

### Length guard

The append runs exactly when `len <= max_size - 4`, where
`max_size = 0x3fffffffffffffff` (the `std::string` max size). The
binary throws `__throw_length_error` when
`(max_size - len) <= 3`.

### Update (supporting window, `0x61cd1a0..0x61cd1b5`)

`mov edi,[rdi+0x8]`; `call 0x61c25f0` (the registered-extend PLT stub,
jumping through the `.bss` slot at `0x6508908`; the initializer at
`0x61c26d0` stores `0x61c21d0`,
`rocksdb::crc32c::ExtendImpl<Slow_CRC32>`, there -- established in PR
#5387); `mov [rbx+0x8],eax`. So `crc_` is the raw CRC32C extend
accumulator. Update is not in the vendor census, so its body hash is
recorded from the binary only.

### Sibling slots (inferences, not modelled here)

- Slot 2, Update (`0x61cd1a0`): modelled above as the accumulator
  producer.
- Slot 4, GetChecksum (`0x61cd510`, FDE `0x61cd510..0x61cd5c4`): copies
  the string at `+0x10` into the caller's return slot (SSO fast path
  for length <= 15, `_M_create` + `memcpy` otherwise). The census
  attributes this address to one of 2 identical bodies (e.g.
  `Transaction::GetName`); the vtable slot and the copy of the string
  at `+0x10` identify this instance as the generator's GetChecksum.
- Slot 5, Name (`0x61cd020`, FDE `0x61cd020..0x61cd02c`): returns the
  pointer at `0x43336e`, the string `FileChecksumCrc32c`. The factory
  at `0x61cd2e0` creates a generator exactly when the context name is
  that same 18-byte string, which corroborates the name.

## Check values

- `finalize(0xe3069283, b"") = b"\xe3\x06\x92\x83"` (the known CRC32C
  vector for `b"123456789"`, appended big-endian).
- `finalize(0, b"abc") = b"abc\x00\x00\x00\x00"`.
- `finalize(0xa282ead8, b"") = b"\xa2\x82\xea\xd8"` (the Mask constant
  itself, byte-swapped only -- no Mask is applied).
- `finalize(0x12345678, b"prefix") = b"prefix\x12\x34\x56\x78"`.
- End to end: `extend(0, b"123456789") = 0xe3069283`, so
  `finalize(extend(0, b"123456789"), b"") = b"\xe3\x06\x92\x83"`.
- Guard: allowed at `len == max_size - 4`, throws at
  `len == max_size - 3`.

## Cases

2400 deterministic cases (boundary prior lengths 0..1024, including
the std::string SSO boundary at 15/16, crossed with structured crc
words 0, 1, all-ones, `0xe3069283`, `0xa282ead8`, `0x80000000`,
`0x12345678`, then random pairs). Model vs independent reference
(struct.pack big-endian vs manual byte-swap + bytearray extend),
0 mismatches. The full run is summarised in `result.json` by its
aggregate digest; the first 64 rows are in `cases.tsv`.
