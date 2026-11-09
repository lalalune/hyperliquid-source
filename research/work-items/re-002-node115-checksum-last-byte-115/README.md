# RE-002: node #115 ComputeBuiltinChecksumWithLastByte CRC32C arm

This packet reconstructs one bounded node #115 behavior: the CRC32C arm
(type 1) of `rocksdb::ComputeBuiltinChecksumWithLastByte` at `0x616bd60`
(FDE `0x616bd60..0x616beac`), as attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the dispatch compares,
  the two extend calls and the Mask immediate are observations. The C++
  symbol attribution comes from the vendor census. The prose names for
  the dispatch arms are inferences from the disassembly. Only the type-1
  arm is modelled; the type-2, type-3 and type-4 arms are recorded as
  observed-but-not-modelled.
- Scope included: the dispatch table, the CRC32C arm
  (`mask(extend(extend(0, data), last_byte))`), the Mask constant's
  unique occurrence in `.text`, and the 2400-case model cross-check.
  Excluded: the semantics of the xxhash / xxhash64 / multiply-xor arms,
  and any claim about which callers use this function or which files the
  node checksums with it.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/checksum_last_byte115.py --verify
python3 tools/checksum_last_byte115.py --out research/work-items/re-002-node115-checksum-last-byte-115
python3 -m unittest tests.test_checksum_last_byte115
(cd research/work-items/re-002-node115-checksum-last-byte-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`compute(type: u8, data: *const u8, n: usize, last_byte: u8) -> u32`,
observed register use: `dil` = type, `rsi` = data, `rdx` = n, `cl` =
last_byte (spilled to `0xc(%rsp)`), `eax` = result.

### Dispatch (observed)

| type | arm | behavior |
| --- | --- | --- |
| 0 (and any other) | default | returns 0 |
| 1 | CRC32C | `mask(extend(extend(0, data), last_byte))` |
| 2 | xxhash | calls into `0x61daa60..0x61dacf0`; not modelled |
| 3 | xxhash64 | `ROCKSDB_XXH64_update` / `ROCKSDB_XXH64_digest`; not modelled |
| 4 | multiply-xor | `hash(data, n)` then `imul $0x6b9083d9` xor last byte; not modelled |

### CRC32C arm (0x616be80..0x616beac)

Two calls through the PLT stub at `0x61c25f0`, which jumps through the
writable slot at `0x6508908` (the initializer at `0x61c26d0` stores
`0x61c21d0`, `rocksdb::crc32c::ExtendImpl<Slow_CRC32>`, there):

1. `extend(0, data, n)` — `edi` is zeroed, `rsi`/`rdx` still hold the
   entry `data`/`n`.
2. `extend(crc, &last_byte, 1)` — `rsi` points at the spilled last byte,
   `edx` is 1, `edi` holds the first result.

The extend is the stored form (complement-in/out), anchored by the
known check value `extend(0, b"123456789") == 0xe3069283`.

Then the Mask is applied inline: `ror $0xf, %eax` followed by
`lea 0xa282ead8(%rax), %ebx`, i.e.
`ror32(crc, 15) + 0xa282ead8 (mod 2**32)`. The constant `0xa282ead8`
occurs exactly once in `.text`, as the immediate at `0x616bea1` of
that `lea`.

So the arm computes `mask(stored_crc32c(data || last_byte))`.

### Check values

- `arm(b"", 0x00) = 0x49258fd2` (extend of the single zero byte is
  `0x527d5351`).
- `arm(b"123456789", 0x00) = 0xdd227149` (stored CRC of the data is the
  known `0xe3069283`).
- `arm(b"", 0x61) = 0x28e46e78` (stored CRC of `b"a"` is the known
  `0xc1d04330`).
- `arm(1024 bytes of 0xab, 0xff) = 0x2a29e790`.
