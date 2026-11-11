# RE-002: node #115 ComputeBuiltinChecksum dispatcher

This packet reconstructs one bounded node #115 behavior: the full
`rocksdb::ComputeBuiltinChecksum` dispatcher at `0x616bca0` (FDE
`0x616bca0..0x616bd51`), as attributed by the vendor census
(`research/byte-windows.json`, whose `target_body_sha256` matches the
body hash in `result.json`). It is the immediate predecessor of
`ComputeBuiltinChecksumWithLastByte` at `0x616bd60`, whose four hash
arms were reconstructed in PRs #5396/#5399/#5402/#5409; this function
dispatches the same four hashes without an appended byte.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the dispatch compares,
  the extend call, the Mask sub-immediate and the callee bodies are
  observations. The C++ symbol attribution comes from the vendor census.
  The prose names for the dispatch arms are inferences from the
  disassembly. All four hash arms are modelled (the type-4 arm only for
  `n <= 17`, per the XXH3 short range).
- Scope included: the dispatch table, all four arms, the Mask constant's
  expression as `sub $0x5d7d1528`, the three callee bodies, and the
  2400-case model cross-check. Excluded: the semantics of the type-4 arm
  for `n > 17`, the RocksDB `ChecksumType` enum name for type 4, and any
  claim about which callers use this function or which files the node
  checksums with it.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/checksum115.py --verify
python3 tools/checksum115.py --out research/work-items/re-002-node115-checksum-115
python3 -m unittest tests.test_checksum115
(cd research/work-items/re-002-node115-checksum-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`compute(type: u8, data: *const u8, n: usize) -> u32`, observed
register use: `dil` = type, `rsi` = data, `rdx` = n, `eax` = result.

### Dispatch (observed)

| type | arm | behavior |
| --- | --- | --- |
| 0 (and any other) | default | returns 0 |
| 1 | CRC32C | `mask(extend(0, data, n))` |
| 2 | xxhash | `XXH32(data, n, seed 0)` (tail call to `0x61da8b0`) |
| 3 | xxhash64 | `(u32) XXH64(data, n, seed 0)` (call to `0x61dae20`) |
| 4 | multiply-xor | `n == 0 ? 0 : (u32) XXH3_64bits(data, n-1) ^ (data[n-1] * 0x6b9083d9)` |

### CRC32C arm (0x616bd18..0x616bd30)

`xor %edi,%edi` (seed 0), one call to the registered extend through the
PLT stub at `0x61c25f0` (`.bss` slot `0x6508908`, target `0x61c21d0`
`rocksdb::crc32c::ExtendImpl<Slow_CRC32>`), then the Mask inline:
`ror $0xf, %eax` then `sub $0x5d7d1528, %eax` at `0x616bd28`. Since
`0x5d7d1528` is the two's complement of `0xa282ead8`, this is
`ror32(crc, 15) + 0xa282ead8 (mod 2**32)` -- the same Mask as the
WithLastByte arm, expressed there as `lea 0xa282ead8` (the constant
`0xa282ead8` occurs exactly once in `.text`, at `0x616bea1`).

### xxhash arm (0x616bcc8..0x616bce0)

Tail call to `ROCKSDB_XXH32` at `0x61da8b0` (FDE `0x61da8b0..0x61daa52`)
with seed 0; the 32-bit digest is the result directly.

### xxhash64 arm (0x616bd30..0x616bd48)

Call to `ROCKSDB_XXH64` at `0x61dae20` (FDE `0x61dae20..0x61db121`)
with seed 0; the caller keeps the low 32 bits.

### multiply-xor arm (0x616bce0..0x616bd18)

If `n == 0` return 0; else call `ROCKSDB_XXH3_64bits` at `0x61db650`
(FDE `0x61db650..0x61db93a`) on `(data, n-1)`, then
`(u32) helper ^ (data[n-1] * 0x6b9083d9)`. The last input byte plays the
role the appended byte plays in the WithLastByte arm. The helper is
modelled only for inputs of length 0..16 (the short branches
reconstructed in PR #5409), so this arm is modelled only for `n <= 17`.

## Check values

- type 1: `checksum(1, b"123456789") = 0xc78ab0e5`
  (`mask(0xe3069283)`); `checksum(1, b"") = 0xa282ead8` (`mask(0)`).
- type 2: `checksum(2, b"") = 0x02cc5d05`,
  `checksum(2, b"a") = 0x550d7456` (published XXH32 vectors).
- type 3: `checksum(3, b"") = 0x51d8e999`,
  `checksum(3, b"a") = 0xa98c6e5b` (low 32 bits of the published XXH64
  vectors `0xef46db3751d8e999` and `0xd24ec4f1a98c6e5b`).
- type 4: `checksum(4, b"") = 0`, `checksum(4, b"a") = 0xf91261fb`,
  `checksum(4, b"abc") = 0xbc378fb7`.
- default: `checksum(0, b"abc") = checksum(5, b"abc") = 0`.
