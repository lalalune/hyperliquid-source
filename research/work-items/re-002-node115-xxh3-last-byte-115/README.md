# RE-002: node #115 ComputeBuiltinChecksumWithLastByte multiply-xor arm

This packet reconstructs one bounded node #115 behavior: the multiply-xor
arm (type 4) of `rocksdb::ComputeBuiltinChecksumWithLastByte` at
`0x616bd60` (FDE `0x616bd60..0x616beac`), for inputs of length 0..16, as
attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the dispatch compares,
  the call target, the secret table and the immediate constants are
  observations. The C++ symbol attribution comes from the vendor
  census. The prose names for the dispatch arms are inferences from
  the disassembly. Only the type-4 arm for lengths 0..16 is modelled;
  the helper branches for length 17 and over are recorded as
  observed-but-not-modelled.
- Scope included: the dispatch table, the multiply-xor arm
  (`(u32) helper(data, n) ^ (last_byte * 0x6b9083d9)`), the helper's
  1-to-3, 4-to-8 and 9-to-16 branches, the default XXH3 secret table,
  the secret-derived immediates, and the 2400-case model cross-check.
  Excluded: the helper branches for lengths 17..128, 129..240 and
  over 240 (shared tails at `0x61d7dc0` and `0x61d8510`), and any claim
  about which callers use this function or which files the node
  checksums with it.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/xxh3_last_byte115.py --verify
python3 tools/xxh3_last_byte115.py --out research/work-items/re-002-node115-xxh3-last-byte-115
python3 -m unittest tests.test_xxh3_last_byte115
(cd research/work-items/re-002-node115-xxh3-last-byte-115 && sha256sum -c MANIFEST.sha256)
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
| 1 | CRC32C | `mask(extend(extend(0, data), last_byte))` — reconstructed in PR #5396 |
| 2 | xxhash | `XXH32(data \|\| last_byte, seed 0)` — reconstructed in PR #5402 |
| 3 | xxhash64 | `(u32) XXH64(data \|\| last_byte, seed 0)` — reconstructed in PR #5399 |
| 4 | multiply-xor | `(u32) XXH3_64bits(data, n) ^ (last_byte * 0x6b9083d9)`; modelled here for `n <= 16` |

### Multiply-xor arm (0x616bdee..0x616be11)

The arm calls the helper at `0x61db650` with `(data, n)` (call at
`0x616bdf4`), loads the spilled last byte (`movzbl 0xc(%rsp),%ebx`
at `0x616bdf9`), multiplies it by `0x6b9083d9` (`imul` at
`0x616be02`, 32-bit), and xors the product with the low 32 bits of
the helper result (`xor %eax,%ebx` at `0x616be08`). The helper
returns a 64-bit value in `rax`, so only its low 32 bits survive.

### Helper (0x61db650..0x61db93a) — XXH3_64bits, default secret, seed 0

The helper is the XXH3-family 64-bit hash. Its short branches use
the default XXH3 secret (the table at `0x97ec80` in `.rodata`,
verified word by word in `verify()`), the XXH3 primes, the rrmxmx
finaliser and the XXH3 avalanche. The short-branch formulas match
public XXH3_64bits line by line, verified against the Ruby prism
`xxh3.c` port of upstream xxHash (`XXH3_64_1to3`, `XXH3_64_4to8`,
`XXH3_64_9to16`).

- len 0 (`0x61db8d4`): returns `0x2d06800538d394c2`, the published
  `XXH3_64bits(b"")` value. The branch loads that constant directly;
  it is also the constant-folded `XXH3_64_empty`, i.e.
  `avalanche_XXH64(secret[56..64) ^ secret[64..72))`, which
  `verify()` re-derives from the secret table.
- len 1..3 (`0x61db8d4..0x61db939`): `combined = data[len-1] |
  data[0]<<16 | len<<8 | data[len>>1]<<24`; `keyed = combined ^
  0x87275a9b`, where `0x87275a9b` is `secret[0..4) ^
  secret[4..8)`; then the XXH64 avalanche without its first
  `h ^= h>>33` step (elided by the compiler: `keyed` is 32-bit, so
  `h>>33` is 0): `h *= PRIME64_2`, `h ^= h>>29`, `h *=
  PRIME64_3`, `h ^= h>>32`. Check: `XXH3_64bits(b"a") =
  0xe6c632b61e964e1f`, the published sanity value.
- len 4..8 (`0x61db860..0x61db8bd`): `input64 = first u32 << 32 |
  last u32`; `keyed = input64 ^ 0xc73ab174c5ecd5a2`, where that
  constant is `secret[8..16) ^ secret[16..24)`; then rrmxmx:
  `h ^= rol(h,49) ^ rol(h,24)`; `h *= 0x9fb21c651e98df25`;
  `h ^= (h>>35) + len`; `h *= 0x9fb21c651e98df25`; `h ^= h>>28`.
- len 9..16 (`0x61db664..0x61db6b8`): `A = read64(input) ^
  0x6782737bea4239b9` (`secret[24..32) ^ secret[32..40)`),
  `B = read64(input+len-8) ^ 0xaf56bc3b0996523a`
  (`secret[40..48) ^ secret[48..56)`); `t = (hi(A*B) ^ lo(A*B)) +
  (B + len) + bswap64(A)`; then the XXH3 avalanche: `t ^= t>>37`,
  `t *= 0x165667919e3779f9`, `t ^= t>>32`.

The 17-to-128 branch (`0x61db6e0..0x61db848`, two mix16B steps plus
`len * PRIME64_1` and the same avalanche), the 129-to-240 branch
(shared tail at `0x61d7dc0`) and the over-240 branch (shared tail
at `0x61d8510`) are observed but not modelled; the arm is pinned
only for inputs of length 0..16.

### Model cross-check

The tool implements the short-input helper twice independently — a
direct transliteration of the instruction sequence, and a
structurally different formulation (byte-buffer packing, struct
round-trips, 32-bit-limb multiplication) — and cross-checks them on
2400 deterministic cases of length 0..16, 0 mismatches.
