# RE-002: node #115 ComputeBuiltinChecksumWithLastByte xxhash64 arm

This packet reconstructs one bounded node #115 behavior: the xxhash64 arm
(type 3) of `rocksdb::ComputeBuiltinChecksumWithLastByte` at `0x616bd60`
(FDE `0x616bd60..0x616beac`), as attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the dispatch compares,
  the five call targets and the prime immediates are observations. The
  C++ symbol attribution comes from the vendor census. The prose names
  for the dispatch arms are inferences from the disassembly. Only the
  type-3 arm is modelled; the type-2 and type-4 arms are recorded as
  observed-but-not-modelled.
- Scope included: the dispatch table, the xxhash64 arm
  (`(u32) XXH64(data || last_byte, seed 0)`), the streaming call
  sequence, the reset accumulator initialisation, the five XXH64 primes
  as immediates in the update/digest, and the 2400-case model
  cross-check. Excluded: the semantics of the xxhash / multiply-xor
  arms, and any claim about which callers use this function or which
  files the node checksums with it.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/xxh64_last_byte115.py --verify
python3 tools/xxh64_last_byte115.py --out research/work-items/re-002-node115-xxh64-last-byte-115
python3 -m unittest tests.test_xxh64_last_byte115
(cd research/work-items/re-002-node115-xxh64-last-byte-115 && sha256sum -c MANIFEST.sha256)
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
| 2 | xxhash | calls into `0x61daa60..0x61dacf0`; not modelled |
| 3 | xxhash64 | `(u32) XXH64(data \|\| last_byte, seed 0)`; modelled here |
| 4 | multiply-xor | `ROCKSDB_XXH3_64bits(data, n)` then `imul $0x6b9083d9` xor last byte; not modelled |

### xxhash64 arm (0x616be28..0x616be80)

The arm runs the `ROCKSDB_XXH64` streaming API with seed 0:

1. `createState` at `0x61db130` — `malloc(0x58)`, the 88-byte state.
2. `reset` at `0x61db160` with seed 0 (`xor %esi,%esi` before the call).
3. `update` at `0x61db1d0` with `(data, n)`.
4. `update` at `0x61db1d0` with `(&last_byte, 1)` — `rsi` points at the
   spilled last byte, `edx` is 1.
5. `digest` at `0x61db3e0` — returns the 64-bit hash in `rax`.
6. `freeState` at `0x61db140` — a `free` wrapper returning 0.

The arm keeps only the low 32 bits of the digest
(`mov %eax,%ebx` at `0x616be65`), so it computes
`(u32) XXH64(data || last_byte, seed 0)`.

### Reset (0x61db160..0x61db1c9)

The reset zeroes the 0x58-byte state, sets `total_len` to 0, and
initialises the four accumulators from the seed:

- `v1 = seed + PRIME64_1 + PRIME64_2` — the sum `0x60ea27eeadc0b5d6`
  is the immediate at `0x61db193`; for seed 0, `v1 = 0x60ea27eeadc0b5d6`.
- `v2 = seed + PRIME64_2`; for seed 0, `v2 = 0xc2b2ae3d27d4eb4f`.
- `v3 = seed`; for seed 0, `v3 = 0`.
- `v4 = seed - PRIME64_1` — the two's complement
  `0x61c8864e7a143579` is the immediate at `0x61db1b5`; for seed 0,
  `v4 = 0x61c8864e7a143579`.

Observed state offsets: `total_len` +0x0, `v1` +0x8, `v2` +0x10,
`v3` +0x18, `v4` +0x20, `memsize` +0x28. No separate seed field is
stored: the digest reads `v3` (+0x18) where the public algorithm
reads the seed, and `v3 == seed` by construction. The update touches
the buffer at +0x40/+0x48; the buffer start offset was not pinned.

### Update and digest

`ROCKSDB_XXH64_update` (`0x61db1d0..0x61db3de`) and
`ROCKSDB_XXH64_digest` (`0x61db3e0..0x61db649`) carry all five XXH64
primes as 64-bit immediates (see `records.json` for the sites), and
their body SHA-256 values match the census `target_body_sha256`
values. The digest shows the public finalisation shape: merge
prologue (`rol` v1 by 1, v2 by 7, v3 by 12, v4 by 18), merge rounds,
8-byte chunks (`rol` 27, `*P1`, `+P4`), a 4-byte chunk (`rol` 23,
`*P2`, `+P3`), single bytes (`*P5`, `rol` 11, `*P1`), then the
avalanche (`shr` 33, `*P2`, `shr` 29, `*P3`, `shr` 32).

### Model cross-check

The tool implements XXH64 twice independently — a streaming state
machine mirroring the binary's create/reset/update/digest sequence,
and the one-shot reference — and cross-checks them on 2400
deterministic cases (boundary lengths 0..1024, then random lengths
0..8192), 0 mismatches. Both implementations agree on the public
check vectors `XXH64(b"", 0) = 0xef46db3751d8e999` and
`XXH64(b"a", 0) = 0xd24ec4f1a98c6e5b`.
