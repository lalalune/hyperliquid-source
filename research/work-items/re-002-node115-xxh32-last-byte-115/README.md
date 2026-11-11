# RE-002: node #115 ComputeBuiltinChecksumWithLastByte xxhash arm

This packet reconstructs one bounded node #115 behavior: the xxhash arm
(type 2) of `rocksdb::ComputeBuiltinChecksumWithLastByte` at `0x616bd60`
(FDE `0x616bd60..0x616beac`), as attributed by the vendor census
(`research/work-items/RE-002-node115-vendor-census/census.json`, whose
`target_body_sha256` matches the body hash in `result.json`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the dispatch compares,
  the five call targets and the prime immediates are observations. The
  C++ symbol attribution comes from the vendor census. The prose names
  for the dispatch arms are inferences from the disassembly. Only the
  type-2 arm is modelled; the type-4 arm is recorded as
  observed-but-not-modelled.
- Scope included: the dispatch table, the xxhash arm
  (`XXH32(data || last_byte, seed 0)`), the streaming call
  sequence, the reset accumulator initialisation, the five XXH32 primes
  as immediates in the update/digest, and the 2400-case model
  cross-check. Excluded: the semantics of the multiply-xor arm, and any
  claim about which callers use this function or which files the node
  checksums with it.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/xxh32_last_byte115.py --verify
python3 tools/xxh32_last_byte115.py --out research/work-items/re-002-node115-xxh32-last-byte-115
python3 -m unittest tests.test_xxh32_last_byte115
(cd research/work-items/re-002-node115-xxh32-last-byte-115 && sha256sum -c MANIFEST.sha256)
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
| 2 | xxhash | `XXH32(data \|\| last_byte, seed 0)`; modelled here |
| 3 | xxhash64 | `(u32) XXH64(data \|\| last_byte, seed 0)` — reconstructed in PR #5399 |
| 4 | multiply-xor | `ROCKSDB_XXH3_64bits(data, n)` then `imul $0x6b9083d9` xor last byte; not modelled |

### xxhash arm (0x616bd96..0x616bde5)

The arm runs the `ROCKSDB_XXH32` streaming API with seed 0:

1. `createState` at `0x61daa60` — `malloc(0x30)`, the 48-byte state.
2. `reset` at `0x61daa90` with seed 0 (`xor %esi,%esi` before the call).
3. `update` at `0x61daac0` with `(data, n)`.
4. `update` at `0x61daac0` with `(&last_byte, 1)` — `rsi` points at the
   spilled last byte, `edx` is 1.
5. `digest` at `0x61dacf0` — returns the 32-bit hash in `eax`.
6. `freeState` at `0x61daa70` — a `free` wrapper returning 0.

The arm returns the digest directly (`mov %eax,%ebx` at `0x616bdd3`),
so it computes `XXH32(data || last_byte, seed 0)`.

### Reset (0x61daa90..0x61daabb)

The reset zeroes the 0x30-byte state and initialises the four
accumulators from the seed with a single vector add: the 16-byte
constant at `0x451ae0` is `[P1+P2, P2, 0, -P1]`
(`0x24234428, 0x85ebca77, 0x00000000, 0x61c8864f`), broadcast-added
to the seed (`pshufd $0x0` then `paddd` at `0x61daa9..0x61daab6`),
and the result is stored at state `+0x8`:

- `v1 = seed + PRIME32_1 + PRIME32_2`; for seed 0, `v1 = 0x24234428`.
- `v2 = seed + PRIME32_2`; for seed 0, `v2 = 0x85ebca77`.
- `v3 = seed`; for seed 0, `v3 = 0`.
- `v4 = seed - PRIME32_1`; for seed 0, `v4 = 0x61c8864f`.

Observed state offsets: `total_len` +0x0 (u64; its high dword at
+0x4 carries the sticky `large_len` flag, set whenever the input
chunk or the new total length exceeds 15), `v1` +0x8, `v2` +0xc,
`v3` +0x10, `v4` +0x14, `mem` +0x18 (16 bytes), `memsize` +0x28.
No separate seed field is stored: the digest reads `v3` (+0x10)
where the public algorithm reads the seed, and `v3 == seed` by
construction.

### Update (0x61daac0..0x61dace6)

16-byte stripes use the XXH32 round (`imul $0x85ebca77` = `*P2`,
`add` the accumulator, `rol $0xd`, `imul $0x9e3779b1` = `*P1`) in a
scalar loop, with a vectorised (SSE) round for a buffered stripe
(`pmuludq` against the P2 constant, `rol` 13 via shifts, `*P1`
strength-reduced to shifts/adds/subs) and a `memcpy` tail for the
remaining bytes. The `large_len` flag is ORed into `+0x4` whenever
the chunk length or the new total length exceeds 15.

### Digest (0x61dacf0..0x61dae18) — standard XXH32

For `total_len >= 16` the digest computes the accumulator
convergence (`rol` v1 by 1, v2 by 7, v3 by 12, v4 by 18, plus
`total_len`) and then the remainder handling. This is exactly the
public XXH32 algorithm: per the upstream xxHash spec (v0.2.0,
"XXH32 Algorithm Description", Step 3), XXH32 convergence is the
rotate-sum only — the `mergeAccumulator` rounds
(`h ^= round(0, v); h = h * P1 + P4`) belong to XXH64, whose
convergence the spec calls "more complex than [the] 32-bit variant".

For `total_len < 16` the digest is `h = seed + P5 + total_len`, as
specified. The public check vectors `XXH32(b"", 0) = 0x02cc5d05`,
`XXH32(b"a", 0) = 0x550d7456` and `XXH32(b"abc", 0) = 0x32d153ff`
anchor the model, and the 16-byte input `0x0123456789abcdef` gives
`0xc2c45b69` under the spec steps.

The remainder handling and avalanche match the public algorithm:
4-byte chunks (`*P3`, `rol` 17, `*P4`), single bytes (`*P5`,
`rol` 11, `*P1`), then the avalanche (`shr` 15, `*P2`, `shr` 13,
`*P3`, `shr` 16). All five primes appear as 32-bit immediates in
the update/digest (see `records.json` for the sites).

Correction note: the first submitted revision of this packet claimed
the digest deviates from public XXH32 by omitting merge rounds.
Slopbot flagged that claim as mistaken, and re-checking the upstream
spec confirmed it was wrong — XXH32 has no merge rounds. The claim
and the tests that encoded it were removed in the correction; the
streaming model itself was already standard XXH32 and is unchanged.

### Model cross-check

The tool implements standard XXH32 twice independently — a
streaming state machine mirroring the binary's
create/reset/update/digest sequence, and the one-shot reference —
and cross-checks them on 2400 deterministic cases (boundary lengths
0..1024, then random lengths 0..8192), 0 mismatches.
