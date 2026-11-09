# RE-002: node #115 ROCKSDB_XXH64 one-shot

This packet reconstructs one bounded node #115 behavior: the full
`ROCKSDB_XXH64` one-shot hash function at `0x61dae20` (FDE
`0x61dae20..0x61db121`, 769 bytes), as attributed by the vendor census
(`research/byte-windows.json`, id `node115-vendor-61dae20`, whose
`target_body_sha256` matches the body hash in `result.json`). It is the
type-3 callee of `rocksdb::ComputeBuiltinChecksum` at `0x616bca0` (call
at `0x616bd38`, reconstructed in PR #5413), which keeps the low 32 bits
of its result. The streaming XXH64 API (createState/reset/update/
digest/freeState at `0x61db130..0x61db3e0`) is a separate set of
functions, modelled only as callees in PR #5399, and is not
reconstructed here.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the five prime
  immediates, the P1*P2 strength-reduced constant, the null branch and
  the dispatcher call site are observations. The C++ symbol attribution
  comes from the vendor census. The prose name for the hash is an
  inference from the disassembly, corroborated by the three published
  XXH64 vectors below.
- Scope included: the full one-shot function (stripes, merge, 8/4/1-byte
  tails, avalanche), the null-input rule, the P1*P2 merge reduction,
  the dispatcher call site, and the 2400-case model cross-check.
  Excluded: the streaming XXH64 API, any claim about which callers
  besides the dispatcher use this function, and any claim about the
  original source repository or compiler.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/xxh64_oneshot115.py --verify
python3 tools/xxh64_oneshot115.py --out research/work-items/re-002-node115-xxh64-oneshot-115
python3 -m unittest tests.test_xxh64_oneshot115
(cd research/work-items/re-002-node115-xxh64-oneshot-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`xxh64(data: *const u8, n: usize, seed: u64) -> u64`, observed
register use: `rdi` = data, `rsi` = n, `rdx` = seed, `rax` = result.

### Behavior (observed)

XXH64 one-shot with primes P1 `0x9e3779b185ebca87`, P2
`0xc2b2ae3d27d4eb4f`, P3 `0x165667b19e3779f9`, P4
`0x85ebca77c2b2ae63`, P5 `0x27d4eb2f165667c5` (each a movabs
immediate; sites in `result.json`):

- `n >= 32`: four lanes `v1 = seed+P1+P2`, `v2 = seed+P2`, `v3 = seed`,
  `v4 = seed-P1`; 32-byte stripes with round
  `rol(acc + k*P2, 31) * P1`; merge `h = rol(v1,1) + rol(v2,7) +
  rol(v3,12) + rol(v4,18)`, then one mergeRound per lane
  (`h ^= round(0, v); h = h*P1 + P4`); the `+ n` term is folded into
  the last mergeRound as `+ P4 + n`.
- `n < 32`: `h = seed + P5 + n`, no lanes.
- 8-byte tail (up to three rounds, unrolled with countdown checks):
  `h ^= round(0, k); h = rol(h, 27)*P1 + P4`.
- 4-byte tail (at most one round): `h ^= u32*P1; h = rol(h, 23)*P2 + P3`.
- 1-byte tail (up to three rounds, unrolled): `h ^= byte*P5; h = rol(h, 11)*P1`.
- Avalanche: `h ^= h>>33; h *= P2; h ^= h>>29; h *= P3; h ^= h>>32`.

### Compiler detail

The mergeRounds do not recompute `round(0, v)` directly. The stripe
loop leaves the pre-multiply lane value `rol(v_prev + k*P2, 31)` in a
scratch register, and the merge multiplies it by `P1*P2 mod 2**64`
(`0xdef35b010f796ca9`, movabs at `0x61daf0f`) before the rol-31/*P1
steps, because `pre * P1 * P2 == v * P2`.

### Null input

`test %rdi,%rdi; je 0x61db0de` at `0x61dae39/0x61dae3c` jumps straight
to the avalanche with `h = seed + P5 + n` and no buffer load, so a null
pointer yields the seeded empty-input avalanche even for a nonzero
length. The model covers the non-null path; `xxh64_null` records the
null rule.

### Check values

- `xxh64(b"", 0) = 0xef46db3751d8e999` (published empty vector)
- `xxh64(b"a", 0) = 0xd24ec4f1a98c6e5b` (published vector)
- `xxh64(b"abc", 0) = 0x44bc2cf5ad770999` (published vector)
- `xxh64(b"123456789", 0) = 0x8cb841db40e6ae83` (model and reference agree)
- One full stripe, no tail: `xxh64(bytes(0..31), 0) = 0xcbf59c5116ff32b4`
- One stripe plus a 1-byte tail: `xxh64(bytes(0..32), 0) = 0x0c535d1acafb8ead`
- Two stripes, nonzero seed: `xxh64(bytes(0..63), 1) = 0x3ce5bdf7575926c0`
