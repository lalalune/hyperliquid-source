# RE-002: node #115 ROCKSDB_XXH64 streaming API

This packet reconstructs one bounded node #115 behavior family: the
streaming XXH64 API — `createState` at `0x61db130` (FDE
`0x61db130..0x61db13e`), `freeState` at `0x61db140` (FDE
`0x61db140..0x61db154`), `reset` at `0x61db160` (FDE
`0x61db160..0x61db1c9`, 105 bytes), `update` at `0x61db1d0` (FDE
`0x61db1d0..0x61db3de`, 526 bytes) and `digest` at `0x61db3e0` (FDE
`0x61db3e0..0x61db649`, 617 bytes). `reset`, `update` and `digest` are
vendor-census entries (`ROCKSDB_XXH64_reset`, `ROCKSDB_XXH64_update`,
`ROCKSDB_XXH64_digest`, librocksdb-sys 0.11.0+8.1.1, ids
`node115-vendor-61db160` / `node115-vendor-61db1d0` /
`node115-vendor-61db3e0`, whose `target_body_sha256` values match the
body hashes in `result.json`); `createState` and `freeState` have no
census records and are pinned by FDE extent and disassembly only. The
family is used by the xxhash64 arm of
`rocksdb::ComputeBuiltinChecksumWithLastByte` at `0x616bd60`
(reconstructed in PR #5399), which creates a state, resets it with
seed 0, updates with the input then with the single last byte,
digests, keeps the low 32 bits, and frees the state. The one-shot
`ROCKSDB_XXH64` at `0x61dae20` was reconstructed separately in PR
#5429; the streaming digest reuses its merge, tail and avalanche
shapes.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the prime
  immediates, the state layout, the null-update rule and the six arm
  call sites are observations. The C++ symbol attribution for reset,
  update and digest comes from the vendor census. The prose name for
  the API is an inference from the disassembly, corroborated by the
  three published XXH64 vectors below and by the one-shot values the
  streaming model reproduces exactly.
- Scope included: all five helpers, the 0x58-byte state layout and
  its update invariant, the null-update rule, the six arm call sites,
  and the 2400-case streaming cross-check under varied chunkings.
  Excluded: any claim about callers besides the arm, any claim about
  update/digest on a state that was never reset (the binary would
  read uninitialised malloc memory), and any claim about the original
  source repository or compiler.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/xxh64_streaming115.py --verify
python3 tools/xxh64_streaming115.py --out research/work-items/re-002-node115-xxh64-streaming-115
python3 -m unittest tests.test_xxh64_streaming115
(cd research/work-items/re-002-node115-xxh64-streaming-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

- `createState() -> *mut state` — `malloc(0x58)` tail call; the
  returned state is uninitialised until `reset` runs.
- `reset(state, seed: u64) -> 0` — observed register use: `rdi` =
  state, `rsi` = seed.
- `update(state, data: *const u8, n: usize) -> 0` — observed register
  use: `rdi` = state, `rsi` = data, `rdx` = n; returns 0 in every path.
- `digest(state) -> u64` — observed register use: `rdi` = state,
  `rax` = result.
- `freeState(state) -> 0` — calls `free`, returns 0.

### State layout (0x58 bytes)

`total_len` +0x00 (u64), `v1` +0x08, `v2` +0x10, `v3` +0x18, `v4`
+0x20, `mem` +0x28 (32 bytes), `memsize` +0x48 (u32). After every
update, `memsize == total_len % 32` and `mem` holds the last
`memsize` input bytes. The trailing 12 bytes (+0x4c..+0x58) are
zeroed by reset and never read or written by update/digest in the
observed code; their purpose is unknown.

### Behavior (observed)

- `reset`: zeroes the whole 0x58-byte state (`total_len` store plus a
  `rep stos` over the rest), then `v1 = seed+P1+P2`, `v2 = seed+P2`,
  `v3 = seed`, `v4 = seed-P1` (seed constants as movabs immediates:
  `P1+P2` `0x60ea27eeadc0b5d6` at `0x61db193`, `P2` at `0x61db1a4`,
  `-P1` `0x61c8864e7a143579` at `0x61db1b5`).
- `update`: a null data pointer returns 0 with the state untouched
  (`test %rsi,%rsi; je 0x61db3b8`); a zero length is observably the
  same no-op. Otherwise `total_len += n`; when `memsize + n <= 31`
  the input is buffered in `mem`; when the buffer fills, the 32-byte
  `mem` block is processed with one round per lane and `memsize` is
  cleared; full 32-byte stripes are then processed in place (round
  `rol(acc + k*P2, 31) * P1` per lane; the fourth lane multiplies
  before adding, which is the same arithmetic); the remainder (under
  32 bytes) is buffered and `memsize` is set to its length.
- `digest`: reads the tail from `mem` with `remaining = total_len &
  31`. When `total_len >= 32`, `h = rol(v1,1) + rol(v2,7) +
  rol(v3,12) + rol(v4,18)`, then one mergeRound per lane (`h ^=
  round(0, v); h = h*P1 + P4`), with `+ total_len` folded into the
  last mergeRound as `+ P4 + total_len`; otherwise `h = v3 +
  total_len + P5`. Then the 8/4/1-byte tail (8-byte rounds with the
  binary's countdown checks, at most one 4-byte round, up to three
  1-byte rounds) and the avalanche `h ^= h>>33; h *= P2; h ^= h>>29;
  h *= P3; h ^= h>>32`.

Primes P1 `0x9e3779b185ebca87`, P2 `0xc2b2ae3d27d4eb4f`, P3
`0x165667b19e3779f9`, P4 `0x85ebca77c2b2ae63`, P5
`0x27d4eb2f165667c5` (each a movabs immediate; sites in
`result.json`).

### Check values

- `stream(b"", 0) = 0xef46db3751d8e999` (published empty vector)
- `stream(b"a", 0) = 0xd24ec4f1a98c6e5b` (published vector)
- `stream(b"abc", 0) = 0x44bc2cf5ad770999` (published vector)
- `stream(b"123456789", 0) = 0x8cb841db40e6ae83` (model and reference agree)
- One full stripe, no tail: `stream(bytes(0..31), 0) = 0xcbf59c5116ff32b4`
- One stripe plus a 1-byte tail, fed in halves: `stream(bytes(0..32), 0) = 0x0c535d1acafb8ead`
- Two stripes, nonzero seed, fed byte-by-byte: `stream(bytes(0..63), 1) = 0x3ce5bdf7575926c0`
