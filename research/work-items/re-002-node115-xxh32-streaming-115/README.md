# RE-002: node #115 ROCKSDB_XXH32 streaming API

This packet reconstructs one bounded node #115 behavior family: the
streaming XXH32 API — `createState` at `0x61daa60` (FDE
`0x61daa60..0x61daa6e`), `freeState` at `0x61daa70` (FDE
`0x61daa70..0x61daa84`), `reset` at `0x61daa90` (FDE
`0x61daa90..0x61daabb`, 43 bytes), `update` at `0x61daac0` (FDE
`0x61daac0..0x61dace6`, 550 bytes) and `digest` at `0x61dacf0` (FDE
`0x61dacf0..0x61dae18`, 296 bytes). `reset`, `update` and `digest` are
vendor-census entries (`ROCKSDB_XXH32_reset`, `ROCKSDB_XXH32_update`,
`ROCKSDB_XXH32_digest`, librocksdb-sys 0.11.0+8.1.1, ids
`node115-vendor-61daa90` / `node115-vendor-61daac0` /
`node115-vendor-61dacf0`, whose `target_body_sha256` values match the
body hashes in `result.json`); `createState` and `freeState` have no
census records and are pinned by FDE extent and disassembly only. The
family is used by the xxhash32 arm of
`rocksdb::ComputeBuiltinChecksumWithLastByte` at `0x616bd60`
(reconstructed in PR #5399), which creates a state, resets it with
seed 0, updates with the input then with the single last byte,
digests, keeps the low 32 bits, and frees the state. The one-shot
`ROCKSDB_XXH32` at `0x61da8b0` was reconstructed separately in
RE-014-checksum-selector2-115; the streaming digest reuses its merge,
tail and avalanche shapes.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the `.rodata`
  constant vectors, the prime immediates, the state layout, the
  null-update rule and the six arm call sites are observations. The
  C++ symbol attribution for reset, update and digest comes from the
  vendor census. The prose name for the API is an inference from the
  disassembly, corroborated by the three published XXH32 vectors below
  and by the one-shot values the streaming model reproduces exactly.
- Scope included: all five helpers, the 0x30-byte state layout and
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
python3 tools/xxh32_streaming115.py --verify
python3 tools/xxh32_streaming115.py --out research/work-items/re-002-node115-xxh32-streaming-115
python3 -m unittest tests.test_xxh32_streaming115
(cd research/work-items/re-002-node115-xxh32-streaming-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

The whole-function disassembly excerpts (`xxh32_*115.objdump.txt`)
were produced from the hash-verified body slices (file offset
VA-0x1000) with:

```sh
python3 -c "data=open('work/hl-node-115.bin','rb').read(); open('/tmp/xxh32/reset.bin','wb').write(data[0x61daa90-0x1000:0x61daabb-0x1000])"
objdump -D -b binary -m i386:x86-64 --adjust-vma=0x61daa90 /tmp/xxh32/reset.bin
```

(and the same extraction for `0x61daa60`, `0x61daa70`, `0x61daac0`,
`0x61dacf0`).

## Evidence

### Contract

- `createState() -> *mut state` — `malloc(0x30)` tail call (PLT
  `0x63f0b30`); the returned state is uninitialised until `reset` runs.
- `reset(state, seed: u32) -> 0` — observed register use: `rdi` =
  state, `rsi` = seed.
- `update(state, data: *const u8, n: usize) -> 0` — observed register
  use: `rdi` = state, `rsi` = data, `rdx` = n; returns 0 in every path.
- `digest(state) -> u32` — observed register use: `rdi` = state,
  `rax` = result.
- `freeState(state) -> 0` — calls `free` (PLT `0x63f0b50`), returns 0.

### State layout (0x30 bytes)

`total_len` +0x00 (u32, wrapping), `large_len` +0x04 (u32, 0/1), `v1`
+0x08, `v2` +0x0c, `v3` +0x10, `v4` +0x14, `mem` +0x18 (16 bytes),
`memsize` +0x28 (u32). After every update, `memsize == total_len % 16`
and `mem` holds the last `memsize` input bytes. The four bytes at
+0x2c..+0x2f are padding, zeroed by reset and never read.

### Behavior (observed)

- `reset`: zeroes the whole 0x30-byte state (three `movups` stores),
  then `v1 = seed+P1+P2`, `v2 = seed+P2`, `v3 = seed`, `v4 = seed-P1`
  (seed constants as one 16-byte `.rodata` vector at `0x451ae0`:
  `P1+P2` `0x24234428`, `P2` `0x85ebca77`, `0`, `-P1` `0x61c8864f`,
  added to the broadcast seed with a single `paddd` at `0x61daaae`).
- `update`: a null data pointer returns 0 with the state untouched
  (`test %rsi,%rsi; je 0x61dacc0`); a zero length is observably the
  same no-op. Otherwise `total_len += n` (u32 wrap) and `large_len`
  is set when `n > 15` or the new `total_len > 15`; when
  `memsize + n <= 15` the input is buffered in `mem` via `memcpy`
  (PLT `0x63f0a60`); when the buffer fills, the 16-byte `mem` block
  is processed with one round per lane (vectorised: `mem` lanes times
  `P2` from the `.rodata` vector at `0x452c60`, added to the lanes,
  `rol` 13, times `P1` via the shift-add chain at
  `0x61dac29..0x61dac7e`) and `memsize` is cleared; full 16-byte
  stripes are then processed in place (round
  `rol(acc + k*P2, 13) * P1` per lane, scalar loop at
  `0x61dab29..0x61daba0`); the remainder (under 16 bytes) is buffered
  and `memsize` is set to its length.
- `digest`: reads the tail from `mem` with `remaining = memsize`.
  When `large_len` is set, `h = rol(v1,1) + rol(v2,7) + rol(v3,12) +
  rol(v4,18)`, then `+ total_len`; otherwise `h = v3 + total_len + P5`.
  Then at most three 4-byte rounds (`h += read32 * P3;
  h = rol(h,17) * P4`) with the binary's unrolled countdown checks,
  at most three 1-byte rounds (`h += byte * P5; h = rol(h,11) * P1`),
  and the avalanche `h ^= h>>15; h *= P2; h ^= h>>13; h *= P3;
  h ^= h>>16`.

Primes P1 `0x9e3779b1`, P2 `0x85ebca77`, P3 `0xc2b2ae3d`, P4
`0x27d4eb2f`, P5 `0x165667b1` (32-bit immediates in update/digest, and
the two `.rodata` vectors above; sites in `result.json`).

### Check values

- `stream(b"", 0) = 0x02cc5d05` (published empty vector)
- `stream(b"a", 0) = 0x550d7456` (published vector)
- `stream(b"abc", 0) = 0x32d153ff` (published vector)
- `stream(b"123456789", 0) = 0x937bad67` (model and reference agree;
  confirmed against the system libxxhash 0.8.2 oracle)
- Two full stripes, no tail: `stream(bytes(0..31), 0) = 0x830741c1`
- Two stripes plus a 1-byte tail, fed in halves:
  `stream(bytes(0..32), 0) = 0xf1e6a545`
- Four stripes, nonzero seed, fed byte-by-byte:
  `stream(bytes(0..63), 1) = 0x55e9e5a0`
- 1024 bytes of `0xab`, fed in thirds:
  `stream(1024 x 0xab, 0) = 0x9248e481`
- `stream(b"", 1) = 0x0b2cb792` (empty input under a nonzero seed)

Development-time oracle check (not an input to the generator):
system libxxhash 0.8.2 `XXH32` one-shot and `XXH32_reset` /
`XXH32_update` / `XXH32_digest` streaming, 600 random cases each,
0 mismatches against both the model and the reference.
