# RE-002: node #115 RocksDB BijectiveHash2x64

This packet reconstructs one bounded node #115 behavior: the
bijective 128-bit hash `rocksdb::BijectiveHash2x64` at `0x61c3e10`
(FDE `0x61c3e10..0x61c3f55`, 325 bytes) and its seed-0 adapter at
`0x61c3f60` (FDE `0x61c3f60..0x61c3f71`, 17 bytes). The main body is a
vendor-census entry (librocksdb-sys 0.11.0+8.1.1,
`_ZN7rocksdb17BijectiveHash2x64EmmmPmS0_`, id
`node115-vendor-61c3e10`, whose `target_body_sha256` matches the body
hash in `result.json`; the census also records `raw_equal` true
against the vendored source body). The adapter has no census record
and is pinned by FDE extent and disassembly only. The two Hash2x64
wrappers next door (`0x61c3db0`/`0x61c3de0`, census
`_ZN7rocksdb8Hash2x64E...`) are NOT part of this packet; they call
the 128-bit one-shots reconstructed in PR #5578 and only share
caller FDEs with the adapter.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the immediates,
  the transfer targets, the caller census, and the two output
  assignments are observations. The C++ symbol attribution comes
  from the vendor census. The prose names for the three inputs
  (`a`, `b`, `c`) describe their observed roles; `c` behaves like
  a seed (it enters only through `K_SEED - c`, and the adapter
  fixes it to 0). The "bijective" name is the census symbol's
  claim: the packet verifies the necessary condition (200,000
  random `(a, b)` pairs at fixed `c` give distinct outputs, and a
  20,000-pair check runs in the test suite) but does NOT prove
  bijectivity by exhibiting an inverse.
- Scope included: the main body end to end, the seed-0 adapter,
  the single call site of each, and the 2400-case cross-check
  between the transliteration and the structured model. Excluded:
  any claim about the callers beyond the census (the adapter's
  caller FDE `0x61b0260` also calls both Hash2x64 wrappers, which
  this packet does not reconstruct), any claim about the original
  source repository or compiler, and any claim that the two
  outputs are independent (they share the mixed word `v`).

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/bijective_hash2x64_115.py --verify
python3 tools/bijective_hash2x64_115.py --out research/work-items/re-002-node115-bijective-hash2x64-115
python3 -m unittest tests.test_bijective_hash2x64_115
(cd research/work-items/re-002-node115-bijective-hash2x64-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

The whole-function disassembly excerpts
(`bijective_hash2x64_115.objdump.txt`,
`seed0_adapter_115.objdump.txt`) were produced from the hash-verified
body slices (file offset VA-0x1000) with:

```sh
python3 -c "data=open('work/hl-node-115.bin','rb').read(); open('/tmp/bij/body.bin','wb').write(data[0x61c3e10-0x1000:0x61c3f55-0x1000])"
objdump -D -b binary -m i386:x86-64 --adjust-vma=0x61c3e10 /tmp/bij/body.bin
```

(and the same extraction for `0x61c3f60..0x61c3f71`).

## Evidence

### Contract

- `bijective_hash2x64(a: u64, b: u64, c: u64, out1: *mut u64, out2: *mut u64) -> ()`
  — observed register use: `rdi` = a, `rsi` = b, `rdx` = c,
  `rcx` = out1, `r8` = out2. No return value; both outputs are
  stored through the out-pointers.
- `seed0_adapter(a: u64, b: u64, out1: *mut u64, out2: *mut u64) -> ()`
  — `rdi` = a, `rsi` = b, `rdx` = out1, `rcx` = out2; moves the
  out-pointers into place, zeroes the third input, tail-jumps to
  the main body.

### Model

All arithmetic is mod 2^64. Write `s = (b ^ a) ^ (0x59973f0033362349 - c)`.

Stage 1 — four 32-bit products from `s` (low half `lo`, high half
`hi`): `p = lo * 0x9e3779b1`, `q = lo * 0x85ebca87`,
`r = 0x85ebca87 * hi`, `t = hi * 0x9e3779b1`; the combined word is
`r + (q >> 32) + (p & 0xffffffff)`.

Stage 2 — pack the halves: `pack = ((combined & 0xffffffff) << 32)
| (q & 0xffffffff)`, then `pack += 0x03c0000000000000`. The second
mix is `m = (0xc202797692d63d58 + c) ^ a` and `v = (m & 0xffffffff)
* 0x85ebca76 + t + m + (p >> 32) + (combined >> 32)`; the packed
word is xored with `bswap(v)`.

Stage 3 — from the packed word `w` (low half `wlo`, high half
`whi`): `d = whi * 0x27d4eb4f + ((wlo * 0x27d4eb4f) >> 32) +
(wlo * 0xc2b2ae3d & 0xffffffff)`; `X = ((d & 0xffffffff) << 32) |
((wlo * 0x27d4eb4f) & 0xffffffff)`; `Y = 0xc2b2ae3d27d4eb4f * v +
whi * 0xc2b2ae3d + ((wlo * 0xc2b2ae3d) >> 32) + (d >> 32)`.
`out2 = XXH3_avalanche(X)` (stored through r8) and
`out1 = XXH3_avalanche(Y)` (stored through rcx), where
`XXH3_avalanche(h) = h ^ (h >> 37); h *= 0x165667919e3779f9;
h ^= h >> 32`. Note the avalanche multiplier here is
`0x165667919e3779f9` (the XXH3 one), distinct from PRIME64_3
`0x165667b19e3779f9` used by the XXH3 mergeAccs helper.

The `0x85ebca87` constant is PRIME32_2 + 0x10 and `0x85ebca76` is
PRIME32_2 - 1; `0x27d4eb4f` is the low 32 bits of PRIME64_2
`0xc2b2ae3d27d4eb4f`, whose high 32 bits are `0xc2b2ae3d`. The immediates
`0x59973f0033362349`, `0xc202797692d63d58` and
`0x03c0000000000000` are recorded as observed constants; no source
meaning is claimed for them.

### Caller census

Whole-`.text` E8/E9 scan, verified by disassembly; no LEA
references to either function:

- `bijective_hash2x64`: exactly one call site, the E9 tail-jump
  at `0x61c3f6c` in the seed-0 adapter (third input zeroed).
- `seed0_adapter`: exactly one call site, the E8 call at
  `0x61b02a5` in FDE `0x61b0260` (which also calls the Hash2x64
  wrappers at `0x61b016d` and `0x61b01c1`).

### Cases

2,400 deterministic cases (boundary triples over twelve u64
edge values times three `c` values, plus random triples):
transliteration vs the independently structured model, 0
mismatches; aggregate SHA-256 in `result.json`. A 200,000-pair
no-collision spot-check at fixed `c = 0` (development-time only,
not an input to the generator) found no duplicate outputs.
