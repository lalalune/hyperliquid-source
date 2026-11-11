# RE-002: XXH3 128-bit one-shots (default secret and with seed)

For node #115, the two public 128-bit one-shot entry points
`ROCKSDB_XXH3_128bits` (0x61deab0) and
`ROCKSDB_XXH3_128bits_withSeed` (0x61defa0) run the public XXH3
128-bit one-shot with the default 192-byte secret: 128bits with seed
0, withSeed with the seed argument. Lengths 0..128 are reconstructed
here — the short branches (len 0, 1..3, 4..8, 9..16) and the full
17..128 mix16B sweep. The 129..240 branch delegates to the
len_129to240 helper at 0x61d80a0 and the >240 branch to the hashLong
helper (0x61d8a60 for 128bits, 0x61d9bc0 for withSeed); both are
recorded as delegation targets in `branches.tsv`.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identities: `node115-vendor-61deab0`
  (`ROCKSDB_XXH3_128bits`, FDE 0x61deab0..0x61def95, body SHA-256
  `065ec95cedd9589b57d746e3ee5b708f3946a71b95ef7f54c428ad23c3a4e077`)
  and `node115-vendor-61defa0`
  (`ROCKSDB_XXH3_128bits_withSeed`, FDE 0x61defa0..0x61df516, body
  SHA-256
  `180dccff605640ea51e5c1aa5b0c48edf317c92a5e409a64181cc2771d6a54e2`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller wrappers and the 2,400-case cross-check are
  observations. The public-algorithm identity of the branches is an
  inference, verified line by line against the disassembly and against
  the published xxh3.h formulas (see below); names beyond the census
  labels, the long branches and the callers' callers are unknowns as
  identified below.
- Scope included and excluded: both entry points, lengths 0..128 only
  (len 0, 1..3, 4..8, 9..16, 17..128). The 129..240 and >240 branches
  are excluded; their dispatch sites and delegation targets are
  recorded in `branches.tsv` (len_129to240 at 0x61d80a0, hashLong at
  0x61d8a60 / 0x61d9bc0).
- Callers (unlike the 64-bit one-shots, these two ARE called
  in-binary): `rocksdb::Hash2x64` (0x61c3db0, census
  `node115-vendor-61c3db0`) calls 128bits at 0x61c3dc0, and the seeded
  `rocksdb::Hash2x64` (0x61c3de0, census `node115-vendor-61c3de0`)
  calls withSeed at 0x61c3df0. Both wrappers store the returned high64
  through their first out-pointer argument and low64 through the
  second; see `callers.tsv`. Both wrapper bodies hash-match their
  census targets.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes both bodies and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_128bits115.py --verify
python3 -m unittest tests.test_xxh3_128bits115
python3 tools/xxh3_128bits115.py --out research/work-items/re-002-node115-xxh3-128bits-115
(cd research/work-items/re-002-node115-xxh3-128bits-115 && sha256sum -c MANIFEST.sha256)
python3 tools/verify_packets.py
```

Byte extraction (the ELF section headers misstate the `.text` file
offset as VA-0x10000; the hash-verified `.text` bytes sit at
VA-0x1000, and the `.rodata` table at file offset == VA):

```sh
python3 -c "
import hashlib
data = open('work/hl-node-115.bin','rb').read()
print(hashlib.sha256(data).hexdigest())
print(hashlib.sha256(data[0x61deab0-0x1000:0x61def95-0x1000]).hexdigest())
print(hashlib.sha256(data[0x61defa0-0x1000:0x61df516-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths 0..128)

- len 0: `(rrmxmx(seed ^ (secret[64:72] ^ secret[72:80])),
  rrmxmx(seed ^ (secret[80:88] ^ secret[88:96])))`. 128bits returns
  the two folded constants directly (`0x6001c324468d497f` /
  `0x99aa06d3014798d8`); withSeed folds the word xors into the
  immediates `0x682e908a3037f8b4` and `0x9655d30bd1a77d49`.
- len 1..3: `combinedl = data[len-1] | data[0]<<16 | len<<8 |
  data[len>>1]<<24`; `combinedh = rotl32(bswap32(combinedl), 13)`;
  `bitflipl = (read32(secret) ^ read32(secret+4)) + seed`;
  `bitfliph = (read32(secret+8) ^ read32(secret+12)) - seed`;
  `(rrmxmx(combinedl ^ bitflipl), rrmxmx(combinedh ^ bitfliph))`.
  withSeed folds the word xors into the immediates `0x87275a9b` and
  `0x302c208b`.
- len 4..8: `seed_t = seed ^ (swap32(seed as u32) << 32)`; `input64 =
  read32(data) + (read32(data+len-4) << 32)`; `bitflip =
  (read64(secret+16) ^ read64(secret+24)) + seed_t`; `(lo, hi) =
  mult128(input64 ^ bitflip, PRIME64_1 + (len<<2))`; `hi += lo<<1`;
  `lo ^= hi>>3`; `lo = xorshift(lo,35) * 0x9FB21C651E98DF25`
  xorshifted by 28; `hi = XXH3_avalanche(hi)`. withSeed folds the
  secret-word xor into the immediate `0xc4f023344dc994ac`.
- len 9..16: `bitflipl = (secret[32:40] ^ secret[40:48]) - seed`;
  `bitfliph = (secret[48:56] ^ secret[56:64]) + seed`; `A =
  read64(data) ^ read64(data+len-8) ^ bitflipl`; `(lo1, hi1) =
  mult128(A, PRIME64_1)`; `C = (u32(read64(data+len-8) ^ bitfliph) *
  0x85EBCA76) + (read64(data+len-8) ^ bitfliph) + hi1`; `low2 = (lo1 +
  ((len-1)<<54)) ^ bswap64(C)`; `(lo2, hi2) = mult128(low2,
  PRIME64_2)`; `D = C * PRIME64_2 + hi2`; `(XXH3_avalanche(lo2),
  XXH3_avalanche(D))`. withSeed folds the word xors into the
  immediates `0x59973f0033362349` (- seed) and `0xc202797692d63d58`
  (+ seed).
- len 17..128: two mix16B accumulators sweep the windows from the
  largest inward (`input+48/secret+96` with `input+len-64/secret+112`,
  then `input+32/secret+64` with `input+len-48/secret+80`, then
  `input+16/secret+32` with `input+len-32/secret+48`), each step
  folding the pair into `(acc, acc2)` with the input-word sums xored
  in; the trailing mix16B pair is `input+0/secret+0` and
  `input+len-16/secret+16`. `low64 = XXH3_avalanche(A + B)`,
  `high64 = -XXH3_avalanche(A * PRIME64_1 + B * PRIME64_4 +
  (len - seed) * PRIME64_2)`, where A and B are the two folded
  trailing mixes. The `(len - seed)` term is what the withSeed body
  computes (`rsi = len - seed` at 0x61df1b5); 128bits uses `len`.
  Every mix16B immediate in both bodies is a raw kSecret word
  (offsets 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104,
  112, 120), verified by byte comparison.

Two corrections made during verification, both recorded honestly:
the len-4..8 input packing first looked like the 64-bit branch's
packing (`read32(data+len-4)` low, `read32(data)` high); the system
xxHash oracle disagreed on lengths 5..8, and re-reading the
disassembly showed the 128-bit branch packs the first word low and
the last word high — the public packing, opposite to the 64-bit
branch's. The model was corrected before submission, and the
corrected transliteration agrees with the oracle on 3,000 cases
(lengths 0..128, 8 seeds, 0 mismatches). The len-0 branch first
looked like a plain avalanche; the withSeed body shows the rrmxmx
sequence, and `rrmxmx` of the two folded immediates reproduces the
seed-0 constants exactly.

## Cases

2,400 deterministic cases in `result.json` (1,200 per entry point;
lengths 0..128 cycled; withSeed over 12 seeds). The tool's
transliteration and an independent reference written from the
published formulas agree on all 2,400 cases (0 mismatches). Published
anchor: `XXH3_128bits(b"", 0) = (0x6001c324468d497f,
0x99aa06d3014798d8)` through both entry points.

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary. The checks run here are static: digest and body
hashes, byte comparisons, disassembly transliteration, and the
two-implementation Python cross-check with the published anchor, plus
a development-time check against the system libxxhash 0.8.2 oracle
(3,000 cases, 0 mismatches) that is not an input to the generator.
