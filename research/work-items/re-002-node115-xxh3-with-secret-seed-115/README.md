# RE-002: XXH3 one-shot short branches with a caller secret and with a seed

For node #115, the two public one-shot entry points
`ROCKSDB_XXH3_64bits_withSecret` (0x61db940) and
`ROCKSDB_XXH3_64bits_withSeed` (0x61dc0c0) run the public XXH3
len-0..16 branches with the seed folded into the secret instead of a
custom-secret array: withSecret uses the caller-supplied secret with
seed 0, withSeed uses the default 192-byte secret with the seed. Only
lengths 0..16 are reconstructed here — the same scope as the
default-secret short branches already reconstructed for the type-4 arm
of `ComputeBuiltinChecksumWithLastByte` (0x616bd60).

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identities: `node115-vendor-61db940`
  (`ROCKSDB_XXH3_64bits_withSecret`, FDE 0x61db940..0x61dc0bc, body
  SHA-256
  `af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58`)
  and `node115-vendor-61dc0c0` (`ROCKSDB_XXH3_64bits_withSeed`, FDE
  0x61dc0c0..0x61dc401, body SHA-256
  `781a95efaa091e8581fa6cc2cda7770a5b3aa356678e40a07f33ec7922fd088f`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates and the 2,400-case cross-check are observations. The
  public-algorithm identity of the short branches is an inference,
  verified line by line against the disassembly and against the
  published xxh3.h source (see below); names beyond the census labels,
  callers and the long branches are unknowns as identified below.
- Scope included and excluded: both entry points, lengths 0..16 only
  (len 0, 1..3, 4..8, 9..16). The 17..128, 129..240 and >240 branches
  are excluded; their dispatch sites and delegation targets are
  recorded in `branches.tsv` (len_17to128 inline, len_129to240 at
  0x61d7dc0, hashLong_withSecret inline SIMD, hashLong_withSeed at
  0x61d9090). No caller contract is claimed: a whole-.text scan found
  no direct call site, lea reference or PLT reference to either
  function, and the binary is stripped.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes both bodies and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_with_secret_seed115.py --verify
python3 -m unittest tests.test_xxh3_with_secret_seed115
python3 tools/xxh3_with_secret_seed115.py --out research/work-items/re-002-node115-xxh3-with-secret-seed-115
(cd research/work-items/re-002-node115-xxh3-with-secret-seed-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61db940-0x1000:0x61dc0bc-0x1000]).hexdigest())
print(hashlib.sha256(data[0x61dc0c0-0x1000:0x61dc401-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths 0..16)

- len 0: `XXH64_avalanche(seed ^ (secret[56:64] ^ secret[64:72]))`.
- len 1..3: `combined = data[len-1] | data[0]<<16 | len<<8 |
  data[len>>1]<<24`; `bitflip = (read32(secret) ^
  read32(secret+4)) + seed`; `XXH64_avalanche(combined ^ bitflip)`.
- len 4..8: `seed ^= swap32(seed as u32) << 32`; `input64 =
  read32(data+len-4) + (read32(data) << 32)`; `bitflip =
  (read64(secret+8) ^ read64(secret+16)) - seed`;
  `rrmxmx(input64 ^ bitflip, len)`.
- len 9..16: `bitflip1 = (secret[24] ^ secret[32]) + seed`;
  `bitflip2 = (secret[40] ^ secret[48]) - seed`; `lo = read64(data)
  ^ bitflip1`; `hi = read64(data+len-8) ^ bitflip2`;
  `XXH3_avalanche(len + bswap64(lo) + hi + mul128_fold64(lo, hi))`.

withSecret always uses seed 0 and reads the four secret windows from
its caller-supplied secret (offsets 0x18/0x20 and 0x28/0x30 for the
9..16 branch). withSeed folds the default-secret word xors into
immediates: `0x6782737bea4239b9` (+ seed) and `0xaf56bc3b0996523a`
(- seed) for 9..16, `0xc73ab174c5ecd5a2` for 4..8,
`0x8726f9105dc21ddc` for len 0, `0x87275a9b` for 1..3 — each verified
against the 192-byte default secret at `.rodata` 0x97ec80. The
withSecret 4th argument (secretSize) is not read on the short path.

Two corrections made during verification, both recorded honestly:
the len-4..8 seed transform and input packing first looked like a
vendored divergence from public xxHash; a check against the published
xxh3.h source (v0.7.3, `XXH3_len_4to8_64b`) showed the binary matches
the public formulas exactly (`seed ^= swap32(seed) << 32`,
`input64 = input2 + (input1 << 32)`), and the model was corrected
before submission. The 17..128 branch's trailing mix reads
secret+16/secret+24; no public-source identity is claimed for that
branch (out of scope).

## Cases

2,400 deterministic cases in `result.json` (1,200 per entry point;
lengths 0..16 cycled; withSecret over the default secret plus 7
seeded-random 192-byte secrets; withSeed over 12 seeds). The tool's
transliteration and an independent reference written from the
published formulas agree on all 2,400 cases (0 mismatches). Published
anchors: `XXH3_64bits(b"", 0) = 0x2d06800538d394c2` and
`XXH3_64bits(b"a", 0) = 0xe6c632b61e964e1f` through both entry points.

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary. The checks run here are static: digest and body
hashes, byte comparisons, disassembly transliteration, and the
two-implementation Python cross-check with published anchors.
