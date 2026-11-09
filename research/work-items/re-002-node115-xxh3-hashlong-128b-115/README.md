# RE-002: XXH3 128-bit hashLong helpers (node #115)

For node #115, the `XXH3_hashLong_128b_default` helper at 0x61d8a60 and
the `XXH3_hashLong_128b_withSeed` helper at 0x61d9bc0 are the len > 240
branch of both 128-bit one-shots: `ROCKSDB_XXH3_128bits` (0x61deab0)
calls the default helper at 0x61def10 with seed 0, and
`ROCKSDB_XXH3_128bits_withSeed` (0x61defa0) calls the withSeed helper
at 0x61df430 with the seed argument; both pass the default 192-byte
kSecret (0x97ec80). Lengths 0..128 are reconstructed in PR #5578 and
129..240 in PR #5595; with these two helpers the 128-bit one-shots are
reconstructed for every length.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identities: `node115-vendor-61d8a60`
  (`XXH3_hashLong_128b_default.constprop.0`, FDE 0x61d8a60..0x61d908a,
  body SHA-256
  `f3abf2320e74a3ac90b6320da89facb1313cf9ca7eeec6aed9cb1f2399afcd11`)
  and `node115-vendor-61d9bc0`
  (`XXH3_hashLong_128b_withSeed.constprop.0`, FDE 0x61d9bc0..0x61da8a3,
  body SHA-256
  `3d4198d467744a6abd1c8de350c15e51fb00e76a6936255110d065f1eec23708`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller sites and the 2,400-case cross-check are
  observations. The public-algorithm identity of the helpers is an
  inference, verified line by line against the disassembly, against
  native execution of the extracted bytes, and against the system
  libxxhash oracle at the entry points (see below); names beyond the
  census labels, the 64-bit hashLong siblings and the callers' callers
  are unknowns as identified below.
- Scope included and excluded: the two helpers at 0x61d8a60 and
  0x61d9bc0, lengths > 240 only. The 64-bit hashLong pair (0x61d8510
  default, 0x61d9090 withSeed) and the 64-bit len_129to240 variant at
  0x61d7dc0 are out of scope.
- Callers (whole-.text E8 scan found exactly two direct call sites, no
  lea references): `ROCKSDB_XXH3_128bits` at 0x61def10 (seed 0) and
  `ROCKSDB_XXH3_128bits_withSeed` at 0x61df430 (seed argument); both
  caller bodies hash-match their census targets, see `callers.tsv`.
  The 128-bit entry points are themselves called by the
  `rocksdb::Hash2x64` wrappers (PR #5578).

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes both bodies and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_hashlong_128b115.py --verify
python3 -m unittest tests.test_xxh3_hashlong_128b115
python3 tools/xxh3_hashlong_128b115.py --out research/work-items/re-002-node115-xxh3-hashlong-128b-115
(cd research/work-items/re-002-node115-xxh3-hashlong-128b-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61d8a60-0x1000:0x61d908a-0x1000]).hexdigest())
print(hashlib.sha256(data[0x61d9bc0-0x1000:0x61da8a3-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths > 240)

- Eight accumulators, initialised to XXH3_INIT_ACC = {PRIME32_3,
  PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5,
  PRIME32_1} from the .rodata constants at 0x455960/0x455950/0x453a30/
  0x4525e0.
- Full blocks of 16 stripes (1024 bytes): nbBlocks = (len-1) >> 10.
  Each stripe is one accumulate_512 over 64 input bytes against a
  64-byte secret window sliding 8 bytes per stripe (secret + s*8,
  restarting at the default secret each block). After each block,
  scrambleAcc with the secret + 128 window.
- Remaining stripes: ((len-1) & 0x3ff) >> 6 stripes from the block
  boundary, secret restarting at kSecret + 0.
- Last stripe (always runs): accumulate_512 over input[len-64..len)
  against secret + 121.
- `low64 = mergeAccs(acc, secret + 11, len * PRIME64_1)`,
  `high64 = mergeAccs(acc, secret + 117, ~(len * PRIME64_2))`, where
  mergeAccs folds four 128-bit products (acc[2i] ^ secret[16i]) *
  (acc[2i+1] ^ secret[16i+8]) low ^ high, then XXH3_avalanche.
- withSeed with seed != 0 builds a 192-byte custom secret on the stack
  (rsp + 0x50): word 2i is kSecret[2i] + seed, word 2i+1 is
  kSecret[2i+1] - seed, then runs the identical loop against that
  secret. With seed == 0 it runs the default path.

One correction made during verification, recorded honestly: the
accumulator init first read the .rodata word at 0x453a30+8 as
0x27D4EB2F (PRIME32_4), which made every hash wrong while the
structure matched. Re-reading the bytes (77 ca eb 85, little-endian
0x85EBCA77 = PRIME32_2, the same value the merged streaming packet
uses for ACC_INIT[5]) and correcting it made the model agree with
native execution and the oracle on 600 oracle cases plus 120 native
cases, 0 mismatches.

## Cases

2,400 deterministic cases in `result.json` (1,200 per entry point;
lengths 241..2048 cycled; 12 seeds including 0, 1, 2, PRIME64_1 and
0xffffffffffffffff). The tool's transliteration and an independent
loop-form reference agree on all 2,400 cases (0 mismatches). Check
values are computed values confirmed against the system libxxhash
0.8.2 oracle at the 128-bit entry points (XXH3_128bits / _withSeed,
lengths 241..5000).

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary as a whole. The checks run here are static: digest
and body hashes, byte comparisons, disassembly transliteration, and
the two-implementation Python cross-check, plus two development-time
checks that are not inputs to the generator: native execution of the
extracted function bytes (a small C harness mapping the code and
.rodata pages at the binary's own VAs; the functions are leaves with
no calls; 120 random cases across both entry points, lengths
241..4096, 0 mismatches) and the system libxxhash 0.8.2 oracle at the
entry points (600/600 cases, 0 mismatches).
