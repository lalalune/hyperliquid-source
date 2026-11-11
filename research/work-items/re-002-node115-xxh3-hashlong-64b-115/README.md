# RE-002: XXH3 64-bit hashLong helpers (node #115)

For node #115, the `XXH3_hashLong_64b_default` helper at 0x61d8510 and
the `XXH3_hashLong_64b_withSeed` helper at 0x61d9090 are the len > 240
branch of both 64-bit one-shots: `ROCKSDB_XXH3_64bits` (0x61db650)
tail-jumps to the default helper at 0x61db6d6 with seed 0, and
`ROCKSDB_XXH3_64bits_withSeed` (0x61dc0c0) tail-jumps to the withSeed
helper at 0x61dc14e with the seed argument; both pass the default
192-byte kSecret (0x97ec80). Lengths 0..128 are reconstructed in PR
#5449 (short branches); 129..240 go through the len_129to240 helper
at 0x61d7dc0 (out of scope here). With these two helpers the 64-bit
one-shots are reconstructed for every length except the withSecret
inline >240 path at 0x61db9ff, which is a different body (it runs
against a caller-supplied secret, so it cannot use the default-secret
constprop helpers).

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identities: `node115-vendor-61d8510`
  (`XXH3_hashLong_64b_default.constprop.0`, FDE 0x61d8510..0x61d8a53,
  body SHA-256
  `56fac98e9537653843403355bc80a6c5e389fffcacabf142817df13110f7c195`)
  and `node115-vendor-61d9090`
  (`XXH3_hashLong_64b_withSeed.constprop.0`, FDE 0x61d9090..0x61d9bb6,
  body SHA-256
  `ade028011ceabba51d386110d42c6441eb91a66b1e5da2a7db9d9abe6896e64b`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller sites and the 2,400-case cross-check are
  observations. The public-algorithm identity of the helpers is an
  inference, verified line by line against the disassembly and against
  the system libxxhash oracle at the entry points (see below); names
  beyond the census labels, the 128-bit hashLong siblings and the
  callers' callers are unknowns as identified below.
- Scope included and excluded: the two helpers at 0x61d8510 and
  0x61d9090, lengths > 240 only. The 128-bit hashLong pair (0x61d8a60
  / 0x61d9bc0, PR #5598), the 64-bit len_129to240 variant at 0x61d7dc0
  and the withSecret inline >240 path at 0x61db9ff are out of scope.
- Callers (whole-.text E8/E9 scan found exactly two tail-jump sites,
  no E8 calls, no lea references): `ROCKSDB_XXH3_64bits` at 0x61db6d6
  (seed 0) and `ROCKSDB_XXH3_64bits_withSeed` at 0x61dc14e (seed
  argument); both caller bodies hash-match their census targets, see
  `callers.tsv`.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes both bodies and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_hashlong_64b115.py --verify
python3 -m unittest tests.test_xxh3_hashlong_64b115
python3 tools/xxh3_hashlong_64b115.py --out research/work-items/re-002-node115-xxh3-hashlong-64b-115
(cd research/work-items/re-002-node115-xxh3-hashlong-64b-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61d8510-0x1000:0x61d8a53-0x1000]).hexdigest())
print(hashlib.sha256(data[0x61d9090-0x1000:0x61d9bb6-0x1000]).hexdigest())
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
- `result = mergeAcc(acc, secret + 11, len * PRIME64_1)`, where
  mergeAcc folds four 128-bit products (acc[2i] ^ secret[16i]) *
  (acc[2i+1] ^ secret[16i+8]) low ^ high, then XXH3_avalanche. This
  is the same merge as the low64 half of the 128-bit pair (PR #5598);
  the high64 merge is dropped.
- withSeed with seed != 0 builds a 192-byte custom secret on the stack
  (rsp + 0x40): word 2i is kSecret[2i] + seed, word 2i+1 is
  kSecret[2i+1] - seed, then runs the identical loop against that
  secret. With seed == 0 it runs the default path. The nbBlocks == 0
  continuations live in cold blocks at 0x61d9b58 (seed 0) and 0x61d9b88
  (seed != 0).

## Cases

2,400 deterministic cases in `result.json` (1,200 per entry point;
lengths 241..2048 cycled; 12 seeds including 0, 1, 2, PRIME64_1 and
0xffffffffffffffff). The tool's transliteration and an independent
loop-form reference agree on all 2,400 cases (0 mismatches). Check
values are computed values confirmed against the system libxxhash
0.8.2 oracle at the 64-bit entry points (XXH3_64bits /
XXH3_64bits_withSeed, lengths 241..5000, 600/600, 0 mismatches).
They equal the low64 halves of the 128-bit pair's check values (PR
#5598), as the 64-bit merge is the same low64 merge.

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary as a whole. The checks run here are static: digest
and body hashes, byte comparisons, disassembly transliteration, and
the two-implementation Python cross-check, plus one development-time
check that is not an input to the generator: the system libxxhash
0.8.2 oracle at the entry points (600/600 cases, 0 mismatches). No
native-execution check was repeated for the 64-bit pair; the same body
shape was checked by native execution of the extracted bytes for the
128-bit pair (PR #5598, 120 cases, 0 mismatches).
