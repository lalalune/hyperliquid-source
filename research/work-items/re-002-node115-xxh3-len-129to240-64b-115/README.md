# RE-002: XXH3 len_129to240 64-bit helper (node #115)

For node #115, the `XXH3_len_129to240_64b` helper at 0x61d7dc0 is the
129..240 branch of all three 64-bit one-shots:
`ROCKSDB_XXH3_64bits` (0x61db650) tail-jumps to it at 0x61db8cf with
seed 0, `ROCKSDB_XXH3_64bits_withSecret` (0x61db940) tail-jumps to it
at 0x61dc03a with seed 0 and the caller's secret, and
`ROCKSDB_XXH3_64bits_withSeed` (0x61dc0c0) tail-jumps to it at
0x61dc384 with the seed argument; the first and third pass the
default 192-byte kSecret (0x97ec80) and secretSize 192. Each
dispatcher compares len against 0x80 then 0xf0 (240) and takes this
branch only for 128 < len <= 240; len > 240 goes to the hashLong
helpers (0x61d8510 / 0x61d9090, PR #5601) or, for withSecret, to the
inlined >240 path at 0x61db9ff. With this packet the 64-bit one-shots
are now reconstructed for every length: 0..128 in PR #5449 (short
branches), 129..240 here, >240 in PR #5601.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identity: `node115-vendor-61d7dc0`
  (`XXH3_len_129to240_64b`, FDE 0x61d7dc0..0x61d8095, body SHA-256
  `7c681cb1552f7259c1b1625b42d79cdfec1a6146ed9aa9d27ece1d7d6ac071d1`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller sites and the 2,400-case cross-check are
  observations. The public-algorithm identity of the helper is an
  inference, verified line by line against the disassembly, against
  native execution of the extracted bytes, and against the system
  libxxhash oracle at the entry points (see below); names beyond the
  census label, the hashLong helpers and the callers' callers are
  unknowns as identified below.
- Scope included and excluded: the helper at 0x61d7dc0, lengths
  129..240 only. The >240 hashLong helpers, the withSecret inlined
  >240 path and the 128-bit len_129to240 variant at 0x61d80a0 (PR
  #5595) are out of scope.
- Callers (whole-binary E8 and E9 scans found exactly three transfer
  sites, all E9 tail-jumps, no E8 calls, no lea references):
  `ROCKSDB_XXH3_64bits` at 0x61db8cf (seed 0),
  `ROCKSDB_XXH3_64bits_withSecret` at 0x61dc03a (seed 0, caller
  secret), `ROCKSDB_XXH3_64bits_withSeed` at 0x61dc384 (seed
  argument); all three caller bodies hash-match their census targets,
  see `callers.tsv`. Correction to the prior run note: the withSeed
  transfer is the E9 at 0x61dc384, reached via the 0x61dc378 setup
  block -- 0x61dc378 itself is a `mov`, not a transfer -- and the
  withSecret tail-jump at 0x61dc03a was not listed in that note.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes the body and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_len_129to240_64b115.py --verify
python3 -m unittest tests.test_xxh3_len_129to240_64b115
python3 tools/xxh3_len_129to240_64b115.py --out research/work-items/re-002-node115-xxh3-len-129to240-64b-115
(cd research/work-items/re-002-node115-xxh3-len-129to240-64b-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61d7dc0-0x1000:0x61d8095-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths 129..240)

- Eight front windows, input+0..112 against secret+0..127 in step
  16, each mix16B with seed, summed into acc starting at
  `len * PRIME64_1` (movabs 0x9e3779b185ebca87 at 0x61d7dc0). The sum
  is then `XXH3_avalanche`'d (multiplier 0x165667919e3779f9).
- Middle windows, one per round i = 8 .. nbRounds-1
  (nbRounds = len >> 4): mix16B(input+16*i, secret+16*(i-8)+3),
  i.e. (input+128/secret+3), (input+144/secret+19),
  (input+160/secret+35), (input+176/secret+51),
  (input+192/secret+67), (input+208/secret+83),
  (input+224/secret+99). The gates are cmp $0x8..$0xd,$0xf against
  %r10d; the i=14 window runs only at len 240.
- Trailing window (always runs): mix16B(input+len-16, secret+119),
  where 119 = XXH3_SECRET_SIZE_MIN (136) - 17.
- `return XXH3_avalanche(avalanche(front) + trailing + middles)`.
  The disassembly folds the trailing mix first (r9 at 0x61d7f05)
  and the middle mixes after; the reference folds middles first --
  addition commutes, so agreement validates the sum.
- The secretSize argument (rcx) is never read: rcx is overwritten
  with len * PRIME64_1 at entry. The function is a leaf: no calls,
  one push/pop of %r12 (never otherwise used; kept for stack
  alignment).

## Cases

2,400 deterministic cases in `result.json` (lengths 129..240 cycled;
12 seeds including 0, 1, 2, PRIME64_1 and 0xffffffffffffffff). The
tool's transliteration and an independent loop-form reference agree
on all 2,400 cases (0 mismatches). Check values are computed values
confirmed against the system libxxhash 0.8.2 oracle at the 64-bit
entry points (XXH3_64bits_withSeed, lengths 129..240, 6 seeds:
672/672; XXH3_64bits_withSecret with custom 192-byte secrets:
100/100).

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary as a whole. The checks run here are static: digest
and body hashes, byte comparisons, disassembly transliteration, and
the two-implementation Python cross-check, plus two development-time
checks that are not inputs to the generator: native execution of the
extracted 725 function bytes (mmap RWX + ctypes trampoline; the
function is a leaf with no calls, run against controlled buffers --
896 default-secret cases and 400 custom-secret cases, 0 mismatches)
and the system libxxhash 0.8.2 oracle at the entry points (772/772
cases, 0 mismatches).
