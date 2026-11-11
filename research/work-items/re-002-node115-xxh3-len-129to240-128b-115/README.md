# RE-002: XXH3 len_129to240 128-bit helper (node #115)

For node #115, the `XXH3_len_129to240_128b` helper at 0x61d80a0 is the
129..240 branch of both 128-bit one-shots: `ROCKSDB_XXH3_128bits`
(0x61deab0) calls it at 0x61dedbc with seed 0, and
`ROCKSDB_XXH3_128bits_withSeed` (0x61defa0) calls it at 0x61df2c1 with
the seed argument; both pass the default 192-byte kSecret (0x97ec80)
and secretSize 192. Lengths 0..128 are reconstructed in PR #5578; the
>240 branch delegates to the hashLong helpers (0x61d8a60 for 128bits,
0x61d9bc0 for withSeed), recorded as delegation targets in
`branches.tsv`.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identity: `node115-vendor-61d80a0`
  (`XXH3_len_129to240_128b`, FDE 0x61d80a0..0x61d850e, body SHA-256
  `67af3571427e45f63f95e514c73304db47b8b7994878de07c69f58ddbc73282d`).
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller sites and the 2,400-case cross-check are
  observations. The public-algorithm identity of the helper is an
  inference, verified line by line against the disassembly, against
  native execution of the extracted bytes, and against the system
  libxxhash oracle at the entry points (see below); names beyond the
  census label, the hashLong helpers and the callers' callers are
  unknowns as identified below.
- Scope included and excluded: the helper at 0x61d80a0, lengths
  129..240 only. The >240 hashLong helpers and the 64-bit len_129to240
  variant at 0x61d7dc0 (called by the 64-bit withSecret/withSeed entry
  points, returning low64 only) are out of scope.
- Callers (whole-.text E8 scan found exactly two direct call sites, no
  lea references): `ROCKSDB_XXH3_128bits` at 0x61dedbc (seed 0) and
  `ROCKSDB_XXH3_128bits_withSeed` at 0x61df2c1 (seed argument); both
  caller bodies hash-match their census targets, see `callers.tsv`.
  The 128-bit entry points are themselves called by the
  `rocksdb::Hash2x64` wrappers (PR #5578).

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes the body and byte-compares the default
secret table before generating anything. GNU objdump 2.42 was used
only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used.

```sh
python3 tools/xxh3_len_129to240_128b115.py --verify
python3 -m unittest tests.test_xxh3_len_129to240_128b115
python3 tools/xxh3_len_129to240_128b115.py --out research/work-items/re-002-node115-xxh3-len-129to240-128b-115
(cd research/work-items/re-002-node115-xxh3-len-129to240-128b-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61d80a0-0x1000:0x61d850e-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths 129..240)

- Eight front windows, paired (input+0, input+16), (input+32,
  input+48), (input+64, input+80), (input+96, input+112) against
  secret+0..127 in step 16, each mix16B with seed. Two accumulators:
  acc starts at `len * PRIME64_1`, acc2 at 0; each pair step folds the
  pair into (acc, acc2) with the partner window's input-word sum xored
  in (the same cross-XOR idiom as the 17..128 path of the 128-bit
  one-shots). Both accumulators are then `XXH3_avalanche`'d.
- Middle windows, in pairs gated on the length: (input+128/secret+3,
  input+144/secret+19) when len > 159; (input+160/secret+35,
  input+176/secret+51) when len > 191; (input+192/secret+67,
  input+208/secret+83) when len > 223. Equivalently the pair (i, i+1)
  runs while i+1 < len//16, so the i=14 window (input+224/secret+99)
  never runs even at len 240.
- Last bytes (always run): the trailing pair is
  mix16B(input+len-16, secret+103) into acc and mix16B(input+len-32,
  secret+119) into acc2, with the seed NEGATED (the disassembly
  subtracts the seed from the low secret word and adds it to the high
  one, the opposite of every earlier mix16B), each xored with the
  partner window's input-word sum.
- `low64 = XXH3_avalanche(A + B)`, `high64 = -XXH3_avalanche(
  A * PRIME64_1 + B * PRIME64_4 + (len - seed) * PRIME64_2)`, where A
  and B are the two folded trailing accumulators. The `(len - seed)`
  term is what the body computes (`rsi = len - seed` at 0x61d8435).
- The secretSize argument (rcx) is never read: rcx is overwritten
  with the secret pointer at entry, and the body contains no other
  read of it.

Two corrections made during verification, both recorded honestly:
the tail's prime assignment first read the `0x85ebca77c2b2ae63`
immediate as PRIME64_2 and `0xc2b2ae3d27d4eb4f` as PRIME64_4, which
made every high64 wrong while low64 matched; inverting the observed
high64 through the avalanche and re-reading the movabs constants
showed the assignment is B * PRIME64_4 + (len - seed) * PRIME64_2,
the same assignment as the 17..128 path, and the corrected model
agrees with native execution on 3,000 cases. The development-time
native-execution harness first passed a truncated mmap return (ctypes
defaults to a 32-bit int return) and then a mis-encoded REX prefix
(`mov rcx, r8` written as `mov r9, rax`) that forced the seed to 0;
both were fixed in the harness only — the seed-0 results were
unaffected, which is why the second bug surfaced only in the seeded
comparison — and the fixed harness agrees with the model on 3,000
cases.

## Cases

2,400 deterministic cases in `result.json` (lengths 129..240 cycled;
12 seeds including 0, 1, 2, PRIME64_1 and 0xffffffffffffffff). The
tool's transliteration and an independent loop-form reference agree
on all 2,400 cases (0 mismatches). Check values are computed values
confirmed against the system libxxhash 0.8.2 oracle at the 128-bit
entry points (XXH3_128bits / _withSeed, lengths 129..240).

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` in a tooled environment, no
compiled-Rust comparison against the vendored xxHash, and no execution
of the node binary as a whole. The checks run here are static: digest
and body hashes, byte comparisons, disassembly transliteration, and
the two-implementation Python cross-check, plus two development-time
checks that are not inputs to the generator: native execution of the
extracted 1134 function bytes (mmap RWX + ctypes trampoline; the
function is a leaf with no calls, run against controlled buffers —
3,000 random cases, lengths 129..240, 8 seeds plus custom 192-byte
secrets, 0 mismatches) and the system libxxhash 0.8.2 oracle at the
entry points (80/80 cases, 0 mismatches).
