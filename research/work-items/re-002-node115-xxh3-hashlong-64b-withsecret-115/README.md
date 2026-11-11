# RE-002: XXH3 64-bit hashLong withSecret inline path (node #115)

For node #115, the len > 240 branch of `ROCKSDB_XXH3_64bits_withSecret`
at 0x61db940 is an inline SIMD hashLong at 0x61db9ff..0x61dbeac (1197
bytes). Unlike the default and withSeed one-shots, withSecret does NOT
call the hashLong helpers at 0x61d8510/0x61d9090 (PR #5601): it runs
against a caller-supplied secret, so its long branch is inlined inside
the entry point itself. Lengths 0..128 are reconstructed in PR #5449
(short branches and the 17..128 sweep); 129..240 tail-jumps to the
len_129to240_64b helper at 0x61d7dc0 (PR #5606, E9 at 0x61dc03a after
cmp $0xf0 at 0x61db9f2). With this packet the withSecret entry point --
and therefore all three 64-bit one-shots -- is reconstructed for every
length.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identity: `node115-vendor-61db940` (FDE 0x61db940..0x61dc0bc,
  body SHA-256
  `af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58`);
  the inline range 0x61db9ff..0x61dbeac has SHA-256
  `995aac1662f7d20f60d96a1662f22a1cc8a9ca583ece958af4930aca4ed937db`.
- Claim status: ELF contents, dispatch sites, secret offsets, folded
  immediates, caller scan and the 2,400-case cross-check are
  observations. The public-algorithm identity of the path is an
  inference, verified line by line against the disassembly and against
  the system libxxhash oracle at the entry point (see below); names
  beyond the census label, the hashLong siblings and the callers'
  callers are unknowns as identified below.
- Scope included and excluded: the inline path at 0x61db9ff, lengths >
  240 only, secretSize >= 136. The 128-bit hashLong pair (0x61d8a60 /
  0x61d9bc0, PR #5598), the 64-bit hashLong helpers (0x61d8510 /
  0x61d9090, PR #5601) and the len_129to240_64b helper (0x61d7dc0, PR
  #5606) are out of scope.
- Callers: none in-binary. A whole-.text E8 scan and rip-relative lea
  scan find no call site or reference to 0x61db940 (the binary is
  stripped); see `callers.tsv`.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes the parent body and the inline range and
byte-compares the INIT_ACC constants and the scramble multiplier before
generating anything. GNU objdump 2.42 was used only for human
inspection; no binutils output is an input to the generator. No node or
visor execution, networking, keys or chain actions were used.

```sh
python3 tools/xxh3_hashlong_64b_withsecret115.py --verify
python3 -m unittest tests.test_xxh3_hashlong_64b_withsecret115
python3 tools/xxh3_hashlong_64b_withsecret115.py --out research/work-items/re-002-node115-xxh3-hashlong-64b-withsecret-115
(cd research/work-items/re-002-node115-xxh3-hashlong-64b-withsecret-115 && sha256sum -c MANIFEST.sha256)
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
print(hashlib.sha256(data[0x61db9ff-0x1000:0x61dbeac-0x1000]).hexdigest())
print(data[0x97ec80:0x97ec80+16].hex())
"
```

## Model (lengths > 240, secretSize >= 136)

- Eight accumulators, initialised to XXH3_INIT_ACC = {PRIME32_3,
  PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5,
  PRIME32_1} from the .rodata constants at 0x455960/0x455950/0x453a30/
  0x4525e0, the same addresses the default helper loads.
- The secret limit is secretSize - 64 (lea -0x40(%rcx),%rcx at
  0x61db9ff). nbStripesPerBlock = secretLimit >> 3, blockBytes =
  nbStripesPerBlock << 6 (16 stripes / 1024 bytes for a 192-byte secret;
  9 / 576 for 136; 24 / 1536 for 256). nbBlocks = (len-1) / blockBytes.
- Full blocks: each stripe is one accumulate_512 over 64 input bytes
  against a 64-byte secret window sliding 8 bytes per stripe (secret +
  s*8, restarting at the caller secret each block). After each block,
  scrambleAcc with the secret + secretLimit window.
- Remaining stripes: ((len-1) % blockBytes) >> 6 stripes from the block
  boundary, secret restarting at secret + 0.
- Last stripe (always runs): accumulate_512 over input[len-64..len)
  against secret + secretLimit - 7.
- `result = mergeAcc(acc, secret + 11, len * PRIME64_1)`, where
  mergeAcc folds four 128-bit products (acc[2i] ^ secret[16i]) *
  (acc[2i+1] ^ secret[16i+8]) low ^ high, then XXH3_avalanche. Unlike
  the default helper, the eight merge-window words are loaded from the
  caller secret at secret+11..67, not folded as immediates. This is the
  same merge as the low64 half of the 128-bit pair (PR #5598); the
  high64 merge is dropped. The avalanche epilogue at 0x61db9a3 is shared
  with the 9..16 branch.

## Cases

2,400 deterministic cases in `result.json` (lengths 241..2048; secrets:
the published kSecret, 11 random 192-byte secrets, and random secrets
of sizes 136/144/160/176/200/208/224/256). The tool's transliteration
and an independent loop-form reference agree on all 2,400 cases (0
mismatches). Check values are computed values confirmed against the
system libxxhash 0.8.2 oracle at the withSecret entry point
(XXH3_64bits_withSecret, lengths 241..5000, secret sizes 136..256,
600/600, 0 mismatches). The three kSecret check values equal PR #5601's
default-helper values, as the inline path with the default secret is
the same algorithm.

## Environment limits (honest)

No cargo/rustc, git-lfs, Ghidra or Java on this VM, so no
`make verify test catalogue-check` run is possible here; the packet
states that instead of claiming it. The `tools/verify_packets.py` run
flags only the pre-existing mismatch in the unrelated packet
RE-001-adjacent-last-115 (present on clean upstream main, untouched by
this change). No native-execution check was repeated for this path: the
oracle check at the entry point exercises this exact inline path
through its dispatch, and the committed cross-check is the Python
reference (the same body shape was natively executed for the 128-bit
pair, PR #5598). No node or visor execution, networking, keys or chain
actions were used. Behaviour for secretSize < 136 is out of scope: the
public contract requires >= 136 and the binary does not check.

## Unknowns

- Whether any caller outside the binary reaches the withSecret entry
  point (no in-binary call site or lea reference; stripped binary).
- No source-level rationale is claimed for the merge window starting at
  secret+11, or for secretLimit being secretSize - 64; both are recorded
  as observed in the disassembly.
