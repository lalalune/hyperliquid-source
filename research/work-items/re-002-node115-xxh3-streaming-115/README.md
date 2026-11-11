# RE-002: XXH3_64bits streaming API (createState / reset / update / digest / freeState)

For node #115, the vendored xxHash streaming API used by
`rocksdb::log::Reader` — `ROCKSDB_XXH3_createState` (0x61dc410),
`ROCKSDB_XXH3_freeState` (0x61dc450), `ROCKSDB_XXH3_64bits_reset`
(0x61dc480), `ROCKSDB_XXH3_64bits_update` (0x61dc500) and
`ROCKSDB_XXH3_64bits_digest` (0x61de260) — is reconstructed as a
deterministic Python state machine in `tools/xxh3_streaming115.py`,
checked against an independent one-shot reference over 2,400
deterministic cases with 0 mismatches. The state is 640 bytes,
64-byte aligned, with the layout pinned from the disassembly (see
`records.json`); the stripe primitives are transliterated op by op
from the AVX2 code.

- Component ID: `xxh3` (vendored xxHash inside librocksdb-sys); this
  advances RE-002 build provenance.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Census identities: `node115-vendor-61dc410` (createState, body
  SHA-256
  `27bbf35050058e218a037e0dc64b96af74f3c038bdd3e0902bf1eafa027c1231`),
  `node115-vendor-61dc450` (freeState, body SHA-256
  `90c8281d910230476a7dc60f62eb7a910e269dcf5f2465e1ae66d2cf5708e439`),
  `node115-vendor-61dc480` (reset, body SHA-256
  `b933244dddd1c752b3119f444409e1d42c40844c6ccabb15da68f8a0d65aaf31`),
  `node115-vendor-61dc500` (update, body SHA-256
  `5df28d5e46b63835c3e0ed20593ad84bd1399a7969f62e90e8f8ff59329f33a9`),
  `node115-vendor-61de260` (digest, body SHA-256
  `0345f58bd469dc522652275379572fa1d220752e0b059810a5e9c93d1d15b415`).
- Claim status: ELF contents, body hashes, state offsets, call sites,
  secret windows and the 2,400-case cross-check are observations. The
  public-algorithm identity of the stripe primitives is an inference,
  verified line by line against the disassembly and against the
  published xxh3.h source; field names beyond the census labels,
  callers beyond the log Reader, and the unknown state fields are
  unknowns as identified in `records.json`.
- Scope included and excluded: all five streaming functions, all
  input lengths, the seeded digest for totalLen <= 240. Excluded:
  `reset_withSecret` / `reset_withSeed` (custom-secret derivation),
  the +0x230 and +0x240..0x280 state fields, and the hashLong helpers
  used by the withSecret/withSeed >240 paths.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and
the materialized `work/hl-node-115.bin`. The generator authenticates
the binary digest, hashes all five bodies and byte-compares the
default secret table before generating anything. GNU objdump 2.42 was
used only for human inspection; no binutils output is an input to the
generator. No node or visor execution, networking, keys or chain
actions were used. No cargo, rustc, git-lfs or Ghidra is available on
this VM, so `make verify` / `make test` / `make catalogue-check`
cannot run here; the Python checks below are the verification that
was run.

```sh
python3 tools/xxh3_streaming115.py --verify
python3 -m unittest tests.test_xxh3_streaming115
python3 tools/xxh3_streaming115.py --out research/work-items/re-002-node115-xxh3-streaming-115
```

## What the binary pins

- createState mallocs 0x280 bytes and rounds the pointer up to the
  next 64-byte boundary (always advancing 1..64 bytes), keeping the
  delta byte at -1 so freeState can recover the malloc base; it zeroes
  only the seed field at +0x228.
- reset returns 1 (XXH_ERROR) on a NULL state; otherwise it writes the
  eight primes into acc, zeroes totalLen / bufferedSize / the useSeed
  flag / nbStripesSoFar, sets customSecret to kSecret (0x97ec80),
  nbStripesPerBlock to 16 and secretLimit to 128, and returns 0.
- update returns 0 with no state change on a NULL input (the length is
  not even read). Otherwise it buffers inputs up to 256 bytes, fills
  and consumes a full buffer as 4 stripes, consumes full stripes in
  blocks of 16 (secret restarts at the block base, scrambleAcc after
  each block), preserves the last 64 bytes of the consumed region at
  buffer[192..256), and keeps the tail at buffer[0..).
- digest tail-calls withSecret / withSeed for totalLen <= 240
  (depending on the useSeed flag at +0x204), and for longer inputs
  consumes the remaining buffered stripes, accumulates the final
  64-byte stripe with the secret window at secretLimit - 7, then
  mergeAccs (secret + 11) plus totalLen * PRIME64_1 and the XXH3
  avalanche.
- scrambleAcc uses the secret window at secret + secretLimit (128),
  confirmed in three places (update 0x61dc735, digest 0x61de6b3,
  one-shot withSecret 0x61dbb8b) — not the secret + 64 offset a
  reading of the public source would suggest.
- Callers are the log Reader: `ReadPhysicalRecord`
  (node115-vendor-5f01a30), `ReadRecord` (node115-vendor-5f01f10) and
  `~Reader` D1 (node115-vendor-5f03500); see `callers.tsv`.

## Files

- `tools/xxh3_streaming115.py` — the model, the one-shot reference,
  the binary authenticator and the case generator.
- `tests/test_xxh3_streaming115.py` — 13 tests.
- `functions.tsv` — the five bodies and the default-secret table.
- `callers.tsv` — the log Reader call sites.
- `check-values.tsv` — the published anchors through the streaming
  API plus computed streaming digests.
- `records.json` — semantic records (identity, state layout, model,
  census, tests, unknowns).
- `result.json` — the 2,400-case cross-check (0 mismatches).
- `xxh3_streaming115.objdump.txt` — whole-function objdump excerpts
  for all five functions.
