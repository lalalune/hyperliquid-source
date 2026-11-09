# RE-002 · Node #115 RocksDB UniqueId external conversion + byte encode/decode

Component: storage (RocksDB unique ids). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/unique_id_external115.py`,
`tests/test_unique_id_external115.py` (2,400 deterministic cases).

## What is reconstructed

Three vendored RocksDB functions from `librocksdb-sys`
(`a17c2a1fdbd85d46-unique_id.o`), all with FDE ranges that match the
vendor census exactly and bodies that hash exactly to the census
`target_body_sha256` values (see [functions.tsv](functions.tsv)):

* `rocksdb::InternalUniqueIdToExternal` at `0x61b0260..0x61b02f3`
  (147 bytes, census `node115-vendor-61b0260`, body SHA-256
  `9a1ae61f46968c646f4819250736e6139b911e675e7b9488a987d54a299533de`):
  transforms a 24-byte UniqueId (three little-endian `u64` words) in
  place. With `(out1, out2) = BijectiveHash2x64(w1 +
  0xf1598607fb45cbd8, w0 + 0x590eb907c873e891, c = 0)`, the result is
  `(out2, out1, w2)`; when the flag is set the third word becomes
  `w2 + out1 + out2`, otherwise it is left untouched. The two additive
  constants are `movabs` immediates in the body (`0x61b0268`,
  `0x61b027d`); no source for them beyond the bytes is claimed.
* `rocksdb::EncodeUniqueIdBytes` at `0x61b0300..0x61b0381`
  (129 bytes, census `node115-vendor-61b0300`, body SHA-256
  `520abebd6899cd3cb64cac38e28f69dcfbb0a0cde30ccfbd0f79b5454c372044`):
  serializes the id to a `std::string`: 24 bytes `(w0, w1, w2)`,
  little-endian, when the flag is set, else 16 bytes `(w0, w1)`.
* `rocksdb::DecodeUniqueIdBytes` at `0x61b0390..0x61b045f`
  (207 bytes, census `node115-vendor-61b0390`, body SHA-256
  `8522807e5003634305476eb6c50f6b987a2e80f4f2326d68f77fa2bc83e97054`):
  the inverse. It requires the string to be exactly 24 bytes when
  the flag is set, else exactly 16 bytes; on a length mismatch it
  returns Status `InvalidArgument` with the message
  "Not a valid unique_id" (21 bytes at `.rodata 0x434324`) and leaves
  the output id untouched. On success it writes `w0`, `w1` (and `w2`
  when the flag is set) and returns an OK Status.

The flag is the same one in all three functions: set selects the
24-byte / third-word form, clear selects the 16-byte form. The only
in-binary caller that uses both the conversion and the encoder,
`GetUniqueIdFromTableProperties` at `0x61b0490`, passes 0 for both
(`0x61b0525`, `0x61b0534`), so the 16-byte form is the live one there;
no claim is made about what the flag is called in the source.

Also bound in the packet, so the transform executes end-to-end: the
callee `rocksdb::BijectiveHash2x64` at `0x61c3e10..0x61c3f55`
(325 bytes, census `node115-vendor-61c3e10`, body SHA-256
`d586664de83493cc5a48eefd3bcef95b10a3ab433b32699334c68671b8cb0864`,
`raw_equal` true) and its seed-0 adapter at `0x61c3f60..0x61c3f71`
(17 bytes, no census record: below the 32-byte minimum), which sets
`c = 0` and forwards `(out1, out2)` through `rcx`/`r8`. The
transliteration is derived from the callee's own disassembly; its
standalone reconstruction is open PR #5720. The three UniqueId
functions above are this packet's claim; the callee is context.

## The BijectiveHash2x64 arithmetic (callee, for the record)

`s = (b^a) ^ (0x59973f0033362349 - c)`; four 32-bit products from the
halves of `s` build a packed word plus the `0x03c0000000000000` round
constant; a second mix `v = (0xc202797692d63d58 + c) ^ a` folds in
through `bswap`; a second multiply stage mixes the packed word's
halves into `m`, `y1` and `r`; `out2 = ((y1 ^ ((m & 0xffffffff) >>
5)) * 0x165667919e3779f9) ^ (>> 32)` (equal to the XXH3 avalanche of
`y1`, since `y1 >> 37` is `(m & 0xffffffff) >> 5`); `out1` is the
XXH3 avalanche of `r ^ (r >> 37)`.

## Callers

`InternalUniqueIdToExternal` has exactly 2 direct `E8` sites:
`rocksdb::VersionEdit::DebugString` (`0x5f58e63`) and
`rocksdb::GetUniqueIdFromTableProperties` (`0x61b0525`, flag 0).
`EncodeUniqueIdBytes` has exactly 3: `VersionEdit::EncodeTo`
(`0x5f561ef`), `VersionEdit::DebugString` (`0x5f58e7d`), and
`GetUniqueIdFromTableProperties` (`0x61b0534`, flag 0).
`DecodeUniqueIdBytes` has exactly 1: `VersionEdit::DecodeNewFile4From`
(`0x5f5b7e6`). See [callers.tsv](callers.tsv); every site was verified
in the binary (`E8` + `rel32` landing on the target).

## Verification

* 1,200 `to_external` cases (transliteration vs independently
  structured model, boundary words plus random triples, both flag
  values), 0 mismatches.
* 600 `encode` cases (exact byte layout + round-trip through
  `decode`), 0 mismatches.
* 600 `decode` cases (300 valid encodings, 300 wrong-length inputs
  including cross-flag lengths), 0 mismatches.
* Cross-check (dev-time, not an input to the generator): this tool's
  `BijectiveHash2x64` transliteration agrees with the independently
  derived tool of open PR #5720 on 5,000 random triples, 0 mismatches.
  The check caught a transcription slip in this tool's `PACK_ADD`
  constant (`0x003c...` vs the binary's `0x03c0...`), corrected before
  submission and re-verified against the raw immediate bytes at
  `0x61c3e6d`.
* Injectivity spot-check: `to_external` is injective on the first two
  words over 5,000 random pairs (a necessary condition for the census
  "bijective" name only; bijectivity is NOT claimed as proven).
* All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* What the flag is called in the source, and what the two additive
  salts in `InternalUniqueIdToExternal` are for; both are recorded
  only as observed immediates / behavior.
* The flag values at the `VersionEdit` call sites (`0x5f58e63`,
  `0x5f561ef`, `0x5f58e7d`, `0x5f5b7e6`): not established from the
  excerpts; only the `GetUniqueIdFromTableProperties` sites pass 0.
* The full signature of the sibling `GetSstInternalUniqueId` at
  `0x61affe0` (which calls the `Hash2x64` wrappers reconstructed in
  PRs #5720/#5723): it is the natural next family, not claimed here.

## Reproduction

Run from the repository root with the node artifact materialized
(`work/hl-node-115.bin` here; the canonical path is
`artifacts/node/115/hl-node`):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
objdump -d --start-address=0x61b0260 --stop-address=0x61b02f3 work/hl-node-115.bin
objdump -d --start-address=0x61b0300 --stop-address=0x61b0381 work/hl-node-115.bin
objdump -d --start-address=0x61b0390 --stop-address=0x61b045f work/hl-node-115.bin
objdump -d --start-address=0x61c3e10 --stop-address=0x61c3f71 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin | grep -E 'pc=00000000061b(0260|0300|0390)|pc=00000000061c3e10'
python3 -m pytest tests/test_unique_id_external115.py -q
python3 tools/verify_packets.py
```

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM, so
`make verify` / `make test` / `make catalogue-check` could not be run
in a tooled environment; the packet tests above and
`tools/verify_packets.py` were run instead. The binary was not executed;
all checks are static reads plus deterministic Python models.
