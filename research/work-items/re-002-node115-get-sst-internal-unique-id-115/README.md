# RE-002 · Node #115 RocksDB GetSstInternalUniqueId + DecodeSessionId

Component: storage (RocksDB unique ids). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/get_sst_internal_unique_id115.py`,
`tests/test_get_sst_internal_unique_id115.py` (2,400 deterministic cases).

## What is reconstructed

Two vendored RocksDB functions from `librocksdb-sys`
(`a17c2a1fdbd85d46-unique_id.o`), both with FDE ranges that match the
vendor census exactly and bodies that hash exactly to the census
`target_body_sha256` values (see [functions.tsv](functions.tsv)):

* `rocksdb::GetSstInternalUniqueId` at `0x61affe0..0x61b0260`
  (640 bytes, census `node115-vendor-61affe0`, body SHA-256
  `1b64d1af98c276016dc33017c08fd35534868998668d2a72e123ddaa0d0db1be`):
  derives a 24-byte internal UniqueId for an SST file from the DB id,
  the DB session id and the file number. Strict mode validates the
  inputs and propagates `DecodeSessionId` errors; lenient mode skips
  validation and falls back to hashing the session string when the
  decode fails. The result words are `(session_id2, file_number ^
  Hash2x64(db_id, seed=session_id).high, Hash2x64(db_id,
  seed=session_id).low)`, where the third word is written only when
  the write_third_word flag is set. All errors carry Status code 3
  (kNotSupported): the Status ctor is called with code 3 (`mov
  $0x3,%esi` at `0x61b00c9`), matching the upstream header's note
  that `DecodeSessionId` returns NotSupported "because non-standard
  session IDs should be allowed with degraded functionality".
* `rocksdb::DecodeSessionId` at `0x61af500..0x61affaf`
  (2735 bytes, census `node115-vendor-61af500`, body SHA-256
  `73426de07243605a472e661f6b4a59094c4a8094cf5dc5b54cf2bfa970761cb9`):
  parses a base-36 DB session id string of 13..24 characters into
  two `u64`s. The string splits into a high part (the first `len-12`
  characters) and a low part (the last 12 characters); with `high =
  base36(s[:len-12])` and `low = base36(s[len-12:])`, `session_id =
  high >> 2` and `session_id2 = ((high & 3) << 62) | (low &
  0x3fffffffffffffff)`. Length 0 / <= 12 / > 24 and non-base-36 digits
  are errors with the messages "Missing db_session_id" (21 bytes at
  `.rodata 0x43430e`) / "Too short db_session_id" (23 bytes at
  `0x435387`) / "Too long db_session_id" (22 bytes at `0x44b53f`) /
  "Bad digit in db_session_id" (26 bytes at `0x43333e`).

The two boolean flags: the census symbol demangles to five
parameters (`const string&, const string&, unsigned long, UniqueIdPtr,
bool`), but the binary function reads two bools — the sixth register
argument (`r9`) gates the third output word and a seventh argument (a
bool on the stack) selects the lenient path. All seven in-binary call
sites pass the first flag clear; the lenient flag is set only at the
two read paths (`BlockBasedTable::Open` `0x6120bc5` and the
`OffsetableCacheKey` constructor `0x5daf6e8`) and clear at the five
write/ingest paths. No source names are claimed for the flags.

Also bound in the packet, so the transform executes end-to-end: the
`Hash2x64` wrappers at `0x61c3db0..0x61c3dd3` (35 bytes, body
`cdf83f11...`) and `0x61c3de0..0x61c3e03` (35 bytes, body `77d46c5d...`),
each one `E8` call to a 128-bit one-shot (`0x61deab0` / `0x61defa0`,
open PR #5578) storing high64 through the first out-pointer and
low64 through the second. The 128-bit one-shot transliteration in
the tool is adapted from the #5578 tool (same author); the one-shots'
standalone reconstruction is #5578, and lengths above 128 delegate
to the len_129to240 helper at `0x61d80a0` (open PR #5595) and the
hashLong helpers at `0x61d8a60` / `0x61d9bc0` (open PR #5598), which
are out of scope here: this packet covers hashed inputs of length
0..128 only, which covers every realistic `db_id` (a UUID string)
and `db_session_id` (13..24 characters) and every in-binary call
site. The two wrappers are this packet's callee context, not its
claim; the claim is the two functions above.

## The DecodeSessionId split (for the record)

The body is a fully unrolled base-36 accumulation: after each of the
first characters it jumps to a per-length finalization block that
advances the data pointer past the characters already consumed, so
the second phase always parses exactly the last 12 characters. The
final block (`0x61afd89`) stores `*out1 = high >> 2` and `*out2 =
((high & 3) << 62) | (low & 0x3fffffffffffffff)`. The low part can
reach `36**12 - 1`, which exceeds `2**62 - 1`, so its bit 62 is
dropped by the mask — a lossy edge in the binary, recorded here
rather than smoothed over (a test pins it). No overflow is possible
in the folds: each part holds at most 12 base-36 digits, below
`2**63`.

## Callers

`GetSstInternalUniqueId` has exactly 7 direct `E8` sites: the
`OffsetableCacheKey` constructor (`0x5daf6e8`, lenient 1),
`CompactionJob::OpenCompactionOutputFile` (`0x5e0d88e`),
`0x5e20111` (enclosing function not in the vendor census, FDE
`0x5e1b9c0..0x5e20481`), `ExternalSstFileIngestionJob::
GetIngestedFileInfo` (`0x5ec2128`), `0x5ee4db1` (enclosing function
not in the vendor census, FDE `0x5ee3840..0x5ee5d2b`),
`BlockBasedTable::Open` (`0x6120bc5`, lenient 1), and
`GetUniqueIdFromTableProperties` (`0x61b04de`). `DecodeSessionId`
has exactly 2: both inside `GetSstInternalUniqueId` (strict path
`0x61b0062`, lenient path `0x61b0133`). See
[callers.tsv](callers.tsv); every site was verified in the binary
(`E8` + `rel32` landing on the target).

## Verification

* 600 `decode_session` cases (transliteration vs the independent
  `int(s, 36)` split model; every length 0..25, valid strings,
  bad digits, case-equivalence pairs), 0 mismatches.
* 600 `hash2x64` cases (transliteration vs the published-formula
  XXH3-128 reference, lengths 0..128, seeded and unseeded),
  0 mismatches.
* 1,200 `get_sst` cases (end-to-end transliteration vs independent
  model; realistic UUID-like ids, boundary file numbers, both flag
  values, strict and lenient mode), 0 mismatches.
* Dev-time oracle check (not an input to the generator): the
  embedded XXH3-128 transliteration agrees with the system
  libxxhash 0.8.2 oracle on 1,200 random cases (lengths 0..128,
  5 seeds), 0 mismatches; the published anchor
  `XXH3_128bits(b"", 0) = (0x6001c324468d497f, 0x99aa06d3014798d8)`
  holds.
* The lenient zero-low fixup (`s2 = s1 | 1` when the fallback hash
  returns a zero low word) cannot be hit by random search, so it is
  exercised in the tests with a stubbed hash; the branch itself is
  recorded from the disassembly (`0x61b01c6..0x61b01db`).
* All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* What the two boolean flags are called in the source, and why the
  read paths (`BlockBasedTable::Open`, `OffsetableCacheKey` ctor)
  take the lenient path while the write/ingest paths are strict;
  both are recorded only as observed behavior and call-site values.
* The enclosing functions of the `0x5e20111` and `0x5ee4db1` call
  sites: they have FDE ranges but no vendor-census record, so no
  symbol is claimed for them.
* The `>128`-byte hashing delegation (len_129to240 / hashLong
  helpers) is out of scope here; inputs above 128 bytes raise in
  this tool rather than being modeled.
* Whether the bit-62 masking in `DecodeSessionId` loses information
  for any real session id: the encoder (`EncodeSessionId`) is not
  reconstructed here, so no claim is made about which strings it
  can produce.

## Reproduction

Run from the repository root with the node artifact materialized
(`work/hl-node-115.bin` here; the canonical path is
`artifacts/node/115/hl-node`):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
objdump -d --start-address=0x61af500 --stop-address=0x61affaf work/hl-node-115.bin
objdump -d --start-address=0x61affe0 --stop-address=0x61b0260 work/hl-node-115.bin
objdump -d --start-address=0x61c3db0 --stop-address=0x61c3e03 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin | grep -E 'pc=00000000061af500|pc=00000000061affe0|pc=00000000061c3db0|pc=00000000061c3de0'
python3 -m pytest tests/test_get_sst_internal_unique_id115.py -q
python3 tools/verify_packets.py
```

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM, so
`make verify` / `make test` / `make catalogue-check` could not be run
in a tooled environment; the packet tests above and
`tools/verify_packets.py` were run instead. The binary was not executed;
all checks are static reads plus deterministic Python models.
