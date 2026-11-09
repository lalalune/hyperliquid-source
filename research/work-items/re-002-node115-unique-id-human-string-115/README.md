# RE-002 · Node #115 RocksDB UniqueId human-string formatters

Component: storage (RocksDB unique ids). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/unique_id_human_string115.py`,
`tests/test_unique_id_human_string115.py` (2,400 deterministic cases).

## What is reconstructed

Two vendored RocksDB functions from `librocksdb-sys`
(`a17c2a1fdbd85d46-unique_id.o`), each with an FDE range that matches
the vendor census exactly and a body that hashes exactly to the
census `target_body_sha256` (see [functions.tsv](functions.tsv)).
Together with open PRs #5831, #5834 and #5837, they complete the
UniqueId family: external conversion, byte encode/decode, SST
derivation, table-properties derivation, and now both human-string
formatters.

* `rocksdb::UniqueIdToHumanString` at `0x61b0660..0x61b06fd`
  (157 bytes, census `node115-vendor-61b0660`, body SHA-256
  `dff45f9ad14f2a5a82be48f8b9f54a5c176d70aa7837386df40b45b4fde5b65e`):
  takes the binary unique id as a `std::string` (16 bytes, or 24
  for the extended form, or any prefix) and returns it as
  uppercase hex with a `-` after every 16 hex characters (every
  64 bits). The upstream header (`rocksdb/unique_id.h`, v8.1.1)
  documents exactly this: "Converts a binary string (unique id)
  to hexadecimal, with each 64 bits separated by '-', e.g.
  6474DF650323BDF0-B48E64F3039308CA-17284B32E7F7444B". The binary
  copies the string's (data, size) into a `Slice`, calls
  `Slice::ToString(true)` (`0x61c7e30`, census
  `node115-vendor-61c7e30`), then inserts `-` at positions 16, 33,
  50, ... while the position is below the current size. For a
  16-byte id that is one dash: 32 hex chars become
  "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX" (33 chars). The `-` byte is
  the `.rodata` byte at `0x4496cf`.

* `rocksdb::InternalUniqueIdToHumanString` at `0x61b0750..0x61b10e3`
  (2451 bytes, census `node115-vendor-61b0750`, body SHA-256
  `4a8a644b3202dfa5ba7f96df2b0c905604f0cbbb10831d94f97df47738fd776d`):
  takes a `UniqueIdPtr` — a `{uint64_t *ptr, bool extended}` struct
  passed by value (pointer in `rsi`, `extended` in `rdx`; see
  RocksDB 8.1.1 `table/unique_id_impl.h`, where `UniqueIdPtr`
  wraps either a `UniqueId64x2` with `extended` false or a
  `UniqueId64x3` with `extended` true) — and returns the internal
  id for debugging as `"{w0,w1}"` or `"{w0,w1,w2}"`, the words in
  memory order, plain decimal, comma-separated, wrapped in `{`
  and `}`. Per open PR #5834, `GetSstInternalUniqueId` derives the
  words as (session_id2, file_number ^
  Hash2x64(db_id, seed=session_id).high, Hash2x64(db_id,
  seed=session_id).low). The decimal formatting is the libstdc++
  `std::to_string(unsigned long long)` inline: a divide-by-10000
  digit count, then a divide-by-100 fill from the end using the
  200-byte two-digit pair table (`"00"`..`"99"`), which the binary
  copies to the stack from thirteen 16-byte `.rodata` chunks
  (the thirteenth overlapping the twelfth at table offset 185;
  the reconstructed table is verified byte-for-byte in the tests).
  The separators are the `.rodata` bytes `,` at `0x43b529` and
  `}` at `0x432097`, and the opening `{` is the immediate `0x7b`.

The census `source_body_sha256` values are reproduced exactly by
hashing each body with its relocation fields zeroed (5 fields for
`UniqueIdToHumanString`, 71 for `InternalUniqueIdToHumanString`,
7 for `Slice::ToString`), so `raw_equal` false is fully explained:
the linked bodies differ from the source bodies only in the call
displacements. Note the census end of
`InternalUniqueIdToHumanString` (`0x61b10e3`) is the true FDE end.
The 18-byte nibble-to-hex-char helper at `0x61c7da0`
(`v <= 9 ? '0'+v : 'A'+v-10`) has no census record; its bytes are
verified directly from the binary.

## Callers

`UniqueIdToHumanString` has exactly two direct `E8` sites, both
verified in the binary (`E8` + `rel32` landing on the target), with
no `E9` tail-jump and no `LEA` reference in a whole-`.text` scan:
`rocksdb::VersionEdit::DebugString` (`0x5f58e88`, humanizing the
`EncodeUniqueIdBytes` result from `0x5f58e7d`) and
`rocksdb::TableProperties::ToString` (`0x61aa029`, humanizing the
`GetUniqueIdFromTableProperties` out string at `rsp+0xc0`).

`InternalUniqueIdToHumanString` has exactly three direct `E8`
sites, likewise verified, with no `E9` and no `LEA`:
`rocksdb::VersionEdit::DebugString` (`0x5f58dec`, after the
`" unique_id(internal): "` label — the binary's verbatim spelling)
and `rocksdb::BlockBasedTable::Open` (`0x6120eea` and `0x6120f09`,
the two operands of the unique-id mismatch error, source order
Expected then Actual). All three callers pass `extended` false
(`xor %edx,%edx` at `0x5f58ddf`, `0x6120ec5`, `0x6120efd`), so the
live form is the two-word `"{w0,w1}"`; the three-word form is the
same code path with the flag set and is modeled and tested here
too. See [callers.tsv](callers.tsv).

## Verification

* 1,200 `human_hex` cases (transliteration insert-loop vs the
  independent 16-char-group model; byte strings of length 0..48
  including every dash-boundary length and the upstream doc
  example), 0 mismatches.
* 1,200 `human_internal` cases (transliteration pair-table
  decimal fill vs the independent `str()` model; random u64
  triples and every decimal digit-count boundary 1..20 in both
  the 64x2 and 64x3 forms), 0 mismatches.
* The relocation-zeroed source hashes, the caller censuses, the
  `.rodata` separator bytes and pair table, and the packet
  `cases.tsv` are all re-checked by the tests.
* Check values: the upstream doc example reproduces exactly
  (`6474DF650323BDF0-B48E64F3039308CA-17284B32E7F7444B`); 16 zero
  bytes give `0000000000000000-0000000000000000`; `(0,0,0)` gives
  `{0,0}` (and `{0,0,0}` extended); the all-ones triple extended
  gives `{18446744073709551615,18446744073709551615,
  18446744073709551615}`.
* All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* Whether any caller outside this binary ever passes
  `extended` true to `InternalUniqueIdToHumanString`; all three
  in-binary callers pass false, and the three-word form is
  claimed only as the same code path with the flag set.
* Which of the two `BlockBasedTable::Open` call sites is the
  Expected operand and which is the Actual operand; only their
  order in the error construction is claimed.
* The `Slice::ToString` raw (non-hex) path is modeled from the
  same function body but has no in-binary caller through
  `UniqueIdToHumanString`; it is covered by unit checks only.

## Reproduction

Run from the repository root with the node artifact materialized
(`work/hl-node-115.bin` here; the canonical path is
`artifacts/node/115/hl-node`):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
objdump -d --start-address=0x61b0660 --stop-address=0x61b06fd work/hl-node-115.bin
objdump -d --start-address=0x61b0750 --stop-address=0x61b10e3 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin | grep -E 'pc=00000000061b0660|pc=00000000061b0750'
python3 -m pytest tests/test_unique_id_human_string115.py -q
python3 tools/verify_packets.py
```

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM, so
`make verify` / `make test` / `make catalogue-check` could not be run
in a tooled environment; the packet tests above and
`tools/verify_packets.py` were run instead. The binary was not executed;
all checks are static reads plus deterministic Python models.
