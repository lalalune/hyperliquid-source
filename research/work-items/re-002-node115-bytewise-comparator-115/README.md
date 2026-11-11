# RE-002 · Node #115 RocksDB bytewise comparator ordering and separators

Component: storage (RocksDB comparators). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/bytewise_comparator115.py`,
`tests/test_bytewise_comparator115.py` (2,400 deterministic cases).

## What is reconstructed

Seven vendored RocksDB behaviours from `librocksdb-sys`
(`6cca28ae25285154-rocksdb.24a2c04d2a41c3d2-cgu.0.rcgu.o`), in eleven
FDE copies, each with an FDE range that matches the vendor census
exactly and a body that hashes exactly to the census
`target_body_sha256` (see [functions.tsv](functions.tsv)). The
`objdump --dwarf=frames` pc ranges were re-checked against the
census ranges and agree for all eleven.

* `rocksdb::BytewiseComparatorImpl::Compare` at `0x61bdbf0..0x61bdc3f`
  (79 bytes, census `node115-vendor-61bdbf0`, body SHA-256
  `e79ff2fe89678f0f4a52dda7710306bccacad523e30e94a0b0370766493bfddc`)
  and its second copy at `0x61bdd50..0x61bdd9f` (79 bytes, census
  `node115-vendor-61bdd50`, body SHA-256
  `5f5ff97289b87f12af55d50c1861796bc1d804c7cc30c1a44b0f6fc55af85e6b`):
  memcmp over the shorter length; the **raw memcmp value** is
  returned — the first differing byte's difference, NOT normalised
  to +/-1 (e.g. `Compare("a\x00", "a\xff")` returns -255) — and
  equal prefixes fall through to a -1/0/+1 length tiebreak. The
  two copies share one source body (census `source_body_sha256`
  `e59acdba386024c6f940fe69bed4f1fae454f9bdd9499c38f15b98b081b9b0de`).

* `rocksdb::ReverseBytewiseComparatorImpl::Compare` at
  `0x61bdcf0..0x61bdd4f` (95 bytes, census `node115-vendor-61bdcf0`,
  body SHA-256
  `f88be433f9e6d233b79590228902419c2ca6485a69b112fe8fd87c00a14a7d1a`)
  and its second copy at `0x61bdda0..0x61bddff` (95 bytes, census
  `node115-vendor-61bdda0`, body SHA-256
  `89bd89228ffef8d530b06fd640528391ee21afa2c7d207f35ef5ddeeb43a4e7f`):
  the exact negation of `Compare` (negated memcmp value, inverted
  length tiebreak). The two copies share one source body (census
  `source_body_sha256`
  `f57200432d7360e73542b44f73db8645368eba45cd3fd0278113b628107407fb`).

* `rocksdb::BytewiseComparatorImpl::CompareWithoutTimestamp` at
  `0x61bdc40..0x61bdc8f` (79 bytes, census `node115-vendor-61bdc40`,
  body SHA-256
  `a18e80bc42d77ac613b6cb61332896ae374339ae1a618c15fd6d452a88b3437a`)
  and `rocksdb::ReverseBytewiseComparatorImpl::CompareWithoutTimestamp`
  at `0x61bdc90..0x61bdcef` (95 bytes, census
  `node115-vendor-61bdc90`, body SHA-256
  `6df1c4b397f1342196512a21927ecf2df14ec37e9790e12ca594b397222f1435`):
  the same as `Compare` / reverse `Compare`, with the two `bool`
  timestamp flags (rsi=&a, edx=flag, rcx=&b, r8d=flag) **ignored**
  by the body — it compares the full slices. This matches the
  merged RE-001-fragmented-tombstone-iterator-115 packet, which
  independently records these two as "plain memcmp ignoring the
  bool flags" / "negated memcmp, reversed length tiebreak".

* `rocksdb::BytewiseComparatorImpl::EqualWithoutTimestamp` at
  `0x61bd950..0x61bd987` (55 bytes, census `node115-vendor-61bd950`,
  body SHA-256
  `9419fa9d0ab15621494c07331be842578ae15c96907c58b04fc600cdff78ebdf`):
  false when the lengths differ, else memcmp == 0. Despite the
  name, this overload takes only two slices; there are no flags.

* `rocksdb::BytewiseComparatorImpl::FindShortSuccessor` at
  `0x61bd990..0x61bd9d9` (73 bytes, census `node115-vendor-61bd990`,
  body SHA-256
  `dbe2ab0a413c4982af82f8345b175772cec98b36229518b1544cbc24b3f4600e`):
  scan from the first byte for the first byte != 0xff, increment
  it, truncate the string to that position + 1; unchanged when the
  key is empty or all 0xff.

* `rocksdb::BytewiseComparatorImpl::FindShortestSeparator` at
  `0x61bd9e0..0x61bdaa1` (193 bytes, census `node115-vendor-61bd9e0`,
  body SHA-256
  `a4cddab163b3924a356e27df93818112d66496aca5098b2e6e9fba30e6113d2d`):
  at the first differing byte i (start[i] < limit[i]): if
  i < len(limit)-1, or start[i]+1 < limit[i], increment start[i]
  and truncate to i+1; otherwise scan start[i+1..] for the first
  non-0xff byte, increment it and truncate there; unchanged when
  no such byte exists, when the slices agree over the common
  prefix, or when start[i] >= limit[i]. Note the strictness:
  `FindShortestSeparator("abc", "abd")` is unchanged, because
  incrementing 'c' to 'd' would equal the limit, not separate
  from it; `FindShortestSeparator("abc", "abde")` gives `"abd"`.

* `rocksdb::ReverseBytewiseComparatorImpl::FindShortestSeparator`
  at `0x61bdab0..0x61bdb1b` (107 bytes, census
  `node115-vendor-61bdab0`, body SHA-256
  `ed6328a3e880a6181ae0734d2d1d601ea7522da35892935867585f51f46530ba`):
  at the first differing byte i with start[i] > limit[i], truncate
  to i+1 with NO byte change — a prefix of start is still strictly
  between limit and start in forward order, hence a separator in
  reverse order. Unchanged in every other case, including when
  i+1 == len(start) (the truncation would be a no-op) and when
  start[i] <= limit[i] (e.g. `("a\xff", "b")` is unchanged even
  though `"a"` would separate in forward order — the binary's rule
  is recorded as-is, not idealised).

* `rocksdb::BytewiseComparatorImpl::IsSameLengthImmediateSuccessor`
  at `0x61bd730..0x61bd7c4` (148 bytes, census
  `node115-vendor-61bd730`, body SHA-256
  `2757a60275388f067b40f554cea32bd25bc407ea5dbd81110b1adae59266a882`,
  raw_equal true): false unless the slices share one nonzero
  length; then true exactly when b is a + 1 as a big-endian number
  (at the first differing byte i, b[i] == a[i]+1, and for every
  j > i, a[j] == 0xff and b[j] == 0x00).

The census `source_body_sha256` values are reproduced exactly by
hashing each body with its relocation fields zeroed (one 4-byte
field each, except `IsSameLengthImmediateSuccessor` with none and
`FindShortestSeparator` with two), so `raw_equal` false is fully
explained: the linked bodies differ from the source bodies only in
the memcmp/resize PLT call displacements.

## Callers

No function here has a direct `E8` call site, an `E9` tail jump, or
an `LEA` reference anywhere in `.text` (whole-`.text` scans, with
the scan method validated against `0x61b0660` -> exactly
`[0x5f58e88, 0x61aa029]` and `0x61bd540` -> exactly 49 sites).
They are reached only through vtable slots, resolved through
`R_X86_64_RELATIVE` entries in `readelf -r` and cross-checked
against the merged RE-001-fragmented-tombstone-iterator-115
`vtables.tsv` (see [callers.tsv](callers.tsv)):

* Bytewise vtable (stored vptr `0x64d7038`): `EqualWithoutTimestamp`
  at +0x98 and +0xd8, `FindShortestSeparator` at +0xa0,
  `FindShortSuccessor` at +0xa8, `IsSameLengthImmediateSuccessor`
  at +0xb0, `CompareWithoutTimestamp` at +0xd0, `Compare`
  (`0x61bdbf0`) at +0xe0.
* Reverse vtable (stored vptr `0x64d7158`): `EqualWithoutTimestamp`
  at +0x98 and +0xd8, the reverse `FindShortestSeparator` at +0xa0,
  the reverse `CompareWithoutTimestamp` at +0xd0, the reverse
  `Compare` (`0x61bdcf0`) at +0xe0.
* The second copies live in secondary vtables (offset-to-top -32,
  stored as the raw value `0xffffffffffffffe0` in the file): the
  Bytewise `Compare` copy 2 (`0x61bdd50`) at slot `0x64d7140` of
  the secondary Bytewise vtable at `0x64d7120` (typeinfo
  `*BytewiseComparatorImpl*`), and the reverse `Compare` copy 2
  (`0x61bdda0`) at slot `0x64d7260` of the secondary Reverse vtable
  at `0x64d7240` (typeinfo `*ReverseBytewiseComparatorImpl*`).
  These are the `ComparatorWithU64TsImpl<...>` wrapper's secondary
  bases: `Compare` never reads `this`, so the plain function serves
  the secondary slot directly with no `this`-adjusting thunk.

Each target address also appears once as a stored 8-byte value in
`.eh_frame` (the unwind index's per-function record); those are
unwind data, not code references, and are not counted as callers.

## Verification

* 600 `compare` cases (transliteration vs independent model;
  fixed boundary pairs plus random pairs of lengths 0..32,
  including shared prefixes and 0x00/0xff extremes), 0 mismatches.
* 300 `reverse_compare` cases (reverse == -compare, value and
  all), 0 mismatches.
* 200 `compare_without_timestamp` cases (all four flag combos on
  every pair; flags change nothing), 0 mismatches.
* 100 `reverse_compare_without_timestamp` cases, 0 mismatches.
* 200 `equal_without_timestamp` cases, 0 mismatches.
* 300 `find_short_successor` cases (empty, all-0xff, trailing
  0xff runs, random), 0 mismatches.
* 300 `find_shortest_separator` cases, 0 mismatches.
* 200 `reverse_find_shortest_separator` cases, 0 mismatches.
* 200 `is_same_length_immediate_successor` cases (60 constructed
  successor pairs plus fixed near-misses and random pairs),
  0 mismatches.
* The relocation-zeroed source hashes, the vtable (RELATIVE) slot
  census, the FDE pc ranges, the absence of direct calls / tail
  jumps / LEA references, and the packet `cases.tsv` are all
  re-checked by the tests.
* Check values: `Compare("a\x00", "a\xff")` is -255 (raw memcmp,
  not -1); `reverse_compare("abc", "abd")` is 1;
  `FindShortestSeparator("abc", "abde")` is `"abd"`;
  `FindShortSuccessor("\xff\xff")` is unchanged;
  `IsSameLengthImmediateSuccessor("\x00\xff", "\x01\x00")` is true.
* All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* Why `EqualWithoutTimestamp` occupies two vtable slots in each
  comparator (+0x98 and +0xd8); only the slot contents are claimed.
* The Reverse vtable's +0xa8/+0xb0/+0xb8 slots hold tiny
  sub-census functions (`0x61bd7d0` 7 bytes, `0x61bd7e0` 12 bytes,
  `0x61bd7f0` 5 bytes, `0x61bd800` 7 bytes); their behaviour is not
  reconstructed here.
* The `ComparatorWithU64TsImpl` wrapper's own `Compare` /
  `CompareWithoutTimestamp` (`0x61bdb20` / `0x61bde00`,
  `CompareTimestamp` `0x61bd920`) and its destructors delegate to
  these functions; that wrapper layer is a follow-up packet, not
  claimed here.
* The secondary-vtable owner identification rests on the -32
  offset-to-top and the matching typeinfo pointers; the exact
  wrapper instantiation behind the secondary Reverse vtable is not
  pinned beyond that.

## Reproduction

Run from the repository root with the node artifact materialized
as `work/hl-node-115.bin` (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):

```
python3 tools/bytewise_comparator115.py --verify --binary work/hl-node-115.bin
python3 -m pytest tests/test_bytewise_comparator115.py -q
python3 tools/verify_packets.py
```

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM, so `make verify` / `make test` / `make catalogue-check`
in a tooled environment were not run; the checks above are the
offline Python verification for this packet. The `.hex` files are
the raw FDE bytes and the `.objdump.txt` files are whole-function
verbatim objdump output (GNU objdump 2.42) with repo-relative
binary paths.
