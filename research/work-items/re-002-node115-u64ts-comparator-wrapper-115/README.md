# RE-002 · Node #115 RocksDB U64Ts comparator wrapper

Component: storage (RocksDB comparators). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/u64ts_comparator_wrapper115.py`,
`tests/test_u64ts_comparator_wrapper115.py` (2,400 deterministic cases).

## What is reconstructed

The `rocksdb::ComparatorWithU64TsImpl<BytewiseComparatorImpl>` wrapper
layer, the follow-up the merged RE-002 bytewise-comparator packet
(#5844) left open. Each function has an FDE range that matches the
vendor census exactly and a body that hashes exactly to the census
`target_body_sha256` (see [functions.tsv](functions.tsv)). The
`objdump --dwarf=frames` pc ranges were re-checked against the
census ranges and agree for all eight.

* `ComparatorWithU64TsImpl::CompareTimestamp` at
  `0x61bd920..0x61bd946` (38 bytes, census `node115-vendor-61bd920`,
  body SHA-256
  `f73501ca409cc995031497f7083712bd48ae14c440d6d180596eb72d88872ef8`,
  raw_equal true): the two slices ARE the timestamps. The first 8
  bytes of each slice's data are read as a little-endian u64 and
  compared ASCENDING: -1 when a_ts < b_ts, +1 when a_ts > b_ts, 0
  when equal. No length is consulted.

* `ComparatorWithU64TsImpl::Compare` at `0x61bdb20..0x61bdb97` (119
  bytes, census `node115-vendor-61bdb20`, body SHA-256
  `2b7cc1dad8c2805c4e7ff60d1487072f62e07897f945006482510bb5c90780aa`)
  and its secondary-vtable copy at `0x61bde60..0x61bded7` (119
  bytes, census `node115-vendor-61bde60`, body SHA-256
  `94ada2c8cdf065aedc1470ab520a400baed474f0877ccdf31600f944206edc25`):
  the timestamp size (8) is read from the object field at +0x28
  (the copy reads it at +0x08, i.e. the same field relative to the
  secondary base at +0x20). The user keys are the slices minus the
  trailing 8 bytes. They are compared with the raw memcmp value
  (first differing byte's difference, NOT normalised) and the
  -1/0/+1 length tiebreak, exactly as the inner
  `BytewiseComparatorImpl::Compare` does -- but the wrapper INLINES
  the memcmp instead of calling the inner `Compare`. When the user
  keys agree byte-for-byte and in length, the trailing 8-byte
  timestamps (little-endian u64) decide, in DESCENDING order: the
  LARGER timestamp sorts FIRST (`Compare("abc"+5, "abc"+3)` is -1,
  `Compare("abc"+3, "abc"+5)` is +1, equal timestamps give 0).
  Precondition: both slices are at least 8 bytes long (the body
  subtracts the timestamp size without a check).

* `ComparatorWithU64TsImpl::CompareWithoutTimestamp` at
  `0x61bde00..0x61bde5f` (95 bytes, census `node115-vendor-61bde00`,
  body SHA-256
  `0dd18014e1551d62de2f292d86abc7e0c4dc2dba10509d29bde2bce106591968`):
  strips the trailing 8 bytes from each slice ONLY when the
  matching bool flag is set (a_has_ts in edx, b_has_ts in r8d),
  then a plain bytewise compare (raw memcmp value, -1/0/+1 length
  tiebreak). The timestamps are never compared here, so
  `CompareWithoutTimestamp("key"+1, true, "key"+2, true)` is 0
  while the same call with both flags clear is -1.
  Precondition: a slice whose flag is set must be at least 8 bytes
  long.

* `ComparatorWithU64TsImpl::~ComparatorWithU64TsImpl()` (D1, the
  complete-object destructor) at `0x61be240..0x61be35b` (283 bytes,
  census `node115-vendor-61be240`, body SHA-256
  `2b3332200b6ef7b55dcd9c8432913457bd8e98e1369cd72c36d54a35c3b8c6b0`)
  and the deleting destructor (D0) at `0x61be120..0x61be23b` (283
  bytes, census `node115-vendor-61be120`, body SHA-256
  `33ef3e926c919da7f2896f2997f5a4ee5ed2a3ebf1f41ec5c2ee75defe7f7bd3`),
  plus the secondary-base thunks D0 at `0x61be360..0x61be473` (275
  bytes, census `node115-vendor-61be360`, body SHA-256
  `a9c2f82e7400d9e828eef348011572c5337eff5637ea38c6197f25337bab6d48`)
  and D1 at `0x61be6e0..0x61be7fb` (283 bytes, census
  `node115-vendor-61be6e0`, body SHA-256
  `c7c2a86c4add966e0d13a531dde5259532535a51039c0c5d39e6aae3023144ee`):
  the three vptrs are reset (primary to the wrapper vtable
  `0x64d7278`, secondary at +0x20 to `0x64d7370`, third at +0x30 to
  the `rocksdb::Configurable` vtable `0x64d3430`); then the two
  member vectors are destroyed element-wise -- each element is 48
  bytes holding a std::string at offset 0 (libstdc++ `_M_dispose`:
  the heap buffer is freed with sized `operator delete(ptr,
  capacity+1)` unless the string is in SSO form) -- and each
  vector's storage buffer is freed with sized `operator
  delete(begin, cap_end - begin)`; the primary vptr is reset once
  more to the `Configurable` vtable `0x64d3430` before the second
  vector (at +0x08/+0x10/+0x18) is destroyed. D0 then frees the
  96-byte object itself (`operator delete(this, 0x60)`); D1
  returns. The thunks adjust `this` by -0x20 first and end the same
  way (thunk D0 frees the object with the adjusted pointer).

## Object layout (confirmed by the factory)

The factory `BytewiseComparatorWithU64Ts` at `0x61be9d0` (not
reconstructed here) builds the singleton object (96 bytes, guarded
by `__cxa_guard`) and confirms the layout independently: it stores
the wrapper vtable at +0x00, the secondary vtable at +0x20
(`0x64d7278 + 0xf8 = 0x64d7370`), the timestamp size 8 at +0x28,
the Bytewise vtable (`0x64d7038`) at +0x30, the Bytewise secondary
vtable (`0x64d7130`) at +0x50, and zeroes both member vectors and
+0x58. The typeinfo for the wrapper vtable names
`rocksdb::(anonymous namespace)::ComparatorWithU64TsImpl<rocksdb::(anonymous
namespace)::BytewiseComparatorImpl>`; the vtable at `0x64d3430` used
in the destructor resets names `rocksdb::Configurable`.

## Vtable binding

R_X86_64_RELATIVE slots, from `readelf -r` (the file holds zeros in
`.data.rel.ro`; the RELA addends are the evidence, as in #5844).
The wrapper primary vtable (stored vptr `0x64d7278`) holds D1 at
+0x00, D0 at +0x08, `Name` at +0x68, `CompareTimestamp` at +0xc8
(slot 25), `CompareWithoutTimestamp` at +0xd0 (slot 26) and
`Compare` at +0xe0 (slot 28); the secondary vtable (stored vptr
`0x64d7370`, offset-to-top -32) holds thunk D1 at +0x00, thunk D0
at +0x08 and thunk `Compare` at +0x10 (slot 2).

No function here has a direct E8 call site, an E9 tail jump, or an
LEA reference anywhere in .text (whole-.text scans): they are
reached only through the vtable slots above.

The census `source_body_sha256` values are reproduced exactly by
hashing each body with its relocation fields zeroed for the three
compare functions and the Compare thunk. The four destructors carry
kind-42 (R_X86_64_GOTPCRELX, relaxed `mov` -> `lea` rewrite)
relocations in addition to the call rel32s, so their source hashes
are NOT reproduced by plain zeroing; only the `target_body_sha256`
bind (which matches exactly for all eight) is claimed for them.

All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* The two member vectors' element type beyond the leading
  std::string: each 48-byte element holds a string at offset 0 and
  16 further bytes the destructor never touches. Their member
  names (and the exact upstream class-member mapping for the
  +0x08/+0x38 vectors) are not pinned from the binary alone.
* `Name` (`0x61bef90`), `kClassNameInternal` (`0x61bebd0`) and the
  factory `BytewiseComparatorWithU64Ts` (`0x61be9d0`) are not
  reconstructed here (string building / construction, a
  follow-up); only the layout facts the factory establishes are
  claimed.
* The wrapper vtable's remaining slots (base `Comparator` /
  `Configurable` virtuals at `0x5d2ca00`..`0x5d2cad0` and
  `0x609xxxx`, the tiny stubs at `0x61bd7d0`/`0x61bd7f0`/
  `0x61bd800`/`0x61bd910`, and the forwarder stubs at `0x61bd8a0`/
  `0x61bd8f0`/`0x61bd900`/`0x61bdba0`) are not reconstructed here;
  they are base-class defaults or thin forwarders to the wrapped
  comparator, not census-covered functions.

## Reproduction

Run from the repository root with the node artifact materialized
as `work/hl-node-115.bin` (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):

```
python3 tools/u64ts_comparator_wrapper115.py --verify --binary work/hl-node-115.bin
python3 -m pytest tests/test_u64ts_comparator_wrapper115.py -q
python3 tools/verify_packets.py
```

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM, so `make verify` / `make test` / `make catalogue-check`
in a tooled environment were not run; the checks above are the
offline Python verification for this packet. The `.hex` files are
the raw FDE bytes and the `.objdump.txt` files are whole-function
verbatim objdump output (GNU objdump 2.42) with repo-relative
binary paths.
