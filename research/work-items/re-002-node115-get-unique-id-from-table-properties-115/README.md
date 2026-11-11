# RE-002 · Node #115 RocksDB GetUniqueIdFromTableProperties

Component: storage (RocksDB unique ids). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/get_unique_id_from_table_properties115.py`,
`tests/test_get_unique_id_from_table_properties115.py` (2,400 deterministic cases).

## What is reconstructed

One vendored RocksDB function from `librocksdb-sys`
(`a17c2a1fdbd85d46-unique_id.o`), with an FDE range that matches the
vendor census exactly and a body that hashes exactly to the census
`target_body_sha256` (see [functions.tsv](functions.tsv)):

* `rocksdb::GetUniqueIdFromTableProperties` at `0x61b0490..0x61b0631`
  (417 bytes, census `node115-vendor-61b0490`, body SHA-256
  `00698ef733869baa717ad1d89956504088b731feb827238875df41cee3d540d4`):
  derives the 16-byte external unique id of an SST file from its
  `TableProperties`. It reads `orig_file_number` (offset 0), `db_id`
  (offset 0xc8) and `db_session_id` (offset 0xe8) from the struct —
  the RocksDB 8.1.1 layout, verified against the upstream header —
  and calls `GetSstInternalUniqueId(db_id, db_session_id,
  orig_file_number, write_third_word=false, lenient=false)`
  (`0x61b04de`). When that call returns a non-OK Status, the out
  string is cleared to `""` (size 0, buffer kept) and the Status is
  returned as-is. On success it calls
  `InternalUniqueIdToExternal(id, flag=false)` (`0x61b0525`) and
  `EncodeUniqueIdBytes(id, flag=false)` (`0x61b0534`) and
  move-assigns the resulting 16-byte string into the out string.
  The third UniqueId word is never written by the GetSst call
  (write_third_word clear) and is passed through untouched by the
  external conversion (flag clear), and the 16-byte encoder reads
  only the first two words, so the unwritten third word cannot
  affect the output.

The census `source_body_sha256`
(`d5faca9cef62ea92b6180a53a1b98823de3c33b975c60cde08a33795b0dfeda6`)
is reproduced exactly by hashing the body with the seven
relocation fields zeroed (six kind-4 `E8` rel32 fields at offsets
79, 150, 165, 279, 351, 401 and one kind-2 `E9` rel32 field at
offset 413), so `raw_equal` false is fully explained: the linked
body differs from the source body only in the call displacements.

Also bound in the packet, so the transform executes end-to-end:
`GetSstInternalUniqueId` + `DecodeSessionId` (open PR #5834),
`InternalUniqueIdToExternal` + `EncodeUniqueIdBytes` +
`BijectiveHash2x64` and its seed-0 adapter (open PR #5831), and
the `Hash2x64` wrappers (open PR #5723). The 128-bit one-shot
transliteration in the tool is adapted from open PR #5578; the
one-shots' standalone reconstruction is #5578, and lengths above
128 delegate to the len_129to240 helper (open PR #5595) and the
hashLong helpers (open PR #5598), which are out of scope here:
this packet covers hashed inputs of length 0..128 only, which
covers every realistic `db_id` (a UUID string) and `db_session_id`
(13..24 characters) and every in-binary call site. The callees
are this packet's context, not its claim; the claim is the one
function above.

## Callers

`GetUniqueIdFromTableProperties` has exactly one direct `E8` site:
`rocksdb::TableProperties::ToString` (`0x61aa011`, census
`0x61a8530..0x61aaa8b`), which passes the Status sret on the stack
(`rsp+0x30`), the properties pointer in `rbp`, and the out string
at `rsp+0xc0`, then checks the returned Status byte. See
[callers.tsv](callers.tsv); the site was verified in the binary
(`E8` + `rel32` landing on the target), and a whole-`.text` scan
found no `E9` tail-jump to the function.

## Verification

* 1,800 `table_properties` cases (end-to-end transliteration vs
  independent model; valid UUID-like ids and valid sessions, every
  error gate — empty db_id, file number 0, empty/short/long/bad
  sessions — boundary file numbers, long ids/sessions),
  0 mismatches.
* 600 `external_encode` cases (the to_external + encode
  composition with flag clear, transliteration vs model),
  0 mismatches.
* The relocation-zeroed source hash, the caller census, the
  `.rodata` error strings and the packet `cases.tsv` are all
  re-checked by the tests.
* The callee transliterations were cross-checked in their own
  packets: the embedded XXH3-128 against the system libxxhash
  0.8.2 oracle (open PR #5834) and BijectiveHash2x64 against the
  independently derived tool in open PR #5720 (open PR #5831).
* All 2,400 cases are committed in [cases.tsv](cases.tsv).

## Unknowns (kept separate from observations)

* What the two boolean flags of `GetSstInternalUniqueId` are
  called in the source; both are clear at this call site and their
  values are recorded only as observed behavior.
* Whether `TableProperties::ToString` uses the derived unique id
  anywhere else besides the call site recorded here; only the one
  call site is claimed.
* The `>128`-byte hashing delegation (len_129to240 / hashLong
  helpers) is out of scope here; inputs above 128 bytes raise in
  this tool rather than being modeled.

## Reproduction

Run from the repository root with the node artifact materialized
(`work/hl-node-115.bin` here; the canonical path is
`artifacts/node/115/hl-node`):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
objdump -d --start-address=0x61b0490 --stop-address=0x61b0631 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin | grep -E 'pc=00000000061b0490|pc=00000000061aa'
python3 -m pytest tests/test_get_unique_id_from_table_properties115.py -q
python3 tools/verify_packets.py
```

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM, so
`make verify` / `make test` / `make catalogue-check` could not be run
in a tooled environment; the packet tests above and
`tools/verify_packets.py` were run instead. The binary was not executed;
all checks are static reads plus deterministic Python models.
