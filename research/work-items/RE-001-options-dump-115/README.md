# RE-001: pin node #115 the ColumnFamilyOptions Dump

Work item: `RE-001-options-dump-115`
Task: RE-001 (RocksDB options reconstruction).

## Bounded question

What does node #115's `ColumnFamilyOptions::Dump` log, field by
field, and through which helpers — so the reconstruction can
reproduce the 93-line options header exactly?

## Answer (pinned)

`ColumnFamilyOptions::Dump` is `0x60b50c0..0x60b79a6` (10470 bytes,
FDE-confirmed). It logs **93 lines**, all at level 5 (HEADER) through
the helper `0x5fceda0..0x5fcee93`, which emits only when the logger's
level is <= the message level. Its sole caller is
`0x5d95e69`, in host `0x5d954b0..0x5d96890`, which first logs the
header `[%s:619] --------------- Options for column family [%s]:\n`
at level 1.

- **93 fields** (`fields.tsv`, `records.json`): every line's format
  string, struct offset and value rule, read from the binary. All 93
  formats are ColumnFamilyOptions fields; no DBOptions field appears.
- **Names** come from vtable slot 14 (0x70) of the pointed-to object.
  Null prints `None` (operators/filters) or `nullptr` (prefix
  extractors); comparator, memtable_factory and table_factory are
  dereferenced without a null check. The table factory and the SST
  partitioner factory have canonical-name fast paths
  (`BlockBasedTable`, `SstPartitionerFixedPrefixFactory`).
- **CompressionType bytes** go through `0x5d8b3c0..0x5d8b4cb`, a
  65-entry jump table at `0x96d4f0` (`enum-table.tsv`): 0-7 named,
  64 `ZSTDNotFinal`, 255 `DisableOption`, anything else the empty
  string. This confirms #4239's as-built values 64 and 255.
- **CompactionStyle / CompactionPri / CompactionStopStyle bytes** go
  through the #4239 std::map registries `0x6507260` / `0x6507220` /
  `0x65071e0`; a miss prints `unknown_<n>` from a cold block.
- **Bool bytes** print `true` when non-zero, else `false`.
- **Branches**: the scalar `Options.compression` line is logged only
  when `compression_per_level` is empty, otherwise one
  `compression[i]` line per element; `bottommost_compression` 0xff
  prints `Disabled`; the blob-cache lines 87-89 are skipped when
  `blob_cache` is null.
- **The helper** `0x5fceda0` has 341 direct call sites (byte-level
  E8 rel32 scan, `levels.tsv`): dynamic 1, level 0: 2, 1: 84, 2: 43,
  3: 31, 4: 0, 5: 180. The sibling helper `0x5fceea0` calls
  `logger->vtable[3]` with no level check and has exactly 1 caller.
- **Cold blocks** (`records.json`): style/pri miss
  (`unknown_<n>`), bottommost enumfn, table-factory Name(),
  compression-empty, blob options, SST partitioner Name(),
  collectors-empty, collector slot mismatch.

## Evidence

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

| File | Contents |
| --- | --- |
| `dump-60b50c0.objdump.txt` | Whole-function objdump of the dump |
| `helper-5fceda0.objdump.txt` | Whole-function objdump of the log helper |
| `helper-nolevel-5fceea0.objdump.txt` | Whole-function objdump of the no-level sibling |
| `enumfn-5d8b3c0.objdump.txt` | Whole-function objdump of the enum-name function |
| `host-5d954b0.objdump.txt` | Whole-function objdump of the sole caller |
| `fields.tsv` | The 93 helper calls: site, level, format, value tokens |
| `enum-table.tsv` | The 65 jump-table entries and their names |
| `levels.tsv` | The log level at every helper call site (341) |
| `callers.tsv` | Every direct call site of the four functions |
| `frames.txt` | The five FDE ranges from readelf |
| `records.json` | Semantic records only: fields, enum mapping, helper contract, sole caller, cold blocks, relocations |
| `export_excerpts.py` | Generates the five excerpts (objdump commands recorded here) |
| `census.py` | Regenerates fields/enum-table/levels/callers/frames |
| `gen_records.py` | Builds records.json from the census, with cross-checks |
| `verify.py` | Runs every check below; prints ALL CHECKS PASSED |

Excerpt commands (run from the repo root):

```sh
objdump -d --start-address=0x60b50c0 --stop-address=0x60b79a6 work/hl-node-115.bin
objdump -d --start-address=0x5fceda0 --stop-address=0x5fcee93 work/hl-node-115.bin
objdump -d --start-address=0x5fceea0 --stop-address=0x5fcef5b work/hl-node-115.bin
objdump -d --start-address=0x5d8b3c0 --stop-address=0x5d8b4cb work/hl-node-115.bin
objdump -d --start-address=0x5d954b0 --stop-address=0x5d96890 work/hl-node-115.bin
```

The mnemonics in the excerpts (`endbr64`, `movzbl`, `cmove`, …) are
genuine instructions present in the target binary, reproduced
verbatim by objdump, not placeholders.

Section map used (readelf -S): `.text` vaddr 0x1419300, file offset
0x1418300 (offset = vaddr − 0x1000); `.rodata` offset == vaddr.

## Verification

```sh
python3 research/work-items/RE-001-options-dump-115/verify.py
python3 -m unittest tests.test_options_dump_115
```

`verify.py` checks: the artifact digest against
`provenance/artifacts.json`; every MANIFEST hash; byte-for-byte
regeneration of all excerpts and census files; 3 seeded random gate
spots byte-for-byte against a fresh objdump run AND the raw binary
bytes; the FDE ranges against readelf; 32 cited instructions against
fresh objdump; the model constants against `records.json`; and the
model tests. The model `tools/options_dump_115.py` reproduces all 93
lines (including the compression/bottommost/blob branches) and is
covered by 22 tests in `tests/test_options_dump_115.py`.

## Open unknowns

- The C++ names for the logger vtable slots 3, 5 and 8 beyond the
  observed contract (header-format call, leveled call, level query).
- The method names behind the slot calls: table_factory slot 0x20
  (line 7), blob_cache slot 0x10 (line 87) and slot 0xc8 (line 88),
  and the table-properties-collector slot 0xa0 (line 62).
- The host function `0x5d954b0`'s C++ name (it logs the column-family
  header at `db/column_family.cc:619`).
- The exact `ColumnFamilyOptions` C++ layout names for the
  `+0x21b`-style padding bytes are not part of this dump's lines and
  remain open.

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify test catalogue-check` could not be run here; the packet's own
`verify.py` and the model tests were run instead. The binary used is
the materialized `work/hl-node-115.bin` whose SHA-256 matches
`provenance/artifacts.json`.
