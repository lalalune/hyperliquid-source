# RE-001: pin node #115 the ColumnFamilyOptions OptionTypeInfo maps

**Task:** RE-001. **Node:** #115. **Artifact:** `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound to `provenance/artifacts.json`).

**Bounded question:** which OptionTypeInfo maps does the static
initializer `0x6089b50..0x6091e5c` build for ColumnFamilyOptions, what
is every entry (name, struct offset, type, verification, flags), and
which consumers use them?

## Answer

The initializer builds **five** maps, not one — 114 entries in total:

| Map | Global | Entries |
| --- | --- | --- |
| CompressionOptions | `0x6506be0` | 9 |
| CompactionOptionsFIFO | `0x6506ba0` | 4 |
| CompactionOptionsUniversal | `0x6506b60` | 8 |
| MutableCFOptions | `0x6506b20` | 62 |
| ImmutableCFOptions | `0x6506ae0` | 31 |

The Mutable/Immutable split is proven by the consumer `0x6086e00`,
which serializes map `0x6506b20` under the literal
`MutableCFOptions` and map `0x6506ae0` under `ImmutableCFOptions`
(via the per-map serializer `0x6099ce0`). The full table is
`entries.tsv`; the semantic records are `records.json`.

This resolves the first open unknown of #4239: **PrepopulateBlobCache
lives in MutableCFOptions** (offset `0x144`, type 18 enum,
verification 0, flags `0x100`), built by the enum helper `0x6083c90`,
which hardcodes type 18 at value+`0xa8`.

## Findings

- **Aliases share struct offsets.** Three names address the same
  TableFactory field at ImmutableCFOptions+`0x78`: `table_factory`
  (type 22, verification 1, flags `0xc402`),
  `block_based_table_factory` and `plain_table_factory` (type 22,
  verification 5, flags `0x402`). Two names address the MemTableFactory
  field at +`0x68`: `memtable_factory` (verification 1) and `memtable`
  (verification 5), both type 22, flags `0x400`. The binary literally
  builds separate entries at the same offset with different
  verification/flags.
- **Verification 4 means accepted-and-ignored.** 19 entries carry
  verification 4; the per-entry apply function `0x60bedc0` compares
  the verification dword at +`0xac` against 4 and jumps past the
  dereference (`0x60bedeb: cmpl $0x4,0xac(%rsi)`, `0x60bedf2: je
  0x60bf000`), so all of them record offset 0. Each map's first entry
  is a genuine first field at offset 0 with verification 0
  (`window_bits`, `max_table_files_size`, `size_ratio`,
  `write_buffer_size`, `compaction_style`).
- **FIFO `ttl` is ignored.** Its entry is verification 4 / offset 0;
  the binary field order is `max_table_files_size` @0,
  `allow_compaction` @8, `age_for_warm` @16.
- **Nested entries route through sub-maps:** `compaction_options_fifo`
  → CompactionOptionsFIFO, `compaction_options_universal` →
  CompactionOptionsUniversal, `compression_opts` and
  `bottommost_compression_opts` → CompressionOptions. The last two are
  built by the nested-template builder `0x607f1b0` (which delegates to
  the type-19 builder `0x5e32c70`) and installed by the pair-move
  helper `0x60842a0`.
- **Vector entries** (`max_bytes_for_level_multiplier_additional` @`0xc0`,
  `compression_per_level` @`0x1c8`) are built by the vector helpers
  `0x6083570` / `0x6083d80`, which hardcode type 20 at value+`0xa8` and
  take an element tag `0x3a` in `r9d`.
- **The DBOptions section string is not built here.** The global
  `0x6506c80` (`DBOptions`) does not appear in this initializer; it
  belongs to the sibling DBOptions initializer analysed in #4237.
  This initializer builds seven section strings (`Version`,
  `CFOptions`, `TableOptions/`, `Unknown`, `compression_opts`,
  `bottommost_compression_opts`, `ColumnFamilyOptions`).

## Evidence

- `census.py` resolves every pair-ctor block, helper call, range
  ctor and `__cxa_atexit` call in the initializer by backward
  register resolution (register-width aliases unified; rip-relative
  loads accept positive and negative displacements). Special pairs
  (helper-built values installed by value moves) are decoded by
  following the move chain time-awarely, because the template scratch
  `-0x3550(%rbp)` is reused for many entries and stack slots are
  reused across the function — a direct write counts only when all
  three field writes are newer than the temp's latest move-in and
  latest helper build.
- `records.json` holds semantic records only — no per-instruction
  mnemonic list. Instruction-level detail lives in the raw
  disassembly excerpts, which are verbatim whole-function objdump
  output. The mnemonics in those excerpts (including `endbr64`) are
  genuine instructions present in the target binary, not
  placeholders.
- `export_excerpts.py` regenerates every excerpt with
  `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin` from the repo root. Nine excerpts are
  re-shipped byte-identical from #4237 (same ranges); the
  `fn-60ba600` / `fn-60c18b0` / `fn-60bfda0` / `fn-60a47f0` excerpts
  of #4237 are not reshipped — no ColumnFamilyOptions-family use of
  those functions was found.
- `verify.py` reproduces the census and the records, regenerates the
  excerpts, checks three seeded random gate spots byte-for-byte
  against a fresh objdump run and the raw binary, checks the FDE
  ranges and the cited instructions, and runs the model tests.
  Run it from the repo root.

## Model and tests

- `tools/cfoptions_maps_115.py` models the five maps: lookup,
  parse/serialize of OPTIONS-file sections (nested `[section]`
  blocks route to their sub-map; verification-4 entries are accepted
  and ignored; unknown keys are rejected), the alias sets, and the
  named-enum name lists (from the #4239 registries).
- `tests/test_cfoptions_maps_115.py` (14 tests) exercises the
  behaviour end-to-end: map counts, the Mutable/Immutable split,
  the FIFO field order and ignored `ttl`, the 19 ignored entries,
  the factory aliases, nested-section routing and round-trip,
  named-enum parse/serialize, the `prepopulate_blob_cache`
  resolution, and unknown-key rejection.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` cannot run here.
The packet's own `verify.py` reproduces every claim from the real
binary instead (digest, excerpts, census, gate spots, model tests).

## Open unknowns

- Exact C++ OptionType enum names for types 4 vs 6 and 3 vs 7 vs 8,
  and for types 5 / 23 (carried from #4237 / #4239; this packet uses
  the #4237 numeric labels).
- What verification values 1, 2, 3 and 5 each check (only
  verification 4 is pinned). Observed here: verification 1 on the
  type-22 factory entries, verification 2 on the type-22
  prefix-extractor entries, verification 3 on `merge_operator`,
  verification 5 on `memtable`, `block_based_table_factory` and
  `plain_table_factory`.
- The `allow_2pc` field (carried from #4237): block 26 of the
  DBOptions map, offset `0x173`, is still not tied to a struct
  member.
- The `0x3a` element tag passed in `r9d` to the vector helpers
  `0x6083570` / `0x6083d80`: identical for both vector entries and
  stored in the parse-function capture; its meaning is not pinned.

## Corrections to prior PRs

None. #4237's single-map claim was already corrected by #4237
itself (two maps), and #4239's open unknown about
PrepopulateBlobCache's map home is resolved here, not corrected. No
#4237/#4239 entry value is changed by this packet.
