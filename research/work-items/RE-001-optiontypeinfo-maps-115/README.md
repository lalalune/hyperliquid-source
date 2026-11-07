# RE-001: pin node #115 the OptionTypeInfo maps

## Bounded question

RE-001: which entry range goes to which OptionTypeInfo map, and how are
the 15 offset-0 entries served? This resolves the open unknowns of
RE-001-optiontypeinfo-mismatches-115 (#4233: map-insert mechanics,
offset-0 access path, `wal_filter` attribution, nested-entry insertion
paths) and corrects its single-map claim.

## Answer

The static initializer `0x60aa2b0..0x60b1d78` builds **two** OptionTypeInfo
maps plus **four** enum-name maps, not the one 92-entry map #4233 claimed:

| Map | Address | Entries | Built by |
| --- | --- | --- | --- |
| MutableDBOptions | `0x6506dc0` | 19 | range ctor `0x5d405b0` at `0x60aba7e`, pairs `-0x4490..-0x3488` (blocks 0-18) |
| DBOptions | `0x6506d80` | 81 | range ctor `0x5d405b0` at `0x60b096c`, pairs `-0x4490..-0x38` (73 pair-ctor pairs, blocks 19-91, + 8 special pairs) |
| WalRecoveryMode names | `0x6506ec0` | 4 | range ctor `0x60a76c0` at `0x60aa4c2` |
| AccessHint names | `0x6506e80` | 4 | range ctor `0x60a7c90` at `0x60aa5a2` |
| CacheTier names | `0x6506e40` | 2 | range ctor `0x60a8260` at `0x60aa64b` |
| InfoLogLevel names | `0x6506e00` | 6 | range ctor `0x60a8830` at `0x60aa737` |

Total: 100 OptionTypeInfo pairs (19 + 81) and 16 enum-name pairs.
Both maps' destructors are registered with `__cxa_atexit(0x5d3f820, …)`;
the five section strings (`Version`, `DBOptions`, `CFOptions`,
`TableOptions/`, `Unknown` at `0x6506f00..0x6506f80`) are destroyed by
`0x609fd10`.

### The 15 offset-0 entries

Two are real first fields (verification 0, offset 0 is genuine):

- `max_background_jobs` (mutable map, int, the first MutableDBOptions field)
- `create_if_missing` (DBOptions map, bool, the first DBOptions field)

Thirteen are accepted and ignored. The per-entry apply function
`0x60bedc0` opens with `cmpl $0x4,0xac(%rsi)` at `0x60bedeb` and jumps
to `0x60bf000` when verification == 4, which writes Status OK and
returns without touching the options struct — the offset is never
dereferenced. The thirteen: `allow_os_buffer`,
`base_background_compactions`, `use_direct_writes`, `disableDataSync`,
`disable_data_sync`, `experimental_allow_mempurge`,
`experimental_mempurge_policy`, `experimental_mempurge_threshold`,
`skip_log_error_on_recovery`, `new_table_reader_for_compaction_inputs`,
`preserve_deletes`, `concurrent_prepare`, `seq_per_batch`.

### How the maps are consumed

- **Apply** (`0x60bedc0`, called from the loop `0x60c18b0`): field =
  `options_base + record->offset` (`movslq 0x0(%rbp),%rax; add %r13,%rax`
  at `0x60beeda`); the value is parsed by the record's first
  `std::function` (`call *0x20(%rbp)` at `0x60bef16`), or by the built-in
  type jump table at `0x9786b4` when that function is empty. Unknown names
  produce `Unrecognized option` (`0x4497a0`) / `Could not find option`
  (`0x44e056`); nested keys split on `'.'` (`0x43821e`) in the lookup
  helper `0x60ba0b0`.
- **Single-option read** (`0x60bfda0`, called by `0x60a2080` with the
  `MutableDBOptions` literal at `0x4541e0`): looks the name up in the map
  and serializes the field through the serialize dispatch `0x60ba600`
  (jump table `0x978650`).
- **Dump** (`0x60a47f0`, the OPTIONS-file writer path): builds default
  DBOptions/ImmutableDBOptions and serializes every entry of both maps
  via `0x6099ce0`.
- **Enum entries** (type 18) carry their enum-name map in the first two
  `std::function`s (built by the mid helpers `0x60a64d0/0x60a65c0/
  0x60a66b0/0x60a67a0`, which hardcode typeverif `0x12`).
- **Nested-struct entries** (type 22: `wal_filter`, `statistics`,
  `file_checksum_gen_factory`) parse through the struct path at
  `0x60bf1e0`; shared-ptr entries (type 26: `env`, `rate_limiter`) carry
  a custom parse `std::function`. `rate_limiter` has verification 4, so
  it is accepted and ignored despite its real offset `0x10`.

### Corrections to #4233

- One 92-entry DBOptions map → two maps, 19 + 81 = 100 pairs.
- `wal_filter` unattributed → the special pair at `-0x3dd0` (offset
  `0x188`, type 22, verification 1, flags `0x1201`).
- Move helpers `0x5e32b10`/`0x5e332c0` are OptionTypeInfo move
  constructors, not `std::function` move ctors.
- The 93rd row of #4233's `entries.tsv` was a mis-parse of the
  `DBOptions` section string.

## Evidence

- `records.json` — semantic records only (maps, enum maps, all 100
  entries, the offset-0 resolution, both type jump tables, consumers,
  ranges, mid helpers, atexit). No per-instruction mnemonic list.
- `*.objdump.txt` — raw disassembly exactly as objdump emitted it, one
  whole function per file. `endbr64` and the other mnemonics are genuine
  instructions present in the target binary, not placeholders.
  Produced by:
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  (see `export_excerpts.py` for the full list; the four excerpts first
  exported for #4233 are regenerated here and are byte-identical).
- `blocks.tsv` / `ranges.tsv` / `midhelpers.tsv` / `atexit.tsv` —
  `census.py`; `enum_maps.tsv` / `special_pairs.tsv` —
  `special_pairs.py`; `consumers.tsv` — `census_consumers.py` (one
  streamed `objdump -d` pass; no 390 MB dump file).
- `frames.txt` — FDE ranges for every cited function.
- `relocations.txt` — the `R_X86_64_RELATIVE` entries for the GOT slots
  the mid helpers load their `std::function` managers from.
- `verify.py` — run from the repo root; prints `ALL CHECKS PASSED`
  (digest, manifest, excerpt regeneration, census reproduction, three
  seeded random gate spots byte-for-byte vs fresh objdump and the raw
  binary, FDE ranges, cited instructions, model vs records, model
  tests).

## Model and tests

- `tools/optiontypeinfo_maps_115.py` — the two maps, the four enum-name
  maps, and `apply`/`serialize` following the consumer rules above.
- `tests/test_optiontypeinfo_maps_115.py` — 16 tests, end to end
  (name → map → offset/type/verification → field write or ignore →
  serialized value).

## Environment limits

This work was done on a VM with no cargo/rustc, no git-lfs, and no
Ghidra/Java, so `make verify test catalogue-check` could not be run in
full here; the packet's own `verify.py` and the model tests above are
the checks that ran. The binary digest is bound in `records.json`.

## Open unknowns

- The full name lists of the seven `.bss` enum registries
  (`0x6506fe0..0x6507160`) used by types 11-16 and 24: the registries
  are runtime-built linked lists, so their contents are not recoverable
  from the static file; only `wal_compression` (type 13) is pinned to
  its registry address.
- The exact C++ `OptionType` enum names for types 4 vs 6 (both parse as
  uint32 via `0x61d1840`) and 3 vs 7 vs 8 (all 8-byte unsigned stores
  with different parse helpers); the packet records the behavior, not
  the header names.
- Type 5 (1-byte parse `0x61d17d0`) and type 23 (string build via
  `0x61c7fc0`) have no DBOptions entries; their names are unknown.
- Block 26 `allow_2pc` (offset `0x173`, type 0, verification 0) does not
  sit in the EnvOptions bool cluster; its field is not yet tied to a
  struct member by a ctor pack.

## Artifact

`work/hl-node-115.bin`, node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(matching `provenance/artifacts.json`).
