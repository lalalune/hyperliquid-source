# RE-001: node #115 DBOptions+0x220 is log_readahead_size

## Correction from subsequent evidence

The later constructor-packing analysis corrects this packet's original
DBOptions tail source offsets. `wal_compression` is at `+0x217`,
`atomic_flush` at `+0x218`, `avoid_unnecessary_blocking_io` at `+0x219`, and
`write_dbid_to_manifest` at `+0x21a`. The byte range `+0x21b..+0x21f` is
padding in the observed layouts. The raw excerpts and original interpretations
below remain available to show the correction. The selected
`log_readahead_size` field is at `+0x220`.
[Constructor-packing evidence](../RE-001-optiontypeinfo-mismatches-115/README.md)
and [PR #4233](https://github.com/lalalune/hyperliquid-source/pull/4233).
The full map count and registrations are resolved separately in the
[corrected map evidence](../RE-001-optiontypeinfo-maps-115/README.md).

Task: RE-001. Bounded question: what field is DBOptions+0x220, the value
the outer `PersistRocksDBOptions` copies into ConfigOptions+0x30 when
non-null? (Open unknown left by #4108, which resolved the ConfigOptions
side but not the DBOptions side.)

## Answer

DBOptions+0x220 is `rocksdb::DBOptions::log_readahead_size` (`size_t`,
default 0). v8.1.1 `include/rocksdb/options.h` L2389–2399: "The number
of bytes to prefetch when reading the log. This is mostly useful for
reading a remotely located log, as it can save the number of round-trips.
If 0, then the prefetching is disabled."

## What this pins

The default ctor `DBOptions::DBOptions()` (`0x60b2db0..0x60b3154`)
stores `0` at +0x220 (`movq $0x0,0x220(%rbx)` at 0x60b2fe9). The full
tail field map (+0x218..+0x290) matches the v8.1.1 declaration order at
every checkable field, and all six `.rodata` constants the ctor loads
are byte-exact (see `records.json`):

| offset | field | default | notes |
|---|---|---|---|
| +0x218 | wal_compression | 0 | 2-byte store with atomic_flush |
| +0x219 | atomic_flush | false | |
| +0x21a | avoid_unnecessary_blocking_io | false | |
| +0x21b | write_dbid_to_manifest | false (header) | **open unknown**: never stored by the ctor, never read binary-wide |
| +0x220 | log_readahead_size | 0 | |
| +0x228 | file_checksum_gen_factory | null | shared_ptr |
| +0x238 | best_efforts_recovery | false | |
| +0x23c | max_bgerror_resume_count | INT_MAX | |
| +0x240 | bgerror_resume_retry_interval | 1,000,000 | |
| +0x248 | allow_data_in_errors | false | |
| +0x250 | db_host_id | `"__hostname__"` | via GOT slot 0x64fee88 |
| +0x270 | checksum_handoff_file_types | empty | |
| +0x278 | compaction_service | null | shared_ptr |
| +0x288 | lowest_used_cache_tier | 1 | kNonVolatileBlockTier |
| +0x289 | enforce_single_del_contracts | true | |

This also resolves the two ConfigOptions names #4108 left open:
+0x2c is `sanity_level` (u8, `0xff` = kSanityLevelExactMatch) and +0x30
is `file_readahead_size` (size_t, `0x80000`), from v8.1.1
`include/rocksdb/convenience.h` L56–188, whose field order and defaults
match the ConfigOptions ctor exactly.

**Copy paths (verbatim).** The copy ctor `0x5d38750`, `DBOptions(const
Options&)` `0x60b3280` and `operator=` `0x60c3480` all move +0x220
qword-for-qword (`mov 0x220(%rbp),%rax` → `mov %rax,0x220(%rbx)`).

**Compaction into ImmutableDBOptions.** The ctor `0x60a3b60` copies
DBOptions+0x220 to ImmutableDBOptions+0x1a0 (`mov 0x220(%rbp),%rax` at
0x60a40c9 → `mov %rax,0x1a0(%rbx)` at 0x60a40d0), along with the rest of
the tail (+0x238→+0x1b8, +0x23c→+0x1bc, +0x240→+0x1c0, +0x248→+0x1c8,
+0x250→+0x1d0, +0x270→+0x1f0, +0x278→+0x228, +0x288→+0x1f8,
+0x289→+0x238) and the packed bool groups (+0x197, +0x190, +0x194,
+0x196, +0x158, +0x15c). The ImmutableDBOptions copy ctor `0x5da6bc0`
copies +0x1a0 to +0x1a0.

**Reverse bridge.** `BuildDBOptions` `0x60c2e20` copies
ImmutableDBOptions+0x1a0 back to DBOptions+0x220 (`mov 0x1a0(%rbp),%rax`
at 0x60c332f → `mov %rax,0x220(%rbx)` at 0x60c3336), exactly
`options_helper.cc` L319. It takes `max_open_files` from
MutableDBOptions instead (L135), because that field is mutable.

**Persist bridge.** The outer `PersistRocksDBOptions` `0x60d4a00`
(`options_parser.cc` L67–97) builds a ConfigOptions with delimiter
`"\n  "`, `invoke_prepare_options` 0, and — only when
`db_opt.log_readahead_size > 0` — copies DBOptions+0x220 into
ConfigOptions+0x30 (`mov 0x220(%rbx),%rax` at 0x60d4a6c, `test`, `je`
skip, `mov %rax,-0x60(%rbp)`). Otherwise +0x30 keeps the `0x80000`
default. The inner Persist `0x60d2820` writes the OPTIONS file and then
verifies it by re-reading: `VerifyRocksDBOptionsFromFile` `0x60d13a0`
forwards ConfigOptions+0x30 into `Parse` `0x60cfb60`, which builds the
`LineFileReader` with that readahead size (`options_parser.cc` L502–504).
So a nonzero `log_readahead_size` sizes the reader that re-reads the
OPTIONS file just written.

**Name → offset map.** The static initializer
`__static_initialization_and_destruction_0v` `0x60aa2b0..0x60b1d78`
builds the DBOptions `OptionTypeInfo` map. `"log_readahead_size"`
(`0x43d7dc`, referenced exactly once binary-wide, by the lea at
0x60afa6d) maps to offset `0x1a0` (`movq $0x1a0,-0x4c10(%rbp)` at
0x60afa9c) — exactly the ImmutableDBOptions slot the ctor writes.
`"best_efforts_recovery"` → `0x1b8` and `"max_bgerror_resume_count"` →
`0x1bc` match the ctor the same way. Three entries do not match the
ImmutableDBOptions layout and are recorded as open unknowns below.
`"file_readahead_size"` has no string in the binary (ConfigOptions
field, no map entry — consistent).

**Configurable view.** The `DBOptionsConfigurable` ctor `0x60a47f0`
embeds a DBOptions at +0x2d8 (copy-constructed, call at 0x60a4980) and
an ImmutableDBOptions at +0x98 (constructed, call at 0x60a4997).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`provenance/artifacts.json`).
- Raw disassembly: one verbatim `objdump -d` excerpt per window, produced
  by `export_excerpts.py` from the relative path `work/hl-node-115.bin`
  (GNU objdump 2.42). All 14 windows are whole functions. Mnemonics such
  as `endbr64` are genuine instructions present in the target binary, not
  placeholders. Two excerpts are re-shipped byte-identical from #4108
  (`configoptions-ctor-60bb890.objdump.txt`,
  `persist-60d4a00.objdump.txt`).
- `records.json` holds semantic records only (field map, copy paths,
  compaction, Persist bridge, verify chain, OptionTypeInfo map, census,
  literals, corrections, open unknowns) — no per-instruction mnemonic list.
- `census.py` reproduces the call census (11 default-ctor calls, 3 copy,
  6 Options, 3 assign, 6 ImmutableDBOptions, 4 ImmutableDBOptions copy,
  12 BuildDBOptions, 1 each for outer/inner Persist, Verify and Parse;
  no tail jumps, no qword hits) and the displacement census (633
  `0x220(%reg)` instructions in 232 FDEs, 681 `0x1a0(%reg)` in 288 FDEs;
  positive displacements only, grouped by FDE).
- `frames.txt` lists the FDE header lines for every excerpted window.
- `relocations.txt` quotes the db_host_id GOT slot relocation
  (`0x64fee88`, R_X86_64_RELATIVE, addend `0x4342d1` → `"__hostname__"`).

## Corrections to earlier PRs

- #4108 left ConfigOptions +0x2c/+0x30 unnamed and DBOptions+0x220 open;
  this work item resolves all three (+0x2c `sanity_level`, +0x30
  `file_readahead_size`, +0x220 `log_readahead_size`).
- #4108 described the outer Persist delimiter as `"\n "` (one space);
  the raw bytes at 0x446696 are `"\n  "` (newline + two spaces),
  matching `options_parser.cc` L79.
- The DBOptions `OptionTypeInfo` map is built by the static initializer
  `__static_initialization_and_destruction_0v` (`0x60aa2b0..0x60b1d78`),
  not by the `DBOptionsConfigurable` ctor.

## Open unknowns (not presented as facts)

- DBOptions+0x21b (`write_dbid_to_manifest` per the v8.1.1 header):
  never stored by the default ctor, never read by any code in the binary;
  whether it is a real field left unwritten or padding in this build is
  unresolved. It does not affect the +0x220 identification.
- The `OptionTypeInfo` offset for `avoid_unnecessary_blocking_io` is
  `0x198`, but the ImmutableDBOptions ctor packs avoid at +0x19a (+0x198
  is `atomic_flush`, +0x199 is `persist_stats_to_disk`).
- The `OptionTypeInfo` offset for `write_dbid_to_manifest` is `0x19a`,
  but the ImmutableDBOptions ctor never reads DBOptions+0x21b and
  `BuildDBOptions` does not copy the field at all.
- The `OptionTypeInfo` offset for `max_open_files` is `0x40`, but
  `max_open_files` is mutable (`BuildDBOptions` takes it from
  MutableDBOptions) and ImmutableDBOptions+0x40 holds `info_log_level`.

## Verification

```
python3 research/work-items/RE-001-dboptions-log-readahead-size-115/verify.py
python3 tests/test_dboptions_log_readahead_size_115.py   # 97 tests
```

`verify.py` checks: the artifact digest against `provenance/artifacts.json`,
the manifest, excerpt regeneration against fresh objdump, fixed samples
plus 3 seeded random gate spots byte-for-byte against fresh objdump AND
the raw binary, the FDE ranges, the census reproduction, the model
constants, the relocation record and the data literals.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify test catalogue-check` could not be run here; the packet's
own `verify.py` and the Python model tests above were run instead. The
node #115 binary is materialized locally and all binds were checked
against it.
