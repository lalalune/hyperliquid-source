# RE-001: pin node #115 the full DBOptions OptionTypeInfo map: the three mismatched offsets and DBOptions+0x21b

## Correction from subsequent evidence

The original 92-entry map interpretation below is superseded. Subsequent
node #115 analysis resolves two maps, 19 MutableDBOptions entries at
`0x6506dc0` and 81 DBOptions entries at `0x6506d80`, together with four enum
registrations. It also identifies eight special pairs and the OptionTypeInfo
move constructors. The original extraction and its successful self-checks
remain here as historical evidence, including the incomplete entry count and
row interpretation. Use the later packet for the complete map and its
field/type/verification assignments. The independently observed constructor
packing and the DBOptions `+0x21b` census below retain their narrower scope.
[Corrected map evidence](../RE-001-optiontypeinfo-maps-115/README.md) and
[PR #4237](https://github.com/lalalune/hyperliquid-source/pull/4237).

Task: RE-001. Bounded question: what is the full DBOptions OptionTypeInfo
map on node #115, and what are #4146's three open unknowns — the
avoid_unnecessary_blocking_io offset mismatch (map 0x198 vs the
ImmutableDBOptions ctor packing avoid at +0x19a), the max_open_files
offset mismatch (map 0x40 vs ImmutableDBOptions+0x40 = info_log_level),
and DBOptions+0x21b (never stored or read)?

## Answer

The map has **92 entries** (see `entries.tsv` for the full table with
block, name, offset, flags). All three of #4146's unknowns resolve
without changing the map:

1. **avoid_unnecessary_blocking_io: the map (0x198) is correct; #4146's
   DBOptions source offset was off by one.** #4146 read the tail as
   wal_compression +0x218 / atomic_flush +0x219 / avoid +0x21a /
   write_dbid +0x21b. The ImmutableDBOptions ctor pack proves the true
   tail is wal_compression **+0x217**, atomic_flush **+0x218**, avoid
   **+0x219**, write_dbid **+0x21a** (see §3). The map offsets
   (0x196–0x19a) match the ctor destinations exactly for all five tail
   entries, so #4146's map entries were right and only its DBOptions
   source offsets were shifted by one byte.
2. **max_open_files: 0x40 is a MutableDBOptions offset, not an
   ImmutableDBOptions offset.** BuildDBOptions (0x60c2e20) reads
   MutableDBOptions+0x40 at 0x60c2f0b and stores it at DBOptions+0x44
   (0x60c2f10). ImmutableDBOptions+0x40 is info_log_level — a different
   struct, so there is no conflict. All nine group-A map offsets match
   BuildDBOptions' MutableDBOptions reads exactly (see §4).
3. **DBOptions+0x21b is alignment padding (+0x21b..+0x21f) before the
   8-byte-aligned log_readahead_size at +0x220.** The default ctor
   writes +0x210..+0x21a and +0x220 but never +0x21b..+0x21f; the
   ImmutableDBOptions ctor reads up to +0x21a; and a whole-binary
   census finds zero DBOptions/ImmutableDBOptions accesses at +0x21b
   (see §5). The field #4146 put at +0x21b (write_dbid_to_manifest)
   is at +0x21a.

## 1. The map

The static initializer `__static_initialization_and_destruction_0v`
(0x60aa2b0..0x60b1d78) builds the map: 92 blocks, each delimited by a
call to the pair constructor 0x5d400f0, each building one (key string,
OptionTypeInfo temp) pair. Block 92 is the function epilogue (teardown
+ landing-pad stubs), not an entry. The full table is `entries.tsv`
(block, name, temp base, offset, flags).

OptionTypeInfo layout (pinned, 0xb8 bytes): +0x00 offset (size_t,
`movq $IMM`; a few entries use `movl $IMM`); +0x08/+0x28/+0x48/+0x68/
+0x88 five std::function members (managers at +0x18/+0x38/+0x58/+0x78/
+0x98; the record destructor 0x5d3f950 calls the five managers with op
3); +0xa8 u32 type + +0xac u32 verification (packed 8-byte store);
+0xb0 u32 flags (`movl $IMM`). A pair is a 0x20-byte std::string key +
a 0xb8-byte OptionTypeInfo = 0xd8; pair destinations are 0xd8 apart.
The pair constructor 0x5d400f0 copies the temp into pair+0x20 (4 bytes
at +0x00, five std::functions, 8 bytes at +0xa8, 4 bytes at +0xb0);
the +0x04 padding dword is never written by the builder or the copy
helper (already noted by a prior contributor in
`tools/optiontypeinfo_slicetransform_115.py`).

Groups (by entry block):

- **A — MutableDBOptions, blocks 0–18, flags 0x100 (19 entries):**
  allow_os_buffer 0x0, base_background_compactions 0x0,
  max_background_jobs 0x0, max_background_compactions 0x4,
  max_subcompactions 0x8, avoid_flush_during_shutdown 0xc,
  writable_file_max_buffer_size 0x10, delayed_write_rate 0x18,
  max_total_wal_size 0x20, delete_obsolete_files_period_micros 0x28,
  stats_dump_period_sec 0x30, stats_persist_period_sec 0x34,
  stats_history_buffer_size 0x38, max_open_files 0x40,
  bytes_per_sync 0x48, wal_bytes_per_sync 0x50,
  strict_bytes_per_sync 0x58, compaction_readahead_size 0x60,
  max_background_flushes 0x68.
- **B — EnvOptions bool cluster, blocks 19–26, flags 0x0 (8 entries):**
  advise_random_on_open 0x10e, allow_mmap_reads 0x108,
  allow_fallocate 0x10c, allow_mmap_writes 0x109, use_direct_reads
  0x10a, use_direct_writes 0x0, use_direct_io_for_flush_and_compaction
  0x10b, allow_2pc 0x173. These offsets are ImmutableDBOptions-relative;
  the ctor packs DBOptions+0x128..0x12d and +0x148 into +0x108..0x10e
  (see §3). use_direct_writes (offset 0) and allow_2pc (0x173) do not
  fit the cluster — see §6.
- **C — DBOptions proper, blocks 27–91, flags 0x0 except db_host_id
  0x1, rate_limiter / rate_limiter_bytes_per_sec 0x2001, listeners
  0x1 (65 entries):** create_if_missing 0x0,
  create_missing_column_families 0x1, disableDataSync 0x0,
  disable_data_sync 0x0, enable_thread_tracking 0x158,
  error_if_exists 0x2, experimental_allow_mempurge 0x0,
  experimental_mempurge_policy 0x0, experimental_mempurge_threshold
  0x0, is_fd_close_on_exec 0x10d, paranoid_checks 0x3,
  flush_verify_memtable_count 0x4, track_and_verify_wals_in_manifest
  0x5, verify_sst_unique_id_in_manifest 0x6, skip_log_error_on_recovery
  0x0, skip_stats_update_on_db_open 0x170,
  skip_checking_sst_file_sizes_on_db_open 0x171,
  new_table_reader_for_compaction_inputs 0x0,
  random_access_max_buffer_size 0x130, use_adaptive_mutex 0x138,
  use_fsync 0x58, max_file_opening_threads 0x44,
  table_cache_numshardbits 0xe0, db_write_buffer_size 0x110,
  keep_log_file_num 0xc8, recycle_log_file_num 0xd0,
  log_file_time_to_roll 0xc0, manifest_preallocation_size 0x100,
  max_log_file_size 0xb8, db_log_dir 0x78, wal_dir 0x98,
  WAL_size_limit_MB 0xf0, WAL_ttl_seconds 0xe8,
  max_manifest_file_size 0xd8, persist_stats_to_disk 0x199,
  fail_if_options_file_error 0x190, enable_pipelined_write 0x159,
  unordered_write 0x15a, allow_concurrent_memtable_write 0x15b,
  enable_write_thread_adaptive_yield 0x15c,
  write_thread_slow_yield_usec 0x168,
  max_write_batch_group_size_bytes 0xf8, write_thread_max_yield_usec
  0x160, dump_malloc_stats 0x191, avoid_flush_during_recovery 0x192,
  allow_ingest_behind 0x193, preserve_deletes 0x0, concurrent_prepare
  0x0, two_write_queues 0x194, manual_wal_flush 0x195,
  wal_compression 0x196, seq_per_batch 0x0, atomic_flush 0x197,
  avoid_unnecessary_blocking_io 0x198, write_dbid_to_manifest 0x19a,
  log_readahead_size 0x1a0, best_efforts_recovery 0x1b8,
  max_bgerror_resume_count 0x1bc, bgerror_resume_retry_interval 0x1c0,
  db_host_id 0x1d0, rate_limiter 0x10, rate_limiter_bytes_per_sec
  0x10, allow_data_in_errors 0x1c8, listeners 0x140,
  enforce_single_del_contracts 0x238.

Cross-check: DBOptions+0x108 = table_cache_numshardbits (int; the
default ctor stores 6 there, the ImmutableDBOptions ctor reads
DBOptions+0x108 (4 bytes) into +0xe0, and the map puts
table_cache_numshardbits at 0xe0) — so the group-B offsets are NOT
DBOptions offsets. The ImmutableDBOptions ctor also copies
DBOptions+0x100..0x188 into +0xd8..0x138 with a −0x28 shift
(+0x100→+0xd8, +0x108→+0xe0, +0x110→+0xe8, +0x120→+0xf8,
+0x128→+0x108, +0x12c→+0x10c, +0x148→+0x10e, +0x150→+0x110,
+0x158→+0x118, +0x168→+0x128, +0x178→+0x130, +0x188 (1 byte)→+0x138).

## 2. How the map was read

`census.py` parses the verbatim objdump of the static initializer.
Per block: the temp base D is recovered from the movups pattern at
D+0x08/+0x28/+0x48/+0x68/+0x88 and confirmed by the temp pointer the
pair-constructor call consumes in %rdx (via `lea D(%rbp),%rdx`, a
`mov %rax,%rdx` after a lea, or a saved slot); the offset is the
`movq $IMM, D(%rbp)` (or `movl $IMM` for blocks 88/90, where the
compiler proves the high half is zero); the name is the .rodata string
from the `lea STR(%rip),%rsi` + string-ctor call (file offset == vaddr
in .rodata, LOAD1 identity mapping, verified against readelf); the
flags are the `movl $IMM, D+0xb0(%rbp)`. Blocks that build a second
temp for a teardown or a nested entry (27, 89, 90) pick the temp the
pair-constructor call actually consumes; the other temp is recorded
separately (§6).

The +0xa8 (type/verification) values are NOT recorded: they are loaded
into registers whose values the initializer does not set in the same
block (stale r12/r13/r14/rax), so register tracking is unreliable for
them. Only name, offset (immediate) and flags (immediate) are claimed
per entry. Known type pattern from verified cases: type 0 = bool
(all-zero +0xa8), type 1 = int, type 4 = uint64, type 9 = string.

## 3. The ImmutableDBOptions ctor pack (the tail correction)

ImmutableDBOptions ctor 0x60a3b60 (rbp = source DBOptions, rbx =
destination ImmutableDBOptions). The tail pack, in byte order (low
byte first):

- +0x158 word ← {DBOptions+0x1c0, +0x1d0, +0x1d1, +0x1d2} (store
  0x60a3ff0); +0x15c ← +0x1d3 (0x60a3ffd). The default ctor stores
  `movl $0x1010000,0x1d0(%rbx)` (0x60b2fa6) — bytes +0x1d0=0,
  +0x1d1=0, +0x1d2=1, +0x1d3=1 — which confirms the identities:
  enable_pipelined_write=false, unordered_write=false,
  allow_concurrent_memtable_write=true,
  enable_write_thread_adaptive_yield=true (the RocksDB 8.1.1 defaults).
- +0x190 word ← {DBOptions+0x210, +0x211, +0x212, +0x214} (store
  0x60a407e); DBOptions+0x213 is SKIPPED — the four bytes are packed
  from +0x210/+0x211/+0x212/+0x214, not a contiguous word.
- +0x194 (2 bytes) ← DBOptions+0x215..0x216 (0x60a408b).
- +0x196 ← DBOptions+0x217 (0x60a4099) — wal_compression.
- +0x197 word ← {DBOptions+0x218, +0x219, +0x138, +0x21a} in byte
  order (store 0x60a40c3): +0x197 ← +0x218 (atomic_flush), +0x198 ←
  +0x219 (avoid_unnecessary_blocking_io), +0x199 ← +0x138
  (persist_stats_to_disk), +0x19a ← +0x21a (write_dbid_to_manifest).
  The assembler loads +0x21a first and shifts it to the top byte;
  edx still holds +0x138 from 0x60a4077 when it is or-ed in second.
- The EnvOptions bool cluster: +0x108 (4 bytes) ← DBOptions+0x128..
  0x12b (0x60a3e5f), +0x10c (2 bytes) ← +0x12c..0x12d (0x60a3e73),
  +0x10e ← +0x148 (0x60a3e88). The default ctor confirms the values:
  `movl $0x0,0x128(%rbx)` (allow_mmap_reads, allow_mmap_writes,
  use_direct_reads, use_direct_io_for_flush_and_compaction all false),
  `%ecx = 0x101` then `mov %cx,0x12c(%rbx)` (allow_fallocate=true,
  is_fd_close_on_exec=true), `movb $0x1,0x148(%rbx)`
  (advise_random_on_open=true).

The default ctor tail confirms the corrected field identities:
`movq $0x0,0x210(%rbx)` zeroes +0x210..+0x217 (wal_compression =
kNoCompression = 0 at +0x217); `%esi` was zeroed at 0x60b2dfa, so
`mov %si,0x218(%rbx)` stores 0x0000 at +0x218..+0x219
(atomic_flush=false, avoid=false); `movb $0x0,0x21a(%rbx)` sets
write_dbid_to_manifest=false; `movq $0x0,0x220(%rbx)` sets
log_readahead_size=0. No store touches +0x21b..+0x21f.

## 4. BuildDBOptions (the max_open_files correction)

BuildDBOptions 0x60c2e20 (rdi = destination DBOptions rbx, rsi =
ImmutableDBOptions rbp, rdx = MutableDBOptions r12). It reads
MutableDBOptions+0x40 at 0x60c2f0b (`mov 0x40(%r12),%eax`) and stores
it at DBOptions+0x44 (0x60c2f10). The other eight group-A reads match
the map exactly: max_background_compactions 0x4, max_subcompactions
0x8, max_total_wal_size 0x20, delete_obsolete_files_period_micros
0x28, bytes_per_sync 0x48, wal_bytes_per_sync 0x50,
strict_bytes_per_sync 0x58, max_background_flushes 0x68. Also
r12+0x0/+0x4/+0x8 → DBOptions+0xd0/+0xd4/+0xd8, r12+0x20→+0x50,
r12+0x28→+0xc8, r12+0x48→+0x190, r12+0x50→+0x198, r12+0x58 (bool)
→+0x1a0, r12+0x68→+0xdc.

## 5. DBOptions+0x21b is padding

`census_21b.py` streams the whole binary through objdump and records
every instruction with a positive `0x21b(%reg)` displacement (see
`census-21b.tsv`): **25 sites** — 20 are `0x21b(%rsp)` stack slots in
unrelated functions, and 5 are `0x21b(%rbx)` in a single function
(FDE 0x5a897e0..0x5a8a1cc, excerpted in
`field-21b-owner-5a897e0.objdump.txt`). That function operates on a
different struct, not DBOptions: it stores std::strings at
+0x18/+0x28/+0x38/+0x40 (where DBOptions holds numbers), writes a 'D'
tag byte at +0x110 (where DBOptions holds db_write_buffer_size), and
writes +0x220 as a single byte = 2 (where DBOptions holds the 8-byte
log_readahead_size). One `-0x21b(%rbp)` stack local (0x5fac529) is a
false positive and is excluded. Census caveat: the scan is by
displacement text; computed-address accesses (base+index) would not
appear. No DBOptions or ImmutableDBOptions function (default ctor,
copy ctor, Options ctor, operator=, ImmutableDBOptions ctor/copy,
BuildDBOptions, Persist, Verify, Parse) reads or writes +0x21b.

## 6. Open unknowns

- **15 entries have offset 0 and null std::function members**
  (allow_os_buffer, base_background_compactions, max_background_jobs,
  use_direct_writes, create_if_missing, disableDataSync,
  disable_data_sync, experimental_allow_mempurge,
  experimental_mempurge_policy, experimental_mempurge_threshold,
  skip_log_error_on_recovery, new_table_reader_for_compaction_inputs,
  preserve_deletes, concurrent_prepare, seq_per_batch): their access
  path is unresolved — offset 0 cannot address a struct field and no
  parse function is installed. disableDataSync/disable_data_sync look
  like an alias pair (old camelCase + new snake_case).
- **use_direct_writes (offset 0) and allow_2pc (offset 0x173)** do not
  fit the EnvOptions bool cluster (+0x108..+0x10e, seven consecutive
  bytes incl. is_fd_close_on_exec at +0x10d). allow_2pc at +0x173
  would be the top byte of the int the ctor copies from
  DBOptions+0x1f0 (0x20000) to +0x170 — that word is not four bools,
  so the attribution is open.
- **Nested entries** (built interleaved or in teardown temps, NOT
  among the 92 pair-constructor blocks): "env" (0x44feff, offset 0x8,
  flags 0x2001, block 89 — DBOptions+0x8 is the env Env* pointer,
  which fits); "file_checksum_gen_factory" (0x434210, offset 0x1a8,
  flags 0x1400, block 90); "statistics" (0x44ff03, offset 0x48,
  flags 0x3401, block 90); "wal_filter" (0x4454b1, offset 0x188,
  flags 0x1201, block 27 — **unattributed**: the teardown temp
  carries offset 0x188 and flags 0x1201 with a live std::function
  manager, but the string-to-temp link is not proven). Their insertion
  paths (via the 0x5e32b10/0x5e332c0 std::function move-constructor
  helpers, or the once-called helpers) are not fully resolved.
- **Exact map-insert mechanics:** which global map object each pair
  range goes to, and the arguments of the once-called helpers
  (0x60a76c0/0x60a7c90/0x60a8260/0x60a8830 prologue,
  0x60a66b0/0x60a65c0/0x60a64d0 blocks ~67–69,
  0x60a63d0/0x60a6450/0x60a0180 block 89, 0x609f1c0 block 88,
  0x609f1f0/0x609f220 block 90, 0x60a67a0 block 91/92 boundary).
- **The pair-copy 4-byte quirk:** the pair constructor 0x5d400f0
  copies only the low 4 bytes of temp+0x00; the +0x04 padding dword is
  never written. Recorded as observed, not explained.

## 7. Model and tests

`tools/optiontypeinfo_map_115.py` models the 92-entry map (name →
offset, flags, group), the ctor pack, the BuildDBOptions mutable
reads, the corrected DBOptions tail, and the +0x21b padding.
`tests/test_optiontypeinfo_map_115.py` (14 tests) exercises the
behavior end to end: name → map offset → ctor pack → DBOptions source
byte, the BuildDBOptions reads, the +0x21b padding claim, and the
#4146 corrections.

## 8. Evidence and verification

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`). The
`.text` file offset is vaddr − 0x1000; the `.rodata` file offset is
vaddr (LOAD1 identity mapping). GNU objdump 2.42.

Excerpts (whole functions, verbatim as objdump emitted them;
`export_excerpts.py` regenerates them):
`static-initializer-60aa2b0.objdump.txt` (0x60aa2b0..0x60b1d78),
`immutabledboptions-ctor-60a3b60.objdump.txt` (0x60a3b60..0x60a4363),
`dboptions-ctor-60b2db0.objdump.txt` (0x60b2db0..0x60b3154),
`builddboptions-60c2e20.objdump.txt` (0x60c2e20..0x60c3477),
`pair-ctor-5d400f0.objdump.txt` (0x5d400f0..0x5d40477),
`record-dtor-5d3f950.objdump.txt` (0x5d3f950..0x5d3f9d3),
`string-ctor-609fb90.objdump.txt` (0x609fb90..0x609fc73),
`field-21b-owner-5a897e0.objdump.txt` (0x5a897e0..0x5a8a1cc). The
first four are re-shipped byte-identical from #4146 (same FDE ranges,
same objdump version) with credit; the other four are new here.
FDE ranges are in `frames.txt`; the cited GOT slots in
`relocations.txt`.

Instruction mnemonics in the excerpts (such as `endbr64`) are genuine
instructions present in the target binary, not placeholders: the
excerpts are unmodified objdump output. `records.json` holds semantic
records only — no per-instruction mnemonic list. Instruction-level
detail lives only in the raw excerpts.

Verification: run `python3 verify.py` from the repository root. It
checks the artifact digest against `provenance/artifacts.json`, the
`MANIFEST.sha256` hashes, byte-for-byte regeneration of every excerpt
and both census outputs, three seeded random gate spots byte-for-byte
against a fresh objdump run and the raw binary bytes, the FDE ranges,
the cited ctor-pack / BuildDBOptions / default-ctor instructions, the
model constants against `records.json`, and the model tests. It prints
`ALL CHECKS PASSED` only when every check holds.

## 9. Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so
`make verify test catalogue-check` cannot run here. The packet's own
`verify.py` and the Python model tests (`tests/
test_optiontypeinfo_map_115.py`, 14 tests) run instead. The tooled
checks (make verify, test, catalogue-check) are left for a tooled
environment.
