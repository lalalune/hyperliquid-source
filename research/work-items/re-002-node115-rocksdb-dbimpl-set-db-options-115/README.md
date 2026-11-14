# RE-002: reconstruct node #115 `rocksdb::DBImpl::SetDBOptions` (DB options setter)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBImpl::SetDBOptions(const unordered_map<string,
string>&)` -- the DB options setter: it parses the options map into
a new MutableDBOptions, defaults bytes_per_sync to 1 MiB,
short-circuits when nothing changed, builds a new DBOptions,
validates it and every live column family, grows the background
thread pools when the new limits increase, re-registers the
periodic dump/persist-stats tasks, stores the new
max_total_wal_size, applies the new mutable options, rebuilds the
compaction FileOptions, switches the WAL when the log size or
wal_bytes_per_sync changed, and persists the options file. It is
the second caller of the one-argument validator (open PR #6379,
0x5e59cd0) and of the per-CF validator (open PR #6449, 0x5d8e3b0).
2,400 byte-checked cases; 31 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBImpl::SetDBOptions` | `0x5d71fe0..0x5d72e50` | 3696 B | `4e93a3e037558cb85400f83f221040af630bac0120a5f3ee70a576a75c78e56b` | `4d429ab1cb2d8f8b-db_impl.o`, `_ZN7rocksdb6DBImpl12SetDBOptionsERKSt13unordered_mapINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES7_St4hashIS7_ESt8equal_toIS7_ESaISt4pairIKS7_S7_EEE` |
| `rocksdb::DBImpl::SetDBOptions.cold` | `0x5d71eea..0x5d71fe0` | 246 B | `1e1c1fff1ddf5c8c7e159c22bd68242787554bc4f23c9898b5ab60a8b3a2ea5e` | same member, same symbol + `.cold` |

The source hashes reproduce exactly by zeroing the census
relocations (main 121, cold 20, kinds 2/4 -- no relaxation).
The main FDE has a `.cold` FDE with a 22-entry LSDA (all
cleanup, entry [0] has no landing pad); the `.cold` FDE has a
1-entry LSDA. The `.eh_frame` records: main at section offset
0x7346d0 (length 0x4c, range 0xe70, aug_len 4, LSDA at
0x4092b8); cold at section offset 0x734720 (length 0x20,
range 0xf6, aug_len 4, LSDA at 0x409343).

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status SetDBOptions(const unordered_map<string,
string>& options_map)` -- the result is returned by value
(hidden sret out in `rdi` = `r12`), `this` in `rsi` = `rbx`,
`options_map` in `rdx`. A stack canary IS used (`%fs:0x28`,
stored at `0xa48(%rsp)`, checked at the epilogue 0x5d720a1 and
in the `.cold` chain at 0x5d71f1c before `_Unwind_Resume`). In
binary order:

1. Empty input: log WARN (`[%s:1212] SetDBOptions(), empty
   input.`) and return InvalidArgument `empty input` -- with no
   lock and no WriteContext.
2. Lock the mutex (via the InstrumentedMutexLock wrapper
   0x606ca40), parse with `GetMutableDBOptionsFromStrings`
   (0x60a1d60, oracle; a parse failure restores the base options
   and its status is returned).
3. `bytes_per_sync == 0` -> 1 MiB (`movq $0x100000,0xe8(%rsp)`).
4. Unchanged short-circuit: when the parsed options equal the
   current mutable options (compared AFTER the 1 MiB default),
   log INFO (`[%s:1232] ... not changed, skipping updating.`),
   `PermitUncheckedError()` the persist status, unlock and
   return OK. A default DB never short-circuits here: its
   `bytes_per_sync` is 0, the parsed one is 1 MiB.
5. Build a new DBOptions (`BuildDBOptions` 0x60c2e20, oracle),
   validate it (`DBImpl::ValidateOptions` 1-arg 0x5e59cd0,
   oracle, open PR #6379) and every live column family
   (`ColumnFamilyData::ValidateOptions` 0x5d8e3b0, oracle, open
   PR #6449; the loop walks the ColumnFamilySet circular list
   via `dummy_cfd_->next_` (+0x938) and skips dropped CFs (byte
   +0x3d); the first failure wins).
6. Grow the background pools when the new BGJobLimits increase
   (`GetBGJobLimits` 0x5dd5f00: flushes==-1 and compactions==-1
   gives a quarter of max_background_jobs to flushes, else
   max(1, each); `IncBackgroundThreadsIfNeeded` HIGH then LOW,
   then `MaybeScheduleFlushOrCompaction`).
7. Unlock, re-register the periodic tasks (`Register` returns
   the status; a dump-register failure skips the persist task),
   store the new `max_total_wal_size` when it changed, relock,
   and return the first failure status.
8. Apply: `write_controller_.set_max_delayed_write_rate`,
   `table_cache_.SetCapacity` (`kInfiniteCapacity` 0x400000
   when `max_open_files == -1`, else `max_open_files - 10`),
   `mutable_db_options_ = new_options`, rebuild the compaction
   FileOptions (`EnvOptions` ctor from the new DBOptions, then
   the base FileSystem `OptimizeForCompactionTableWrite/Read`
   hooks), `versions_->ChangeFileOptions`.
9. `WriteThread::Writer` + `EnterUnbatched`; switch the WAL
   (`SwitchWAL` 0x5e8c5e0) when `total_log_size_` exceeds the
   max or `wal_bytes_per_sync` changed -- a SwitchWAL failure
   is only logged (`[%s:1338] Unable to purge WAL files ...`),
   never returned. Persist the options file
   (`WriteOptionsFile` 0x5d713f0) and `ExitUnbatched`.
10. Log the inputs and the outcome (`[%s:1352] SetDBOptions(),
    inputs:`, per-entry `[%s:1354] %s: %s\n`, `[%s:1358]
    SetDBOptions() succeeded` / `[%s:1371] SetDBOptions
    failed`), `MutableDBOptions::Dump`, `LogFlush`, and return
    the parse/validation/scheduler status -- or IOError
    `SetDBOptions() succeeded, but unable to persist options:
    IO error: <persist status>` when the options file could
    not be persisted and `fail_if_options_file_error` is set.

Status plumbing: the two Status ctor calls are the empty-input
error (0x5d7208b) and the persist IOError (0x5d724a2), both to
0x61cf670 (census-bound, `status.o`). The persist message's
msg2 is the persist status rendered by `Status::ToString`
(0x61cfed0) -- pinned from its own disassembly: a jump table at
0x97e958 loads a human phrase per code (`IO error: `,
`NotFound: `, `Invalid argument: `, ...; code 0 is built inline
as `OK`; codes > 15 render as `Unknown code(%d): `), a
non-zero subcode appends its string from the table at
0x64d7b00 (e.g. subcode 1 `Timeout Acquiring Mutex`, 4 `No
space left on device`, 9 `No such file or directory`), then
`: ` + state. The enum names with the `k` prefix (`kIOError`)
never appear in ToString output.

The common epilogue (0x5d72238..0x5d72337) runs
`WriteContext::Clean` + delete memtables,
`SuperVersionContext` dtor, `delete[]` of the persist/s
`state_` buffers (null after the moves), then the canary
check at 0x5d720a1. The 15 landing-pad stubs at
0x5d72d9c..0x5d72e44 (each `endbr64` + `mov %rax,%rbx` + `jmp
rel32`) jump into the `.cold` FDE, which runs the destructor
chain in order (string `_M_dispose`, WriteContext dtor,
ColumnFamilyOptions/DBOptions dtors, FileOptions property_bag
clear/dispose, FileSystemPtr release, Writer dtor,
Mutex::Unlock) and then checks the canary before resuming --
so a throw with a bad canary becomes StackCheckFailed after
cleanup, unlike the no-LSDA packets. The empty-input Log and
Status ctor and the LogFlush call have NO landing pad (LSDA
entry [0] and the LogFlush site): a throw there propagates
with no cleanup and no canary check.

The ten log/message strings are the upstream strings quoted
verbatim (meta/rocksdb v8.1.1, `db/db_impl.cc:1209-1376`,
read live this cycle), each verified byte-for-byte against
the .rodata string at its address, with their source line
numbers.

DBImpl/DBOptions field offsets were verified this cycle by
compiling `offsetof()` against the real v8.1.1 headers (g++).
The vendored build's layout differs from a stock v8.1.1
compile after `mutable_db_options_` (`mutex_` +0x700 vs
+0x740, `table_cache_` +0x750 vs +0x7d0,
`file_options_for_compaction_` +0x8d0 vs +0x950,
`write_controller_` +0x1120 vs +0x11b0, `total_log_size_`
+0xc28 vs +0xcb8, `max_total_wal_size_` +0x1860 vs +0x1978,
`periodic_task_scheduler_` +0x1748 vs +0x1858) and inside
DBOptions (`fail_if_options_file_error` at +0x190 vs +0x210).
The model follows the binary offsets; the stock-header
offsets are recorded as the observation, not the ground
truth. Early members match exactly
(`immutable_db_options_` +0x330, `mutable_db_options_`
+0x5a0, `versions_` +0x68, `env_` +0x318), as do
MutableDBOptions (0x70 B), ColumnFamilyOptions
(+0xe8/+0x160/+0x2b8), ColumnFamilyData (`dropped_` +0x3d,
`next_` +0x938), ColumnFamilySet (`dummy_cfd_` +0x110) and
VersionSet (`column_family_set_` +0x40).

Binary-vs-source observations (recorded, not hidden):
0x60d52f0 is `port::Mutex::Unlock`, not Lock: the census
lists 9 identical candidate symbols for that 149-byte body
(Lock/Unlock/CondVar::Signal/...); the disassembly calls
`pthread_mutex_unlock` (PLT 0x63f0b70). The Lock copy is
0x60d5230, reached through the InstrumentedMutexLock wrapper
0x606ca40 (not in the vendor census). The FileOptions temp is
built by `EnvOptions::EnvOptions(const DBOptions&)`
(`AssignEnvOptions` + the base no-op `SanitizeEnvOptions`)
with IOOptions defaults, temperature kUnknown and handoff
checksum kCRC32c; the base FileSystem
`OptimizeForCompactionTableWrite` sets `use_direct_writes`
from `use_direct_io_for_flush_and_compaction` and
`OptimizeForCompactionTableRead` sets `use_direct_reads`
from `use_direct_reads` (PosixFileSystem does not override
either). `GetMutableDBOptionsFromStrings` restores the base
options on a parse failure (its contract,
`options/db_options.cc:1049`); the model takes the parse
outcome as an oracle input.

## Caller census

Exactly 0 direct calls, 0 tail jumps, 0 LEA refs
(whole-`.text` scan, Capstone-validated, `census.py`) -- it
is a virtual API, not a direct callee. `DB::SetDBOptions`
is reached through the DB vtable slot 0x248:
`StackableDB::SetDBOptions` 0x5d30750 (census-bound, `c.o`)
calls the slot at 0x5d3081b (`call *0x248(%rax)`, verified
live from the disassembly) after a devirtualization chain.
The empty census is the expected result.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (22 modes: empty,
  parse-fail, unchanged, bytes-per-sync-default,
  validate1-fail, cf-fail-first, cf-fail-second,
  cf-dropped-skipped, bg-flush-up, bg-compaction-up,
  bg-both-up, bg-none, scheduler-dump-0,
  scheduler-dump-register-fail, scheduler-persist-0,
  scheduler-persist-register-fail, wal-switch-total,
  wal-switch-changed, wal-switch-fail, persist-fail-ignore,
  persist-fail-error, mixed) + 600 status (100 each: OK
  image, empty-input error, persist-IOError with `": "` join,
  ctor msg2 join, arbitrary code/subcode/severity/state
  images, BadAlloc in the empty-input Status ctor with no
  landing pad) + 600 throw (one armed fail_at per case across
  all 40 THROW_SITES, in 5 modes: throw alone, throw + bad
  canary, BadAlloc + bad canary, canary failure on a normal
  return, alloc_ok=False with no fail_at) + 600 bindings
  (caller-site independence across the vtable slot and the
  empty direct-call census, both FDE hashes as expected
  values).
  `tools/set_db_options115.py --verify-cases` reproduces all
  2,400 with 0 mismatches.
- `tests/test_set_db_options115.py`: 31 tests, all pass.
- Live check (`tools/set_db_options115.py --live`): 171/171
  legs -- both FDE body hashes, both source hashes (121 + 20
  relocations zeroed), the census symbols/members, both FDE
  records (lengths 0x4c/0x20, ranges 0xe70/0xf6, aug_len 4,
  LSDA pointers 0x4092b8/0x409343), the LSDA call-site
  tables (22 + 1 entries, all cleanup), the 15 landing-pad
  stub mappings, the engine-call counts (main 96 call lines,
  cold 20), the field cmp instructions, the message bytes
  plus the empty msg2, the empty caller census plus the
  vtable slot, and the model end-to-end legs (defaults OK,
  empty input, unchanged short-circuit, parse/validate1/
  per-CF failures, jobs 2->16 growing both pools (4/12),
  register-dump failure, SwitchWAL failure logged only,
  persist failure ignored vs IOError, ctor `state_` buffer =
  msg + NUL, ctor `": "` join, throw + bad canary ->
  StackCheckFailed, BadAlloc + bad canary with no pad ->
  BadAlloc, normal return + bad canary -> StackCheckFailed).

## Bugs caught and fixed in-cycle (not in-PR)

1. The live `unchanged options short-circuit` leg as written
   could never fire: it passed a default DB (bytes_per_sync
   0) against parsed options that default to 1 MiB, so the
   guard never triggered. Fixed the leg to set the DB's
   mutable bytes_per_sync to 1048576 first.
2. The `unchanged` case mode was mislabeled the same way: it
   never exercised the short-circuit. Fixed the mode to set
   the DB override; 28 checks cases now genuinely cover the
   short-circuit.
3. `status_tostring` rendered enum names (`kIOError: ...`).
   The binary's ToString jump table uses human phrases (`IO
   error: ...`, `Not implemented: `, ...). Fixed from the
   disassembly (jump table 0x97e958 + subcode table
   0x64d7b00 via RELATIVE relocs); this changed the
   persist-IOError, SwitchWAL-warn, and register effect
   strings in the cases.
4. The `SOURCE_SHA256` constant had a dropped `7` (63 chars).
   Fixed from the census record; the computed hash was
   already correct.
5. The engine-call table listed one `call 5d519d0`
   (WriteContext dtor) in the main FDE; that call lives only
   in the `.cold` FDE. Removed; main total 97 -> 96.
6. The `s.code` check count was 6; the disassembly has 7
   (`cmpb $0x0,0x60(%rsp)` at 0x5d72366, 0x5d723e6,
   0x5d72591, 0x5d7261a, 0x5d72638, 0x5d7274a, 0x5d727b5) --
   the unchanged guard is the seventh.
7. The `bg-none` case mode set jobs 2->4, which grows
   compactions 1->3, so it did not test "no pool growth".
   Fixed to keep jobs at the DB default (2).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the setter in Python from its
whole-FDE disassembly; the Status ctor's observable behavior
is pinned from its own disassembly, and ToString's rendering
from its jump table and subcode table. Status `state_`
buffers are deterministic heap ids, not real pointers; the
subcode padding bytes (+0x6..+0x7) the binary never writes
are modelled as zero. `make verify`/`test`/`catalogue-check`
in a tooled environment is still owed upstream.

## Open unknowns

- Whether the `new char[]` in the Status ctor can throw for
  these two messages on a real allocation failure is modelled,
  not observed: the binary is never executed, so the BadAlloc
  path is a reconstruction of the ctor's control flow, not a
  witnessed throw. The exception type is never named by the
  binary (the LSDA has cleanup entries only, no catch), so
  the model records the throwing site, not an exception type.
- The subcode table has 10 entries (subcodes 0..9); a
  subcode above 9 would read past it in the binary. No status
  this FDE produces or consumes has a non-zero subcode, so
  that path is unmodelled.
- The parse, build, and validation callees are oracles: their
  bodies are reconstructed in their own packets (open PRs
  #6379 and #6449 for the validators) or taken from upstream
  v8.1.1 source. A parse failure's restore-the-base-options
  contract is taken from `options/db_options.cc:1049`, not
  from the binary.

## Next candidates (noted, not submitted)

- `DBImpl::Open` 0x5e62c50..0x5e65462 (10258 B, census-bound):
  the sole caller of the two-argument validator; the whole
  open sequence. NOTE: at 10 KB / 206 calls it is far larger
  than any Shape A packet so far; model it only as a full
  reconstruction or not at all, never as a partial bind.
- `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518 (7304 B,
  census-bound).
