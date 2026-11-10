# RE-002: reconstruct node #115 `rocksdb::DBImpl::ValidateOptions`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBImpl::ValidateOptions(const DBOptions&, const
std::vector<ColumnFamilyDescriptor>&)` -- the gate `DBImpl::Open`
runs before it touches any column family: it validates every
requested column family's options against the DB options, then
validates the DB options alone, and returns the first non-OK status.
2,400 byte-checked cases; 29 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBImpl::ValidateOptions` | `0x5e5a000..0x5e5a151` | 337 B | `8b4ef72750b4932b47334802a85dd4030dab7985dc7cbf1a964e4f8490d1b7c7` | `4d429ab1cb2d8f8b-db_impl_open.o`, `_ZN7rocksdb6DBImpl15ValidateOptionsERKNS_9DBOptionsERKSt6vectorINS_22ColumnFamilyDescriptorESaIS5_EE` |
| `rocksdb::DBImpl::ValidateOptions.cold` | `0x5e59fd4..0x5e59fff` | 43 B | `9a82fbb229028dc489614db7989d2521b930301f6fda856b380bed01ed468da2` | none (body hash only) |

The main source hash reproduces exactly by zeroing the 8 census
relocations (kinds 2/4, no relaxation):
`b3d3ffa353d65c669b904a080ecb7c57e809e43d76a77611456c4eeacb01dab8`.
The .cold FDE has no vendor census record, so it is bound by body
hash only, per the no-census convention. This is the direct
follow-up to the CreateWAL packet (open PR #6222, 0x5e5c270, the
next step of the same open sequence), the BuildDBOptions packet
(open PR #6297, 0x60c2e20) and the DBOptions ctor trio (open PRs
#6337/#6338/#6341): Open sanitizes the options, builds the
DBOptions, validates them here, and only then creates the WAL and
the DBImpl.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status DBImpl::ValidateOptions(const DBOptions&
db_options, const std::vector<ColumnFamilyDescriptor>&
column_families)` -- the result is returned by value (hidden sret
out in `rdi` = `rbx`), `db_options` in `rsi` (= `r12`), the
descriptor vector in `rdx` (begin in `rbp`, end in `r14`). A stack
canary IS used (`%fs:0x28`, stored at `0x18(%rsp)`, checked on the
return path and in `.cold`). In binary order:

1. `out = OK` (0x5e5a028..0x5e5a043): code u32 at +0x0 = 0, subcode
   u16 at +0x4 = 0, `state_` ptr at +0x8 = nullptr. Bytes
   +0x6..+0x7 (the subcode padding) are never written -- the model
   zeroes them and records them as unwritten padding.
2. The loop (0x5e5a044..0x5e5a0c3): `p = begin; while (p != end)`:
   call `ColumnFamilyData::ValidateOptions(db_options, p->options)`
   -- 0x5d8e3b0, sret temp at `(%rsp)`, `db_options` in `rsi`,
   `&descriptor.options` in `rdx` = `p + 0x20` -- then MOVE the temp
   status into `out` (see 4) and test `out.code`: if non-zero,
   return `out` at once (first failure wins; later column families
   are never validated and the DB-options check never runs). Else
   `p += 0x320` (the descriptor stride: name string 0x20 +
   ColumnFamilyOptions 0x300) and loop. The descriptor NAME is never
   read anywhere in this FDE -- only options at +0x20.
3. After the loop -- including the empty-list case, which jumps
   straight here (0x5e5a049 -> 0x5e5a0e8): call
   `DBImpl::ValidateOptions(db_options)` -- 0x5e59cd0, the
   one-argument overload, sret temp at `(%rsp)` -- then MOVE the
   temp into `out` (see 4) and return `out`. The DB-options check
   runs exactly once, after every column family passed.
4. The Status move (twice: 0x5e5a06f..0x5e5a0b9 after the per-CF
   call, 0x5e5a0f3..0x5e5a139 after the DB-options call): copy the
   temp's code u32 (+0x0) and subcode u16 (+0x4) into `out`, take
   the temp's `state_` ptr (+0x8) into `out`, zero the temp's
   code/subcode/`state_`, then -- only if `out`'s OLD `state_` was
   non-null -- free it with `operator delete[]` (PLT 0x63f0dc0).
   The move transfers ownership: the old `out` state_ is freed,
   the new state_ is shared with no copy, and the temp is left as
   a null OK status. (The `movzwl (%rsp),%eax` at 0x5e5a076 is dead
   -- its result is never used; the gate reads `out.code` fresh at
   0x5e5a0be.)
5. The gate (0x5e5a0be..0x5e5a0c3): `movzbl (%rbx),%eax; test
   %al,%al; je` -- only the code BYTE at `out+0x0` is tested.
   Subcode and `state_` never decide anything in this FDE.
6. Epilogue (0x5e5a0c5..0x5e5a0e4): stack-canary check (`mov
   0x18(%rsp),%rax; sub %fs:0x28,%rax; jne __stack_chk_fail`), add
   `$0x20,%rsp`; pop `rbx/rbp/r12/r13/r14`; `ret rax = out`.

The LSDA call-site table (decoded from `.gcc_except_table` with
the repo's `tools/fde_extents.py` FDE index -- main LSDA at
0x40fa2d, 10 bytes, header `ff ff 01 06` + 1 call-site entry;
`.cold` LSDA at 0x40fa37, 8 bytes, header `ff ff 01 04` + 1 entry).
One guarded range in the main FDE:

- FDE+0x6a..+0xf3 (0x5e5a06a..0x5e5a0f3) -- both ValidateOptions
  calls AND the four `delete[]` calls -> pad 0x5e5a145, action 0
  (cleanup only, no catch).

The pad (0x5e5a145..0x5e5a14f) is one `endbr64` stub: `mov
%rax,%rbp` (the exception object into `rbp`) then `jmp 0x5e59fd4`
into `.cold`. `.cold` (0x5e59fd4..0x5e59fff) frees `out.state_` if
non-null (0x5e59fd4..0x5e59fdd, `delete[]` PLT 0x63f0dc0), checks
the stack canary (0x5e59fe2..0x5e59ff0, `__stack_chk_fail` on
mismatch) and resumes unwinding with `_Unwind_Resume(%rbp)`
(0x5e59ff2..0x5e59ff9). It never touches the temp status on the
stack -- the throwing call never completed its sret store -- and
it never touches any descriptor. The `.cold` LSDA routes its own
`_Unwind_Resume` call (FDE+0x21..+0x26) to NO pad (already inside
the cleanup); the `__stack_chk_fail` call has no entry.

## The two callees are oracles

Their bodies are NOT reconstructed here; the packet pins the
dispatcher's loop, move, gate, LSDA and pad, and the call
order/targets. The reference oracles in
`tools/dbimpl_validate_options115.py` are derived from upstream
RocksDB v8.1.1 source read live this cycle:

- `ColumnFamilyData::ValidateOptions` 0x5d8e3b0 (1555 B,
  census-bound, member `4d429ab1cb2d8f8b-column_family.o`): the
  per-CF validator, called once per descriptor. Upstream
  (`db/column_family.cc`, same-era source) runs, in order,
  `CheckCompressionSupported`, then -- only if the DB options allow
  concurrent memtable writes -- `CheckConcurrentWritesSupported`,
  then the `unordered_write` + `max_successive_merges` rule, then
  `CheckCFPathsSupported`, then the `ttl` / periodic-compaction
  table-factory rules. Message wordings are model wording except
  `CheckCompressionSupported`, `CheckConcurrentWritesSupported`
  (inplace-update arm), `CheckCFPathsSupported` and the TTL arm,
  which are quoted verbatim from the upstream read. The 0x5d8e3b0
  body itself is an open follow-up candidate.
- `DBImpl::ValidateOptions(const DBOptions&)` 0x5e59cd0 (771 B,
  census-bound, member `4d429ab1cb2d8f8b-db_impl_open.o`, 21
  relocations): the one-argument overload, called once after the
  loop. Upstream `db/db_impl/db_impl_open.cc:392-484` runs nine
  checks in order -- `db_paths.size() > 4`,
  `allow_mmap_reads && use_direct_reads`, `allow_mmap_writes &&
  use_direct_io_for_flush_and_compaction`, `keep_log_file_num == 0`,
  `unordered_write && !allow_concurrent_memtable_write`,
  `unordered_write && enable_pipelined_write`, `atomic_flush &&
  enable_pipelined_write`, `atomic_flush && best_efforts_recovery`,
  `use_direct_io_for_flush_and_compaction &&
  writable_file_max_buffer_size == 0` -- and returns OK otherwise.
  The reference oracle implements those nine checks with the
  upstream messages quoted verbatim. The 0x5e59cd0 body itself is
  an open follow-up candidate.

Binary-vs-source observation (recorded, not hidden): the binary
calls `ColumnFamilyData::ValidateOptions` per column family, NOT
the free function `rocksdb::ValidateOptions(DBOptions,
ColumnFamilyOptions)` 0x60b94c0 (`options_helper.o`) -- the
anonymous-namespace `ValidateOptionsByTable` helper in
`db_impl_open.cc` calls the free function, but
`DBImpl::ValidateOptions` does not use that helper. The binary
returns the moved status directly (no extra copy), and the
empty-list path skips the loop entirely by jumping to the
DB-options call.

## Caller census

Exactly 1 direct call, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`): `DBImpl::Open` 0x5e62c50
(site 0x5e62e52, census-bound, `db_impl_open.o`). The validator
runs once per DB open, before any column family is created.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 loop (descriptor lists of 0-5,
  per-CF failures at each position, DB failures,
  CF-failure-masks-DB-failure, name-independence) + 600 move
  (Status move semantics: state_ transfer, temp zeroing, old
  state_ freed) + 600 throw (oracle `BadAlloc` at each call site,
  pad cleanup lists, canary failures) + 600 bindings
  (caller-site independence, FDE/LSDA hashes as expected values).
  `tools/dbimpl_validate_options115.py --verify-cases` reproduces
  all 2,400 with 0 mismatches.
- `tests/test_dbimpl_validate_options115.py`: 29 tests, all pass.
- Live check (`tools/dbimpl_validate_options115.py --live`): 20/20
  legs -- both FDE body hashes, the main source hash, both LSDAs,
  the 1-site caller census, the engine-call counts (1x
  0x5d8e3b0, 1x 0x5e59cd0, 4x `delete[]` + 1x `__stack_chk_fail`
  in main; 1x `delete[]` + 1x `_Unwind_Resume` + 1x
  `__stack_chk_fail` in `.cold`), the descriptor stride
  (`add $0x320,%rbp`) and options offset (`lea 0x20(%rbp),%rdx`),
  the code-byte gate, the canary sites, the pad, and the
  reference-oracle end-to-end legs.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the dispatcher in Python; the two
callees are reference oracles derived from upstream RocksDB v8.1.1
source read live this cycle (their binary bodies, 0x5d8e3b0 and
0x5e59cd0, are NOT reconstructed here). Status `state_` buffers
are deterministic heap ids, not real pointers; the subcode padding
bytes (+0x6..+0x7) the binary never writes are modelled as zero.
`make verify`/`test`/`catalogue-check` in a tooled environment is
still owed upstream.

## Open unknowns

- The type-table entry the LSDA action-1 record would name does
  not exist here: the single main-LSDA entry has action 0
  (cleanup only), so there is no catch and no type to resolve.
- The linked compression set the per-CF oracle reads
  (`supported`) is an explicit model input, not a binary claim;
  the dispatcher never reads it.
- Whether the `periodic_compaction_seconds` and
  `unordered_write` + `max_successive_merges` messages in the
  per-CF oracle match the binary's strings byte-for-byte is not
  pinned (model wording); the dispatcher copies the oracle's
  status opaquely, so no dispatcher claim depends on them.

## Next candidates (noted, not submitted)

- `DBImpl::ValidateOptions(const DBOptions&)` 0x5e59cd0..0x5e59fd3
  (771 B, census-bound, 21 relocations): the one-argument
  overload this packet calls as an oracle -- its nine checks.
- `ColumnFamilyData::ValidateOptions` 0x5d8e3b0..0x5d8e9c3
  (1555 B, census-bound, 49 relocations): the per-CF validator
  this packet calls as an oracle.
- `DBImpl::Open` 0x5e62c50..0x5e65462 (10258 B, census-bound):
  the sole caller of this validator; the whole open sequence.
- `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518 (7304 B,
  census-bound).
