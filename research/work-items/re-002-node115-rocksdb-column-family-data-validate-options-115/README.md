# RE-002: reconstruct node #115 `rocksdb::ColumnFamilyData::ValidateOptions` (per-CF options gate)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `ColumnFamilyData::ValidateOptions(const DBOptions&, const
ColumnFamilyOptions&)` -- the per-column-family options validator
that checks a CF's options against the three helper oracles and
seven inline rules of upstream `db/column_family.cc` and returns
the first non-OK status, or OK. It is called once per column family
by the two-argument dispatcher (open PR #6342, 0x5e5a000, site
0x5e5a06a), once by `DBImpl::SetDBOptions` (0x5d71fe0, site
0x5d725f6) and once per `ColumnFamilyData::SetOptions` call
(0x5d8ea70, site 0x5d8eb60). 2,400 byte-checked cases; 34 tests, all
pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::ColumnFamilyData::ValidateOptions` | `0x5d8e3b0..0x5d8e9c3` | 1555 B | `4c564ac336f94f2e9a06f9a725d47902a850a87162844c5ce7691f07672591d0` | `25dac13516458d4d-column_family.o`, `_ZN7rocksdb16ColumnFamilyData15ValidateOptionsERKNS_9DBOptionsERKNS_19ColumnFamilyOptionsE` |
| same symbol `.cold` | `0x5d8e356..0x5d8e3a5` | 79 B | `4df4d5cd1f379d7866ba92c9b18e0ea634492a6136623aae87e50f435c93cd9c` | same member, `.cold` suffix |

The source hashes reproduce exactly by zeroing the census
relocations (main: 49, kinds 2/4/42; cold: 6, kind 4 -- no
relaxation; the two kind-42 sites are plain `cmp` displacements).
The main FDE has an LSDA at 0x40a30f (8 entries, all cleanup); the
`.cold` FDE has an LSDA at 0x40a344 (1 entry, for the
`_Unwind_Resume` call). This packet supersedes the reference
oracle for this function in the dispatcher packet (open PR #6342)
with the full reconstruction.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status ColumnFamilyData::ValidateOptions(const DBOptions&
db_options, const ColumnFamilyOptions& cf_options)` -- the result
is returned by value (hidden sret out in `rdi` = `rbp`),
`db_options` in `rsi` = `r12`, `cf_options` in `rdx` = `rbx`. A
stack canary IS used (`%fs:0x28`, stored at `0x78(%rsp)`, checked
on the epilogue at 0x5d8e457 and in every LSDA pad via the `.cold`
FDE). Two stack temps: T1 at `0x40(%rsp)` (helper-result temp,
`r13`), T2 at `0x10(%rsp)` (`r14`, shallow copy / move-assign
target). In binary order:

1. `CheckCompressionSupported(cf_options)` (0x5d8dcc0, census-bound)
   -> T1; T2 = shallow copy of T1; if T1.code != 0 -> error-return
   block 0x5d8e428.
2. If `db_options.allow_concurrent_memtable_write` (+0x1d2) != 0:
   `CheckConcurrentWritesSupported(cf_options)` (0x5d8ba60,
   census-bound) -> T1; T2 = move-assign(T1) via 0x5d89b20; if
   T2.code != 0 -> error-return block.
3. If `db_options.unordered_write` (+0x1d1) != 0 AND
   `cf_options.max_successive_merges` (+0x150, u64) != 0 ->
   InvalidArgument (code 4), msg at 0x9601d8 len 62:
   `max_successive_merges > 0 is incompatible with
   unordered_write`. Built into T1 via the Status ctor 0x61cf670,
   then T2 = move-assign(T1) and the shared error-return block --
   the only inline error routed that way (the source assigns to
   the local Status `s` and hits the `if (!s.ok()) return s` gate).
4. `CheckCFPathsSupported(db_options, cf_options)` (0x5d8bb50,
   census-bound) -> T1; T2 = move-assign(T1); if T2.code != 0 ->
   error-return block.
5. TTL: if `cf_options.ttl` (+0x160, u64) != 0 AND !=
   `kDefaultTtl` (0xFFFFFFFFFFFFFFFE) -> `table_factory->
   IsInstanceOf("BlockBasedTable")`; if false -> NotSupported
   (code 3), msg 0x96b4c0 len 51: `TTL is only supported in
   Block-Based Table format. ` (trailing space).
6. Periodic: if `cf_options.periodic_compaction_seconds` (+0x168,
   u64) != 0 AND != `kDefaultPeriodicCompSecs`
   (0xFFFFFFFFFFFFFFFE) -> same IsInstanceOf check; if false ->
   NotSupported, msg 0x9669d0 len 67: `Periodic Compaction is only
   supported in Block-Based Table format. ` (trailing space).
7. Blob GC: if `cf_options.enable_blob_garbage_collection` (+0x1a9,
   bool) != 0: if `blob_garbage_collection_age_cutoff` (+0x1b0,
   double) outside [0.0, 1.0] -> InvalidArgument, msg 0x96bde8 len
   77: `The age cutoff for blob garbage collection should be in
   the range [0.0, 1.0].`; if
   `blob_garbage_collection_force_threshold` (+0x1b8, double)
   outside [0.0, 1.0] -> InvalidArgument, msg 0x958e00 len 98:
   `The garbage ratio threshold for forcing blob garbage
   collection should be in the range [0.0, 1.0].` (NaN passes both
   range checks: comisd unordered sets ZF=1 so `ja` is not taken
   and `jbe` is taken -- the same as the source `x < 0.0 || x >
   1.0`, which is false for NaN.)
8. FIFO: if `cf_options.compaction_style` (+0xe8, byte compare ==
   2 = kCompactionStyleFIFO) AND `db_options.max_open_files`
   (+0x44, i32) != -1 AND `cf_options.ttl` (+0x160) != 0 ->
   NotSupported, msg 0x95b860 len 56: `FIFO compaction only
   supported with max_open_files = -1.` (ttl tested as plain != 0
   here, no kDefaultTtl exclusion -- unlike check 5.)
9. Memtable protection: `std::vector<uint32_t> supported{0,1,2,4,8}`
   heap-allocated (operator new(0x14), 20 B; 16 B copied from
   .rodata 0x4544c0 = {0,1,2,4}, 5th int 8 stored at +0x10);
   `std::find` constant-folded into a switch on
   `cf_options.memtable_protection_bytes_per_key` (+0x1e4, u32):
   values 0/1/2/4/8 match, anything else -> error directly. If not
   found -> NotSupported, msg 0x96a950 len 87: `Memtable per
   key-value checksum protection only supports 0, 1, 2, 4 or 8
   bytes per key.` The vector is freed with sized delete
   `_ZdlPvm` (0x14) on BOTH the error path (0x5d8e79d) and the OK
   path (via jmp 0x5d8e79d).
10. Else return OK (out = move-assign(T2), i.e. the last helper's OK
    status; a code-0-with-state helper result would propagate into
    out -- modelled and tested).

The three helpers are oracles: their bodies are NOT reconstructed
here. They are modelled from the v8.1.1 source they implement
(`db/column_family.cc:113-192`, read live this cycle) with the
build-dependent linked-codec set as an explicit model input:
CheckCompressionSupported checks each per-level (or single)
compression type against the linked set, the zstd dict-trainer /
finalize support flags and `max_dict_bytes != 0`, then the blob
compression type; CheckConcurrentWritesSupported rejects
`inplace_update_support` and a memtable factory that does not
support concurrent inserts; CheckCFPathsSupported rejects > 1
cf_paths (or empty cf_paths with > 1 db_paths) outside universal /
level compaction.

Status plumbing: helpers' errors return via the shared
error-return block 0x5d8e428 (out = move-assign(T2) via
0x5d89b20 -- NOT in the census; decoded from its disassembly:
self-assign guard, copies the 6 bytes code/subcode/severity, moves
state_, zeroes the source, frees the destination's OLD state_ via
operator delete[] tail-jump), then delete[] T2.state_ (dead after
the move, since T2.state_ is zeroed). Inline error blocks build
the error Status DIRECTLY into out via the 5-arg Status ctor
0x61cf670 (census-bound, `6cca28ae25285154-status.o`; args out,
code, subcode 0, &msg Slice, &msg2 Slice = {0x4376fd, 0} where the
byte at 0x4376fd is 0x00, severity 0) then jump to the epilogue.
The OK path zeroes out then move-assigns T2 into it. Epilogue
(0x5d8e448): delete[] T2.state_ if non-null (dead on every normal
path); canary check; return out. Bytes +0x6..+0x7 of out are never
written by any path -- the model zeroes them and records them as
unwritten padding.

The ttl/periodic IsInstanceOf checks devirtualize: the
table_factory vtable slot 16 function pointer is compared against
the GOT slot 0x64eceb8 (`R_X86_64_RELATIVE` addend 0x5d2e770 =
`Customizable::IsInstanceOf`); if equal, the constprop clone
0x5d89e80 is called directly, else the virtual `call *%rcx`.

LSDA (decoded from `.gcc_except_table`; `.eh_frame` records at
section offsets 0x735798 (main, length 0x4c, range 0x613) and
0x7357e8 (cold, length 0x20, range 0x4f), both aug_len 4 with the
LSDA pointer as pcrel sdata4): main LSDA at 0x40a30f, 53 bytes,
header `ff ff 01`, table length 0x31, 8 entries, all action 0
(cleanup only) -- pads 0x607 generic (delete T2.state_ if
non-null), 0x5fb dispose the "BlockBasedTable" string + generic
(ttl IsInstanceOf), 0x5e3 dispose the string + generic (periodic
IsInstanceOf), 0x5ef sized-delete the 20-byte vector + generic
(memtable Status ctor). Cold LSDA at 0x40a344, 8 bytes, 1 entry
for the `_Unwind_Resume` call at 0x5d8e381 (pad 0). Every pad runs
its cleanup, then the canary check, then resumes -- so a throw
with a bad canary raises `__stack_chk_fail` from the pad instead
of resuming.

The seven inline messages are the upstream strings quoted
verbatim (meta/rocksdb v8.1.1, `db/column_family.cc:1364-1448`,
read live this cycle), each verified byte-for-byte against the
.rodata string at its address. Note the trailing space in the TTL
and periodic messages -- it is in the source strings and in the
binary.

Binary-vs-source observations (recorded, not hidden): the
unordered_write error is built into T1 and routed through the
shared error-return block, while the six later inline errors
return directly; the ttl/periodic IsInstanceOf calls are
devirtualized against the GOT slot; the memtable-protection
`std::find` is constant-folded into a switch; the vector is freed
with sized delete on both paths; the blob range checks use comisd,
so NaN passes; the FIFO check tests ttl as plain != 0 with no
kDefaultTtl exclusion, unlike the TTL check. A newer
rust-rocksdb mirror (commit bad0727b) contains EXTRA checks the
binary does NOT have (a UDT/comparator-timestamp block, a
`block_protection_bytes_per_key` check and a
`file_temperature_age_thresholds` check) -- the mirror is newer
than v8.1.1; the model follows v8.1.1.

## Caller census

Exactly 4 direct calls, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`): `DBImpl::
CreateColumnFamilyImpl` 0x5d69a00 (site 0x5d69a9d, census-bound,
`db_impl.o`), `DBImpl::SetDBOptions` 0x5d71fe0 (site 0x5d725f6,
census-bound, `db_impl.o`), `ColumnFamilyData::SetOptions`
0x5d8ea70 (site 0x5d8eb60, census-bound, `column_family.o`;
matches v8.1.1 `column_family.cc:2828`), and the two-argument
dispatcher `DBImpl::ValidateOptions` 0x5e5a000 (site 0x5e5a06a,
census-bound, `db_impl_open.o`, open PR #6342). The validator runs
once per column family at open, once per SetDBOptions and once per
SetOptions call.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (each check failing
  alone, pairs where the earlier one must win, boundaries: ttl 1 /
  kDefaultTtl-1 / kDefaultTtl, periodic 1 / kDefaultPeriodic, blob
  cutoffs 0 / 0.5 / 1 / 1+eps / -eps / NaN, memtable values
  0/1/2/4/8 vs 3/5/9/0xffffffff, FIFO with kDefaultTtl, mixed
  options) + 600 status (OK image, each error image with
  code/subcode/severity/pad/`state_` content, the ctor's `": "`
  join with a non-empty msg2, move-assign semantics, OK-with-state
  helper propagation) + 600 throw (BadAlloc in the Status ctor at
  each of the 7 inline error sites with the half-built status and
  the pad's cleanup attached, callee throws at every helper /
  string-ctor / IsInstanceOf / operator-new site with its LSDA
  pad, canary failures on OK and error returns, BadAlloc beating
  a bad canary via the pad's canary check, alloc_ok=False with no
  fail_at) + 600 bindings (caller-site independence across all
  four callers, FDE/LSDA hashes as expected values).
  `tools/cf_data_validate_options115.py --verify-cases` reproduces
  all 2,400 with 0 mismatches. (NaN cutoff inputs are stored as
  the string `"nan"` in cases.tsv and decoded by the tool; the
  expected outputs contain no NaN.)
- `tests/test_cf_data_validate_options115.py`: 34 tests, all pass.
- Live check (`tools/cf_data_validate_options115.py --live`):
  87/87 legs -- the FDE body hashes, the source hashes (49 + 6
  relocations zeroed), the census symbols/members, the LSDA bytes
  and both `.eh_frame` records (lengths 0x4c/0x20, ranges
  0x613/0x4f, aug_len 4, LSDA pointers 0x40a30f/0x40a344), the
  engine-call counts (4x Status ctor, 1x `__stack_chk_fail`,
  4x `delete[]`, 1x sized delete, 5x endbr64, 5x move-assign, 1x
  each helper, 2x string ctor, 2x IsInstanceOf constprop, 2x
  indirect IsInstanceOf, canary stored once + checked once, msg2
  lea x7, operator new(0x14), vector seed from .rodata 0x4544c0,
  GOT slot 0x64eceb8; cold: 1x each `__stack_chk_fail` /
  `delete[]` / sized delete / `_Unwind_Resume`, 0x endbr64,
  canary once), the twelve field cmp instructions, all seven
  message bytes plus the empty msg2, the 4-site caller census,
  and the model end-to-end legs (defaults OK, each of the 10
  checks failing with its message, check 1 masking check 5,
  check 3 masking check 10, NaN cutoffs passing, kDefaultTtl /
  kDefaultPeriodic passing, FIFO firing for kDefaultTtl, helper
  OK-with-state propagating to out, ctor `state_` buffer = msg +
  NUL, ctor `": "` join).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the validator in Python from its
whole-FDE disassembly; the three helper oracles are modelled from
the v8.1.1 source they implement (their bodies are not
reconstructed here); the Status ctor's and move-assign's
observable behavior is pinned from their own disassembly (their
bodies are not reconstructed here). Status `state_` buffers are
deterministic heap ids, not real pointers; the subcode padding
bytes (+0x6..+0x7) the binary never writes are modelled as zero.
`make verify`/`test`/`catalogue-check` in a tooled environment is
still owed upstream.

## Open unknowns

- Whether the `new char[]` in the Status ctor can throw for these
  seven messages on a real allocation failure is modelled, not
  observed: the binary is never executed, so the BadAlloc path is
  a reconstruction of the ctor's control flow, not a witnessed
  throw. The same holds for the helper calls, the string ctor,
  the IsInstanceOf calls and the vector operator new: their
  exception types are never named by the binary (all LSDA actions
  are 0, cleanup only), so the model records the throwing site,
  its pad and the pad's cleanup, not an exception type.
- The exact linked-codec set of the node #115 build (which
  CompressionType values `CompressionTypeSupported` accepts) is
  not pinned by this FDE: the compression oracle takes the
  linked set as an explicit input, defaulting to all standard
  types.

## Next candidates (noted, not submitted)

- `DBImpl::Open` 0x5e62c50..0x5e65462 (10258 B, census-bound): the
  sole caller of the two-argument validator; the whole open
  sequence. NOTE: at 10 KB / 206 calls it is far larger than any
  Shape A packet so far; model it only as a full reconstruction
  or not at all, never as a partial bind.
- `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518 (7304 B,
  census-bound).
- `DBImpl::SetDBOptions` 0x5d71fe0..0x5d72e50 (3696 B,
  census-bound): the second caller of the one-argument validator
  and of this per-CF validator; validates rebuilt options before
  applying them.
- `CheckCompressionSupported` 0x5d8dcc0 (census-bound, 69
  relocations), `CheckConcurrentWritesSupported` 0x5d8ba60 (6
  relocations) and `CheckCFPathsSupported` 0x5d8bb50 (6
  relocations): the three helper oracles of this packet, as full
  reconstructions -- the compression helper would pin the
  linked-codec set that this packet leaves as an input.
