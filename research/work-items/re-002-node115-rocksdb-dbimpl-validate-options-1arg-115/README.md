# RE-002: reconstruct node #115 `rocksdb::DBImpl::ValidateOptions` (one-argument overload)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBImpl::ValidateOptions(const DBOptions&)` -- the
one-argument overload that checks a DBOptions against the nine
rules of upstream `db/db_impl/db_impl_open.cc` and returns the first
non-OK status, or OK. It is called once by the two-argument
dispatcher (open PR #6342, 0x5e5a000, site 0x5e5a0ee) after every
column family passed, and once by `DBImpl::SetDBOptions` (0x5d71fe0,
site 0x5d7256d) after it builds the new DBOptions. 2,400
byte-checked cases; 29 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBImpl::ValidateOptions` | `0x5e59cd0..0x5e59fd3` | 771 B | `fe207dc0945912c63ccf42fee9aec9147a2969a5c005339aee8d9c31f6f221a2` | `4d429ab1cb2d8f8b-db_impl_open.o`, `_ZN7rocksdb6DBImpl15ValidateOptionsERKNS_9DBOptionsE` |

The source hash reproduces exactly by zeroing the 21 census
relocations (kinds 2/4, no relaxation):
`858395f2ce9f424c05ca9a0adf90f25390883c15b38f40fe7389af759e4c47e6`.
There is no `.cold` FDE and no LSDA: the FDE's augmentation
length in `.eh_frame` is 0 (record at section offset 0x3533f4,
length 0x20, initial_location 0x5e59cd0, range 0x303), so there
is no LSDA pointer, no call-site table, no landing pad, no catch
and no cleanup in this FDE. This packet supersedes the reference
oracle for this function in the dispatcher packet (open PR #6342)
with the full reconstruction.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status DBImpl::ValidateOptions(const DBOptions&
db_options)` -- the result is returned by value (hidden sret out
in `rdi` = `rbx`), `db_options` in `rsi`. A stack canary IS used
(`%fs:0x28`, stored at `0x28(%rsp)`, checked on the single return
path at 0x5e59e0b). In binary order:

1. The nine checks, each one cmp + a conditional jump to its error
   block; the fall-through continues to the next check. Field
   offsets are the DBOptions layout pinned by the default-ctor
   packet (open PR #6337, 0x60b2db0):
   - Check 1 (0x5e59cea..0x5e59cf8): `rax = *(rsi+0x78) -
     *(rsi+0x70)` (end - begin of the `db_paths` vector); if `rax
     > 0xa0` (160 = 4 DbPaths of 0x28 bytes) -> error 1. So
     `db_paths.size() > 4`.
   - Check 2 (0x5e59cfe..0x5e59d0e): if byte +0x128
     (`allow_mmap_reads`) != 0 and byte +0x12a (`use_direct_reads`)
     != 0 -> error 2.
   - Check 3 (0x5e59d14, 0x5e59d90..0x5e59d97): if byte +0x129
     (`allow_mmap_writes`) != 0 and byte +0x12b
     (`use_direct_io_for_flush_and_compaction`) != 0 -> error 3.
   - Check 4 (0x5e59d1d..0x5e59d25): if qword +0xf0
     (`keep_log_file_num`) == 0 -> error 4.
   - Check 5 (0x5e59d2b..0x5e59d3f): if byte +0x1d1
     (`unordered_write`) != 0 and byte +0x1d2
     (`allow_concurrent_memtable_write`) == 0 -> error 5.
   - Check 6 (0x5e59d45..0x5e59d4c): if byte +0x1d1 != 0 (already
     known) and byte +0x1d0 (`enable_pipelined_write`) != 0 ->
     error 6.
   - Check 7 (0x5e59d52, 0x5e59e30..0x5e59e44): if byte +0x218
     (`atomic_flush`) != 0 and byte +0x1d0 != 0 -> error 7.
     Reached two ways: from check 6 when `unordered_write` is
     false (0x5e59d2b -> 0x5e59e30), and from check 6's
     fall-through when `atomic_flush` is set (0x5e59d52 ->
     0x5e59eb0 -> check 8 first). The two entries share the
     +0x218 read at 0x5e59e30.
   - Check 8 (0x5e59eb0..0x5e59eb7): if byte +0x218 != 0 and byte
     +0x238 (`best_efforts_recovery`) != 0 -> error 8. Reached
     from check 7's fall-through (0x5e59d52) and from check 7's
     entry when `enable_pipelined_write` is false (0x5e59e3d ->
     0x5e59eb0).
   - Check 9 (0x5e59d5f..0x5e59d70): if byte +0x12b != 0 and qword
     +0x180 (`writable_file_max_buffer_size`) == 0 -> error 9.
   The first failing check wins: later checks never run.
2. The error blocks (nine, one per check): each builds two Slices
   on the stack -- msg = {ptr, len} at `(%rsp)`, msg2 = {0x4376fd,
   0} at `0x10(%rsp)` (the byte at 0x4376fd is 0x00, so msg2 is the
   empty string) -- then jumps to one of two shared tails:
   `esi=3` (`kNotSupported`) at 0x5e59df1..0x5e59e06 for checks 1-3,
   `esi=4` (`kInvalidArgument`) at 0x5e59f19..0x5e59f2e for checks
   4-9. Both tails call the Status ctor 0x61cf670 (census-bound,
   member `6cca28ae25285154-status.o`) with (rdi=out, esi=code,
   edx=subcode=0, rcx=&msg, r8=&msg2, r9d=severity=0). The ctor
   (decoded from its own disassembly): code u8 -> out+0x0, subcode
   u8 -> out+0x1, severity u8 -> out+0x2, zeroes out+0x3..+0x5,
   `state_` = nullptr first, then `new char[size+1]` where size =
   len1 + (len2 ? len2+2 : 0), memcpy msg at buf+0, `": "` + msg2
   at buf+len1 if len2, NUL at buf[size], `state_` = buf. For this
   FDE msg2 is always empty, so `state_` is exactly msg + NUL
   (alloc len+1). The ctor's trailing `delete[]` of the old
   `state_` is DEAD on this path: it zeroes `state_` at 0x61cf6b0
   before reading it at 0x61cf6e4, so the free never fires. If
   `new` throws (`bad_alloc`), the exception propagates straight
   through this frame: this FDE has no LSDA, so no cleanup runs
   here -- the caller's pad handles it.
3. The OK path (0x5e59d76..0x5e59d8a): out = OK -- `movl $0x0,
   (%rbx)` (bytes +0x0..+0x3), `mov %ax,0x4(%rbx)` with eax=0
   (bytes +0x4..+0x5), `movq $0x0,0x8(%rbx)` (`state_` = nullptr).
   Bytes +0x6..+0x7 are never written by any path in this FDE --
   the model zeroes them and records them as unwritten padding.
4. Epilogue (0x5e59e0b..0x5e59e27): the single return path for both
   OK and error results -- stack-canary check (`mov 0x28(%rsp),%rax;
   sub %fs:0x28,%rax; jne __stack_chk_fail` at 0x5e59fce), add
   `$0x30,%rsp`, pop rbx, `ret rax = out`. A canary mismatch raises
   `StackCheckFailed` instead of returning. The ctor-throw path
   never reaches the epilogue, so a throw is not masked by a canary
   failure.

The nine messages are the upstream strings quoted verbatim
(meta/rocksdb v8.1.1, `db/db_impl/db_impl_open.cc:243-298`, read
live this cycle), each verified byte-for-byte against the .rodata
string at its address. Note the trailing space in the first three
messages -- it is in the source strings and in the binary. The
#6342 packet cited this function as :392-484; the file read live
this cycle has the two-argument dispatcher at :229-241 and the
one-argument overload at :243-298 (the function content matches
exactly).

Status layout, corrected from the #6342 packet's loose wording:
the #6342 packet described the Status words as "code u32 +0x0,
subcode u16 +0x4" from the zero-writes of the OK path. The ctor at
0x61cf670 proves the byte layout: code u8 +0x0, subcode u8 +0x1,
severity u8 +0x2, padding +0x3..+0x7 (ctor writes +0x3..+0x5 zero;
+0x6..+0x7 never written), `state_` +0x8. The two descriptions are
behaviorally identical for the OK/error values both packets pin
(all three bytes are zero except the code byte), but this packet
models the byte layout the ctor proves.

Binary-vs-source observations (recorded, not hidden): the binary
checks the `db_paths` BYTE size (> 0xa0) rather than the element
count -- the same rule, since DbPath is 0x28 bytes; the binary
passes an empty second Slice to the Status ctor (the source calls
`NotSupported`/`InvalidArgument` with one message, which delegates
to the five-argument ctor with msg2 empty); the binary's check 7 is
reached through two entries that share one +0x218 read, and check 8
is reached two ways -- the source's straight-line order is
preserved, only the control flow is folded. Upstream
`db_impl.cc:1242` confirms the SetDBOptions caller: after
BuildDBOptions it calls `ValidateOptions` on the new DBOptions
before validating each column family.

## Caller census

Exactly 2 direct calls, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`): the two-argument
dispatcher 0x5e5a000 (site 0x5e5a0ee, census-bound,
`db_impl_open.o`) and `DBImpl::SetDBOptions` 0x5d71fe0 (site
0x5d7256d, census-bound, `db_impl.o`). The validator runs once per
DB open (after the column families pass) and once per SetDBOptions
call (on the rebuilt DBOptions).

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (each check failing
  alone, pairs where the earlier one must win, boundaries: 4 vs 5
  db_paths, keep_log 1 vs 0, buffer 1 vs 0, mixed bools) + 600
  status (OK image, each error image with code/subcode/severity/
  pad/`state_` content, the ctor's `": "` join with a non-empty
  msg2) + 600 throw (BadAlloc in the Status ctor at each of the 9
  error sites with the half-built status attached and no cleanup in
  this frame, canary failures on OK and error returns, BadAlloc
  beating a bad canary) + 600 bindings (caller-site independence
  across both callers, FDE hashes as expected values).
  `tools/dbimpl_validate_options_1arg115.py --verify-cases`
  reproduces all 2,400 with 0 mismatches.
- `tests/test_dbimpl_validate_options_1arg115.py`: 29 tests, all pass.
- Live check (`tools/dbimpl_validate_options_1arg115.py --live`):
  52/52 legs -- the FDE body hash, the source hash (21
  relocations zeroed), the census symbol/member, the no-LSDA fact
  (FDE aug_len 0, CFI bytes follow), the engine-call counts (2x
  Status ctor, 1x `__stack_chk_fail`, 0x `delete[]`, 1x endbr64,
  canary stored once + checked once, msg2 lea x9), the twelve field
  cmp instructions, all nine message bytes plus the empty msg2, the
  2-site caller census, and the model end-to-end legs (defaults OK,
  each check failing with its message, check 1 masking check 4,
  ctor `state_` buffer = msg + NUL, ctor `": "` join).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the validator in Python from its
whole-FDE disassembly; the Status ctor's observable behavior is
pinned from its own disassembly (its body is not reconstructed
here). Status `state_` buffers are deterministic heap ids, not real
pointers; the subcode padding bytes (+0x6..+0x7) the binary never
writes are modelled as zero. `make verify`/`test`/`catalogue-check`
in a tooled environment is still owed upstream.

## Open unknowns

- The type-table entry an LSDA action record would name does not
  exist here: the FDE has no LSDA at all (aug_len 0), so there is
  no catch and no type to resolve.
- Whether the `new char[]` in the Status ctor can throw for these
  nine messages on a real allocation failure is modelled, not
  observed: the binary is never executed, so the BadAlloc path is
  a reconstruction of the ctor's control flow, not a witnessed throw.

## Next candidates (noted, not submitted)

- `ColumnFamilyData::ValidateOptions` 0x5d8e3b0..0x5d8e9c3 (1555 B,
  census-bound, 49 relocations): the per-CF validator the
  dispatcher packet (open PR #6342) calls as an oracle.
- `DBImpl::Open` 0x5e62c50..0x5e65462 (10258 B, census-bound): the
  sole caller of the two-argument validator; the whole open
  sequence. NOTE: at 10 KB / 206 calls it is far larger than any
  Shape A packet so far; model it only as a full reconstruction or
  not at all, never as a partial bind.
- `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518 (7304 B,
  census-bound).
- `DBImpl::SetDBOptions` 0x5d71fe0..0x5d72e50 (3696 B,
  census-bound): the second caller of this validator; validates
  rebuilt options before applying them.
