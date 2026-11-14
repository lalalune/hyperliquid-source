# RE-002: reconstruct node #115 `rocksdb::DBImpl::CreateWAL`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `DBImpl::CreateWAL(uint64_t log_file_num, uint64_t
recycle_log_number, size_t preallocate_block_size, log::Writer**
new_log)` -- the WAL-file creation routine `DBImpl::Open` and
`DBImpl::SwitchMemtable` call to open a new WAL: build the log file
name, open (or recycle) the file, wrap it in a `WritableFileWriter`
and a `log::Writer`, write the compression-type record, and hand the
writer back in `*new_log`. 2,400 byte-checked cases; 29 tests, all
pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs, both pinned by recomputation
and BOTH census-bound:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::DBImpl::CreateWAL` | `0x5e5c270..0x5e5c9a3` | 1843 B | `b880ae88e16d2303236572e99c4ff6b830f0a28f975fda43f7be504b5a36f5a1` | `node115-vendor-5e5c270`, 52 relocations (kinds 2/4/42, two gotpcrelx-mov-lea restorations at offsets 1052 and 1111), source hash `4c32a6956608b1e3735419f59c45958d72613a2c82032338bd6ed60c73a300b0` (recomputed) |
| `...::CreateWAL.cold` | `0x5e5c1a0..0x5e5c26e` | 206 B | `524efe782ae066d528f239fa39712b2b81efad70fdc6b8c55212b91ace414734` | `node115-vendor-5e5c1a0`, 13 relocations (kind 4), source hash `7d05c87bc2a2c96fa856f82eeab50ef9da199935c6d80eb7475755b9cc7dd084` (recomputed) |

Symbol (from the vendor census):
`_ZN7rocksdb6DBImpl9CreateWALEmmmPPNS_3log6WriterE`, member
`4d429ab1cb2d8f8b-db_impl_open.o`, librocksdb-sys 0.11.0+8.1.1. This
is the direct follow-up to open PR #6012
(`log::Writer::EmitPhysicalRecord`'s caller note) and to the
`WritableFileWriter` engine family (#6041 Append, #6057 Flush, #6070
Pad, #6088 WriteBuffered, #6094 WriteBufferedWithChecksum, #6204
WriteDirect, #6215 WriteDirectWithChecksum), whose constructors and
members this routine wires together.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `IOStatus DBImpl::CreateWAL(uint64_t log_file_num, uint64_t
recycle_log_number, size_t preallocate_block_size, log::Writer**
new_log)`; sret `rdi`, `this` `rsi`, log number `rdx`, recycle number
`rcx`, preallocate size `r8`, `new_log` `r9`. The return status is
built in a 16-byte stack slot at `-0x3e0(%rbp)` and moved into the
sret (`rbx`) by the standard status move-assign shape (bytes 0-1, 3-4,
5, 8-15; byte 2 forced to 0).

**1. BuildDBOptions (0x60c2e20).** `BuildDBOptions` into a stack
`DBOptions` temp (`-0x2d0`) from `immutable_db_options_` (`this+0x330`)
and `mutable_db_options_` (`this+0x5a0`). The temp is destroyed at
the epilogue (`DBOptions` dtor 0x5d354b0); no field of it is observable
downstream except through step 2.

**2. fs selection + OptimizeForLogWrite (0x5e5c2fd..0x5e5c379).** The
`fs_` `FileSystemPtr` at `this+0x570` is `{shared_ptr fs_ +0x570/+0x578,
shared_ptr io_tracer_ +0x580/+0x588, shared_ptr fs_with_tracer_
+0x590/+0x598}` (pinned from the `FileSystemPtr` copy ctor 0x5d50400,
which copies `src+0x00` or `src+0x20` by the same rule). If
`io_tracer_` is null, or the byte at `+0x68` of the tracer object is 0,
the raw `fs_` is used; otherwise the tracer-wrapped fs at `+0x590`.
The selected shared_ptr is copied (refcount++, plain or `lock addl`
by the `__gthread_active_p` flag at 0x64ed290) and released after the
call (`_Sp_counted_base::M_release` 0x5d350c0). The virtual call is
`fs->OptimizeForLogWrite(&opt_file_options, &file_options_
[this+0x838], &db_options)` through vtable slot 0x198; the returned
`FileOptions` (stack, `-0x3d0`) is the options used for every later
file call.

**3. wal_dir (0x5e5c379..0x5e5c3aa).** `GetWalDir` (0x60a1500, not in the
vendor census) on `immutable_db_options_` returns a pointer to a
`std::string`: `&wal_dir` (`immutable+0x98`) when its size (`+0xa0`)
is non-zero, else the string pointer stored at `immutable+0x60` (the
dbname string) -- exactly upstream `wal_dir.empty() ? dbname :
wal_dir`. The local `wal_dir` copy (`-0x330`) is built from the
returned string's `[ptr, ptr+size)` by the libstdc++ range helper
0x5e57bf0.

**4. log_fname (0x5e5c3af..0x5e5c3ca).** `LogFileName` (0x603d050,
census-bound) into `-0x310`: `MakeFileName` (0x603cb70) formats
`"%06llu.%s"` with the number and `"log"` (format string at 0x4394a1,
type string `"log"` at 0x44fd57) and joins `wal_dir + "/" + that` --
so `<wal_dir>/000007.log` for log file number 7, and `/000007.log`
when `wal_dir` is empty (the join is unconditional). Numbers >=
1000000 print with more digits (`%06llu` never truncates).

**5. Recycle branch, only when `recycle_log_number != 0`
(0x5e5c7c8..0x5e5c86f).** `ROCKS_LOG_INFO` (0x5fcf060) on
`immutable_db_options_.info_log` (`this+0x360`) with `"reusing log
%llu from recycle list"`; `old_log_fname = LogFileName(wal_dir,
recycle_log_number)` (`-0x2f0`); then `fs->ReuseWritableFile(log_fname,
old_log_fname, opt_file_options, &lfile, nullptr)` through vtable slot
0xc8, with the fs selected by a `FileSystemPtr` copy (0x5d50400).
The non-recycle branch (0x5e5c3f9..0x5e5c429) calls the free function
`NewWritableFile` (0x6048500, census-bound):
`NewWritableFile(fs, log_fname, &lfile, opt_file_options)`.

**6. Status check (0x5e5c42e..0x5e5c497).** The returned `IOStatus`
is moved into the return slot; if not OK, return at once -- no writer
is built and `*new_log` is never written.

**7. On OK (0x5e5c49d..0x5e5c535).** `lfile->SetWriteLifeTimeHint`
(vtable slot 0x70) with the constant 2 (`WriteLifeTimeHint`
kWLTHShort) -- `CalculateWALWriteHint()` has no separate call site;
its result is the constant 2 in this build -- then
`lfile->SetPreallocationBlockSize` (vtable slot 0x98) with
`preallocate_block_size`.

**8. WritableFileWriter (0x5e5c4c6..0x5e5c535).** Operator new 0xe0
bytes, then the ctor (0x5e5ba60, census-bound) with
(`std::move(lfile)`, `log_fname`, `opt_file_options`,
`immutable_db_options_.clock` [`this+0x540`], `io_tracer_`
[`this+0x320`], `nullptr` stats, `listeners` [`this+0x470`],
`nullptr` checksum_gen, `Contains(kWalFile)`, `Contains(kWalFile)`)
-- the two trailing bools are the SAME value pushed twice:
(`this+0x520 & 1`), the bit-0 test on
`checksum_handoff_file_types`. The ctor stores bool 1 into
`perform_data_verification_` (`+0xd1`) and bool 2 into
`buffered_data_with_checksum_` (`+0xd8`), verified in the ctor body
(0x5e5bd3f..0x5e5bd5e).

**9. log::Writer (0x5e5c53e..0x5e5c58a).** Operator new 0x58 bytes,
then the ctor (0x5f04c00, census-bound) with
(`std::move(file_writer)`, `log_file_num`, `recycle_log_file_num > 0`
[`this+0x400 != 0`], `manual_wal_flush` [`this+0x4c5` byte],
`wal_compression` [`this+0x4c6` byte]). The recycle flag comes from
the IMMUTABLE option `recycle_log_file_num`, NOT from the
`recycle_log_number` argument -- the two are independent. The ctor
moves the `file_writer` pointer into its `dest_` and zeroes the source
slot (0x5f04c2e: `movq $0, (%rsi)`); its layout is `dest_ +0x00`,
zero-initialized qword `+0x08`, `log_number_ +0x10`, recycle flag
`+0x18`, `type_crc_[10] +0x1c`, `manual_flush +0x44`,
`wal_compression +0x45`.

**10. `*new_log` assignment, then AddCompressionTypeRecord
(0x5e5c58f..0x5e5c5a3).** `*new_log = ` the new `log::Writer`, THEN
`io_s = (*new_log)->AddCompressionTypeRecord()` (0x5f041d0,
census-bound; sret into the `io_s` slot) -- so on an
`AddCompressionTypeRecord` failure the caller still receives the
writer in `*new_log` and the failure status. The record bytes
themselves are the subject of the sibling `AddCompressionTypeRecord`
packet; this model scripts the call's status (default OK).

**11. Dead Close guard (0x5e5c60c..0x5e5c70e).** After the status is
copied to the return slot, the binary loads the `file_writer` slot
(`-0x3f0`) and, if non-null, calls `WritableFileWriter::Close`
(0x6052b80, census-bound) and then runs the inlined
`WritableFileWriter` destructor (release `checksum_generator_`, clear
`listeners_`, free `buf_`, tear down the `FSWritableFile` wrapper with
devirtualization, dispose `file_name_`, operator delete 0xe0). The slot
is NULLED by the `log::Writer` ctor's move (step 9), so on the normal
path the guard is false and the sequence is skipped; the Close result,
if it ran, would land in the already-moved-from `io_s` slot and be
discarded (the return value was already copied to `rbx`). The upstream
v8.1.1 source has no Close call here. The model records
`close_guard_taken = False` with this evidence and never takes the
guard.

**12. Epilogue (0x5e5c713..0x5e5c79c).** Dispose the `log_fname` /
`wal_dir` / `old_log_fname` strings, destroy the `DBOptions` temp,
release the fs shared_ptr copy, check the stack canary, return the
status in `rbx`. The `.cold` (0x5e5c1a0..0x5e5c26e) is unwind-only:
the same destructions plus `_Unwind_Resume`.

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **2 direct calls** to CreateWAL, 0 tail jumps, 0 LEA refs; the
`.cold` pad has exactly 1 tail jump from 0x5e5c94a. The callers:

| site | caller FDE | caller |
|---|---|---|
| 0x5e63ea0 | 0x5e62c50..0x5e65462 | `rocksdb::DBImpl::Open` |
| 0x5e8a9c6 | 0x5e8a890..0x5e8c518 | `rocksdb::DBImpl::SwitchMemtable` |

CreateWAL calls its helpers through direct calls (`BuildDBOptions`,
`GetWalDir`, `LogFileName`, `NewWritableFile`, the two ctors,
`AddCompressionTypeRecord`, `Close`) and through vtable slots
(`OptimizeForLogWrite` 0x198, `ReuseWritableFile` 0xc8,
`SetWriteLifeTimeHint` 0x70, `SetPreallocationBlockSize` 0x98) -- the
slots are pinned by the disassembly, not by the scan.

## Evidence

- `tools/dbimpl_createwal115.py` -- the CreateWAL model.
- `tests/test_dbimpl_createwal115.py` -- 29 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 filenames
  + 600 writer_params + 600 bindings), 0 mismatches on replay
  (`python3 tools/dbimpl_createwal115.py --verify`).
- Live engine check (`--live`): all 8 legs pass -- a plain new WAL
  (file created with the `LogFileName` name, empty, hint 2,
  preallocation recorded, `*new_log` assigned), a recycle (the old
  file renamed to the new name with its bytes preserved, old name
  gone), the `wal_dir` fallback (empty `wal_dir` uses `dbname`), a
  `NewWritableFile` failure (status returned, no writer, `*new_log`
  untouched, no file), a reuse of a missing old log (code 5, nothing
  created), an `AddCompressionTypeRecord` failure (status returned
  WITH `*new_log` assigned, file exists, Close guard not taken), a
  7-digit log number (prints in full, preallocation recorded), and the
  writer params (handoff bit set -> both writer bools true;
  `recycle_log_file_num > 0` -> the `log::Writer` recycle flag,
  independently of the recycle argument); the model file image equalled
  the real file bytes after every CreateWAL.
- `records.json` -- semantic records only (never a per-instruction
  mnemonic list); `functions.tsv`, `callers.tsv`, `census.json` -- the
  census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags
  only the pre-existing mismatch in unrelated packet
  RE-001-adjacent-last-115 (present on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt` per
  function), with the repo-relative binary path `work/hl-node-115.bin`
  (no absolute home paths).

## Upstream cross-check

`meta/rocksdb` v8.1.1, read live this cycle
(`db/db_impl/db_impl_open.cc`, `CreateWAL`, lines 1715-1759 -- the
repo has since moved from `facebook/rocksdb` to `meta/rocksdb`),
confirms the packet step for step: `BuildDBOptions`,
`OptimizeForLogWrite`, `GetWalDir`, `LogFileName`, the recycle branch
(`ROCKS_LOG_INFO` "reusing log %llu from recycle list", old
`LogFileName`, `ReuseWritableFile`) vs `NewWritableFile`, the OK gate,
`SetWriteLifeTimeHint` (`CalculateWALWriteHint()`) +
`SetPreallocationBlockSize`, the `WritableFileWriter` construction
(`clock`, `io_tracer_`, `listeners`, `Contains(kWalFile)` twice), the
`log::Writer` construction (`recycle_log_file_num > 0`,
`manual_wal_flush`, `wal_compression`), and `AddCompressionTypeRecord`
as the last step.

Binary-vs-source observations, recorded not hidden:

- The binary has NO `TEST_SYNC_POINT` call in the recycle branch,
  while upstream names two (`"DBImpl::CreateWAL:
  BeforeReuseWritableFile1/2"`). The model records them as absent.
- The binary passes the constant 2 to `SetWriteLifeTimeHint`
  (`CalculateWALWriteHint()` has no separate call site).
- The binary contains a guarded `WritableFileWriter::Close` + destroy
  sequence after `AddCompressionTypeRecord` that upstream does not
  have, and that sequence is unreachable on the normal path because
  the `log::Writer` ctor nulls the `file_writer` slot. Recorded as a
  dead guard, never taken by the model.
- The binary's `GetWalDir` returns a string POINTER (the caller copies
  it), while upstream declares a by-value return -- the observable
  behaviour (`wal_dir` when non-empty, else `dbname`) is identical.
- The census symbol for 0x5d50400 (`FileSystemPtr::operator->`) does
  not match its body, which is the `FileSystemPtr` copy constructor;
  the packet follows the disassembly.

## Open unknowns (not claimed)

- The `OptimizeForLogWrite` per-field tweaks: the model passes the
  `FileOptions` through unchanged and records the call. The returned
  options are the ones used for `NewWritableFile` /
  `ReuseWritableFile` and for the `WritableFileWriter` ctor.
- The `AddCompressionTypeRecord` record bytes: that call is scripted
  (default OK); its bytes are the sibling packet's subject. Live legs
  that assert file bytes use `wal_compression` 0.
- `GetWalDir` (0x60a1500) and the string range helper (0x5e57bf0) have
  no vendor census record; their behaviour is pinned from their bodies.
- The `.cold` helper 0x5e1b260 is unidentified (not in the census); it
  runs only on the unwind path and is not modelled.
- The zero-initialized qword at `log::Writer +0x08` is not named from
  this FDE.
- The `FileSystemPtr` tracer-enabled byte at `+0x68` of the `IOTracer`
  object is identified only by its use (raw vs wrapped fs selection);
  its upstream name is not pinned from the binary (literals stripped).
- Why the dead Close guard exists in the binary when upstream has no
  Close call here: open. The guard is unreachable on the normal path
  (the slot is nulled by the ctor move) and is recorded, not modelled
  as live behaviour.
- The next natural follow-ups: the unidentified FDE 0x60d4cf0
  (`SequentialFileReader::Read` caller, open unknown from #5992); or
  `DBImpl::Open` 0x5e62c50 / `DBImpl::SwitchMemtable` 0x5e8a890, the two
  callers found by this packet's census.

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. The `FileSystem`, clock,
listeners and `OptimizeForLogWrite` internals are recorded opaque calls,
not reimplemented, and the `AddCompressionTypeRecord` record bytes are
the sibling packet's subject. `make verify` / `test` / `catalogue-check`
in a tooled environment is still owed upstream.
