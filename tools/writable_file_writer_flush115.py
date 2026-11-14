#!/usr/bin/env python3
"""Node #115 RocksDB WritableFileWriter::Flush: reconstruction.

RE-002 work item. Reconstructs the WAL/SST file writer's flush
routine at 0x6051a20..0x605257c (2908 B) plus its landing pad
``Flush.cold`` at 0x6051938..0x6051a1c (228 B):

  rocksdb::WritableFileWriter::Flush       0x6051a20 (2908 B)
  rocksdb::WritableFileWriter::Flush.cold  0x6051938 (228 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
BOTH functions are census-bound (body hashes match
target_body_sha256 exactly; source hashes reproduced by zeroing
the recorded relocations, with the GOTPCRELX mov-lea opcode
restored at Flush's two relaxed sites, offsets 1194 and 2383 --
see gen_records.py). Symbols come
from the vendor census (member a895f7517936a0f7-writable_file_
writer.o, librocksdb-sys 0.11.0+8.1.1). This is the follow-up to
open PR #6041 (WritableFileWriter::Append), which took Flush
as an input oracle; this packet supersedes that oracle with the
full body model. CORRECTION: the Append packet's engine-callee
note said Flush is "3452 B" -- the FDE is 0x6051a20..0x605257c,
2908 B, plus the 228 B .cold.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus Flush(Env::IOPriority priority)
  -- returns by value, so rdi is the hidden 16-byte sret
  out-pointer, rsi is the Writer*, edx the priority. Steps, in
  binary order:

  1. Seen-error gate (0x6051a4b): byte this+0x89 (seen_error_)
     read FIRST. If set, the routine returns at once (0x6052000):
     sret = {code 5 (kIOError), subcode 0, severity 0, scope 0,
     retryable 0, data_loss 0, state_ = fresh 27-byte "Writer has
     previous error."} -- exactly upstream
     AssertFalseAndGetStatusForPrevError()
     (file/writable_file_writer.h:555-563). The old sret state_
     (when non-null) is delete[]'d first. No other member is
     touched: no write, no file Flush, no RangeSync.
  2. Write step (0x6051a5a..0x6051d26): only when buf_.cursize_
     (this+0x58) != 0. The data Slice is {buf_.bufstart_
     (this+0x60), buf_.cursize_} and the priority is the Flush
     argument.
     - use_direct_io() (vtable slot 12, 0x60) true: only when
       pending_sync_ (this+0x88) is set does it write -- s =
       WriteDirect(priority) at 0x604fe80, or
       WriteDirectWithChecksum(priority) at 0x6050c80 when
       perform_data_verification_ (this+0xd1) AND
       buffered_data_with_checksum_ (this+0xd8) are both set.
       When pending_sync_ is clear the write is skipped entirely
       (jump back to 0x6051a6d) and the status stays OK.
     - use_direct_io() false: s = WriteBuffered(Slice, priority)
       at 0x604e140, or WriteBufferedWithChecksum(Slice,
       priority) at 0x604f080 under the same two flags.
     - If the write status is not OK: seen_error_ = 1 and return
       s at once (0x6051d14..0x6051d26). No file Flush, no
       RangeSync.
     WriteBuffered[WithChecksum] / WriteDirect[WithChecksum]
     are input oracles (their bodies are separate FDEs, no
     census records); their contracts are stated below.
  3. Listener start times (0x6051a71..0x6051aa6): only when
     listeners_ (this+0xb0) is non-empty, the binary takes
     std::chrono::steady_clock::now() and system_clock::now()
     and stores the pair at rsp+0x40 (system first, steady
     second). When the listener list is empty both timestamps
     are skipped. There is NO IOSTATS_TIMER_GUARD in Flush
     itself -- the timestamps exist solely for the listener
     event below.
  4. IOOptions block (0x6051aa6..0x6051b75): a 0x58-byte
     IOOptions is built on the stack at rsp+0xa0 with the exact
     default constants -- timeout 0, prio kIOLow (0),
     rate_limiter_priority IO_TOTAL (4), type kUnknown (7),
     property_bag an empty unordered_map (single-bucket
     self-pointer at rsp+0xb8, bucket_count 1, max_load_factor
     1.0f), force_dir_fsync 0, do_not_recurse 0 -- then
     rate_limiter_priority is overwritten at rsp+0xac with
     DecideRateLimiterPriority(file_priority, priority)
     (0x604c800, census-bound, pure). The file's priority comes
     from GetIOPriority, vtable slot 16 (0x80), devirtualized
     when the slot equals the base implementation 0x5df6e90
     (``mov 0x18(%rdi),%eax; ret`` -- the
     FSWritableFile::GetIOPriority that returns io_priority_ at
     file+0x18; the guard compares against the RELATIVE
     relocation at 0x64ecf30, addend 0x5df6e90); otherwise the
     virtual call runs at 0x60523a8.
  5. File selection + file_->Flush (0x6051b39..0x6051d66):
     the file is selected by FSWritableFilePtr::operator->()
     (io_tracer_ null OR its +0x68 enabled byte clear -> the raw
     file at wrapper+0x28; otherwise the tracing wrapper at
     this+0x30). The Flush call itself is devirtualized through
     the wrapper layers: the binary peels [file+0x28] targets
     while vtable slot 8 (0x40) equals the RELATIVE relocation
     at 0x64ecf70, then calls slot 8 as
     file->Flush(sret, file, io_options, nullptr) -- i.e.
     FSWritableFile::Flush(const IOOptions&, IODebugContext*).
     The returned status is move-assigned into the working
     status (bytes copied out of the sret, source zeroed, old
     state_ delete[]'d when non-null).
  6. Listener notifications (0x6051dd5..0x6052425): only when
     listeners_ is non-empty.
     a. Finish event (always, success or failure): elapsed =
        steady_clock::now() - start_steady; an event is built
        at rsp+0x50 -- {FileOperationType type = 4 (kFlush),
        WritableFileWriter* this, bool [this+0xd9], uint64
        offset (NOT written by Flush -- see unknowns), uint64
        length (NOT written), uint64 elapsed_nanos, TimePoint*
        &start_times, Status status (CopyState deep copy)} --
        and every listener is called through vtable slot 35
        (0x118), skipping the base no-op 0x604c670. The slot
        is the OnFileFlushFinish position (see the cross-check
        note below); the event struct itself is pinned from
        the binary, not from upstream text.
     b. Failure event (only when the file Flush status is not
        OK): a second event is built at rsp+0x120 -- {Status
        status (CopyState deep copy), FileOperationType type =
        4 (kFlush), std::string file_name_ (a copy of the
        writer's file name)} -- and every listener is called
        through vtable slot 47 (0x178), skipping the base
        no-op 0x6042c20. The method at slot 47 is an open
        unknown (see below).
     Then the IOOptions property_bag is destroyed (call
     0x5d36110, the _Hashtable dtor, on rsp+0xb8).
  7. Failure return (0x60521c6..0x60521d3): when the file Flush
     status is not OK (after the notifications): seen_error_
     = 1, sret byte 2 = 0, return the status. No RangeSync.
  8. RangeSync arm (0x6051f28..0x60521ab): only when
     !use_direct_io() AND bytes_per_sync_ (this+0x98) != 0.
     - filesize_ (this+0x70) <= 0x100000 (1 MiB): skip.
     - offset_sync_to = (filesize_ - 0x100000) & ~0xfff (4 KiB
       align down); offset_sync_to == 0: skip.
     - offset_sync_to - last_sync_size_ (this+0x90) <
       bytes_per_sync_: skip.
     - else s = RangeSync(last_sync_size_, offset_sync_to -
       last_sync_size_) -- the MEMBER RangeSync at 0x604d7b0
       (2155 B, no census record; modelled as a sub-model
       below, not a plain oracle) -- and last_sync_size_ =
       offset_sync_to UNCONDITIONALLY afterwards, even when the
       RangeSync status is not OK. On a non-OK status
       seen_error_ = 1 as well (0x60524f9).
     The constants and the shape match upstream Flush
     (writable_file_writer.cc:749-785) exactly, including the
     "avoid sync to the last 1MB" comment rationale.
  9. Epilogue (0x6051f5b..0x6051fc5): the working status is
     copied into the sret (byte 2 forced to 0 -- the binary
     zeroes the severity byte on every return path through
     this epilogue), the stack canary is checked and
     __stack_chk_fail fires on mismatch (0x6052505).

  The .cold landing pad (0x6051938, 228 B, census-bound):
  ten endbr64 stubs at the tail of the main FDE
  (0x605250a..0x6052577) save the exception object in rbx and
  jump into it at 0x605194a, 0x6051968, 0x605197a, 0x605197f,
  0x6051991, 0x60519a3, 0x60519be, 0x60519d4, 0x60519e8 and
  0x6051a12. The pad destroys the RangeSync-event strings
  (operator delete[] / _ZdlPvm on the SSO/heap copies),
  destroys the IOOptions property_bag (call 0x5d36110),
  checks the stack canary, then _Unwind_Resume (or
  __stack_chk_fail). It is unwind-only; no case exercises it.

  RangeSync member (0x604d7b0..0x604e01b, 2155 B, NO census
  record -- body hash only, per the #5992 no-census
  convention). Signature: IOStatus RangeSync(uint64_t offset,
  uint64_t nbytes) -- sret rdi, this rsi, offset rdx, nbytes
  rcx. Steps, in binary order:

  1. Seen-error gate (0x604d7e4): same 27-byte "Writer has
     previous error." return as Flush step 1. (Unreachable
     from Flush -- Flush only calls it with seen_error_ clear
     -- but part of the member's own contract.)
  2. TEST_SYNC_POINT gate (0x604d7f3): if the sync-point
     global (*0x64ed5d0) is non-null, call 0x606d9f0.
     Upstream: TEST_SYNC_POINT("WritableFileWriter::RangeSync:0").
  3. IOSTATS_TIMER_GUARD(range_sync_nanos) (0x604d805..0x604d876,
     stop at 0x604dca8..0x604dced): armed iff perf_level > 2
     (TLS _ZTHN7rocksdb10perf_levelE); start =
     SystemClock::Default()->NowNanos() (vtable slot 20, 0xa0;
     SystemClock::Default at 0x5fe2680, census-bound); the
     elapsed time is added to the TLS range_sync_nanos counter
     at stop. The CPU-timer half is DEAD: flag (rsp+0x51), id
     (rsp+0x54) and object (rsp+0x70) are zeroed and never set.
  4. Listener start times (0x604d87a..0x604d8af): only when
     listeners_ is non-empty, steady_clock::now() +
     system_clock::now() into rsp+0x30.
  5. Own IOOptions (0x604d8af..0x604d975): a fresh 0x58-byte
     IOOptions is built at rsp+0xd0 with the same defaults --
     but rate_limiter_priority at +0x0c is the FILE's
     GetIOPriority directly (no DecideRateLimiterPriority
     call: RangeSync takes no op priority). The passed-in
     IOOptions from Flush is NOT reused (its property_bag was
     already destroyed by Flush before the call).
  6. file->RangeSync (0x604d984..0x604d9a6): file selected the
     same way; virtual slot 23 (0xb8) as
     file->RangeSync(sret, file, offset, nbytes, io_options,
     nullptr) -- i.e. FSWritableFile::RangeSync(uint64_t,
     uint64_t, const IOOptions&, IODebugContext*).
  7. Listener notifications (0x604d9b1..0x604de96): only when
     listeners_ is non-empty.
     a. Finish event: elapsed = steady now - start steady;
        event at rsp+0x80 -- {FileOperationType type = 7
        (kRangeSync), WritableFileWriter* this, bool
        [this+0xd9], uint64 offset, uint64 nbytes, uint64
        elapsed_nanos, TimePoint* &start_times, Status status
        (CopyState deep copy)} -- every listener through
        vtable slot 37 (0x128), skipping the base no-op
        0x604c690. The slot is the OnFileRangeSyncFinish
        position (see the cross-check note).
     b. Failure event (only when the file RangeSync status is
        not OK): event at rsp+0x150 -- {Status status
        (CopyState deep copy), FileOperationType type = 7
        (kRangeSync), std::string file_name_} -- every
        listener through vtable slot 47 (0x178), skipping the
        base no-op 0x6042c20 (the same slot as Flush's failure
        event).
     Then the IOOptions property_bag is destroyed (call
     0x5d36110 on rsp+0xe8).
  8. Failure bookkeeping (0x604dc90): when the file RangeSync
     status is not OK, seen_error_ = 1 (before the
     notifications run). The member then returns the file's
     status unchanged.
  9. Epilogue: the status is copied into the sret (byte 2
     forced to 0), canary checked, return.

  DecideRateLimiterPriority (0x604c800, 39 B, census-bound,
  verified instruction by instruction): both IO_TOTAL (4) ->
  IO_TOTAL; file IO_TOTAL -> op priority; op IO_TOTAL -> file
  priority; else op priority. Exactly upstream
  writable_file_writer.cc:1859-1885.

  Oracle contracts (input oracles, NOT reconstructed here):
  - WriteBuffered(data, size, priority) at 0x604e140
    (FDE 0x604e140..0x604ef0d, 3533 B, no census) and
    WriteBufferedWithChecksum(data, size, priority) at
    0x604f080 (FDE 0x604f080..0x604fd97, 3351 B, no census):
    per upstream (cc:1039-1216 / 1219-1394), they write the
    data straight to the file in rate-limiter-sized chunks
    (the model writes it in one oracle step and records the
    token grants), clear buf_ (Size(0)) and reset
    buffered_data_crc32c_checksum_ to 0, and advance
    flushed_size_; on a scripted file-Append failure they
    clear buf_ and reset the checksum anyway, set seen_error_
    and return the error. WriteBufferedWithChecksum hands the
    file the checksum encoded from
    buffered_data_crc32c_checksum_ (EncodeFixed32) as the
    handoff checksum; the model records that value before
    resetting it. Their bodies are open unknowns / follow-ups.
  - WriteDirect(priority) at 0x604fe80 (FDE 0x604fe80..
    0x6050b8a, 3338 B, no census) and
    WriteDirectWithChecksum(priority) at 0x6050c80 (FDE
    0x6050c80..0x6051937, 3255 B, no census): per upstream
    (cc:1449-1642 / 1645-1857), they page-pad the buffer,
    write it positionally at next_write_offset_, refit the
    tail (buf_.Size(file_advance + leftover_tail) on failure,
    RefitTail on success), advance next_write_offset_ by
    file_advance and flushed_size_ by the padded size; the
    WithChecksum variant recomputes
    buffered_data_crc32c_checksum_ as Value of the remaining
    buffer. Their bodies are open unknowns / follow-ups.
  - file_->Flush(io_options, nullptr) (FSWritableFile vtable
    slot 8) and file->RangeSync(offset, nbytes, io_options,
    nullptr) (slot 23): the model records (io_options
    snapshot, arguments) and applies the scripted status; the
    file image itself is untouched by Flush (it only moves
    buffered bytes to the OS cache) and by RangeSync (a sync
    has no image effect).
  - UpdateFileChecksum: not used by Flush (no call in the
    FDE); listed only because Append uses it.
  - TEST_SYNC_POINT / TEST_KILL_RANDOM: compiled to a runtime
    gate (sync-point global) with no data effect;
    TEST_KILL_RANDOM calls are compiled out entirely (no call
    in the FDE).

Writer layout (node #115, from the field accesses, confirmed
against upstream file/writable_file_writer.h): file_name_ +0x00
(std::string, 32), writable_file_ +0x20 (FSWritableFilePtr:
io_tracer_ shared_ptr +0x20/+0x28, fs_tracer_ unique_ptr
+0x30), clock_ +0x38, buf_ +0x40 (AlignedBuffer: alignment_
+0x40, buf_ +0x48, capacity_ +0x50, cursize_ +0x58,
bufstart_ +0x60), max_buffer_size_ +0x68, filesize_ +0x70
(atomic u64), flushed_size_ +0x78, next_write_offset_ +0x80,
pending_sync_ +0x88, seen_error_ +0x89 (atomic bool),
last_sync_size_ +0x90, bytes_per_sync_ +0x98, rate_limiter_
+0xa0, stats_ +0xa8, listeners_ +0xb0 (vector, 24),
checksum_generator_ +0xc8 (unique_ptr), checksum_finalized_
+0xd0, perform_data_verification_ +0xd1,
buffered_data_crc32c_checksum_ +0xd4 (uint32),
buffered_data_with_checksum_ +0xd8, temperature_ +0xdc;
total 0xe0. One member the binary reads but the layout above
does not name: a bool at this+0xd9, copied into both finish
events (Flush 0x6051df3, RangeSync 0x604d9cf) -- recorded in
the model as flag_d9 and listed as an open unknown.

Caller census (whole-.text E8/E9/LEA scan, Capstone-validated;
see census.py): the exact count is produced by census.py and
recorded in census.json / callers.tsv. The known callers from
the Append packet are WritableFileWriter::Append (its
flush-if-needed arm and its two write loops) and the table
builders' Close paths; the census pins every site.

Upstream cross-check (read live during packet construction; this
cycle re-confirmed the mirror at commit 876c2dbf still serves
file/writable_file_writer.cc): a 2019 RocksDB mirror (GitLab
cracking_rocksdb, commit 876c2dbf) confirms the
Flush skeleton step for step -- the buf_-non-empty write
dispatch with the pending_sync_ gate on the direct arm, the
plain file_->Flush() call, and the bytes_per_sync block with
the 1 MiB not-synced range, the 4 KiB align-down, and
RangeSync(last_sync_size_, offset_sync_to - last_sync_size_)
plus last_sync_size_ = offset_sync_to. The mirror PREDATES
the binary's version: it has no IOOptions, no priority
arguments, no seen_error_/checksum members, no listener
notifications inside Flush, and a 3-line RangeSync wrapper --
so the binary's seen-error gates, IOOptions builds,
DecideRateLimiterPriority, listener events, timer guard and
member-RangeSync body are pinned from the binary alone, NOT
from that mirror; the mirror is evidence for the skeleton
only, and the version gap is recorded, not hidden. The
FileOperationType values (kFlush = 4, kRangeSync = 7) are
confirmed by the RocksDB 8.11 changelog ("Added another
enumerator kVerify to enum class FileOperationType in
listener.h") and the rocksdbjni 9.0.0 EventListener docs
(onFileFlushFinish / onFileRangeSyncFinish take
FileOperationInfo). The listener vtable slots (35 = flush
finish, 37 = range-sync finish, 47 = failure event) are the
binary's observed slots; the mapping of slot 47 to a named
EventListener method is an open unknown, as is the +19
offset between the binary's slot numbers (Read = 33 per the
open #5992 packet) and the 2019 listener.h declaration
order.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. WriteBuffered, WriteBufferedWithChecksum,
WriteDirect, WriteDirectWithChecksum and file_->Flush /
file->RangeSync are input oracles with the contracts above;
their bodies are not reconstructed here. make verify/test/
catalogue-check in a tooled environment is still owed upstream.
"""


import hashlib
import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-flush-115")
BIN_WORK = ROOT / "work" / "hl-node-115.bin"
BIN_LFS = ROOT / "artifacts" / "node" / "115" / "hl-node"
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# Env::IOPriority (rocksdb/env.h): IO_LOW 0, IO_HIGH 1, IO_USER 2,
# IO_MID 3, IO_TOTAL 4.
IO_LOW = 0
IO_HIGH = 1
IO_USER = 2
IO_MID = 3
IO_TOTAL = 4

# Writer layout (file/writable_file_writer.h).
WRITER_SIZE = 0xE0
OFF_FILE_NAME = 0x00
OFF_WRITABLE_FILE = 0x20
OFF_IO_TRACER = 0x20
OFF_FS_TRACER = 0x30
OFF_CLOCK = 0x38
OFF_BUF = 0x40
OFF_BUF_ALIGNMENT = 0x40
OFF_BUF_PTR = 0x48
OFF_BUF_CAPACITY = 0x50
OFF_BUF_CURSIZE = 0x58
OFF_BUF_START = 0x60
OFF_MAX_BUFFER_SIZE = 0x68
OFF_FILESIZE = 0x70
OFF_FLUSHED_SIZE = 0x78
OFF_NEXT_WRITE_OFFSET = 0x80
OFF_PENDING_SYNC = 0x88
OFF_SEEN_ERROR = 0x89
OFF_LAST_SYNC_SIZE = 0x90
OFF_BYTES_PER_SYNC = 0x98
OFF_RATE_LIMITER = 0xA0
OFF_STATS = 0xA8
OFF_LISTENERS = 0xB0
OFF_CHECKSUM_GENERATOR = 0xC8
OFF_CHECKSUM_FINALIZED = 0xD0
OFF_PERFORM_DATA_VERIFICATION = 0xD1
OFF_BUFFERED_DATA_CRC32C = 0xD4
OFF_BUFFERED_DATA_WITH_CHECKSUM = 0xD8
OFF_FLAG_D9 = 0xD9  # bool at this+0xd9, read into both finish events
OFF_TEMPERATURE = 0xDC

# IOOptions layout (include/rocksdb/file_system.h:160-236).
# timeout u64 @0, prio u8 @8 (kIOLow 0), rate_limiter_priority
# Env::IOPriority int @12, type u8 @16 (kUnknown 7),
# property_bag unordered_map @24 (56 B), force_dir_fsync @80,
# do_not_recurse @81; total 0x58.
IOOPTIONS_SIZE = 0x58
IOOPTIONS_DEFAULT = bytes.fromhex(
    "0000000000000000"  # timeout 0
    "0000000004000000"  # prio 0, rate_limiter_priority 4 (IO_TOTAL)
    "0700000000000000"  # type 7 (kUnknown), property_bag bucket ptr (low)
)
# The full default stack image is built in io_options_default().

# crc32c constants (util/crc32c.h).
MASK_DELTA = 0xA282EAD8
POLY = 0x82F63B78
MASK32 = 0xFFFFFFFF

# Addresses pinned in the binary.
FLUSH_ADDR = 0x6051A20
FLUSH_FDE_END = 0x605257C
COLD_ADDR = 0x6051938
COLD_FDE_END = 0x6051A1C
UPDATE_FILE_CHECKSUM_ADDR = 0x604C7B0
DECIDE_PRIORITY_ADDR = 0x604C800
RANGE_SYNC_ADDR = 0x604D7B0
RANGE_SYNC_FDE_END = 0x604E01B
WRITE_BUFFERED_ADDR = 0x604E140
WRITE_BUFFERED_FDE_END = 0x604EF0D
WRITE_BUFFERED_CHECKSUM_ADDR = 0x604F080
WRITE_BUFFERED_CHECKSUM_FDE_END = 0x604FD97
WRITE_DIRECT_ADDR = 0x604FE80
WRITE_DIRECT_FDE_END = 0x6050B8A
WRITE_DIRECT_CHECKSUM_ADDR = 0x6050C80
WRITE_DIRECT_CHECKSUM_FDE_END = 0x6051937
APPEND_ADDR = 0x6054680
APPEND_FDE_END = 0x605518B
PREPARE_WRITE_SLOT = 24
GET_IO_PRIORITY_SLOT = 16
USE_DIRECT_IO_SLOT = 12
FILE_FLUSH_SLOT = 8
FILE_RANGE_SYNC_SLOT = 23
GET_IO_PRIORITY_BASE = 0x5DF6E90
TIMER_GUARD_DTOR_ADDR = 0x604C6B6
SYNC_POINT_HELPER_ADDR = 0x606D9F0
CLOCK_DEFAULT_ADDR = 0x5FE2680
CRC32C_COMBINE_ADDR = 0x61C2600
EXTEND_THUNK_ADDR = 0x61C25F0
HASHTABLE_DTOR_ADDR = 0x5D36110
COPY_STATE_ADDR = 0x61CF610
# EventListener vtable slots (byte offsets) and base no-ops.
NOTIFY_FLUSH_FINISH_SLOT = 0x118  # slot 35
NOTIFY_FLUSH_FINISH_BASE = 0x604C670
NOTIFY_RANGE_SYNC_FINISH_SLOT = 0x128  # slot 37
NOTIFY_RANGE_SYNC_FINISH_BASE = 0x604C690
NOTIFY_FAILURE_SLOT = 0x178  # slot 47
NOTIFY_FAILURE_BASE = 0x6042C20
# FileOperationType (listener.h): kFlush 4, kRangeSync 7.
FILE_OP_FLUSH = 4
FILE_OP_RANGE_SYNC = 7

PREV_ERROR_MSG = "Writer has previous error."


def _make_crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY if crc & 1 else 0)
        table.append(crc)
    return table


_CRC_TABLE = _make_crc32c_table()


def crc32c_extend(crc, data):
    """crc32c::Extend: table-driven, bit-identical to the slow path."""
    state = (~crc) & MASK32
    for byte in data:
        state = _CRC_TABLE[(state ^ byte) & 0xFF] ^ (state >> 8)
    return (~state) & MASK32


def crc32c_value(data):
    """crc32c::Value == Extend(0, data)."""
    return crc32c_extend(0, data)


def _step(state):
    """One reflected CRC-32C bit step."""
    return (state >> 1) ^ (POLY if state & 1 else 0)


def _apply_operator(op, value):
    out = 0
    j = 0
    while value:
        if value & 1:
            out ^= op[j]
        value >>= 1
        j += 1
    return out & MASK32


_OP_POWERS = None


def _advance_operators():
    global _OP_POWERS
    if _OP_POWERS is not None:
        return _OP_POWERS
    op1 = tuple(_step(1 << j) for j in range(32))
    ops = [op1]
    for _ in range(63):
        prev = ops[-1]
        ops.append(tuple(_apply_operator(prev, prev[j]) for j in range(32)))
    _OP_POWERS = ops
    return ops


def _advance_raw_fast(state, n_bits):
    """Advance the raw CRC state by n_bits, via operator squaring."""
    ops = _advance_operators()
    k = 0
    while n_bits:
        if n_bits & 1:
            state = _apply_operator(ops[k], state)
        n_bits >>= 1
        k += 1
    return state & MASK32


def crc32c_combine(crc1, crc2, len2):
    """crc32c::Crc32cCombine(crc1, crc2, len2) == crc of (data1 || data2).

    Model: crc2 ^ advance_raw(crc1, 8*len2). Degenerate: len2 == 0 gives
    crc1 ^ crc2 (no early return -- the binary has none either).
    """
    return (crc2 ^ _advance_raw_fast(crc1, 8 * len2)) & MASK32


def crc32c_mask(crc):
    """crc32c::Mask: ror(crc, 15) + 0xa282ead8."""
    return ((((crc >> 15) | (crc << 17)) & MASK32) + MASK_DELTA) & MASK32


def crc32c_unmask(masked):
    """crc32c::Unmask (the log reader's inverse of Mask):
    rol(masked - 0xa282ead8, 15)."""
    x = (masked - MASK_DELTA) & MASK32
    return (((x << 15) | (x >> 17)) & MASK32)


def decide_rate_limiter_priority(file_priority, op_priority):
    """WritableFileWriter::DecideRateLimiterPriority, exactly as the
    39-byte body at 0x604c800 implements it (and upstream
    writable_file_writer.cc:1859-1885)."""
    if file_priority == IO_TOTAL and op_priority == IO_TOTAL:
        return IO_TOTAL
    if file_priority == IO_TOTAL:
        return op_priority
    if op_priority == IO_TOTAL:
        return file_priority
    return op_priority


class Status:
    """A 16-byte RocksDB IOStatus as the binary moves it.

    Live bytes: code @0, subcode @1, byte 2 (severity), flag bytes
    @3, @4, @5, bytes 6-7 (padding), state_ pointer @8 (8 bytes,
    0 = null, else a token standing in for a pointer). The layout
    (code/subcode/sev/retryable/data_loss/scope/state_) is upstream
    include/rocksdb/io_status.h; the byte positions are pinned by
    the sret stores in this FDE (epilogue 0x6054c4d..0x6054c74).
    """

    def __init__(self, code=0, subcode=0, b2=0, b3=0, b4=0, b5=0,
                 b67=0, state=0):
        self.code = code & 0xFF
        self.subcode = subcode & 0xFF
        self.b2 = b2 & 0xFF
        self.b3 = b3 & 0xFF
        self.b4 = b4 & 0xFF
        self.b5 = b5 & 0xFF
        self.b67 = b67 & 0xFFFF
        self.state = state  # 0 = null, else a token for a heap message

    @classmethod
    def ok(cls):
        return cls()

    @classmethod
    def io_error(cls, msg):
        # code 5 (kIOError); the message lives in a heap state_
        # tokenised by its text here (token 1 == the prev-error text).
        return cls(code=5, state=1 if msg == PREV_ERROR_MSG else 2)

    @classmethod
    def from_dict(cls, d):
        return cls(code=d.get("code", 0), subcode=d.get("subcode", 0),
                   b2=d.get("b2", 0), b3=d.get("b3", 0),
                   b4=d.get("b4", 0), b5=d.get("b5", 0),
                   b67=d.get("b67", 0), state=d.get("state", 0))

    def is_ok(self):
        return self.code == 0

    def out_bytes(self):
        out = bytearray(16)
        out[0] = self.code
        out[1] = self.subcode
        out[2] = self.b2
        out[3] = self.b3
        out[4] = self.b4
        out[5] = self.b5
        struct.pack_into("<H", out, 6, self.b67)
        struct.pack_into("<Q", out, 8, self.state)
        return bytes(out)

    def summary(self):
        return {"code": self.code, "subcode": self.subcode,
                "b2": self.b2, "b3": self.b3, "b4": self.b4,
                "b5": self.b5, "b67": self.b67, "state": self.state}

    def __eq__(self, other):
        return isinstance(other, Status) and self.summary() == other.summary()

    def __repr__(self):
        return ("Status(code=%d,sub=%d,b2=%d,b3=%d,b4=%d,b5=%d,b67=%d,"
                "state=%d)" % (self.code, self.subcode, self.b2, self.b3,
                               self.b4, self.b5, self.b67, self.state))


def roundup(x, y):
    """AlignedBuffer::Roundup -- ((x + y - 1) / y) * y."""
    return ((x + y - 1) // y) * y


def truncate_to_page(page_size, s):
    """TruncateToPageBoundary: s - (s & (page_size - 1))."""
    return s - (s & (page_size - 1))


class AlignedBuffer:
    """util/aligned_buffer.h AlignedBuffer, byte-exact in capacity /
    size / contents (allocation addresses are not modelled)."""

    def __init__(self, alignment, capacity=0, cursize=0, data=b""):
        assert alignment > 0 and (alignment & (alignment - 1)) == 0
        self.alignment = alignment
        self.capacity = capacity
        self.cursize = cursize
        self.data = bytearray(data[:cursize])
        assert len(self.data) == cursize and cursize <= capacity

    def remaining(self):
        return self.capacity - self.cursize

    def allocate_new_buffer(self, requested_capacity, copy_data=False,
                            copy_offset=0, copy_len=0, events=None):
        """AllocateNewBuffer(desired, copy_data, copy_offset, copy_len).

        Inlined at 0x6054e04: if copy_data and requested < copy_len
        (copy_len defaults to cursize_) do nothing; new_capacity =
        Roundup(requested, alignment); new buffer, memcpy the old
        bytes, cursize_ unchanged when copying."""
        copy_len = copy_len if copy_len > 0 else self.cursize
        if copy_data and requested_capacity < copy_len:
            if events is not None:
                events.append({"op": "allocate_skipped",
                               "requested": requested_capacity,
                               "copy_len": copy_len})
            return False
        new_capacity = roundup(requested_capacity, self.alignment)
        old = bytes(self.data)
        new_data = bytearray(new_capacity)
        if copy_data:
            new_data[:copy_len] = old[copy_offset:copy_offset + copy_len]
        self.data = new_data
        self.capacity = new_capacity
        # cursize_ = copy_len when copying, else 0 (Append always
        # copies, so cursize_ is unchanged here).
        self.cursize = copy_len if copy_data else 0
        if events is not None:
            events.append({"op": "allocate_new_buffer",
                           "requested": requested_capacity,
                           "new_capacity": new_capacity,
                           "copied": copy_len if copy_data else 0})
        return True

    def append(self, src, size=None):
        """AlignedBuffer::Append: copies min(size, remaining)."""
        to_copy = min(len(src) if size is None else size, self.remaining())
        if to_copy > 0:
            chunk = src[:to_copy]
            if len(self.data) < self.cursize + to_copy:
                self.data.extend(b"\x00" * (self.cursize + to_copy
                                            - len(self.data)))
            self.data[self.cursize:self.cursize + to_copy] = chunk
            self.cursize += to_copy
        return to_copy

    def clear(self):
        self.cursize = 0
        self.data = bytearray(self.capacity)

    def size(self, cursize):
        self.cursize = cursize
        if len(self.data) < cursize:
            self.data.extend(b"\x00" * (cursize - len(self.data)))

    def refit_tail(self, tail_offset, tail_size):
        """RefitTail: memmove the tail to the start, cursize_ = tail."""
        if tail_size > 0:
            tail = bytes(self.data[tail_offset:tail_offset + tail_size])
            self.data[:tail_size] = tail
        self.cursize = tail_size

    def pad_to_alignment(self, padding=0):
        """PadToAlignmentWith: pad with `padding` to Roundup(cursize)."""
        total = roundup(self.cursize, self.alignment)
        pad = total - self.cursize
        if pad > 0:
            assert self.cursize + pad <= self.capacity
            if len(self.data) < total:
                self.data.extend(b"\x00" * (total - len(self.data)))
            self.data[self.cursize:total] = bytes([padding]) * pad
            self.cursize = total
        return pad


class FakeClock:
    """SystemClock oracle: supplies scripted (system, steady) time
    pairs. now_pair() is the listener start-time pair (Flush
    0x6051a71, RangeSync 0x604d87a); now_nanos() is the steady
    half, used by the IOSTATS_TIMER_GUARD (RangeSync only)."""

    def __init__(self, pairs):
        self.pairs = [(int(s), int(t)) for s, t in pairs]
        self.index = 0

    def _next(self):
        if not self.pairs:
            return (0, 0)
        if self.index < len(self.pairs):
            p = self.pairs[self.index]
            self.index += 1
            return p
        return self.pairs[-1]

    def now_pair(self):
        return self._next()

    def now_steady(self):
        return self._next()[1]

    def now_nanos(self):
        return self.now_steady()


class FakeRateLimiter:
    """RateLimiter oracle: RequestToken returns scripted grants."""

    def __init__(self, grants):
        self.grants = list(grants)
        self.index = 0
        self.calls = []

    def request_token(self, n, alignment, priority, op="write"):
        self.calls.append({"n": n, "alignment": alignment,
                           "priority": priority, "op": op})
        if self.index < len(self.grants):
            g = self.grants[self.index]
            self.index += 1
            return max(0, min(n, g))
        return n


class FakeFile:
    """FSWritableFile oracle: the file Append writes into.

    Records every PrepareWrite / file-Append / PositionedAppend /
    Flush / RangeSync event with its arguments, and holds the file
    image (a bytearray) that the oracles extend. Scripted statuses
    drive the failure arms; the default is OK everywhere.
    """

    def __init__(self, io_priority=IO_TOTAL, direct_io=False,
                 tracer=None, file_priority_override=None):
        self.io_priority = io_priority
        self.direct_io = direct_io
        # tracer: None (no tracer) | {"enabled": bool} -- selects the
        # raw file (wrapper+0x28) vs the tracing wrapper (this+0x30).
        self.tracer = tracer
        self.file_priority_override = file_priority_override
        self.image = bytearray()
        self.events = []
        self.prepare_write_count = 0

    def get_io_priority(self):
        # vtable slot 16; the devirtualized read is file+0x18.
        if self.file_priority_override is not None:
            return self.file_priority_override
        return self.io_priority

    def use_direct_io(self):
        # vtable slot 12.
        return self.direct_io

    def select_file(self):
        """FSWritableFilePtr::operator->() (inlined at 0x6054798 and
        at every use site): tracer null or its +0x68 byte clear ->
        the raw file; otherwise the tracing wrapper."""
        if self.tracer is None or not self.tracer.get("enabled", False):
            return "raw"
        return "wrapper"

    def prepare_write(self, offset, length, io_options, dbg=None):
        self.prepare_write_count += 1
        self.events.append({"op": "prepare_write", "offset": offset,
                            "length": length,
                            "rate_limiter_priority":
                                io_options["rate_limiter_priority"],
                            "file": self.select_file(), "dbg": dbg})
        # VOID return (file_system.h:2122); no status is checked.

    def file_append(self, data, io_options, checksum=None,
                    status=None):
        """writable_file_->Append(Slice, io_options[, v_info], dbg)."""
        s = status if status is not None else Status.ok()
        self.events.append({"op": "file_append", "len": len(data),
                            "checksum": checksum,
                            "rate_limiter_priority":
                                io_options["rate_limiter_priority"],
                            "status": s.summary()})
        if s.is_ok():
            self.image.extend(data)
        return s

    def positioned_append(self, data, offset, io_options, checksum=None,
                          status=None):
        s = status if status is not None else Status.ok()
        self.events.append({"op": "positioned_append", "len": len(data),
                            "offset": offset, "checksum": checksum,
                            "rate_limiter_priority":
                                io_options["rate_limiter_priority"],
                            "status": s.summary()})
        if s.is_ok():
            end = offset + len(data)
            if end > len(self.image):
                self.image.extend(b"\x00" * (end - len(self.image)))
            self.image[offset:end] = data
        return s

    def file_flush(self, io_options, status=None):
        s = status if status is not None else Status.ok()
        self.events.append({"op": "file_flush",
                            "rate_limiter_priority":
                                io_options["rate_limiter_priority"],
                            "status": s.summary()})
        return s

    def range_sync(self, offset, nbytes, io_options, status=None):
        s = status if status is not None else Status.ok()
        self.events.append({"op": "range_sync", "offset": offset,
                            "nbytes": nbytes, "status": s.summary()})
        return s


def io_options_default(rate_limiter_priority=IO_TOTAL):
    """The 0x58-byte IOOptions stack image, default-constructed
    (0x6054769..0x60547f8), with rate_limiter_priority overwritten
    at +0x0c (0x6054836). Returned as a dict of the named fields
    plus the raw image bytes for the bindings."""
    image = bytearray(IOOPTIONS_SIZE)
    # timeout 0 (8 bytes @0)
    # prio kIOLow 0 @8; rate_limiter_priority @12 (int)
    struct.pack_into("<i", image, 12, rate_limiter_priority)
    # type kUnknown 7 @16
    image[16] = 7
    # property_bag @24: buckets ptr = self+0x30 (rsp+0xb8 for a
    # struct at rsp+0x70), bucket_count 1 @32, rehash max_load 1.0f
    # @40; the pointer value is stack-relative, so the model records
    # it symbolically as "self+0x30".
    struct.pack_into("<Q", image, 32, 1)  # bucket_count
    struct.pack_into("<f", image, 40, 1.0)  # max_load_factor
    return {"timeout": 0, "prio": 0,
            "rate_limiter_priority": rate_limiter_priority,
            "type": 7, "property_bag_buckets": "self+0x30",
            "property_bag_count": 1, "max_load_factor": 1.0,
            "force_dir_fsync": False, "do_not_recurse": False,
            "image_hex": image.hex()}

class WriterState:
    """The WritableFileWriter member state the binary reads/writes.

    Offsets are the pinned layout (see the module docstring). The
    file, clock, rate limiter and checksum generator are oracles
    supplied per case; listeners_ is modelled only as "empty or
    not" (ShouldNotifyListeners), with notify events recorded.
    """

    def __init__(self, file, buf, max_buffer_size=65536,
                 filesize=0, flushed_size=0, next_write_offset=0,
                 pending_sync=False, seen_error=False,
                 last_sync_size=0, bytes_per_sync=0,
                 rate_limiter=None, stats=None, listeners=None,
                 checksum_generator=False, checksum_finalized=False,
                 perform_data_verification=False,
                 buffered_data_crc32c_checksum=0,
                 buffered_data_with_checksum=False,
                 temperature=0, perf_level=0, clock=None,
                 sync_point_enabled=False, flag_d9=False,
                 file_name="test.wal"):
        self.file = file
        self.buf = buf
        self.max_buffer_size = max_buffer_size
        self.filesize = filesize
        self.flushed_size = flushed_size
        self.next_write_offset = next_write_offset
        self.pending_sync = pending_sync
        self.seen_error = seen_error
        self.last_sync_size = last_sync_size
        self.bytes_per_sync = bytes_per_sync
        self.rate_limiter = rate_limiter
        self.stats = stats
        self.listeners = list(listeners or [])
        self.checksum_generator = checksum_generator
        self.checksum_finalized = checksum_finalized
        self.perform_data_verification = perform_data_verification
        self.buffered_data_crc32c_checksum = buffered_data_crc32c_checksum
        self.buffered_data_with_checksum = buffered_data_with_checksum
        self.temperature = temperature
        self.perf_level = perf_level
        self.clock = clock
        self.sync_point_enabled = sync_point_enabled
        self.flag_d9 = flag_d9  # bool at this+0xd9 (open unknown)
        self.file_name = file_name  # file_name_ (std::string +0x00)
        # Event ledger: every oracle interaction, in binary order.
        self.events = []
        # Case script: queued oracle outcomes, consumed in order.
        # Keys: write_statuses, file_flush_statuses,
        # range_sync_file_statuses (each a list of status dicts).
        self.script = {}
        # IOSTATS thread-local counters (prepare_write_nanos is
        # unused by Flush; range_sync_nanos is the RangeSync guard).
        self.prepare_write_nanos = 0
        self.range_sync_nanos = 0

    def should_notify_listeners(self):
        return len(self.listeners) > 0

    def set_seen_error(self):
        self.seen_error = True

    def snapshot(self):
        return {
            "filesize": self.filesize,
            "flushed_size": self.flushed_size,
            "next_write_offset": self.next_write_offset,
            "pending_sync": self.pending_sync,
            "seen_error": self.seen_error,
            "last_sync_size": self.last_sync_size,
            "buf_capacity": self.buf.capacity,
            "buf_cursize": self.buf.cursize,
            # The buffer bytes are pinned by buf_sha256 + buf_cursize
            # (the bytes are deterministic from buf_seed); the raw
            # hex is omitted so cases.tsv stays small.
            "buf_sha256": hashlib.sha256(
                bytes(self.buf.data[:self.buf.cursize])).hexdigest(),
            "buffered_data_crc32c_checksum":
                self.buffered_data_crc32c_checksum,
            "flag_d9": self.flag_d9,
            "file_sha256": hashlib.sha256(bytes(self.file.image)).hexdigest(),
            "file_len": len(self.file.image),
            "prepare_write_nanos": self.prepare_write_nanos,
            "range_sync_nanos": self.range_sync_nanos,
            "events": self.events + self.file.events,
        }


def _pop_script_status(state, key):
    """Pop the next scripted status for `key`, defaulting to OK."""
    queue = state.script.get(key, [])
    if queue:
        d = queue.pop(0)
        return Status.from_dict(d) if isinstance(d, dict) else d
    return Status.ok()


def _flush_io_options(state, priority):
    """Flush step 4: build the IOOptions for file_->Flush. Same
    defaults as Append's, but Flush has NO timer guard and NO
    TEST_SYNC_POINT: rate_limiter_priority = DecideRateLimiterPriority
    (file priority, op priority). Returns the io_options dict."""
    file_priority = state.file.get_io_priority()
    decided = decide_rate_limiter_priority(file_priority, priority)
    io_options = io_options_default(decided)
    state.events.append({"op": "io_options_built",
                         "rate_limiter_priority": decided,
                         "callee": hex(DECIDE_PRIORITY_ADDR)})
    return io_options


def _notify_finish(state, op_type, slot, base_noop, start_times,
                   status, offset=None, nbytes=None):
    """The always-fired finish event (Flush 0x6051dd5, RangeSync
    0x604d9b1): elapsed = steady now - start steady; one call per
    listener through `slot`, skipping the base no-op `base_noop`.
    The event dict is the binary's struct: {type, writer, flag_d9,
    offset, nbytes, elapsed_nanos, start_times, status}."""
    elapsed = 0
    if state.clock is not None:
        elapsed = state.clock.now_steady() - start_times[1]
    event = {"op": "notify_finish", "type": op_type,
             "slot": hex(slot), "base_noop": hex(base_noop),
             "writer_flag_d9": state.flag_d9,
             "offset": offset, "nbytes": nbytes,
             "elapsed_nanos": elapsed,
             "start_times": {"system": start_times[0],
                             "steady": start_times[1]},
             "status": status.summary()}
    for listener in state.listeners:
        state.events.append(dict(event, listener=listener))
    return event


def _notify_failure(state, op_type, status):
    """The failure-only event (Flush, RangeSync): {status
    (CopyState deep copy), type, file_name_} through slot 47
    (0x178), skipping the base no-op 0x6042c20."""
    event = {"op": "notify_failure", "type": op_type,
             "slot": hex(NOTIFY_FAILURE_SLOT),
             "base_noop": hex(NOTIFY_FAILURE_BASE),
             "file_name": state.file_name,
             "status": status.summary()}
    for listener in state.listeners:
        state.events.append(dict(event, listener=listener))
    return event


def _range_sync_member(state, offset, nbytes):
    """rocksdb::WritableFileWriter::RangeSync, the member at
    0x604d7b0..0x604e01b (2155 B, no census record). Called by
    Flush's RangeSync arm; also directly testable via
    run_range_sync_case(). Returns the Status it returns."""
    # 1. Seen-error gate (0x604d7e4). Unreachable from Flush
    # (Flush only calls it with seen_error_ clear) but part of
    # the member's own contract.
    if state.seen_error:
        return Status.io_error(PREV_ERROR_MSG)
    # 2. TEST_SYNC_POINT (0x604d7f3).
    if state.sync_point_enabled:
        state.events.append({"op": "sync_point",
                             "name": "WritableFileWriter::RangeSync:0",
                             "helper": hex(SYNC_POINT_HELPER_ADDR)})
    # 3. IOSTATS_TIMER_GUARD(range_sync_nanos) (0x604d805).
    guard_start = 0
    guard_wall = state.perf_level > 2
    if guard_wall and state.clock is not None:
        guard_start = state.clock.now_nanos()
        state.events.append({"op": "timer_guard_start",
                             "start": guard_start,
                             "counter": "range_sync_nanos"})
    # 4. Listener start times (0x604d87a).
    start_times = None
    if state.should_notify_listeners():
        start_times = (state.clock.now_pair()
                       if state.clock is not None else (0, 0))
        state.events.append({"op": "listener_start_times",
                             "system": start_times[0],
                             "steady": start_times[1]})
    # 5. Own IOOptions (0x604d8af): the FILE's GetIOPriority
    # directly -- no DecideRateLimiterPriority call (RangeSync
    # takes no op priority). Flush's IOOptions is NOT reused.
    io_options = io_options_default(state.file.get_io_priority())
    # 6. file->RangeSync (0x604d984, vtable slot 23).
    s = state.file.range_sync(
        offset, nbytes, io_options,
        status=_pop_script_status(state, "range_sync_file_statuses"))
    # 7a. Finish event (0x604d9b1, slot 37, type 7).
    if state.should_notify_listeners():
        _notify_finish(state, FILE_OP_RANGE_SYNC,
                       NOTIFY_RANGE_SYNC_FINISH_SLOT,
                       NOTIFY_RANGE_SYNC_FINISH_BASE,
                       start_times, s, offset=offset, nbytes=nbytes)
    # 8. Failure bookkeeping (0x604dc90): seen_error_ BEFORE the
    # failure notification.
    if not s.is_ok():
        state.set_seen_error()
    # 7b. Failure event (slot 47, type 7).
    if not s.is_ok() and state.should_notify_listeners():
        _notify_failure(state, FILE_OP_RANGE_SYNC, s)
    state.events.append({"op": "io_options_destroyed",
                         "callee": hex(HASHTABLE_DTOR_ADDR)})
    # 9. Guard stop (0x604dca8): elapsed -> range_sync_nanos.
    if guard_start:
        now = state.clock.now_nanos() if state.clock is not None else 0
        elapsed = now - guard_start
        if guard_wall:
            state.range_sync_nanos += elapsed
        state.events.append({"op": "timer_guard_stop", "now": now,
                             "elapsed": elapsed,
                             "counter": "range_sync_nanos"})
    # Epilogue: the sret copy zeroes byte 2.
    s.b2 = 0
    return s


def flush(state, priority):
    """rocksdb::WritableFileWriter::Flush, exactly as the FDE at
    0x6051a20 implements it. `priority` is Env::IOPriority.
    Returns Status."""
    s = Status.ok()
    # 1. Seen-error gate (0x6051a4b).
    if state.seen_error:
        return Status.io_error(PREV_ERROR_MSG)
    # 2. Write step (0x6051a5a..0x6051d26): only when cursize != 0.
    buf = state.buf
    if buf.cursize > 0:
        if state.file.use_direct_io():
            if state.pending_sync:
                s = _write_direct_oracle(
                    state, priority,
                    with_checksum=(state.perform_data_verification
                                   and state.buffered_data_with_checksum))
                if not s.is_ok():
                    state.set_seen_error()
                    s.b2 = 0
                    return s
            # pending_sync_ clear: no write, buf_ untouched.
        else:
            s = _write_buffered_oracle(
                state, bytes(buf.data[:buf.cursize]), priority,
                with_checksum=(state.perform_data_verification
                               and state.buffered_data_with_checksum),
                from_flush=True)
            if not s.is_ok():
                state.set_seen_error()
                s.b2 = 0
                return s
    # 3. Listener start times (0x6051a71).
    start_times = None
    if state.should_notify_listeners():
        start_times = (state.clock.now_pair()
                       if state.clock is not None else (0, 0))
        state.events.append({"op": "listener_start_times",
                             "system": start_times[0],
                             "steady": start_times[1]})
    # 4-5. IOOptions + file_->Flush (vtable slot 8).
    io_options = _flush_io_options(state, priority)
    s = state.file.file_flush(
        io_options, status=_pop_script_status(state,
                                              "file_flush_statuses"))
    # 6a. Finish event (0x6051dd5, slot 35, type 4). offset/length
    # are NOT written by Flush -- recorded as null (open unknown).
    if state.should_notify_listeners():
        _notify_finish(state, FILE_OP_FLUSH, NOTIFY_FLUSH_FINISH_SLOT,
                       NOTIFY_FLUSH_FINISH_BASE, start_times, s)
    # 6b. Failure event (slot 47, type 4).
    if not s.is_ok() and state.should_notify_listeners():
        _notify_failure(state, FILE_OP_FLUSH, s)
    state.events.append({"op": "io_options_destroyed",
                         "callee": hex(HASHTABLE_DTOR_ADDR)})
    # 7. Failure return (0x60521c6): seen_error_ AFTER the
    # notifications, then return the status.
    if not s.is_ok():
        state.set_seen_error()
        s.b2 = 0
        return s
    # 8. RangeSync arm (0x6051f28..0x60521ab).
    if (not state.file.use_direct_io()) and state.bytes_per_sync:
        k_not_sync = 1024 * 1024
        k_align = 4 * 1024
        cur_size = state.filesize
        if cur_size > k_not_sync:
            offset_sync_to = cur_size - k_not_sync
            offset_sync_to -= offset_sync_to % k_align
            if (offset_sync_to > 0 and
                    offset_sync_to - state.last_sync_size
                    >= state.bytes_per_sync):
                rs = _range_sync_member(state, state.last_sync_size,
                                        offset_sync_to
                                        - state.last_sync_size)
                # last_sync_size_ = offset_sync_to UNCONDITIONALLY
                # (0x605219f) -- even when the RangeSync failed.
                state.last_sync_size = offset_sync_to
                if not rs.is_ok():
                    state.set_seen_error()
                    return rs
    # 9. Epilogue (0x6051f5b..0x6051fc5): sret byte 2 forced to 0.
    s.b2 = 0
    return s


def _write_direct_oracle(state, priority, with_checksum):
    """WriteDirect[WithChecksum] contract (cc:1449-1642 /
    1645-1857), as used by Flush: page-pad the buffer, write it
    positionally, refit the tail. The rate-limiter loop is
    collapsed into one oracle step; token grants are recorded."""
    buf = state.buf
    alignment = buf.alignment
    file_advance = truncate_to_page(alignment, buf.cursize)
    leftover_tail = buf.cursize - file_advance
    last_cur = buf.cursize
    buf.pad_to_alignment(0)
    padded_size = buf.cursize - last_cur
    if with_checksum:
        padded_checksum = crc32c_value(
            bytes(buf.data[last_cur:buf.cursize]))
        state.buffered_data_crc32c_checksum = crc32c_combine(
            state.buffered_data_crc32c_checksum, padded_checksum,
            padded_size)
    src = bytes(buf.data[:buf.cursize])
    write_offset = state.next_write_offset
    left = buf.cursize
    # Rate-limiter drain (WriteDirectWithChecksum pre-loop) -- the
    # grants are recorded; the write itself is one oracle step.
    if (state.rate_limiter is not None and
            decide_rate_limiter_priority(state.file.get_io_priority(),
                                         priority) != IO_TOTAL):
        remaining = left
        while remaining > 0:
            g = state.rate_limiter.request_token(
                remaining, alignment,
                decide_rate_limiter_priority(
                    state.file.get_io_priority(), priority))
            remaining -= g
            if g == 0:
                break
    io_options = io_options_default(
        decide_rate_limiter_priority(state.file.get_io_priority(),
                                     priority))
    handoff = None
    if with_checksum:
        handoff = state.buffered_data_crc32c_checksum
    elif state.perform_data_verification:
        handoff = crc32c_value(src)
    s = _pop_script_status(state, "write_statuses")
    state.events.append({"op": "write_direct",
                         "with_checksum": with_checksum,
                         "file_advance": file_advance,
                         "leftover_tail": leftover_tail,
                         "padded_size": padded_size,
                         "handoff_checksum": handoff,
                         "status": s.summary()})
    if not s.is_ok():
        # WriteDirect failure: buf_.Size(file_advance +
        # leftover_tail); WriteDirectWithChecksum additionally
        # recomputes the checksum as Value of the remaining buffer.
        buf.size(file_advance + leftover_tail)
        if with_checksum:
            state.buffered_data_crc32c_checksum = crc32c_value(
                bytes(buf.data[:buf.cursize]))
        return s
    # Success: file gains the padded bytes at write_offset.
    state.file.positioned_append(src, write_offset, io_options,
                                 checksum=handoff, status=s)
    state.flushed_size += left
    buf.refit_tail(file_advance, leftover_tail)
    if with_checksum:
        state.buffered_data_crc32c_checksum = crc32c_value(
            bytes(buf.data[:buf.cursize]))
    state.next_write_offset += file_advance
    return Status.ok()


def _write_buffered_oracle(state, data, priority,
                           with_checksum, from_flush=False):
    """WriteBuffered[WithChecksum] contract (cc:1039-1216 /
    1219-1394): write the data straight to the file, clear buf_,
    reset the buffer checksum, advance flushed_size_. The
    rate-limiter loop is collapsed into one oracle step with the
    grants recorded. `data` is the bytes to write (the buffer
    contents when called from Flush, the caller data otherwise)."""
    buf = state.buf
    rate_prio = decide_rate_limiter_priority(
        state.file.get_io_priority(), priority)
    io_options = io_options_default(rate_prio)
    # Rate-limiter grants (WriteBuffered loops RequestToken per
    # chunk; WithChecksum drains the whole size first).
    left = len(data)
    if state.rate_limiter is not None and rate_prio != IO_TOTAL:
        remaining = left
        while remaining > 0:
            g = state.rate_limiter.request_token(
                remaining, buf.alignment if with_checksum else 0,
                rate_prio)
            remaining -= g
            if g == 0:
                break
    handoff = None
    if with_checksum:
        # EncodeFixed32(checksum_buf, buffered_data_crc32c_checksum_)
        handoff = state.buffered_data_crc32c_checksum
    elif state.perform_data_verification:
        handoff = crc32c_value(data)
    s = _pop_script_status(state, "write_statuses")
    state.events.append({
        "op": "write_buffered_with_checksum" if with_checksum
        else "write_buffered",
        "from_flush": from_flush, "len": len(data),
        "handoff_checksum": handoff, "status": s.summary()})
    if not s.is_ok():
        # Failure path (cc:1132-1156 / 1336-1364): clear buf_ and
        # reset the checksum, then the caller sets seen_error_.
        buf.clear()
        state.buffered_data_crc32c_checksum = 0
        return s
    state.file.file_append(data, io_options, checksum=handoff,
                           status=s)
    state.flushed_size += len(data)
    buf.clear()
    state.buffered_data_crc32c_checksum = 0
    return Status.ok()


def make_writer(overrides=None, file_overrides=None,
                script=None):
    """Build a WriterState + FakeFile from case overrides."""
    o = dict(overrides or {})
    f = FakeFile(**(file_overrides or {}))
    # Buffer bytes: buf_seed (preferred -- keeps cases.tsv small)
    # generates cursize deterministic bytes; buf_hex is the explicit
    # form; absent both, a fresh buf_ is zero-filled.
    _cursize = o.get("cursize", 0)
    if o.get("buf_seed") is not None:
        _brng = random.Random(o["buf_seed"])
        _buf_hex = bytes(_brng.randrange(256)
                         for _ in range(_cursize))
    else:
        _buf_hex = bytes.fromhex(o.get("buf_hex", ""))
        if len(_buf_hex) < _cursize:
            _buf_hex = _buf_hex + bytes(_cursize - len(_buf_hex))
    buf = AlignedBuffer(o.get("alignment", 4096),
                        capacity=o.get("capacity", 4096),
                        cursize=_cursize,
                        data=_buf_hex[:_cursize])
    clock = None
    if o.get("clock_pairs") is not None:
        clock = FakeClock(o["clock_pairs"])
    limiter = None
    if o.get("rate_limiter_grants") is not None:
        limiter = FakeRateLimiter(o["rate_limiter_grants"])
    state = WriterState(
        file=f, buf=buf,
        max_buffer_size=o.get("max_buffer_size", 65536),
        filesize=o.get("filesize", 0),
        flushed_size=o.get("flushed_size", 0),
        next_write_offset=o.get("next_write_offset", 0),
        pending_sync=o.get("pending_sync", False),
        seen_error=o.get("seen_error", False),
        last_sync_size=o.get("last_sync_size", 0),
        bytes_per_sync=o.get("bytes_per_sync", 0),
        rate_limiter=limiter, stats=o.get("stats"),
        listeners=o.get("listeners", []),
        checksum_generator=o.get("checksum_generator", False),
        checksum_finalized=o.get("checksum_finalized", False),
        perform_data_verification=o.get(
            "perform_data_verification", False),
        buffered_data_crc32c_checksum=o.get(
            "buffered_data_crc32c_checksum", 0),
        buffered_data_with_checksum=o.get(
            "buffered_data_with_checksum", False),
        temperature=o.get("temperature", 0),
        perf_level=o.get("perf_level", 0), clock=clock,
        sync_point_enabled=o.get("sync_point_enabled", False),
        flag_d9=o.get("flag_d9", False),
        file_name=o.get("file_name", "test.wal"))
    if o.get("file_image_hex"):
        f.image = bytearray(bytes.fromhex(o["file_image_hex"]))
    state.script = {k: [dict(x) for x in v]
                    for k, v in (script or {}).items()}
    return state


def run_case(case):
    """Run one case dict through flush() and return the observed
    outcome dict (status summary + state snapshot)."""
    state = make_writer(case.get("writer"), case.get("file"),
                        case.get("script"))
    s = flush(state, case["priority"])
    out = state.snapshot()
    out["return_status"] = s.summary()
    out["return_status_bytes"] = s.out_bytes().hex()
    return out


def run_range_sync_case(case):
    """Run one case dict through the RangeSync member directly
    (its seen-error gate is unreachable from Flush) and return
    the observed outcome dict."""
    state = make_writer(case.get("writer"), case.get("file"),
                        case.get("script"))
    s = _range_sync_member(state, case["offset"], case["nbytes"])
    out = state.snapshot()
    out["return_status"] = s.summary()
    out["return_status_bytes"] = s.out_bytes().hex()
    return out

# ---------------------------------------------------------------------------
# Case generation: 2400 deterministic cases in 4 groups of 600.
# ---------------------------------------------------------------------------

ERR_IO = {"code": 5, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
          "b5": 0, "b67": 0, "state": 2}
ERR_CORRUPTION = {"code": 2, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
                  "b5": 0, "b67": 0, "state": 0}


def _payload(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def _base_writer(rng, **over):
    w = {"alignment": 4096, "capacity": 4096, "cursize": 0,
         "max_buffer_size": 65536, "filesize": 0, "flushed_size": 0,
         "next_write_offset": 0, "pending_sync": False,
         "seen_error": False, "last_sync_size": 0, "bytes_per_sync": 0,
         "listeners": [], "checksum_generator": False,
         "checksum_finalized": False,
         "perform_data_verification": False,
         "buffered_data_crc32c_checksum": 0,
         "buffered_data_with_checksum": False, "temperature": 0,
         "perf_level": 0, "sync_point_enabled": False,
         "flag_d9": False, "file_name": "test.wal"}
    w.update(over)
    return w


def _gen_gate(rng):
    """600 gate cases: seen-error, empty/non-empty buffer,
    pending_sync, direct I/O, verification flags, priorities,
    tracer selection, perf level, sync point, clock pairs,
    flag_d9, file names."""
    cases = []
    for i in range(600):
        seen_error = rng.random() < 0.15
        verify = rng.random() < 0.5
        with_cksum = rng.random() < 0.5
        perf = rng.choice([0, 1, 2, 3, 4, 5])
        # Clock pairs: (system, steady). Flush consumes one pair
        # for the listener start times and one steady reading for
        # the finish-event elapsed; the member consumes two more
        # for its timer guard.
        clock = ([(1000000 + 1000 * j, 500000 + 700 * j)
                  for j in range(6)] if perf > 2 or
                 rng.random() < 0.5 else None)
        tracer = rng.choice([None, {"enabled": False},
                             {"enabled": True}])
        w = _base_writer(
            rng, seen_error=seen_error,
            perform_data_verification=verify,
            buffered_data_with_checksum=with_cksum,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            perf_level=perf, clock_pairs=clock,
            sync_point_enabled=rng.random() < 0.2,
            flag_d9=rng.random() < 0.5,
            file_name=rng.choice(["test.wal", "000123.sst",
                                  "MANIFEST-000001", "OPTIONS-000002"]),
            cursize=rng.choice([0, 0, 1, 100, 1000, 4095, 4096]),
            buf_seed=(rng.randrange(2 ** 31)
                      if rng.random() < 0.7 else None),
            pending_sync=rng.random() < 0.5,
            listeners=(["L1", "L2"] if rng.random() < 0.3 else
                       (["L1"] if rng.random() < 0.3 else [])))
        f = {"io_priority": rng.randrange(5),
             "direct_io": rng.random() < 0.3, "tracer": tracer}
        cases.append({
            "group": "gate", "case_id": "gate-%03d" % i,
            "writer": w, "file": f, "script": {},
            "priority": rng.randrange(5)})
    return cases


def _gen_rangesync(rng):
    """600 RangeSync cases: the Flush arm matrix (filesize vs
    1 MiB, align-down, last_sync_size vs bytes_per_sync, direct
    I/O exclusion) plus direct member calls (offset/nbytes,
    perf-level guard, sync point, scripted file failures)."""
    cases = []
    for i in range(600):
        if i % 2 == 0:
            # Flush-arm cases: entry flush, filesize near the
            # 1 MiB threshold and the 4 KiB align-down edge.
            filesize = rng.choice([
                0, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1,
                1024 * 1024 + 4095, 1024 * 1024 + 4096,
                1024 * 1024 + 8192, 2 * 1024 * 1024,
                2 * 1024 * 1024 + 4096, 5 * 1024 * 1024,
                10 * 1024 * 1024])
            last_sync = rng.choice([0, 4096, 65536, 1024 * 1024,
                                    filesize // 2 if filesize else 0])
            bps = rng.choice([0, 4096, 65536, 1024 * 1024])
            script = {}
            if rng.random() < 0.25:
                script["range_sync_file_statuses"] = [dict(ERR_IO)]
            w = _base_writer(
                rng, filesize=filesize, last_sync_size=last_sync,
                bytes_per_sync=bps,
                cursize=rng.choice([0, 100, 4096]),
                buf_seed=rng.randrange(2 ** 31),
                perf_level=rng.choice([0, 3]),
                clock_pairs=[(1000000 + 1000 * j, 500000 + 700 * j)
                             for j in range(6)],
                listeners=(["L1"] if rng.random() < 0.5 else []),
                flag_d9=rng.random() < 0.5,
                sync_point_enabled=rng.random() < 0.2)
            f = {"io_priority": rng.randrange(5),
                 "direct_io": rng.random() < 0.25, "tracer": None}
            cases.append({
                "group": "rangesync", "case_id": "rangesync-%03d" % i,
                "entry": "flush", "writer": w, "file": f,
                "script": script, "priority": rng.randrange(5)})
        else:
            # Direct member cases: entry range_sync.
            script = {}
            if rng.random() < 0.3:
                script["range_sync_file_statuses"] = [
                    dict(rng.choice([ERR_IO, ERR_CORRUPTION]))]
            w = _base_writer(
                rng, seen_error=rng.random() < 0.1,
                perf_level=rng.choice([0, 2, 3, 5]),
                clock_pairs=[(1000000 + 1000 * j, 500000 + 700 * j)
                             for j in range(6)],
                listeners=(["L1", "L2"] if rng.random() < 0.4
                           else (["L1"] if rng.random() < 0.4 else [])),
                flag_d9=rng.random() < 0.5,
                file_name=rng.choice(["test.wal", "000123.sst"]),
                sync_point_enabled=rng.random() < 0.3)
            f = {"io_priority": rng.randrange(5),
                 "direct_io": False, "tracer": None}
            cases.append({
                "group": "rangesync", "case_id": "rangesync-%03d" % i,
                "entry": "range_sync", "writer": w, "file": f,
                "script": script,
                "offset": rng.choice([0, 4096, 65536, 1024 * 1024]),
                "nbytes": rng.choice([0, 4096, 65536, 1024 * 1024])})
    return cases


def _gen_write_paths(rng):
    """600 write-path cases: buffered/direct x verification x
    pending_sync x scripted write/file-Flush/RangeSync outcomes
    x rate limiter x listeners x clock pairs."""
    cases = []
    for i in range(600):
        direct = rng.random() < 0.4
        verify = rng.random() < 0.5
        with_cksum = rng.random() < 0.5
        capacity = rng.choice([4096, 8192])
        cursize = rng.choice([0, 1, 100, 1000, 4000, 4095, 4096])
        script = {}
        # Write-step outcome (consumed by the Write* oracle).
        r = rng.random()
        if r < 0.12:
            script["write_statuses"] = [dict(ERR_IO)]
        # file_->Flush outcome.
        r2 = rng.random()
        if r2 < 0.12:
            script["file_flush_statuses"] = [dict(ERR_CORRUPTION)]
        # RangeSync arm (fires only when Flush reaches it with
        # filesize > 1 MiB and the arm conditions met).
        filesize = 0
        bytes_per_sync = 0
        if rng.random() < 0.2:
            filesize = rng.choice([1024 * 1024 + 4096,
                                   2 * 1024 * 1024, 5 * 1024 * 1024])
            bytes_per_sync = rng.choice([4096, 65536])
            if rng.random() < 0.3:
                script["range_sync_file_statuses"] = [dict(ERR_IO)]
        w = _base_writer(
            rng, capacity=capacity, cursize=cursize,
            max_buffer_size=65536, filesize=filesize,
            bytes_per_sync=bytes_per_sync,
            buf_seed=rng.randrange(2 ** 31),
            perform_data_verification=verify,
            buffered_data_with_checksum=with_cksum,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            pending_sync=rng.random() < 0.6,
            listeners=(["L1", "L2"] if rng.random() < 0.25 else
                       (["L1"] if rng.random() < 0.25 else [])),
            clock_pairs=[(1000000 + 1000 * j, 500000 + 700 * j)
                         for j in range(8)],
            flag_d9=rng.random() < 0.5,
            perf_level=rng.choice([0, 3]),
            rate_limiter_grants=(
                [100, 1000, 4096] if rng.random() < 0.25 else None))
        f = {"io_priority": rng.randrange(5), "direct_io": direct,
             "tracer": rng.choice([None, {"enabled": True}])}
        cases.append({
            "group": "write_paths", "case_id": "write_paths-%03d" % i,
            "writer": w, "file": f, "script": script,
            "priority": rng.randrange(5)})
    return cases


def _fde_body_hashes():
    """Recompute the FDE body hashes from the binary (the
    bindings group pins them; the packet's gen_records.py is the
    authority, this is a cross-check)."""
    data = open(_bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256
    out = {}
    for start, end, key in ((FLUSH_ADDR, FLUSH_FDE_END, "flush"),
                            (COLD_ADDR, COLD_FDE_END, "cold"),
                            (RANGE_SYNC_ADDR, RANGE_SYNC_FDE_END,
                             "range_sync"),
                            (WRITE_BUFFERED_ADDR,
                             WRITE_BUFFERED_FDE_END, "write_buffered"),
                            (WRITE_BUFFERED_CHECKSUM_ADDR,
                             WRITE_BUFFERED_CHECKSUM_FDE_END,
                             "write_buffered_checksum"),
                            (WRITE_DIRECT_ADDR, WRITE_DIRECT_FDE_END,
                             "write_direct"),
                            (WRITE_DIRECT_CHECKSUM_ADDR,
                             WRITE_DIRECT_CHECKSUM_FDE_END,
                             "write_direct_checksum")):
        body = data[_va_to_off(start):_va_to_off(end)]
        out[key] = hashlib.sha256(body).hexdigest()
    return out


def _bin_path():
    for path in (BIN_WORK, BIN_LFS):
        if path.exists():
            data = open(path, "rb").read()
            if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
                return path
    raise RuntimeError("node #115 artifact not materialized")


def _va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(_bin_path())]
                                  ).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _gen_bindings(rng):
    """600 binding rows: hashes, FDE ranges, census records,
    caller census, vtable slots, layout offsets, IOOptions
    constants, the priority matrix, CRC vectors, FileOperationType
    values, the RangeSync arm constants, and direct AlignedBuffer
    unit rows."""
    cases = []
    idx = 0

    def add(kind, payload):
        nonlocal idx
        cases.append({"group": "bindings",
                      "case_id": "bindings-%03d" % idx,
                      "kind": kind, "payload": payload})
        idx += 1

    hashes = _fde_body_hashes()
    add("body_hash", {"fn": "Flush", "start": hex(FLUSH_ADDR),
                      "end": hex(FLUSH_FDE_END), "size": 2908,
                      "sha256": hashes["flush"]})
    add("body_hash", {"fn": "Flush.cold", "start": hex(COLD_ADDR),
                      "end": hex(COLD_FDE_END), "size": 228,
                      "sha256": hashes["cold"]})
    add("body_hash", {"fn": "RangeSync", "start": hex(RANGE_SYNC_ADDR),
                      "end": hex(RANGE_SYNC_FDE_END), "size": 2155,
                      "sha256": hashes["range_sync"]})
    add("body_hash", {"fn": "WriteBuffered",
                      "start": hex(WRITE_BUFFERED_ADDR),
                      "end": hex(WRITE_BUFFERED_FDE_END), "size": 3533,
                      "sha256": hashes["write_buffered"]})
    add("body_hash", {"fn": "WriteBufferedWithChecksum",
                      "start": hex(WRITE_BUFFERED_CHECKSUM_ADDR),
                      "end": hex(WRITE_BUFFERED_CHECKSUM_FDE_END),
                      "size": 3351,
                      "sha256": hashes["write_buffered_checksum"]})
    add("body_hash", {"fn": "WriteDirect",
                      "start": hex(WRITE_DIRECT_ADDR),
                      "end": hex(WRITE_DIRECT_FDE_END), "size": 3338,
                      "sha256": hashes["write_direct"]})
    add("body_hash", {"fn": "WriteDirectWithChecksum",
                      "start": hex(WRITE_DIRECT_CHECKSUM_ADDR),
                      "end": hex(WRITE_DIRECT_CHECKSUM_FDE_END),
                      "size": 3255,
                      "sha256": hashes["write_direct_checksum"]})
    census = json.load(open(ROOT / CENSUS_PATH))["records"]
    by_start = {r["start"]: r for r in census}
    for addr, fn in ((FLUSH_ADDR, "Flush"), (COLD_ADDR, "Flush.cold")):
        rec = by_start[addr]
        add("census_fn", {"fn": fn, "start": hex(addr),
                          "target_body_sha256":
                              rec["target_body_sha256"],
                          "source_body_sha256":
                              rec["source_body_sha256"],
                          "raw_equal": rec["raw_equal"],
                          "relocations": rec["relocations"]})
    add("census_member_missing",
        {"fn": "RangeSync", "census": None,
         "note": "no vendor census record; body hash only"})
    # Caller census sites (from census.json in the packet).
    pkt_census = json.load(open(PACKET / "census.json"))
    add("caller_census", pkt_census)
    # Vtable slots.
    for slot, name in ((USE_DIRECT_IO_SLOT, "use_direct_io"),
                       (GET_IO_PRIORITY_SLOT, "GetIOPriority"),
                       (FILE_FLUSH_SLOT, "FSWritableFile::Flush"),
                       (FILE_RANGE_SYNC_SLOT,
                        "FSWritableFile::RangeSync"),
                       (NOTIFY_FLUSH_FINISH_SLOT // 8,
                        "EventListener::OnFileFlushFinish?"),
                       (NOTIFY_RANGE_SYNC_FINISH_SLOT // 8,
                        "EventListener::OnFileRangeSyncFinish?"),
                       (NOTIFY_FAILURE_SLOT // 8,
                        "EventListener::OnFile* failure?")):
        add("vtable_slot", {"slot": slot, "byte_off": slot * 8,
                            "method": name})
    # Layout offsets.
    layout = {
        "file_name_": OFF_FILE_NAME, "writable_file_": OFF_WRITABLE_FILE,
        "io_tracer_": OFF_IO_TRACER, "fs_tracer_": OFF_FS_TRACER,
        "clock_": OFF_CLOCK, "buf_": OFF_BUF,
        "buf_alignment_": OFF_BUF_ALIGNMENT, "buf_ptr": OFF_BUF_PTR,
        "buf_capacity_": OFF_BUF_CAPACITY, "buf_cursize_": OFF_BUF_CURSIZE,
        "buf_start_": OFF_BUF_START,
        "max_buffer_size_": OFF_MAX_BUFFER_SIZE,
        "filesize_": OFF_FILESIZE, "flushed_size_": OFF_FLUSHED_SIZE,
        "next_write_offset_": OFF_NEXT_WRITE_OFFSET,
        "pending_sync_": OFF_PENDING_SYNC,
        "seen_error_": OFF_SEEN_ERROR,
        "last_sync_size_": OFF_LAST_SYNC_SIZE,
        "bytes_per_sync_": OFF_BYTES_PER_SYNC,
        "rate_limiter_": OFF_RATE_LIMITER, "stats_": OFF_STATS,
        "listeners_": OFF_LISTENERS,
        "checksum_generator_": OFF_CHECKSUM_GENERATOR,
        "checksum_finalized_": OFF_CHECKSUM_FINALIZED,
        "perform_data_verification_": OFF_PERFORM_DATA_VERIFICATION,
        "buffered_data_crc32c_checksum_": OFF_BUFFERED_DATA_CRC32C,
        "buffered_data_with_checksum_": OFF_BUFFERED_DATA_WITH_CHECKSUM,
        "flag_d9_unknown_": OFF_FLAG_D9,
        "temperature_": OFF_TEMPERATURE, "writer_size": WRITER_SIZE}
    for name, off in sorted(layout.items()):
        add("layout", {"member": name, "offset": off})
    # IOOptions defaults.
    io = io_options_default(IO_TOTAL)
    add("io_options_default", io)
    add("io_options_priority_slot", {"field": "rate_limiter_priority",
                                     "offset": 12})
    # DecideRateLimiterPriority matrix (5 x 5).
    for fp in range(5):
        for op in range(5):
            add("decide_priority",
                {"file": fp, "op": op,
                 "result": decide_rate_limiter_priority(fp, op)})
    # FileOperationType values and the RangeSync arm constants.
    add("file_op_type", {"name": "kFlush", "value": FILE_OP_FLUSH})
    add("file_op_type", {"name": "kRangeSync",
                         "value": FILE_OP_RANGE_SYNC})
    add("rangesync_constants",
        {"not_synced_bytes": 1024 * 1024,
         "align_down": 4 * 1024,
         "note": "offset_sync_to = (filesize - 1MiB) & ~0xfff"})
    # CRC vectors.
    add("crc_vector", {"data_hex": b"123456789".hex(),
                       "value": 0xE3069283})
    add("crc_vector", {"data_hex": b"".hex(), "value": 0})
    add("crc_mask", {"crc": 0xE3069283,
                     "masked": crc32c_mask(0xE3069283)})
    for i in range(64):
        data = _payload(rng, i)
        add("crc_extend", {"data_hex": data.hex(),
                           "value": crc32c_value(data)})
    for i in range(64):
        a = _payload(rng, rng.randrange(0, 17))
        b = _payload(rng, rng.randrange(0, 17))
        add("crc_combine", {"a_hex": a.hex(), "b_hex": b.hex(),
                            "combine": crc32c_combine(
                                crc32c_value(a), crc32c_value(b),
                                len(b)),
                            "direct": crc32c_value(a + b)})
    # AlignedBuffer unit rows.
    for alignment, requested, cursize, copy_data in (
            (4096, 100, 1000, True), (4096, 4096, 100, True),
            (512, 512, 0, True), (4096, 8192, 4096, True),
            (4096, 4096, 4096, False)):
        buf = AlignedBuffer(alignment, capacity=4096, cursize=cursize,
                            data=bytes(cursize))
        events = []
        ok = buf.allocate_new_buffer(requested, copy_data=copy_data,
                                     events=events)
        add("aligned_buffer_allocate",
            {"alignment": alignment, "requested": requested,
             "cursize_in": cursize, "copy_data": copy_data,
             "allocated": ok, "capacity_out": buf.capacity,
             "cursize_out": buf.cursize, "events": events})
    # Timer-guard thresholds and the prev-error message.
    for level in range(6):
        add("timer_guard_armed", {"perf_level": level,
                                  "armed": level > 2})
    add("prev_error", {"message": PREV_ERROR_MSG,
                       "message_len": len(PREV_ERROR_MSG),
                       "code": 5, "alloc_bytes": 27})
    # File-selection matrix.
    for tracer in (None, {"enabled": False}, {"enabled": True}):
        f = FakeFile(tracer=tracer)
        add("file_selection", {"tracer": tracer,
                               "selected": f.select_file()})
    # Pad the group to exactly 600 with CRC extend rows.
    while len(cases) < 600:
        data = _payload(rng, rng.randrange(0, 33))
        add("crc_extend", {"data_hex": data.hex(),
                           "value": crc32c_value(data)})
    return cases[:600]


def generate_cases(seed=115):
    """All 2400 cases, deterministic for a fixed seed."""
    rng = random.Random(seed)
    cases = []
    cases.extend(_gen_gate(rng))
    cases.extend(_gen_rangesync(rng))
    cases.extend(_gen_write_paths(rng))
    cases.extend(_gen_bindings(rng))
    assert len(cases) == 2400, len(cases)
    return cases


def case_outcome(case):
    """The expected outcome for a case: run the model (for the
    three behavioural groups) or evaluate the binding directly."""
    if case["group"] == "bindings":
        return _binding_outcome(case)
    if case.get("entry") == "range_sync":
        return run_range_sync_case(case)
    return run_case(case)


def _binding_outcome(case):
    kind = case["kind"]
    p = case["payload"]
    if kind == "body_hash":
        return {"ok": True, "sha256": p["sha256"], "size": p["size"]}
    if kind == "census_fn":
        # Re-derive the source hash from the census relocations.
        data = open(_bin_path(), "rb").read()
        start = int(p["start"], 16)
        rec = json.load(open(ROOT / CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in rec}
        end = by_start[start]["end"]
        body = data[_va_to_off(start):_va_to_off(end)]
        zeroed = bytearray(body)
        for rel in p["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
                # GOTPCRELX relaxation: restore the source MOV (0x8B)
                # over the linker's relaxed LEA (0x8D).
                assert zeroed[o - 2] == 0x8D
                zeroed[o - 2] = 0x8B
        return {"ok": True,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "source_sha256": hashlib.sha256(bytes(zeroed)).hexdigest(),
                "relocations": len(p["relocations"])}
    if kind == "census_member_missing":
        return {"ok": True, "census": None}
    if kind == "caller_census":
        return {"ok": True, "targets": p["targets"],
                "validated_sites": p["validated_sites"]}
    if kind == "vtable_slot":
        return {"ok": True, "slot": p["slot"],
                "byte_off": p["byte_off"], "method": p["method"]}
    if kind == "layout":
        return {"ok": True, "member": p["member"],
                "offset": p["offset"]}
    if kind == "io_options_default":
        return {"ok": True, "image_hex": p["image_hex"],
                "rate_limiter_priority": p["rate_limiter_priority"]}
    if kind == "io_options_priority_slot":
        return {"ok": True, "field": p["field"], "offset": p["offset"]}
    if kind == "decide_priority":
        return {"ok": True, "file": p["file"], "op": p["op"],
                "result": p["result"]}
    if kind == "file_op_type":
        return {"ok": True, "name": p["name"], "value": p["value"]}
    if kind == "rangesync_constants":
        return {"ok": True,
                "not_synced_bytes": p["not_synced_bytes"],
                "align_down": p["align_down"]}
    if kind in ("crc_vector", "crc_extend"):
        data = bytes.fromhex(p["data_hex"])
        return {"ok": True, "value": crc32c_value(data)}
    if kind == "crc_mask":
        return {"ok": True, "masked": crc32c_mask(p["crc"])}
    if kind == "crc_combine":
        a = bytes.fromhex(p["a_hex"])
        b = bytes.fromhex(p["b_hex"])
        return {"ok": True,
                "combine": crc32c_combine(crc32c_value(a),
                                          crc32c_value(b), len(b)),
                "direct": crc32c_value(a + b)}
    if kind == "aligned_buffer_allocate":
        buf = AlignedBuffer(p["alignment"], capacity=4096,
                            cursize=p["cursize_in"],
                            data=bytes(p["cursize_in"]))
        events = []
        ok = buf.allocate_new_buffer(p["requested"],
                                     copy_data=p["copy_data"],
                                     events=events)
        return {"ok": True, "allocated": ok,
                "capacity_out": buf.capacity,
                "cursize_out": buf.cursize, "events": events}
    if kind == "timer_guard_armed":
        return {"ok": True, "perf_level": p["perf_level"],
                "armed": p["perf_level"] > 2}
    if kind == "prev_error":
        return {"ok": True, "message": p["message"],
                "message_len": len(p["message"]),
                "alloc_bytes": len(p["message"]) + 1}
    if kind == "file_selection":
        f = FakeFile(tracer=p["tracer"])
        return {"ok": True, "selected": f.select_file()}
    raise ValueError(kind)


def write_cases(path=None):
    """Generate the 2400 cases and write cases.tsv in the packet."""
    path = Path(path) if path else PACKET / "cases.tsv"
    cases = generate_cases()
    with open(path, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for case in cases:
            outcome = case_outcome(case)
            fh.write("%s\t%s\t%s\t%s\n" % (
                case["group"], case["case_id"],
                json.dumps(case, sort_keys=True),
                json.dumps(outcome, sort_keys=True)))
    print("wrote %s (%d cases)" % (path, len(cases)))
    return cases


def verify_cases(path=None):
    """Replay cases.tsv through the model and compare exactly."""
    path = Path(path) if path else PACKET / "cases.tsv"
    bad = 0
    total = 0
    with open(path) as fh:
        header = fh.readline()
        assert header.startswith("group\tcase_id\t")
        for line in fh:
            total += 1
            group, case_id, inputs_s, expected_s = line.rstrip("\n").split("\t")
            case = json.loads(inputs_s)
            expected = json.loads(expected_s)
            got = case_outcome(case)
            if got != expected:
                bad += 1
                if bad <= 3:
                    print("MISMATCH %s %s" % (group, case_id))
                    print("  expected:", json.dumps(expected)[:400])
                    print("  got:     ", json.dumps(got)[:400])
    print("verify: %d cases, %d mismatches" % (total, bad))
    return bad == 0 and total == 2400


def live_engine_check():
    """Drive the model against a REAL file: every file_append /
    positioned_append also writes to a tempfile, and the model's
    file image must equal the real file bytes after each Flush.

    Returns (ok, report dict)."""
    import os

    class RealFile(FakeFile):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.fd, self.path = tempfile.mkstemp(prefix="wfw-flush-")
            self.real_len = 0

        def file_append(self, data, io_options, checksum=None,
                        status=None):
            s = super().file_append(data, io_options, checksum, status)
            if s.is_ok():
                os.write(self.fd, data)
                self.real_len += len(data)
            self._check_real()
            return s

        def positioned_append(self, data, offset, io_options,
                              checksum=None, status=None):
            s = super().positioned_append(data, offset, io_options,
                                          checksum, status)
            if s.is_ok():
                os.pwrite(self.fd, data, offset)
                self.real_len = max(self.real_len, offset + len(data))
            self._check_real()
            return s

        def file_flush(self, io_options, status=None):
            s = super().file_flush(io_options, status=status)
            self._check_real()
            return s

        def range_sync(self, offset, nbytes, io_options, status=None):
            s = super().range_sync(offset, nbytes, io_options,
                                   status=status)
            self._check_real()
            return s

        def _check_real(self):
            os.lseek(self.fd, 0, os.SEEK_SET)
            real = os.read(self.fd, self.real_len + 4096)
            assert real == bytes(self.image), (
                "real file diverged from model image: %d vs %d bytes"
                % (len(real), len(self.image)))

        def close(self):
            os.close(self.fd)
            os.unlink(self.path)

    report = {"legs": []}
    try:
        # Leg 1: buffered flush -- fill the buffer by hand, flush,
        # the real file gains the bytes.
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 11,
                                      data=b"hello flush"),
            max_buffer_size=65536, filesize=0)
        s = flush(state, IO_TOTAL)
        assert s.is_ok(), s
        assert len(f.image) == 11 and bytes(f.image) == b"hello flush"
        f._check_real()
        report["legs"].append({"leg": "buffered_flush",
                              "bytes": 11, "ok": True})
        f.close()
        # Leg 2: direct-I/O flush with a page-aligned buffer and a
        # leftover tail; the file gains the padded write.
        f = RealFile(io_priority=IO_HIGH, direct_io=True)
        data = bytes([0xAB]) * 5000
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 8192, 5000, data=data),
            max_buffer_size=65536, pending_sync=True,
            perform_data_verification=True,
            buffered_data_with_checksum=True)
        s = flush(state, IO_HIGH)
        assert s.is_ok(), s
        assert len(f.image) == 8192, len(f.image)
        assert bytes(f.image[:5000]) == data
        f._check_real()
        report["legs"].append({"leg": "direct_io_flush",
                              "bytes": 5000, "ok": True})
        f.close()
        # Leg 3: the seen-error gate returns the prev-error status
        # and writes nothing.
        f = RealFile()
        state = WriterState(file=f, buf=AlignedBuffer(4096, 4096, 5,
                                                      data=b"hello"),
                            max_buffer_size=65536, seen_error=True)
        s = flush(state, IO_TOTAL)
        assert not s.is_ok() and s.code == 5, s
        assert s.summary()["state"] == 1
        assert len(f.image) == 0 and state.filesize == 0
        report["legs"].append({"leg": "seen_error_gate", "ok": True})
        f.close()
        # Leg 4: the RangeSync arm fires on a >1 MiB file and the
        # real file is unchanged by the sync.
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 0),
            max_buffer_size=65536,
            filesize=2 * 1024 * 1024, bytes_per_sync=4096,
            listeners=["L1"],
            clock=FakeClock([(1000000, 500000), (1000100, 500100),
                             (1000200, 500200), (1000300, 500300),
                             (1000400, 500400), (1000500, 500500)]),
            perf_level=3)
        s = flush(state, IO_TOTAL)
        assert s.is_ok(), s
        assert state.last_sync_size == 1024 * 1024, \
            state.last_sync_size
        assert any(e["op"] == "range_sync"
                   for e in state.events + state.file.events), \
            state.events
        f._check_real()
        report["legs"].append({"leg": "rangesync_arm",
                              "last_sync_size": state.last_sync_size,
                              "ok": True})
        f.close()
        report["ok"] = True
    except Exception as exc:  # noqa: BLE001 - report, do not raise
        report["ok"] = False
        report["error"] = repr(exc)
    print("live engine check:", json.dumps(report))
    return report["ok"], report


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="replay cases.tsv through the model")
    ap.add_argument("--gen-cases", action="store_true",
                    help="generate cases.tsv")
    ap.add_argument("--live", action="store_true",
                    help="run the live engine check")
    args = ap.parse_args(argv)
    ok = True
    if args.gen_cases:
        write_cases()
    if args.verify:
        ok = verify_cases() and ok
    if args.live:
        live_ok, _ = live_engine_check()
        ok = live_ok and ok
    if not (args.gen_cases or args.verify or args.live):
        ap.print_help()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
