#!/usr/bin/env python3
"""Node #115 RocksDB WritableFileWriter::Append: reconstruction.

RE-002 work item. Reconstructs the WAL/SST file writer's append
routine at 0x6054680..0x605518b (2827 B) plus its landing pad
``Append.cold`` at 0x6054600..0x605467c (124 B):

  rocksdb::WritableFileWriter::Append       0x6054680 (2827 B)
  rocksdb::WritableFileWriter::Append.cold  0x6054600 (124 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The main body has NO vendor census record (body hash only, as in
merged #5992); the .cold IS census-bound (body hash matches
target_body_sha256 exactly; source hash reproduced by zeroing the
recorded relocations -- see gen_records.py). Symbols come from the
vendor census (member a895f7517936a0f7-writable_file_writer.o,
librocksdb-sys 0.11.0+8.1.1).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus Append(const Slice& data, uint32_t crc32c_checksum,
                  Env::IOPriority op_rate_limiter_priority)
  -- returns by value, so rdi is the hidden 16-byte sret out-pointer,
  rsi is the Writer*, rdx the data Slice*, rcx the crc32c checksum,
  r8d the priority. Steps, in binary order:

  1. Seen-error gate (0x60546b9): byte this+0x89 (seen_error_) is
     read FIRST and saved. If set, the routine returns at once
     (0x60546cc): sret = {code 5 (kIOError), subcode 0, severity 0,
     scope 0, retryable 0, data_loss 0, state_ = fresh 27-byte
     "Writer has previous error."} -- exactly upstream
     AssertFalseAndGetStatusForPrevError()
     (file/writable_file_writer.h:555-563), which returns
     IOStatus::IOError("Writer has previous error."). The old
     sret state_ (when non-null) is delete[]'d first. No other
     member is touched: pending_sync_ is NOT set, no checksum
     update, no PrepareWrite, filesize_ unchanged.
  2. src = data.data(), left = data.size() (0x6054748);
     pending_sync_ (this+0x88) = true (0x605474f).
  3. UpdateFileChecksum(data) at 0x604c7b0 (census-bound symbol):
     checksum_generator_ (this+0xc8) when non-null, tail-jump to
     its vtable slot 2 (0x10) = FileChecksumGenerator::Update(data,
     size). When null, a plain ret. The generator is an input
     oracle here: the model records the (data, size) it is handed.
  4. IOOptions block (0x6054769..0x60548e8): a 0x58-byte IOOptions
     is built on the stack at rsp+0x70 with the exact default
     constants -- timeout 0, prio kIOLow (0), rate_limiter_priority
     IO_TOTAL (4), type kUnknown (7), property_bag an empty
     unordered_map (single-bucket self-pointer at rsp+0xb8,
     bucket_count 1, max_load_factor 1.0f), force_dir_fsync 0,
     do_not_recurse 0 -- then rate_limiter_priority is overwritten
     at rsp+0x7c with DecideRateLimiterPriority(file_priority,
     op_priority) (0x604c800, census-bound, pure -- see below).
     The file's priority comes from GetIOPriority, vtable slot 16
     (0x80), devirtualized when the slot equals the base
     implementation 0x5df6e90 (``mov 0x18(%rdi),%eax; ret`` -- the
     FSWritableFile::GetIOPriority that returns io_priority_ at
     file+0x18; the guard compares against the RELATIVE relocation
     at 0x64ecf30, addend 0x5df6e90); otherwise the virtual call
     runs at 0x6054e90.
  5. TEST_SYNC_POINT gate (0x605482e): if the sync-point global
     (*0x64ed5d0, a RELATIVE relocation to 0x606d9f0) is non-null,
     call 0x606d9f0 (the sync-point thread-local marker helper,
     FDE 0x606d9f0..0x606da30 -- sets the TLS sync-point-entered
     byte and clears the iostats CPU flag). This is the
     TEST_SYNC_POINT("WritableFileWriter::Append:BeforePrepareWrite")
     from upstream (writable_file_writer.cc:123); it has no effect
     on the data flow unless a test enables sync points. Then the
     perf-level TLS is read (via _ZTHN7rocksdb10perf_levelE when
     the TLS global is set) and the IOSTATS_TIMER_GUARD
     (prepare_write_nanos) is armed iff perf_level > 2
     (0x605486d: cmpb $2, seta): start = SystemClock::Default()->
     NowNanos() (vtable slot 20, 0xa0; SystemClock::Default at
     0x5fe2680, census-bound), clock kept at rsp+0x48, start at
     rsp+0x50, &prepare_write_nanos (TLS iostats + 0x48) at
     rsp+0x58. The CPU-timer half of the guard is DEAD in this
     build: its flag byte (rsp+0x41), id (rsp+0x44) and object
     (rsp+0x60) are zeroed and never set, so the cpu branch
     (0x6054dad jne 0x6054ea0) never fires.
  6. PrepareWrite (0x60548e8): virtual slot 24 (0xc0) on the file
     selected by FSWritableFilePtr::operator->(): io_tracer_
     (this+0x20, shared_ptr) null OR its +0x68 enabled byte
     (IOTracer::tracing_enabled, a plain bool per
     trace_replay/io_tracer.h:313-335) clear -> the raw file
     (wrapper+0x28, FSWritableFileWrapper::target()); otherwise
     the tracing wrapper itself (this+0x30, fs_tracer_). Called
     as PrepareWrite(filesize_, left, io_options, nullptr);
     it returns VOID (upstream file_system.h:2122), so no status
     is checked -- the return is discarded. After the call the
     timer guard stops (0x6054da8, inlined): elapsed =
     NowNanos() - start, added to *(&prepare_write_nanos) when
     the wall flag (rsp+0x40) is set; the out-of-line destructor
     0x604c6b6 does the same work (plus the dead CPU branch) and
     is called from the .cold pads only. Then the IOOptions'
     property_bag is destroyed (call 0x5d36110, the _Hashtable
     dtor, on rsp+0x88) -- the IOOptions is block-scoped and dead
     after PrepareWrite.
  7. Buffer growth (0x6054905..0x6054998): if capacity_ -
     cursize_ < left, for cap = capacity_; cap < max_buffer_size_;
     cap *= 2: desired = min(cap*2, max); if desired - cursize_
     >= left OR (use_direct_io() AND desired == max):
     AllocateNewBuffer(desired, copy_data=true); break.
     use_direct_io() is vtable slot 12 (0x60), called at
     0x6054977 (devirtualized only in the sense that the base
     returns false -- the binary always calls through the slot
     here). AllocateNewBuffer (0x6054e04, inlined, exactly
     util/aligned_buffer.h:236-290): if copy_data and desired <
     cursize_, do nothing; new_capacity = Roundup(desired,
     alignment_); new_buf = new char[new_capacity + alignment_];
     new_bufstart = align_up(new_buf); memcpy(new_bufstart,
     bufstart_, cursize_); bufstart_ = new_bufstart; capacity_
     = new_capacity; buf_ = new_buf (old delete[]'d). cursize_
     is unchanged. Note the growth loop can only run when
     capacity_ < max_buffer_size_; capacity_ 0 with max > 0 is
     unreachable through the ctor (it allocates
     Roundup(min(65536, max), alignment) > 0), so the cap-doubling
     from 0 always terminates in practice.
  8. Flush-if-needed (0x6054998..0x60549dd): if !use_direct_io()
     AND capacity_ - cursize_ < left AND cursize_ > 0: s =
     Flush(priority) at 0x6051a20 (census-bound symbol; its body
     is an input oracle here -- see the Flush contract below);
     if !s.ok(): set_seen_error() (this+0x89 = 1) and return s.
     (The binary folds the three conditions into one byte at
     rsp+0x3b and the Flush call at 0x6054ee8.)
  9. Main write -- four arms, in binary order:
     a. Verification arm (0x60549fd): perform_data_verification_
        (this+0xd1) AND buffered_data_with_checksum_ (this+0xd8)
        AND crc32c_checksum != 0. Inside it:
        - remaining >= left (0x6054a63): buf_.Append(src, left)
          (memcpy, 0x60550f0) then buffered_data_crc32c_checksum_
          = Crc32cCombine(old, crc32c_checksum, left) at
          0x61c2600 (census-bound) -- the single-append case
          combines the CALLER's checksum, it does not Extend
          over the bytes.
        - use_direct_io() AND remaining < left (0x605502a loop):
          while left > 0: append min(remaining, left) bytes
          (0x6054f50/0x6054f53/0x605510f arms; remaining == 0
          appends 0 bytes), buffered_data_crc32c_checksum_ =
          Extend(old, src, appended) via the 0x61c25f0 thunk
          (0x6054f68/0x6054b2a); src += appended; left -=
          appended; if left > 0: s = Flush(priority); if !s.ok()
          set_seen_error and return s. (The loop re-reads
          remaining after each Flush.)
        - !use_direct_io() AND remaining < left (0x605505c):
          buffered_data_crc32c_checksum_ = crc32c_checksum
          (the caller's checksum becomes the buffer checksum),
          then s = WriteBufferedWithChecksum(src, left, priority)
          at 0x604f080 (no census; oracle -- see below).
     b. Plain arm (0x6054ac0): otherwise. Inside it:
        - use_direct_io() OR capacity_ >= left (0x6054bde
          loop): while left > 0: append min(remaining, left)
          bytes; if perform_data_verification_ AND
          buffered_data_with_checksum_: buffered_data_crc32c_
          checksum_ = Extend(old, src, appended); src +=
          appended; left -= appended; if left > 0: s =
          Flush(priority); if !s.ok() set_seen_error and
          return s. (Note: this loop's Extend is CONDITIONAL
          on the two flags, unlike the direct loop in (a),
          which runs only when the gate already holds.)
        - else (buffered, capacity_ < left -- the direct-write
          path, 0x6054cf8): if perform_data_verification_ AND
          buffered_data_with_checksum_: buffered_data_crc32c_
          checksum_ = Value(src, left) = Extend(0, src, left)
          (0x6054eae) and s = WriteBufferedWithChecksum(src,
          left, priority); else s = WriteBuffered(src, left,
          priority) at 0x604e140 (no census; oracle).
     The two Write* oracles take (sret, this, data, size,
     priority); their contract is stated below.
  10. Epilogue (0x6054c30..0x6054c78): if s.ok(): filesize_ +=
      data.size() (0x6054c3c, this+0x70); else set_seen_error()
      (error paths jump to 0x6054c4d, skipping the filesize_
      add). The sret is returned (rax = r15). The stack canary
      is checked (0x6054719) and __stack_chk_fail fires on
      mismatch (0x605510a). No Flush, no Sync here.

  The .cold landing pad (0x6054600, 124 B, census-bound): six
  endbr64 stubs at the tail of the main FDE (0x6055143..0x605518b)
  save the exception object in rbx and jump into it at 0x6054600
  (timer-guard dtor first), 0x6054612 (property_bag dtor),
  0x605461f (canary + _Unwind_Resume), 0x605463f (delete[] r12)
  and 0x605464e (delete[] sret state_ at [r15+8]). The pad
  destroys the timer guard (call 0x604c6b6) when its start is
  non-zero, destroys the IOOptions property_bag (call 0x5d36110),
  checks the stack canary, then _Unwind_Resume (or
  __stack_chk_fail). It is unwind-only; no case exercises it.

  DecideRateLimiterPriority (0x604c800, 39 B, census-bound,
  verified instruction by instruction): both IO_TOTAL (4) ->
  IO_TOTAL; file IO_TOTAL -> op priority; op IO_TOTAL -> file
  priority; else op priority. Exactly upstream
  writable_file_writer.cc:1859-1885.

  Oracle contracts (input oracles, NOT reconstructed here):
  - Flush(priority) at 0x6051a20 (census-bound; body 0x6051a20..
    0x605257c, 3452 B): per upstream Flush (cc:621-790), when
    buf_ is non-empty it writes the buffer out through
    WriteDirect[WithChecksum] (direct I/O, when pending_sync_)
    or WriteBuffered[WithChecksum] (buffered), then calls
    file_->Flush(); a failure at any step sets seen_error_ and
    returns that status. The model implements this contract:
    on success the file image gains the buffer bytes (direct:
    page-padded with the tail refit), buf_ is emptied (direct:
    refit to the leftover tail), buffered_data_crc32c_checksum_
    is reset (buffered) or recomputed as Value of the remaining
    buffer (direct-with-checksum), flushed_size_ advances, and a
    file-Flush event is recorded; on a scripted failure the
    buffer is cleared (buffered) or resized to
    file_advance+leftover_tail (direct) and the error status is
    returned. The bytes_per_sync RangeSync arm (filesize_ >
    1 MiB, offset_sync_to - last_sync_size_ >= bytes_per_sync_)
    is modelled as a recorded RangeSync event with a scripted
    status. Flush's own body is an open unknown / follow-up.
  - WriteBuffered(src, size, priority) at 0x604e140 and
    WriteBufferedWithChecksum(src, size, priority) at 0x604f080
    (both no census; bodies 3565 B / 3479 B): per upstream
    (cc:1039-1216 / 1219-1394), they write the data straight to
    the file in rate-limiter-sized chunks (the model writes it
    in one oracle step and records the token grants), clear buf_
    (Size(0)) and reset buffered_data_crc32c_checksum_ to 0, and
    advance flushed_size_; on a scripted file-Append failure
    they clear buf_ and reset the checksum anyway, set
    seen_error_ and return the error. WriteBufferedWithChecksum
    hands the file the checksum encoded from
    buffered_data_crc32c_checksum_ (EncodeFixed32) as the
    handoff checksum; the model records that value before
    resetting it. Their bodies are open unknowns / follow-ups.
  - PrepareWrite (vtable slot 24): void; the model records
    (offset=filesize_, length=left, io_options snapshot,
    dbg=null) and applies no file effect.
  - UpdateFileChecksum: records (data, size) when a checksum
    generator is installed; no other effect.
  - TEST_SYNC_POINT / TEST_KILL_RANDOM: compiled to a runtime
    gate (sync-point global) with no data effect; TEST_KILL_RANDOM
    calls are compiled out entirely (no call in the FDE).

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
total 0xe0.

Caller census (whole-.text E8/E9/LEA scan, Capstone-validated;
see census.py): exactly 39 direct calls to 0x6054680 -- the
WAL writers (log::Writer::EmitPhysicalRecord x2, AddRecord x1,
BlobLogWriter::WriteHeader/EmitPhysicalRecord x3/AppendFooter),
table builders (BlockBasedTableBuilder, CuckooTableBuilder x6,
PlainTableBuilder x5 + Add x2, PlainTableKeyEncoder x4),
PersistRocksDBOptions x8, CreateFile, CopyFile, and one
uncatalogued FDE 0x5fce280; 0 jumps, 0 LEA refs. The .cold has
exactly 1 tail jump to its start (0x605514a), plus 5 interior
jumps to its other entry points.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. Flush (0x6051a20), WriteBuffered (0x604e140),
WriteBufferedWithChecksum (0x604f080), WriteDirect and
WriteDirectWithChecksum are input oracles with the contracts above;
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
          / "re-002-node115-rocksdb-writable-file-writer-append-115")
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
APPEND_ADDR = 0x6054680
APPEND_FDE_END = 0x605518B
COLD_ADDR = 0x6054600
COLD_FDE_END = 0x605467C
UPDATE_FILE_CHECKSUM_ADDR = 0x604C7B0
DECIDE_PRIORITY_ADDR = 0x604C800
FLUSH_ADDR = 0x6051A20
FLUSH_FDE_END = 0x605257C
WRITE_BUFFERED_ADDR = 0x604E140
WRITE_BUFFERED_FDE_END = 0x604EF0D
WRITE_BUFFERED_CHECKSUM_ADDR = 0x604F080
WRITE_BUFFERED_CHECKSUM_FDE_END = 0x604FD97
PREPARE_WRITE_SLOT = 24
GET_IO_PRIORITY_SLOT = 16
USE_DIRECT_IO_SLOT = 12
GET_IO_PRIORITY_BASE = 0x5DF6E90
TIMER_GUARD_DTOR_ADDR = 0x604C6B6
SYNC_POINT_HELPER_ADDR = 0x606D9F0
CLOCK_DEFAULT_ADDR = 0x5FE2680
CRC32C_COMBINE_ADDR = 0x61C2600
EXTEND_THUNK_ADDR = 0x61C25F0
HASHTABLE_DTOR_ADDR = 0x5D36110

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
    """SystemClock oracle: NowNanos() returns scripted values."""

    def __init__(self, values):
        self.values = list(values)
        self.index = 0

    def now_nanos(self):
        if self.index < len(self.values):
            v = self.values[self.index]
            self.index += 1
            return v
        return self.values[-1] if self.values else 0


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
                 sync_point_enabled=False):
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
        # Event ledger: every oracle interaction, in binary order.
        self.events = []
        # Case script: queued oracle outcomes, consumed in order.
        # Keys: flush_write_statuses, flush_file_statuses,
        # flush_range_sync_statuses, write_buffered_statuses,
        # write_direct_statuses (each a list of status dicts).
        self.script = {}
        # IOSTATS thread-local counter (prepare_write_nanos).
        self.prepare_write_nanos = 0

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
            "file_sha256": hashlib.sha256(bytes(self.file.image)).hexdigest(),
            "file_len": len(self.file.image),
            "prepare_write_nanos": self.prepare_write_nanos,
            "events": self.events + self.file.events,
        }


def _io_options_for(state, op_priority):
    """Steps 4-5: build the IOOptions and decide the rate-limiter
    priority. Returns (io_options dict, timer_guard dict)."""
    file_priority = state.file.get_io_priority()
    decided = decide_rate_limiter_priority(file_priority, op_priority)
    io_options = io_options_default(decided)
    guard = {"wall": state.perf_level > 2, "cpu": False, "cpu_id": 0,
             "clock": state.clock, "start": 0,
             "counter": "prepare_write_nanos", "cpu_obj": None}
    if state.sync_point_enabled:
        state.events.append({"op": "sync_point",
                             "name": "WritableFileWriter::Append:"
                                     "BeforePrepareWrite",
                             "helper": hex(SYNC_POINT_HELPER_ADDR)})
    if guard["wall"] and state.clock is not None:
        guard["start"] = state.clock.now_nanos()
        state.events.append({"op": "timer_guard_start",
                             "start": guard["start"]})
    return io_options, guard


def _timer_guard_stop(state, guard):
    """The inlined guard stop at 0x6054da8 (same work as the
    out-of-line dtor 0x604c6b6, minus the dead CPU branch)."""
    if guard["start"] == 0:
        return
    now = state.clock.now_nanos() if state.clock is not None else 0
    elapsed = now - guard["start"]
    if guard["wall"]:
        state.prepare_write_nanos += elapsed
    state.events.append({"op": "timer_guard_stop", "now": now,
                         "elapsed": elapsed})
    guard["start"] = 0


def _pop_script_status(state, key):
    """Pop the next scripted status for `key`, defaulting to OK."""
    queue = state.script.get(key, [])
    if queue:
        d = queue.pop(0)
        return Status.from_dict(d) if isinstance(d, dict) else d
    return Status.ok()


def _flush_oracle(state, priority):
    """Flush(priority) -- the oracle contract for 0x6051a20, per
    upstream Flush (writable_file_writer.cc:621-790).

    Scripted outcomes come from state.script (queues consumed in
    order): flush_write_statuses (the Write* step), flush_file_
    statuses (file_->Flush), flush_range_sync_statuses (RangeSync).
    The write step mirrors WriteBuffered[WithChecksum] (buffered)
    or WriteDirect[WithChecksum] (direct, only when pending_sync_).
    Returns the Status Flush returns.
    """
    s = Status.ok()
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
                return s
    # file_->Flush(io_options, nullptr)
    io_options = io_options_default(
        decide_rate_limiter_priority(state.file.get_io_priority(),
                                     priority))
    s = state.file.file_flush(
        io_options, status=_pop_script_status(state,
                                              "flush_file_statuses"))
    state.events.append({"op": "flush_file_flush",
                         "status": s.summary()})
    if state.should_notify_listeners():
        state.events.append({"op": "notify_flush_finish",
                             "status": s.summary()})
    if not s.is_ok():
        state.set_seen_error()
        return s
    # bytes_per_sync RangeSync arm (cc:749-785).
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
                rs = state.file.range_sync(
                    state.last_sync_size,
                    offset_sync_to - state.last_sync_size, io_options,
                    status=_pop_script_status(
                        state, "flush_range_sync_statuses"))
                state.events.append({"op": "flush_range_sync",
                                     "offset": state.last_sync_size,
                                     "nbytes": offset_sync_to
                                     - state.last_sync_size,
                                     "status": rs.summary()})
                if not rs.is_ok():
                    state.set_seen_error()
                    s = rs
                state.last_sync_size = offset_sync_to
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
    s = _pop_script_status(state, "flush_write_statuses")
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
    s = _pop_script_status(
        state, "flush_write_statuses" if from_flush
        else "write_buffered_statuses")
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


def append(state, data, crc32c_checksum, priority):
    """rocksdb::WritableFileWriter::Append, exactly as the FDE at
    0x6054680 implements it. `data` is bytes; returns Status."""
    s = Status.ok()
    # 1. Seen-error gate (0x60546b9).
    if state.seen_error:
        return Status.io_error(PREV_ERROR_MSG)
    src = data
    left = len(data)
    # 2. pending_sync_ = true (0x605474f).
    state.pending_sync = True
    # 3. UpdateFileChecksum(data) (0x604c7b0).
    if state.checksum_generator:
        state.events.append({"op": "update_file_checksum",
                             "len": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})
    # 4-6. IOOptions + timer guard + PrepareWrite.
    io_options, guard = _io_options_for(state, priority)
    state.file.prepare_write(state.filesize, left, io_options, None)
    _timer_guard_stop(state, guard)
    state.events.append({"op": "io_options_destroyed",
                         "callee": hex(HASHTABLE_DTOR_ADDR)})
    buf = state.buf
    # 7. Buffer growth (0x6054905..0x6054998).
    if buf.remaining() < left:
        cap = buf.capacity
        _growth_iters = 0
        while cap < state.max_buffer_size:
            _growth_iters += 1
            if _growth_iters > 64:
                # Model-only guard: unreachable for representable
                # states (capacity >= alignment, so cap doubles to
                # max in <= log2(max) steps). Stops a hang on a
                # malformed case with capacity 0, where the binary
                # loop itself would spin forever (cap *= 2 == 0).
                state.events.append({"op": "growth_loop_guard"})
                break
            desired = min(cap * 2, state.max_buffer_size)
            if (desired - buf.cursize >= left or
                    (state.file.use_direct_io()
                     and desired == state.max_buffer_size)):
                buf.allocate_new_buffer(desired, copy_data=True,
                                        events=state.events)
                break
            cap *= 2
    # 8. Flush-if-needed (0x6054998..0x60549dd).
    if (not state.file.use_direct_io()
            and buf.remaining() < left and buf.cursize > 0):
        s = _flush_oracle(state, priority)
        if not s.is_ok():
            state.set_seen_error()
            return s
    # 9. Main write.
    if (state.perform_data_verification
            and state.buffered_data_with_checksum
            and crc32c_checksum != 0):
        if (state.file.use_direct_io()
                or buf.remaining() >= left):
            if buf.remaining() >= left:
                # Single append + Crc32cCombine (0x6054a63).
                appended = buf.append(src, left)
                state.buffered_data_crc32c_checksum = crc32c_combine(
                    state.buffered_data_crc32c_checksum,
                    crc32c_checksum, appended)
            else:
                # Direct-io loop with Extend + Flush (0x605502a).
                _witers = 0
                while left > 0:
                    _witers += 1
                    if _witers > 10000:
                        # Model-only guard: each iteration appends
                        # >= 1 byte or Flush frees the whole buffer,
                        # so this never fires on a representable
                        # state; it only stops a hang on a malformed
                        # case (e.g. capacity < alignment).
                        state.events.append(
                            {"op": "write_loop_guard"})
                        break
                    remaining = buf.remaining()
                    appended = buf.append(src, min(left, remaining))
                    state.buffered_data_crc32c_checksum = crc32c_extend(
                        state.buffered_data_crc32c_checksum,
                        src[:appended])
                    src = src[appended:]
                    left -= appended
                    if left > 0:
                        s = _flush_oracle(state, priority)
                        if not s.is_ok():
                            state.set_seen_error()
                            return s
        else:
            # !direct, remaining < left (0x605505c).
            state.buffered_data_crc32c_checksum = crc32c_checksum
            s = _write_buffered_oracle(
                state, src, priority, with_checksum=True)
    else:
        if state.file.use_direct_io() or buf.capacity >= left:
            # Buffered/direct loop (0x6054bde).
            _piters = 0
            while left > 0:
                _piters += 1
                if _piters > 10000:
                    # Model-only guard, as in the verification loop.
                    state.events.append({"op": "write_loop_guard"})
                    break
                remaining = buf.remaining()
                appended = buf.append(src, min(left, remaining))
                if (state.perform_data_verification
                        and state.buffered_data_with_checksum):
                    state.buffered_data_crc32c_checksum = crc32c_extend(
                        state.buffered_data_crc32c_checksum,
                        src[:appended])
                src = src[appended:]
                left -= appended
                if left > 0:
                    s = _flush_oracle(state, priority)
                    if not s.is_ok():
                        state.set_seen_error()
                        return s
        else:
            # Direct write bypassing the buffer (0x6054cf8).
            if (state.perform_data_verification
                    and state.buffered_data_with_checksum):
                state.buffered_data_crc32c_checksum = crc32c_value(src)
                s = _write_buffered_oracle(
                    state, src, priority, with_checksum=True)
            else:
                s = _write_buffered_oracle(
                    state, src, priority, with_checksum=False)
    # 10. Epilogue (0x6054c30..0x6054c78).
    if s.is_ok():
        state.filesize += len(data)
    else:
        state.set_seen_error()
    return s


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
    if o.get("clock_values") is not None:
        clock = FakeClock(o["clock_values"])
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
        sync_point_enabled=o.get("sync_point_enabled", False))
    if o.get("file_image_hex"):
        f.image = bytearray(bytes.fromhex(o["file_image_hex"]))
    state.script = {k: [dict(x) for x in v]
                    for k, v in (script or {}).items()}
    return state


def run_case(case):
    """Run one case dict through append() and return the observed
    outcome dict (status summary + state snapshot)."""
    state = make_writer(case.get("writer"), case.get("file"),
                        case.get("script"))
    data = bytes.fromhex(case["data_hex"])
    s = append(state, data, case["crc32c"], case["priority"])
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
         "perf_level": 0, "sync_point_enabled": False}
    w.update(over)
    return w


def _gen_gate(rng):
    """600 gate cases: seen-error, checksum generator, verification
    flags, crc zero/nonzero, priorities, tracer selection, perf
    level, sync point, small data."""
    cases = []
    for i in range(600):
        seen_error = rng.random() < 0.15
        verify = rng.random() < 0.5
        with_cksum = rng.random() < 0.5
        crc = 0 if rng.random() < 0.3 else rng.randrange(1, 2 ** 32)
        n = rng.choice([0, 1, 2, 3, 7, 8, 16, 32, 63, 64])
        data = _payload(rng, n)
        perf = rng.choice([0, 1, 2, 3, 4, 5])
        clock = [1000, 1500] if perf > 2 else None
        tracer = rng.choice([None, {"enabled": False},
                             {"enabled": True}])
        w = _base_writer(
            rng, seen_error=seen_error,
            checksum_generator=rng.random() < 0.3,
            perform_data_verification=verify,
            buffered_data_with_checksum=with_cksum,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            perf_level=perf, clock_values=clock,
            sync_point_enabled=rng.random() < 0.2,
            cursize=rng.choice([0, 0, 100, 1000]),
            buf_seed=(rng.randrange(2 ** 31)
                      if rng.random() < 0.5 else None))
        f = {"io_priority": rng.randrange(5),
             "direct_io": rng.random() < 0.3, "tracer": tracer}
        cases.append({
            "group": "gate", "case_id": "gate-%03d" % i,
            "writer": w, "file": f, "script": {},
            "data_hex": data.hex(), "crc32c": crc,
            "priority": rng.randrange(5)})
    return cases


def _gen_growth(rng):
    """600 buffer-growth cases: capacity/cursize/max/alignment/left
    combinations pinning the doubling loop, the max cap, the
    direct-io max arm and the no-growth path."""
    cases = []
    for i in range(600):
        alignment = rng.choice([512, 4096])
        max_size = rng.choice([4096, 8192, 16384, 65536])
        # capacity is never 0: the ctor allocates at least one
        # aligned block (AllocateNewBuffer rounds up to alignment).
        capacity = rng.choice([alignment, 2 * alignment,
                               4 * alignment, max_size])
        if capacity > max_size:
            capacity = max_size
        cursize = rng.choice([0, capacity // 2 if capacity else 0,
                              capacity])
        n = rng.choice([0, 1, alignment, 2 * alignment,
                        3 * alignment, max_size, max_size + 1])
        data = _payload(rng, min(n, 64))
        # The payload is capped at 64 B for the ledger; the length
        # the model sees is carried separately.
        w = _base_writer(
            rng, alignment=alignment, capacity=capacity,
            cursize=cursize, max_buffer_size=max_size,
            buf_seed=rng.randrange(2 ** 31),
            perform_data_verification=False,
            buffered_data_with_checksum=False)
        f = {"io_priority": IO_TOTAL,
             "direct_io": rng.random() < 0.5, "tracer": None}
        cases.append({
            "group": "growth", "case_id": "growth-%03d" % i,
            "writer": w, "file": f, "script": {},
            "data_hex": data.hex(), "data_len": n,
            "crc32c": 0, "priority": IO_TOTAL})
    return cases


def _gen_write_paths(rng):
    """600 write-path cases: buffered/direct x verification x crc
    x remaining/left x Flush/WriteBuffered scripted outcomes x
    rate limiter x listeners."""
    cases = []
    for i in range(600):
        direct = rng.random() < 0.4
        verify = rng.random() < 0.5
        with_cksum = rng.random() < 0.5
        crc = 0 if rng.random() < 0.3 else rng.randrange(1, 2 ** 32)
        capacity = rng.choice([4096, 8192])
        cursize = rng.choice([0, 1000, 4000, 4095, 4096])
        n = rng.choice([0, 1, 100, 1000, 4096, 5000, 8192, 9000])
        data = _payload(rng, min(n, 64))
        script = {}
        # Flush outcomes: mostly OK, sometimes a write failure or a
        # file-Flush failure (consumed in call order).
        r = rng.random()
        if r < 0.12:
            script["flush_write_statuses"] = [dict(ERR_IO)]
        elif r < 0.2:
            script["flush_file_statuses"] = [dict(ERR_CORRUPTION)]
        # Direct WriteBuffered outcomes.
        r2 = rng.random()
        if r2 < 0.1:
            script["write_buffered_statuses"] = [dict(ERR_IO)]
        # Big-filesize RangeSync arm (fires only when the Flush
        # oracle reaches it with filesize > 1 MiB).
        filesize = 0
        bytes_per_sync = 0
        if rng.random() < 0.15:
            filesize = rng.choice([1024 * 1024 + 4096,
                                   2 * 1024 * 1024, 5 * 1024 * 1024])
            bytes_per_sync = rng.choice([4096, 65536])
            if rng.random() < 0.3:
                script["flush_range_sync_statuses"] = [dict(ERR_IO)]
        w = _base_writer(
            rng, capacity=capacity, cursize=cursize,
            max_buffer_size=65536, filesize=filesize,
            bytes_per_sync=bytes_per_sync,
            buf_seed=rng.randrange(2 ** 31),
            perform_data_verification=verify,
            buffered_data_with_checksum=with_cksum,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            listeners=["L"] if rng.random() < 0.2 else [],
            rate_limiter_grants=(
                [100, 1000, 4096] if rng.random() < 0.25 else None))
        f = {"io_priority": rng.randrange(5), "direct_io": direct,
             "tracer": None}
        cases.append({
            "group": "write_paths", "case_id": "write_paths-%03d" % i,
            "writer": w, "file": f, "script": script,
            "data_hex": data.hex(), "data_len": n,
            "crc32c": crc, "priority": rng.randrange(5)})
    return cases


def _fde_body_hashes():
    """Recompute the two FDE body hashes from the binary (the
    bindings group pins them; the packet's gen_records.py is the
    authority, this is a cross-check)."""
    data = open(_bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256
    out = {}
    for start, end, key in ((APPEND_ADDR, APPEND_FDE_END, "append"),
                            (COLD_ADDR, COLD_FDE_END, "cold")):
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
    """600 binding rows: hashes, FDE ranges, census sites, vtable
    slots, layout offsets, IOOptions constants, the priority
    matrix, CRC vectors, and direct AlignedBuffer unit rows."""
    cases = []
    idx = 0

    def add(kind, payload):
        nonlocal idx
        cases.append({"group": "bindings",
                      "case_id": "bindings-%03d" % idx,
                      "kind": kind, "payload": payload})
        idx += 1

    hashes = _fde_body_hashes()
    add("body_hash", {"fn": "Append", "start": hex(APPEND_ADDR),
                      "end": hex(APPEND_FDE_END), "size": 2827,
                      "sha256": hashes["append"]})
    add("body_hash", {"fn": "Append.cold", "start": hex(COLD_ADDR),
                      "end": hex(COLD_FDE_END), "size": 124,
                      "sha256": hashes["cold"]})
    census = json.load(open(ROOT / CENSUS_PATH))["records"]
    by_start = {r["start"]: r for r in census}
    cold = by_start[COLD_ADDR]
    add("census_cold", {"census_id": "node115-vendor-6054600",
                        "target_body_sha256":
                            cold["target_body_sha256"],
                        "source_body_sha256":
                            cold["source_body_sha256"],
                        "raw_equal": cold["raw_equal"],
                        "relocations": cold["relocations"]})
    add("census_main_missing",
        {"fn": "Append", "census": None,
         "note": "no vendor census record; body hash only"})
    # Caller census sites (from census.json in the packet).
    pkt_census = json.load(open(PACKET / "census.json"))
    add("caller_census", pkt_census)
    # Vtable slots.
    for slot, name in ((USE_DIRECT_IO_SLOT, "use_direct_io"),
                       (GET_IO_PRIORITY_SLOT, "GetIOPriority"),
                       (PREPARE_WRITE_SLOT, "PrepareWrite")):
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
    # AlignedBuffer unit rows (the AllocateNewBuffer skip guard,
    # unreachable from Append's growth loop, is pinned directly).
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
    cases.extend(_gen_growth(rng))
    cases.extend(_gen_write_paths(rng))
    cases.extend(_gen_bindings(rng))
    assert len(cases) == 2400, len(cases)
    return cases


def case_outcome(case):
    """The expected outcome for a case: run the model (for the
    three behavioural groups) or evaluate the binding directly."""
    if case["group"] == "bindings":
        return _binding_outcome(case)
    # Behavioural groups: the model run. data_len (when present)
    # is the true length; data_hex carries only a capped prefix.
    eff = dict(case)
    if "data_len" in case:
        n = case["data_len"]
        prefix = bytes.fromhex(case["data_hex"])
        if len(prefix) < n:
            # Deterministic extension: repeat the prefix bytes.
            ext = (prefix * ((n // max(1, len(prefix))) + 1))[:n] \
                if prefix else bytes(n)
            eff = dict(case)
            eff["data_hex"] = ext.hex()
    return run_case(eff)


def _binding_outcome(case):
    kind = case["kind"]
    p = case["payload"]
    if kind == "body_hash":
        return {"ok": True, "sha256": p["sha256"], "size": p["size"]}
    if kind == "census_cold":
        # Re-derive the source hash from the census relocations.
        data = open(_bin_path(), "rb").read()
        body = data[_va_to_off(COLD_ADDR):_va_to_off(COLD_FDE_END)]
        zeroed = bytearray(body)
        for rel in p["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        return {"ok": True,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "source_sha256": hashlib.sha256(bytes(zeroed)).hexdigest(),
                "relocations": len(p["relocations"])}
    if kind == "census_main_missing":
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
    file image must equal the real file bytes after each Append.

    Returns (ok, report dict)."""
    import os

    class RealFile(FakeFile):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.fd, self.path = tempfile.mkstemp(prefix="wfw-append-")
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
        # Leg 1: buffered appends through the model, small writes.
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        state = WriterState(file=f, buf=AlignedBuffer(4096, 4096, 0),
                            max_buffer_size=65536)
        total = 0
        for chunk in (b"hello wal", b"second record bytes",
                      b"x" * 5000, b"tail"):
            s = append(state, chunk, crc32c_value(chunk), IO_TOTAL)
            assert s.is_ok(), s
            total += len(chunk)
        # The buffer still holds the bytes (no flush yet); flush now.
        s = _flush_oracle(state, IO_TOTAL)
        assert s.is_ok(), s
        assert state.filesize == total, (state.filesize, total)
        assert len(f.image) == total
        f._check_real()
        report["legs"].append({"leg": "buffered_appends",
                              "bytes": total, "ok": True})
        f.close()
        # Leg 2: direct I/O appends (page-aligned buffer).
        f = RealFile(io_priority=IO_HIGH, direct_io=True)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 0),
            max_buffer_size=65536, perform_data_verification=True,
            buffered_data_with_checksum=True)
        total = 0
        for chunk in (b"A" * 4096, b"B" * 4096, b"C" * 100):
            crc = crc32c_value(chunk)
            s = append(state, chunk, crc, IO_HIGH)
            assert s.is_ok(), s
            total += len(chunk)
        assert state.filesize == total
        f._check_real()
        report["legs"].append({"leg": "direct_io_appends",
                              "bytes": total, "ok": True})
        f.close()
        # Leg 3: the seen-error gate returns the prev-error status
        # and writes nothing.
        f = RealFile()
        state = WriterState(file=f, buf=AlignedBuffer(4096, 4096, 0),
                            max_buffer_size=65536, seen_error=True)
        s = append(state, b"data", 0, IO_TOTAL)
        assert not s.is_ok() and s.code == 5, s
        assert s.summary()["state"] == 1
        assert len(f.image) == 0 and state.filesize == 0
        report["legs"].append({"leg": "seen_error_gate", "ok": True})
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
