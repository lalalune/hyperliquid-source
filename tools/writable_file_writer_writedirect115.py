#!/usr/bin/env python3
"""Node #115 RocksDB WritableFileWriter::WriteDirect: reconstruction.

RE-002 work item. Reconstructs the WAL/SST file writer's direct-I/O
write routine at 0x604fe80..0x6050b8a (3338 B) plus its landing pad
``WriteDirect.cold`` at 0x604fd98..0x604fe7b (227 B):

  rocksdb::WritableFileWriter::WriteDirect       0x604fe80 (3338 B)
  rocksdb::WritableFileWriter::WriteDirect.cold  0x604fd98 (227 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The main body has NO vendor census record (body hash only, per the
#5992 no-census convention); the .cold IS census-bound (body hash
matches target_body_sha256 exactly; source hash reproduced by
zeroing the recorded relocations -- see gen_records.py). Symbol
from the vendor census (member a895f7517936a0f7-writable_file_
writer.o, librocksdb-sys 0.11.0+8.1.1). This is the direct
follow-up to open PR #6057 (WritableFileWriter::Flush), which
calls it at 0x60520b9 (its direct-I/O write step, only when
pending_sync_ is set) and took it as an input oracle; open PR
#6041 (WritableFileWriter::Append) takes it as the direct-I/O
engine its write loop reaches through Flush. This packet
supersedes those oracle notes with the full body model.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus WriteDirect(Env::IOPriority priority)
  -- returns by value, so rdi is the hidden 16-byte sret
  out-pointer, rsi is the Writer*, rdx (edx) the priority. Steps,
  in binary order:

  1. Seen-error gate (0x604feb5): byte this+0x89 (seen_error_)
     read FIRST. If set, the routine returns at once
     (0x604fec6..0x604ff3c): sret = {code 5 (kIOError), 27-byte
     heap state_ "Writer has previous error."} -- exactly upstream
     IOStatus::IOError("Writer has previous error.") (the direct
     return at file/writable_file_writer.cc:1458, NOT
     AssertFalseAndGetStatusForPrevError -- the binary builds the
     same 27-byte state_ inline, movdqa from 0x451480/0x452bf0).
     The old sret state_ (when non-null) is delete[]'d first. No
     other member is touched: no file call, no buffer change.
     NOTE: unlike the siblings, the gate return here is INLINE
     in the main FDE; the .cold is unwind-only.
  2. Page pad (0x604ff40..0x604ff78, 0x6050a97): alignment =
     buf_.Alignment() (this+0x40), cursize = buf_.CurrentSize()
     (this+0x58); pad = Roundup(cursize, alignment) - cursize,
     computed by the div at 0x604ff65 (rcx = cursize + alignment
     - 1, divided by alignment, remainder subtracted). If pad !=
     0 (jne 0x6050a97): memset(bufstart_ + cursize_, 0, pad)
     and cursize_ += pad -- exactly AlignedBuffer::
     PadToAlignmentWith(0). file_advance =
     TruncateToPageBoundary(alignment, ENTRY cursize) and
     leftover_tail = ENTRY cursize - file_advance are computed
     LAZILY at the success epilogue (0x6050803..0x605081a) from
     the saved entry cursize_ (-0x218) and alignment (-0x220):
     file_advance = cursize & -alignment, leftover = cursize -
     file_advance.
  3. IOOptions + file priority (0x604ff7e..0x605007d): the
     file's GetIOPriority (vtable slot 16, devirtualized when
     the slot equals the RELATIVE reloc at 0x64ecf30, else the
     virtual call at 0x6050ac6) feeds DecideRateLimiterPriority
     (0x604c800, census-bound, pure) with the op priority; a
     0x58-byte IOOptions is built on the stack with the exact
     defaults (timeout 0, prio kIOLow 0, rate_limiter_priority
     the Decide result, type kUnknown 7, property_bag an empty
     unordered_map, force_dir_fsync 0, do_not_recurse 0).
     PINNED DIFFERENCE from WriteBuffered[WithChecksum]: there
     is NO file->GetFileSize call here, NO perf_level
     save/restore, and NO TEST_SYNC_POINT before the loop head
     -- the first sync-point gate is the loop-head gate (step 5).
     If the padded cursize (left) is 0, the loop is skipped
     (je 0x6050b06): the saved status bytes are zeroed and the
     success epilogue runs with file_advance = 0, leftover = 0.
     QUIRK (observed, recorded): on that entry-empty path the
     sret subcode byte is read from -0x1d2, which no instruction
     on that path writes -- a stale stack slot; the model emits
     0 (the deterministic value). The path is unreachable from
     Flush (which only calls WriteDirect with cursize_ > 0).
  4. Write loop (0x60500b0..0x60507fd), while left > 0, one
     iteration per rate-limiter grant:
     (a) size = left; when rate_limiter_ (this+0xa0) is non-null
     AND the decided priority != IO_TOTAL (4) (setne byte at
     -0x1d7, 0x605009f), size = rate_limiter_->RequestToken
     (left, buf_.Alignment() (this+0x40), decided priority,
     stats_ (this+0xa8), OpType kWrite = 1) through vtable slot
     6 (base impl 0x61c43f0); otherwise size = left (0x6050890).
     (b) TEST_SYNC_POINT gate (0x6050108, helper 0x606d9f0).
     The string name is not pinned from the binary (literals
     stripped); upstream v8.1.1 names the loop's TEST_SYNC_POINT
     "WritableFileWriter::Flush:BeforeAppend"; the model records
     the site address instead.
     (c) IOSTATS_TIMER_GUARD(write_nanos) setup
     (0x605011c..0x6050198, 0x60508a0): the nanos half is armed
     iff perf_level > 2 (clock = *SystemClock::Default(),
     0x5fe2680, dereferenced once; start = NowNanos, vtable
     slot 20; stop adds the elapsed time to the TLS counter at
     fs-0x3f8+0x28). PINNED DIFFERENCE from WriteBuffered
     [WithChecksum]: the CPU half is DEAD here -- the flag byte
     at -0x18f is written 0 at 0x605012c and never set, the
     second clock slot at -0x170 is never filled, and no
     clock-or-default helper is called in this FDE, so the
     slot-22 stop at 0x605071b is unreachable; the stop always
     takes the NowNanos branch (0x6050af8). The model records
     cpu_armed = False for every perf level.
     (d) Listener start times (0x60501b1): only when listeners_
     (this+0xb0) is non-empty, steady_clock::now() +
     system_clock::now(); write_offset (next_write_offset_)
     and src (bufstart_) are the per-iteration cursors.
     (e) Verification arm (0x60501ea): ONLY when
     perform_data_verification_ (this+0xd1) is set --
     buffered_data_with_checksum_ (this+0xd8) is NOT
     consulted (pinned difference from WriteDirectWithChecksum,
     which asserts both): checksum = crc32c::Extend(0, src,
     size) through the 19-byte helper 0x604c7e0, EncodeFixed32
     into checksum_buf, v_info.checksum = Slice(checksum_buf,
     4); file->PositionedAppend(Slice{src, size}, write_offset,
     io_options, v_info, nullptr) through vtable slot 5
     (0x6050976). Otherwise file->PositionedAppend(Slice{src,
     size}, write_offset, io_options, nullptr) through vtable
     slot 4 (0x605024f). Direct writes are positional -- the
     file offset is always write_offset, never the file's
     append position.
     (f) The result is written to a 16-byte stack IOStatus at
     -0x160(%rbp) and then copied (bytes 0-1, 3-4, 5, 8-15;
     byte 2 forced to 0 in every copy out). The code bytes
     spill at -0x1d1..-0x1d5 -- the high bytes of the low
     qword in reverse order, byte 2 never stored.
     (g) Listener events (0x60502d9..0x6050693), only when
     listeners_ is non-empty. Finish event (always):
     {FileOperationType type = 1 (kWrite), WritableFileWriter*
     this, bool [this+0xd9], uint64 offset = write_offset,
     uint64 length = size, uint64 elapsed_nanos, TimePoint*
     &start_times, Status status (CopyState deep copy at
     0x61cf610)} through vtable slot 34 (0x110), skipping the
     base no-op 0x604c660. Failure event (only when the
     PositionedAppend status is not OK): {Status status
     (CopyState deep copy), FileOperationType type = 9,
     std::string file_name_, uint64 size, uint64 write_offset}
     through vtable slot 47 (0x178), skipping the base no-op
     0x6042c20. The failure type 9 is
     FileOperationType::kPositionedAppend (v8.1.1
     include/rocksdb/listener.h:236-248, implicit 0-based:
     kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4,
     kSync 5, kFsync 6, kRangeSync 7, kAppend 8,
     kPositionedAppend 9, kOpen 10) -- exactly upstream
     NotifyOnIOError(s, kPositionedAppend, file_name(), size,
     write_offset).
     (h) Failure return (0x605046e..0x60506fb): buf_.Size
     (file_advance + leftover_tail) -- i.e. cursize_ restored
     to the ENTRY cursize_ (0x6050693..0x60506a5); seen_error_
     = 1 AFTER the notifications; the sret is built (byte 2
     forced to 0); the nanos guard stops at 0x6050704..0x6050759
     (after the sret build); the IOOptions property_bag is
     destroyed (0x5d36110); no retry; flushed_size_ is NOT
     advanced for the failed chunk (earlier chunks keep theirs).
     (i) Success tail (0x605077d..0x60507fd): the nanos guard
     stops at 0x60509a0 (elapsed -> the TLS counter at
     fs-0x3f8+0x28) when armed; TEST_SYNC_POINT (0x6050795);
     then -- when the TLS flag at fs-0x3f8+0x98 is clear -- a
     third TEST_SYNC_POINT (0x60507bd) and the TLS counter at
     fs-0x3f8+0x8 advances by the size (the flag's identity is
     an open unknown); src += size; write_offset += size;
     flushed_size_ (this+0x78) += size; left -= size; loop
     while left > 0.
  5. Success epilogue (0x6050803..0x6050878): file_advance and
     leftover_tail from the saved entry cursize_; when
     leftover_tail != 0, buf_.RefitTail(file_advance,
     leftover_tail) (memmove at 0x6050ad7: the tail bytes move
     to the buffer start, cursize_ = leftover_tail);
     next_write_offset_ += file_advance; cursize_ =
     leftover_tail; the sret copy (byte 0 forced to 0 -- the
     status is OK -- byte 2 forced to 0); the IOOptions
     property_bag destroyed (0x5d36110); the stack canary
     checked. filesize_ is NEVER advanced here (only
     flushed_size_ per chunk and next_write_offset_ at the
     end) -- the file's logical size is the caller's business.
  6. WriteDirect.cold (0x604fd98..0x604fe7b) is the unwind-only
     landing pad: destroy the file_name_ string copy, delete[]
     the saved state_ when non-null, stop the timer guard
     through the shared destructor 0x604c6b6, destroy the
     property_bag, stack check, _Unwind_Resume. It is reached
     by the eight endbr64 landing-pad stubs at the tail of the
     main FDE (0x6050b30..0x6050b85); one of them (0x6050b37)
     jumps directly to the .cold entry 0x604fd98, the other
     seven jump to interior .cold addresses.

Callers (whole-.text census, Capstone-validated; see census.json):
exactly 1 direct call -- Flush 0x6051a20 (site 0x60520b9, its
direct-I/O write step, only when pending_sync_ is set); 0 jumps,
0 LEA refs. The .cold has exactly 1 tail jump to its entry
(0x6050b37) plus 7 interior landing-pad jumps from the main FDE
tail. This routine never calls Flush, Pad, RangeSync,
WriteBuffered or WriteBufferedWithChecksum; the file's Flush/
RangeSync are not reached from here.

Flush (0x6051a20), WriteBuffered (0x604e140),
WriteBufferedWithChecksum (0x604f080), WriteDirectWithChecksum
(0x6050c80), RangeSync (0x604d7b0), UpdateFileChecksum
(0x604c7b0) and the file's Append/PositionedAppend/Flush/
RangeSync are input oracles with the contracts from open PRs
#6088 (WriteBuffered), #6094 (WriteBufferedWithChecksum),
#6057 (Flush) and #6041 (Append); their bodies are not
reconstructed here. The Flush oracle is implemented at the
same fidelity as #6057 for the live check's final flush.

Open unknowns (recorded, not hidden): the sret subcode byte on
the entry-empty path (stale stack slot -0x1d2, see step 3);
the TLS flag at fs-0x3f8+0x98 (bytes-add gate); the flag byte
at this+0xd9 (read into the finish event); the exact
TEST_SYNC_POINT string names (literals stripped from the
binary); why the CPU half of the timer guard is never armed
here while the siblings arm it iff perf_level > 3.

Writer layout (file/writable_file_writer.h), pinned by the
Append (#6041) and Flush (#6057) packets and re-confirmed
here: file_name_ +0x00, writable_file_ +0x20, clock_ +0x38,
buf_ AlignedBuffer +0x40 (alignment +0x40, ptr +0x48,
capacity +0x50, cursize +0x58, bufstart +0x60),
max_buffer_size_ +0x68, filesize_ +0x70, flushed_size_ +0x78,
next_write_offset_ +0x80, pending_sync_ +0x88, seen_error_
+0x89, last_sync_size_ +0x90, bytes_per_sync_ +0x98,
rate_limiter_ +0xa0, stats_ +0xa8, listeners_ +0xb0,
checksum_generator_ +0xc8, checksum_finalized_ +0xd0,
perform_data_verification_ +0xd1,
buffered_data_crc32c_checksum_ +0xd4,
buffered_data_with_checksum_ +0xd8, flag +0xd9 (unknown),
temperature_ +0xdc; total 0xe0. AlignedBuffer layout
(util/aligned_buffer.h): alignment_ +0x00, buf_ (unique_ptr)
+0x08, capacity_ +0x10, cursize_ +0x18, bufstart_ +0x20.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. make verify/test/catalogue-check in a tooled
environment is still owed upstream.
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
          / "re-002-node115-rocksdb-writable-file-writer-writedirect-115")
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
WRITE_BUFFERED_ADDR = 0x604E140
WRITE_BUFFERED_FDE_END = 0x604EF0D
COLD_ADDR = 0x604E01C
COLD_FDE_END = 0x604E139
# This packet's own target.
WD_ADDR = 0x604FE80
WD_FDE_END = 0x6050B8A
WD_COLD_ADDR = 0x604FD98
WD_COLD_FDE_END = 0x604FE7B
# Sibling oracle (WriteBufferedWithChecksum.cold, for the bindings).
WBC_COLD_ADDR = 0x604EF0E
WBC_COLD_FDE_END = 0x604F079
FLUSH_ADDR = 0x6051A20
FLUSH_FDE_END = 0x605257C
WRITE_BUFFERED_CHECKSUM_ADDR = 0x604F080
WRITE_BUFFERED_CHECKSUM_FDE_END = 0x604FD97
WRITE_DIRECT_ADDR = 0x604FE80
WRITE_DIRECT_FDE_END = 0x6050B8A
WRITE_DIRECT_CHECKSUM_ADDR = 0x6050C80
WRITE_DIRECT_CHECKSUM_FDE_END = 0x6051937
RANGE_SYNC_ADDR = 0x604D7B0
RANGE_SYNC_FDE_END = 0x604E01B
DECIDE_PRIORITY_ADDR = 0x604C800
UPDATE_FILE_CHECKSUM_ADDR = 0x604C7B0
APPEND_ADDR = 0x6054680
APPEND_FDE_END = 0x605518B
# File->Append / GetFileSize vtable slots (byte offsets) and base no-ops.
GET_IO_PRIORITY_SLOT = 16
FILE_APPEND_SLOT = 2
FILE_APPEND_CHECKSUM_SLOT = 3
FILE_GET_FILE_SIZE_SLOT = 18
FILE_POSITIONED_APPEND_SLOT = 4
FILE_POSITIONED_APPEND_CHECKSUM_SLOT = 5
# Shared helpers still used by the Flush/RangeSync oracles below.
SYNC_POINT_HELPER_ADDR = 0x606D9F0
HASHTABLE_DTOR_ADDR = 0x5D36110
EXTEND_THUNK_ADDR = 0x61C25F0
TIMER_GUARD_DTOR_ADDR = 0x604C6B6  # IOSTATS_TIMER_GUARD destructor
COPY_STATE_ADDR = 0x61CF610  # Status state_ deep copy (two-arg form)
# EventListener vtable slots (byte offsets) and base no-ops.
NOTIFY_WRITE_FINISH_SLOT = 0x110  # slot 34
NOTIFY_WRITE_FINISH_BASE = 0x604C660
NOTIFY_FLUSH_FINISH_SLOT = 0x118  # slot 35
NOTIFY_FLUSH_FINISH_BASE = 0x604C670
NOTIFY_RANGE_SYNC_FINISH_SLOT = 0x128  # slot 37
NOTIFY_RANGE_SYNC_FINISH_BASE = 0x604C690
NOTIFY_FAILURE_SLOT = 0x178  # slot 47
NOTIFY_FAILURE_BASE = 0x6042C20
# FileOperationType (listener.h v8.1.1:236-248, implicit 0-based):
# kWrite 1, kFlush 4, kRangeSync 7, kAppend 8. The failure event
# here carries 8 = kAppend (NotifyOnIOError(s, kAppend, ...) in
# WriteBuffered) -- the prior draft's "unnamed" unknown, resolved
# by the live v8.1.1 read this cycle (see README).
FILE_OP_WRITE = 1
FILE_OP_WRITE_FAILURE = 8
FILE_OP_FLUSH = 4
FILE_OP_RANGE_SYNC = 7
FILE_OP_POSITIONED_APPEND = 9
# WriteDirect's own call sites and helpers.
CRC_VALUE_HELPER_ADDR = 0x604C7E0  # Crc32cHandoffChecksumCalculation: Extend(0, data, size) -> *out
WD_SYNC_POINT_SITES = (0x6050108, 0x6050795, 0x60507BD)
WD_PAD_SITE = 0x6050A97  # PadToAlignmentWith(0) inline (memset)
WD_REFIT_SITE = 0x6050AD7  # RefitTail inline (memmove)
WD_GATE_ADDR = 0x604FEB5
WD_LOOP_HEAD_ADDR = 0x60500B0
REQUEST_TOKEN_ADDR = 0x61C43F0  # RateLimiter::RequestToken (base impl)
SYSTEM_CLOCK_DEFAULT_ADDR = 0x5FE2680  # SystemClock::Default()
PERF_LEVEL_GET_ADDR = 0x606DDD0  # GetPerfLevel (TLS byte)
PERF_LEVEL_SET_ADDR = 0x606DDB0  # SetPerfLevel (TLS byte)
RATE_LIMITER_OP_WRITE = 1  # RateLimiter::OpType::kWrite
GET_FILE_SIZE_TRACING_WRAPPER_ADDR = 0x600A770  # FSWritableFileTracingWrapper::GetFileSize

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
    the sret stores in this FDE (epilogue 0x605264f..0x6052666).
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
    size / contents (allocation addresses are not modelled).

    Unlike the Flush tool's copy, clear() here RETAINS the bytes:
    the binary's AlignedBuffer::Clear only resets cursize_, and
    Pad's verification arm reads buffer bytes past cursize_
    (buffer + entry cursize_, length size) after a mid-loop
    Flush -- the stale first-chunk zeros are part of the Extend
    input. The Flush tool's zeroing clear is equivalent there
    because nothing reads the stale bytes; here it would be
    wrong. data is always capacity bytes long."""

    def __init__(self, alignment, capacity=0, cursize=0, data=b""):
        assert alignment > 0 and (alignment & (alignment - 1)) == 0
        assert cursize <= capacity
        self.alignment = alignment
        self.capacity = capacity
        self.cursize = cursize
        self.data = bytearray(capacity)
        self.data[:cursize] = data[:cursize]

    def remaining(self):
        return self.capacity - self.cursize

    def allocate_new_buffer(self, requested_capacity, copy_data=False,
                            copy_offset=0, copy_len=0, events=None):
        """AllocateNewBuffer(desired, copy_data, copy_offset, copy_len).

        Inlined at 0x6054e04 in Append: if copy_data and requested <
        copy_len (copy_len defaults to cursize_) do nothing;
        new_capacity = Roundup(requested, alignment); new buffer,
        memcpy the old bytes, cursize_ unchanged when copying."""
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
            self.data[self.cursize:self.cursize + to_copy] = chunk
            self.cursize += to_copy
        return to_copy

    def write_zeros(self, n):
        """Pad's memset(bufstart_ + cursize_, 0, n); cursize_ += n."""
        assert 0 <= n <= self.remaining()
        if n > 0:
            self.data[self.cursize:self.cursize + n] = b"\x00" * n
            self.cursize += n
        return n

    def clear(self):
        # AlignedBuffer::Clear resets cursize_ ONLY; the bytes stay
        # (Pad's verification arm reads them after a Flush).
        self.cursize = 0

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
            self.data[self.cursize:total] = bytes([padding]) * pad
            self.cursize = total
        return pad


class FakeClock:
    """SystemClock oracle: supplies scripted (system, steady) time
    pairs. now_pair() is the listener start-time pair (Flush
    0x6051a71, RangeSync 0x604d87a); now_nanos() is the steady
    half, used by the IOSTATS_TIMER_GUARD (RangeSync only);
    cpu_nanos() is the CPU-time accessor (vtable slot 22), the
    guard's CPU half (WriteBuffered 0x604e477)."""

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

    def cpu_nanos(self):
        # Slot 22 (0xb0): the CPU-time accessor the timer guard's
        # CPU half stops with (destructor 0x604c6b6, guard byte +1).
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

    def get_file_size(self, io_options):
        """FSWritableFile::GetFileSize(io_options, nullptr)
        (vtable slot 18). WriteBuffered calls it once per chunk
        (0x604e3c5) and DISCARDS the return value -- the model
        records the call and returns the image length, matching
        the tracing wrapper's contract (0x600a770) without
        claiming the discarded value is used anywhere."""
        self.events.append({"op": "get_file_size",
                            "rate_limiter_priority":
                                io_options["rate_limiter_priority"]})
        return len(self.image)

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
    (0x6054769..0x60547f8 in Append), with rate_limiter_priority
    overwritten at +0x0c. Returned as a dict of the named fields
    plus the raw image bytes for the bindings."""
    image = bytearray(IOOPTIONS_SIZE)
    # timeout 0 (8 bytes @0)
    # prio kIOLow 0 @8; rate_limiter_priority @12 (int)
    struct.pack_into("<i", image, 12, rate_limiter_priority)
    # type kUnknown 7 @16
    image[16] = 7
    # property_bag @24: buckets ptr = self+0x30, bucket_count 1 @32,
    # rehash max_load 1.0f @40; the pointer value is stack-relative,
    # so the model records it symbolically as "self+0x30".
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
                 file_name="test.wal", iostats_bytes_flag=False):
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
        # Keys: append_statuses (each a list of status dicts).
        self.script = {}
        # IOSTATS thread-local counters (prepare_write_nanos is
        # unused by WriteBuffered; range_sync_nanos is the
        # RangeSync guard; the WriteBuffered guards are below).
        self.prepare_write_nanos = 0
        self.range_sync_nanos = 0
        # WriteBuffered run record (set by write_buffered()): the
        # per-chunk rate-limiter grants, how many file->Append /
        # GetFileSize / checksum calls ran, and the two
        # IOSTATS_TIMER_GUARD counters plus the IOStats bytes
        # counter the loop advances per successful chunk.
        self.wb_grants = []
        self.wb_append_calls = 0
        self.wb_get_file_size_calls = 0
        self.wb_checksum_calls = 0
        self.write_buffered_nanos = 0
        self.write_buffered_cpu_nanos = 0
        self.iostats_bytes_written = 0
        # WriteBufferedWithChecksum run record (set by
        # write_buffered_with_checksum()): the rate-limiter
        # drain grants, the single file->Append / GetFileSize
        # calls, and the two IOSTATS_TIMER_GUARD counters.
        self.wbc_grants = []
        # WriteDirect run record (set by write_direct()): the
        # per-iteration rate-limiter grants, the PositionedAppend
        # count, the nanos-guard counter (the CPU half is never
        # armed in this FDE, so wd_cpu_nanos stays 0), and the
        # pad / file_advance / leftover_tail of the run.
        self.wd_grants = []
        self.wd_positioned_appends = 0
        self.wd_nanos = 0
        self.wd_cpu_nanos = 0
        self.wd_pad = 0
        self.wd_file_advance = 0
        self.wd_leftover_tail = 0
        self.wbc_append_calls = 0
        self.wbc_get_file_size_calls = 0
        self.write_buffered_with_checksum_nanos = 0
        self.write_buffered_with_checksum_cpu_nanos = 0
        # TLS flag byte at fs-0x3f8+0x98 (identity open): when set,
        # the IOStats bytes add is skipped (0x604e767).
        self.iostats_bytes_flag = iostats_bytes_flag

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
            "wb_grants": self.wb_grants,
            "wb_append_calls": self.wb_append_calls,
            "wb_get_file_size_calls": self.wb_get_file_size_calls,
            "wb_checksum_calls": self.wb_checksum_calls,
            "write_buffered_nanos": self.write_buffered_nanos,
            "write_buffered_cpu_nanos": self.write_buffered_cpu_nanos,
            "iostats_bytes_written": self.iostats_bytes_written,
            "wbc_grants": self.wbc_grants,
            "wbc_append_calls": self.wbc_append_calls,
            "wbc_get_file_size_calls": self.wbc_get_file_size_calls,
            "write_buffered_with_checksum_nanos":
                self.write_buffered_with_checksum_nanos,
            "write_buffered_with_checksum_cpu_nanos":
                self.write_buffered_with_checksum_cpu_nanos,
            "wd_grants": self.wd_grants,
            "wd_positioned_appends": self.wd_positioned_appends,
            "wd_nanos": self.wd_nanos,
            "wd_cpu_nanos": self.wd_cpu_nanos,
            "wd_pad": self.wd_pad,
            "wd_file_advance": self.wd_file_advance,
            "wd_leftover_tail": self.wd_leftover_tail,
            "iostats_bytes_flag": self.iostats_bytes_flag,
            "events": self.events + self.file.events,
        }


def _pop_script_status(state, key):
    """Pop the next scripted status for `key`, defaulting to OK."""
    queue = state.script.get(key, [])
    if queue:
        d = queue.pop(0)
        return Status.from_dict(d) if isinstance(d, dict) else d
    return Status.ok()


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


def _notify_failure(state, op_type, status, extra=None):
    """The failure-only event (Flush, RangeSync, WriteBuffered):
    {status (CopyState deep copy), type, file_name_} through slot
    47 (0x178), skipping the base no-op 0x6042c20. `extra` holds
    the op-specific trailing fields -- WriteBuffered's failure
    event appends two uint64s (granted, then next_write_offset_)
    after the file_name_ (0x604eae8..0x604ebc3)."""
    event = {"op": "notify_failure", "type": op_type,
             "slot": hex(NOTIFY_FAILURE_SLOT),
             "base_noop": hex(NOTIFY_FAILURE_BASE),
             "file_name": state.file_name,
             "status": status.summary()}
    if extra:
        event.update(extra)
    for listener in state.listeners:
        state.events.append(dict(event, listener=listener))
    return event


def _write_buffered_io_options(state, priority):
    """WriteBuffered step 2: build the IOOptions for the chunk
    Appends. Same defaults as Append's/Flush's, but the file
    priority comes from the file selected by
    FSWritableFilePtr::operator->() (raw file vs tracing
    wrapper, recorded) and the rate-limiter priority is the
    DecideRateLimiterPriority result. Returns the io_options
    dict."""
    file_priority = state.file.get_io_priority()
    decided = decide_rate_limiter_priority(file_priority, priority)
    io_options = io_options_default(decided)
    state.events.append({"op": "io_options_built",
                         "rate_limiter_priority": decided,
                         "file": state.file.select_file(),
                         "callee": hex(DECIDE_PRIORITY_ADDR)})
    return io_options


def write_direct(state, priority):
    """rocksdb::WritableFileWriter::WriteDirect, the member at
    0x604fe80..0x6050b8a (3338 B). Page-pads the buffer, writes it
    positionally in rate-limiter-sized chunks, refits the tail.
    Returns the Status it returns. Contract from the whole-FDE
    disassembly (see the module docstring); the guard stops and
    the listener events follow the binary's order exactly,
    including the asymmetry that the nanos guard stops per
    iteration on the success path (0x60509a0, before the
    sync-point and the bytes add) and after the sret build on
    the failure path (0x6050704..0x6050759), while the CPU half
    is never armed at all (flag -0x18f stays 0).
    """
    buf = state.buf
    # 1. Seen-error gate (0x604feb5): byte this+0x89 read FIRST.
    if state.seen_error:
        return Status.io_error(PREV_ERROR_MSG)
    # 2. Page pad (0x604ff40..0x604ff78, 0x6050a97): pad =
    # Roundup(cursize, alignment) - cursize; memset zeros and
    # cursize_ += pad when pad != 0 (PadToAlignmentWith(0)).
    # file_advance / leftover_tail are computed lazily at the
    # success epilogue from the saved ENTRY cursize_.
    entry_cursize = buf.cursize
    alignment = buf.alignment
    pad = roundup(entry_cursize, alignment) - entry_cursize
    if pad:
        buf.write_zeros(pad)
        state.events.append({"op": "pad_to_alignment", "pad": pad,
                             "site": hex(WD_PAD_SITE)})
    file_advance = truncate_to_page(alignment, entry_cursize)
    leftover_tail = entry_cursize - file_advance
    state.wd_pad = pad
    state.wd_file_advance = file_advance
    state.wd_leftover_tail = leftover_tail
    # 3. IOOptions + file priority (0x604ff7e..0x605007d).
    # No GetFileSize call, no perf_level save/restore here.
    io_options = _write_buffered_io_options(state, priority)
    decided = io_options["rate_limiter_priority"]
    # The write loop works on the padded buffer.
    src = bytes(buf.data[:buf.cursize])
    write_offset = state.next_write_offset
    left = buf.cursize
    consumed = 0
    # Entry-empty path (0x605007d -> 0x6050b06): left == 0 skips
    # the loop; the saved status bytes are zeroed and the success
    # epilogue runs with file_advance = 0, leftover = 0. QUIRK:
    # the sret subcode byte is read from -0x1d2, which no
    # instruction on this path writes; the model emits 0.
    if left == 0:
        state.events.append({"op": "entry_empty_skip",
                             "site": hex(0x6050B06)})
        s = Status.ok()
        state.events.append({"op": "io_options_destroyed",
                             "callee": hex(HASHTABLE_DTOR_ADDR)})
        return s
    # 4. Write loop (0x60500b0..0x60507fd), while left > 0.
    guard = 0
    while left > 0:
        guard += 1
        if guard > 10000:
            raise ValueError("write_direct loop did not converge")
        # (a) size = left, or the rate-limiter grant.
        size = left
        if state.rate_limiter is not None and decided != IO_TOTAL:
            size = state.rate_limiter.request_token(
                left, alignment, decided, op="write")
            state.wd_grants.append(size)
            if size == 0:
                # The binary has no zero-grant exit (it would
                # spin); the model stops the loop instead of
                # hanging the case replay. No case scripts a
                # zero grant.
                break
        # (b) TEST_SYNC_POINT gate (0x6050108).
        if state.sync_point_enabled:
            state.events.append({"op": "sync_point",
                                 "site": hex(0x6050108),
                                 "helper": hex(SYNC_POINT_HELPER_ADDR)})
        # (c) IOSTATS_TIMER_GUARD(write_nanos) setup: the nanos
        # half is armed iff perf_level > 2 (clock =
        # *SystemClock::Default(), start = NowNanos slot 20).
        # The CPU half is DEAD in this FDE (flag -0x18f is never
        # set; no clock-or-default helper is called), so no CPU
        # start is ever recorded.
        nanos_armed = state.perf_level > 2
        nanos_start = None
        if nanos_armed and state.clock is not None:
            nanos_start = state.clock.now_nanos()
            state.events.append({"op": "timer_guard_start",
                                 "start": nanos_start,
                                 "counter": "write_direct_nanos"})
        # (d) Listener start times (0x60501b1): only when
        # listeners_ is non-empty.
        start_times = None
        if state.should_notify_listeners():
            start_times = (state.clock.now_pair()
                           if state.clock is not None else (0, 0))
            state.events.append({"op": "listener_start_times",
                                 "system": start_times[0],
                                 "steady": start_times[1]})
        # (e) Verification arm (0x60501ea): ONLY when
        # perform_data_verification_ is set; the checksum is a
        # fresh Extend(0, src, size) per chunk through the
        # 0x604c7e0 helper, handed to the file as
        # v_info.checksum = Slice(checksum_buf, 4) via vtable
        # slot 5. Otherwise the plain slot-4 PositionedAppend.
        chunk = src[consumed:consumed + size]
        if state.perform_data_verification:
            checksum = crc32c_value(chunk)
            slot = FILE_POSITIONED_APPEND_CHECKSUM_SLOT
        else:
            checksum = None
            slot = FILE_POSITIONED_APPEND_SLOT
        s = state.file.positioned_append(
            chunk, write_offset, io_options, checksum=checksum,
            status=_pop_script_status(
                state, "positioned_append_statuses"))
        state.wd_positioned_appends += 1
        state.events.append({
            "op": "positioned_append_call",
            "slot": slot,
            "verification": state.perform_data_verification,
            "offset": write_offset, "len": size,
            "checksum": checksum})
        # (f) The result is saved (bytes 0-1, 3-4, 5, 8-15;
        # byte 2 forced to 0 in every copy out).
        s.b2 = 0
        # (g) Listener events (0x60502d9..0x6050693): finish
        # always (type 1 = kWrite, slot 34), failure only when
        # the status is not OK (type 9 = kPositionedAppend,
        # slot 47, trailing u64s (size, write_offset)).
        if state.should_notify_listeners():
            _notify_finish(state, FILE_OP_WRITE,
                           NOTIFY_WRITE_FINISH_SLOT,
                           NOTIFY_WRITE_FINISH_BASE,
                           start_times, s,
                           offset=write_offset,
                           nbytes=size)
            if not s.is_ok():
                _notify_failure(state, FILE_OP_POSITIONED_APPEND, s,
                                extra={"size": size,
                                       "write_offset": write_offset})
        # (h) Failure return (0x605046e..0x60506fb): buf_.Size
        # (file_advance + leftover_tail) -- cursize_ restored
        # to the ENTRY cursize_; seen_error_ = 1 AFTER the
        # notifications; the nanos guard stops after the sret
        # build; no retry; flushed_size_ NOT advanced for the
        # failed chunk.
        if not s.is_ok():
            buf.size(file_advance + leftover_tail)
            state.set_seen_error()
            if nanos_start is not None:
                now = (state.clock.now_nanos()
                       if state.clock is not None else 0)
                elapsed = now - nanos_start
                if nanos_armed:
                    state.wd_nanos += elapsed
                state.events.append({"op": "timer_guard_stop",
                                     "now": now, "elapsed": elapsed,
                                     "counter": "write_direct_nanos"})
            state.events.append({"op": "io_options_destroyed",
                                 "callee": hex(HASHTABLE_DTOR_ADDR)})
            return s
        # (i) Success tail (0x605077d..0x60507fd): the nanos
        # guard stops at 0x60509a0 when armed; TEST_SYNC_POINT
        # (0x6050795); then -- when the TLS flag at fs-0x3f8+0x98
        # is clear -- a third TEST_SYNC_POINT (0x60507bd) and
        # the TLS counter at fs-0x3f8+0x8 advances by the size.
        if nanos_start is not None:
            now = (state.clock.now_nanos()
                   if state.clock is not None else 0)
            elapsed = now - nanos_start
            if nanos_armed:
                state.wd_nanos += elapsed
            state.events.append({"op": "timer_guard_stop",
                                 "now": now, "elapsed": elapsed,
                                 "counter": "write_direct_nanos"})
        if state.sync_point_enabled:
            state.events.append({"op": "sync_point",
                                 "site": hex(0x6050795),
                                 "helper": hex(SYNC_POINT_HELPER_ADDR)})
        if not state.iostats_bytes_flag:
            if state.sync_point_enabled:
                state.events.append({"op": "sync_point",
                                     "site": hex(0x60507BD),
                                     "helper": hex(SYNC_POINT_HELPER_ADDR)})
            state.iostats_bytes_written += size
        consumed += size
        write_offset += size
        state.flushed_size += size
        left -= size
    # 5. Success epilogue (0x6050803..0x6050878): when
    # leftover_tail != 0, buf_.RefitTail(file_advance,
    # leftover_tail) (memmove); next_write_offset_ +=
    # file_advance; cursize_ = leftover_tail; the sret copy
    # (byte 0 forced to 0 -- the status is OK -- byte 2
    # forced to 0); the IOOptions property_bag destroyed.
    # filesize_ is NEVER advanced here.
    if leftover_tail:
        buf.refit_tail(file_advance, leftover_tail)
        state.events.append({"op": "refit_tail",
                             "offset": file_advance,
                             "size": leftover_tail,
                             "site": hex(WD_REFIT_SITE)})
    else:
        buf.size(0)
    state.next_write_offset += file_advance
    s = Status.ok()
    state.events.append({"op": "io_options_destroyed",
                         "callee": hex(HASHTABLE_DTOR_ADDR)})
    return s


def _range_sync_member(state, offset, nbytes):
    """rocksdb::WritableFileWriter::RangeSync, the member at
    0x604d7b0..0x604e01b (2155 B, no census record). Called by
    the Flush oracle's RangeSync arm. Returns the Status it
    returns. Contract from open PR #6057 (Flush)."""
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


def _write_buffered_oracle(state, data, priority,
                           with_checksum, from_flush=False):
    """WriteBuffered[WithChecksum] contract (cc:1039-1216 /
    1219-1394), as used by the Flush oracle: write the data
    straight to the file, clear buf_, reset the buffer checksum,
    advance flushed_size_. The rate-limiter loop is collapsed
    into one oracle step with the grants recorded. `data` is the
    bytes to write (the buffer contents when called from Flush,
    the caller data otherwise). Contract from #6057."""
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


def _write_direct_oracle(state, priority, with_checksum):
    """WriteDirect[WithChecksum] contract (cc:1449-1642 /
    1645-1857), as used by the Flush oracle: page-pad the buffer,
    write it positionally, refit the tail. The rate-limiter loop
    is collapsed into one oracle step; token grants are recorded.
    Contract from #6057."""
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


def _flush_oracle(state, priority):
    """rocksdb::WritableFileWriter::Flush, the oracle Pad calls
    at 0x605269a -- the contract of open PR #6057, implemented
    at the same fidelity. `priority` is Env::IOPriority.
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
        file_name=o.get("file_name", "test.wal"),
        iostats_bytes_flag=o.get("iostats_bytes_flag", False))
    if o.get("file_image_hex"):
        f.image = bytearray(bytes.fromhex(o["file_image_hex"]))
    state.script = {k: [dict(x) for x in v]
                    for k, v in (script or {}).items()}
    return state


def run_case(case):
    """Run one case dict through write_direct() and return the
    observed outcome dict (status summary + state snapshot).
    The buffer comes from the writer (buf_seed + cursize); the
    routine takes no data/size arguments -- only the priority.
    """
    state = make_writer(case.get("writer"), case.get("file"),
                        case.get("script"))
    s = write_direct(state, case["priority"])
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


def _clock_pairs(n=64):
    """Scripted (system, steady) clock pairs. A chunk reads up to
    seven steady values (nanos start, listener pair, CPU start,
    CPU stop, finish-event steady, nanos stop) plus one system
    value; 64 pairs cover ~9 full chunks, after which the clock
    repeats its last pair (elapsed 0) -- deterministic."""
    return [(1000000 + 1000 * j, 500000 + 700 * j) for j in range(n)]


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
         "flag_d9": False, "file_name": "test.wal",
         "iostats_bytes_flag": False}
    w.update(over)
    return w


def _aligned_cursize(rng, alignment, capacity):
    """A cursize whose page-pad fits the capacity: roundup(cursize,
    alignment) <= capacity (PadToAlignmentWith asserts it)."""
    cands = [0, 1, 100, alignment - 1, alignment, alignment + 1,
             2 * alignment - 1, 2 * alignment,
             capacity - 1 if capacity > 1 else 0, capacity]
    ok = [c for c in cands
          if 0 <= c <= capacity
          and roundup(c, alignment) <= capacity]
    return rng.choice(ok)


def _gen_gate(rng):
    """600 gate cases: seen-error, entry cursize/capacity/
    alignment, verification on/off (the checksum arm depends
    ONLY on perform_data_verification_ -- buffered_data_with_
    checksum_ is not consulted), priorities, tracer selection,
    perf level, sync point, clock pairs, flag_d9, file names,
    scripted PositionedAppend failures, iostats flag. NOTE:
    unlike WriteBufferedWithChecksum there is NO data/size
    argument -- the buffer IS the input; a zero cursize skips
    the loop (0x6050b06) and returns OK with no file write."""
    cases = []
    for i in range(600):
        seen_error = rng.random() < 0.15
        verify = rng.random() < 0.5
        perf = rng.choice([0, 1, 2, 3, 4, 5])
        clock = (_clock_pairs() if perf > 2 or rng.random() < 0.5
                 else None)
        tracer = rng.choice([None, {"enabled": False},
                             {"enabled": True}])
        alignment = rng.choice([512, 4096])
        capacity = rng.choice([512, 1024, 4096, 8192, 65536])
        if capacity < alignment:
            capacity = alignment
        cursize = _aligned_cursize(rng, alignment, capacity)
        script = {}
        if rng.random() < 0.12:
            script["positioned_append_statuses"] = [dict(ERR_IO)]
        w = _base_writer(
            rng, seen_error=seen_error,
            perform_data_verification=verify,
            buffered_data_with_checksum=rng.random() < 0.5,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            perf_level=perf, clock_pairs=clock,
            sync_point_enabled=rng.random() < 0.2,
            flag_d9=rng.random() < 0.5,
            file_name=rng.choice(["test.wal", "000123.sst",
                                  "MANIFEST-000001", "OPTIONS-000002"]),
            alignment=alignment,
            capacity=capacity, cursize=cursize,
            buf_seed=(rng.randrange(2 ** 31)
                      if rng.random() < 0.7 else None),
            pending_sync=rng.random() < 0.5,
            iostats_bytes_flag=rng.random() < 0.2,
            listeners=(["L1", "L2"] if rng.random() < 0.3 else
                       (["L1"] if rng.random() < 0.3 else [])),
            next_write_offset=rng.choice([0, 512, 4096, 100000]),
            flushed_size=rng.choice([0, 100, 4096]))
        f = {"io_priority": rng.randrange(5),
             "direct_io": True, "tracer": tracer}
        if rng.random() < 0.2:
            w["file_image_hex"] = _payload(
                rng, rng.randrange(0, 500)).hex()
        cases.append({
            "group": "gate", "case_id": "gate-%03d" % i,
            "writer": w, "file": f, "script": script,
            "priority": rng.randrange(5)})
    return cases


def _gen_write_loop(rng):
    """600 write-loop cases: the per-iteration grant matrix --
    padded size vs the scripted rate-limiter grants (single
    grant, exact split, tiny grants, grant exhaustion). Each
    grant is one PositionedAppend at the advancing write
    offset; the grants change the chunking, never the total
    bytes. A scripted failure on iteration 1/2/3 restores
    cursize_ to the ENTRY cursize_, sets seen_error_ after the
    notifications, and keeps flushed_size_ from the earlier
    chunks; listeners + guards armed, iostats flag, file image
    pre-filled (positional writes at offsets)."""
    cases = []
    for i in range(600):
        grants = rng.choice([
            None, [1], [7], [100], [1000], [4096],
            [100, 1000, 4096], [4096, 4096, 4096],
            [1, 1, 1, 1, 1], [500, 500], [3, 2, 1],
            [10000], [4096, 100], [512, 512, 512, 512]])
        alignment = rng.choice([512, 4096])
        capacity = rng.choice([4096, 8192, 65536])
        if capacity < alignment:
            capacity = alignment
        cursize = _aligned_cursize(rng, alignment, capacity)
        perf = rng.choice([0, 2, 3, 4, 5])
        script = {}
        # A scripted failure hits one PositionedAppend: the
        # failure iteration index is chosen by the number of
        # scripted OK statuses queued before the error.
        fail_at = rng.random()
        if fail_at < 0.10:
            script["positioned_append_statuses"] = [dict(ERR_IO)]
        elif fail_at < 0.16:
            script["positioned_append_statuses"] = [
                {"code": 0, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
                 "b5": 0, "b67": 0, "state": 0}, dict(ERR_IO)]
        elif fail_at < 0.20:
            script["positioned_append_statuses"] = [
                {"code": 0, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
                 "b5": 0, "b67": 0, "state": 0},
                {"code": 0, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
                 "b5": 0, "b67": 0, "state": 0},
                dict(ERR_CORRUPTION)]
        w = _base_writer(
            rng, alignment=alignment,
            capacity=capacity, cursize=cursize,
            buf_seed=rng.randrange(2 ** 31),
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            perf_level=perf,
            clock_pairs=_clock_pairs(),
            listeners=(["L1", "L2"] if rng.random() < 0.3 else
                       (["L1"] if rng.random() < 0.3 else [])),
            flag_d9=rng.random() < 0.5,
            sync_point_enabled=rng.random() < 0.2,
            iostats_bytes_flag=rng.random() < 0.2,
            rate_limiter_grants=grants,
            next_write_offset=rng.choice([0, 4096, 100000]),
            flushed_size=rng.choice([0, 4096]),
            perform_data_verification=rng.random() < 0.4)
        f = {"io_priority": rng.randrange(5),
             "direct_io": True,
             "tracer": rng.choice([None, {"enabled": True}])}
        if rng.random() < 0.2:
            w["file_image_hex"] = _payload(
                rng, rng.randrange(0, 500)).hex()
        cases.append({
            "group": "write_loop", "case_id": "write_loop-%03d" % i,
            "writer": w, "file": f, "script": script,
            "priority": rng.randrange(5)})
    return cases


def _gen_verification(rng):
    """600 verification cases: perform_data_verification_ on/off
    x buffered_data_with_checksum_ on/off -- the checksum arm
    depends ONLY on perform_data_verification_ (0x60501ea);
    when on, each PositionedAppend carries Extend(0, chunk,
    size) for THAT chunk (the 0x604c7e0 helper), pinned in the
    positioned_append events; when off, the slot-4 arm carries
    no checksum. Refit-tail rows (leftover_tail > 0 vs == 0),
    file_advance rows, and failures on the verification arm."""
    cases = []
    for i in range(600):
        verify = rng.random() < 0.7
        alignment = rng.choice([512, 4096])
        capacity = rng.choice([4096, 8192, 65536])
        cursize = _aligned_cursize(rng, alignment, capacity)
        grants = rng.choice([None, [100], [1000, 1000], [4096],
                             [7, 7, 7], [500, 500, 500], [512]])
        script = {}
        if rng.random() < 0.12:
            script["positioned_append_statuses"] = [dict(ERR_IO)]
        w = _base_writer(
            rng, alignment=alignment,
            capacity=capacity, cursize=cursize,
            buf_seed=rng.randrange(2 ** 31),
            perform_data_verification=verify,
            buffered_data_with_checksum=rng.random() < 0.5,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            listeners=(["L1"] if rng.random() < 0.3 else []),
            clock_pairs=_clock_pairs(),
            flag_d9=rng.random() < 0.5,
            perf_level=rng.choice([0, 3, 4]),
            rate_limiter_grants=grants,
            sync_point_enabled=rng.random() < 0.2,
            iostats_bytes_flag=rng.random() < 0.2,
            next_write_offset=rng.choice([0, 4096]))
        f = {"io_priority": rng.randrange(5),
             "direct_io": True, "tracer": None}
        cases.append({
            "group": "verification", "case_id": "verification-%03d" % i,
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
    for start, end, key in ((WD_ADDR, WD_FDE_END, "write_direct"),
                            (WD_COLD_ADDR, WD_COLD_FDE_END,
                             "write_direct_cold"),
                            (WRITE_BUFFERED_ADDR,
                             WRITE_BUFFERED_FDE_END, "write_buffered"),
                            (COLD_ADDR, COLD_FDE_END, "cold"),
                            (FLUSH_ADDR, FLUSH_FDE_END, "flush"),
                            (WRITE_BUFFERED_CHECKSUM_ADDR,
                             WRITE_BUFFERED_CHECKSUM_FDE_END,
                             "write_buffered_checksum"),
                            (WBC_COLD_ADDR, WBC_COLD_FDE_END,
                             "write_buffered_with_checksum_cold"),
                            (WRITE_DIRECT_ADDR, WRITE_DIRECT_FDE_END,
                             "write_direct"),
                            (WRITE_DIRECT_CHECKSUM_ADDR,
                             WRITE_DIRECT_CHECKSUM_FDE_END,
                             "write_direct_checksum"),
                            (RANGE_SYNC_ADDR, RANGE_SYNC_FDE_END,
                             "range_sync"),
                            (APPEND_ADDR, APPEND_FDE_END, "append"),
                            (DECIDE_PRIORITY_ADDR,
                             DECIDE_PRIORITY_ADDR + 39,
                             "decide_priority"),
                            (UPDATE_FILE_CHECKSUM_ADDR,
                             UPDATE_FILE_CHECKSUM_ADDR + 33,
                             "update_file_checksum"),
                            (CRC_VALUE_HELPER_ADDR,
                             CRC_VALUE_HELPER_ADDR + 19,
                             "crc_value_helper"),
                            (TIMER_GUARD_DTOR_ADDR,
                             TIMER_GUARD_DTOR_ADDR + 82,
                             "timer_guard_dtor")):
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
    values, the WriteBuffered call-site constants, the timer-guard
    thresholds, and direct AlignedBuffer unit rows."""
    cases = []
    idx = 0

    def add(kind, payload):
        nonlocal idx
        cases.append({"group": "bindings",
                      "case_id": "bindings-%03d" % idx,
                      "kind": kind, "payload": payload})
        idx += 1

    hashes = _fde_body_hashes()
    add("body_hash", {"fn": "WriteDirect",
                      "start": hex(WD_ADDR),
                      "end": hex(WD_FDE_END), "size": 3338,
                      "sha256": hashes["write_direct"]})
    add("body_hash", {"fn": "WriteDirect.cold",
                      "start": hex(WD_COLD_ADDR),
                      "end": hex(WD_COLD_FDE_END), "size": 227,
                      "sha256": hashes["write_direct_cold"]})
    add("body_hash", {"fn": "WriteBufferedWithChecksum",
                      "start": hex(WRITE_BUFFERED_CHECKSUM_ADDR),
                      "end": hex(WRITE_BUFFERED_CHECKSUM_FDE_END),
                      "size": 3351,
                      "sha256": hashes["write_buffered_checksum"]})
    add("body_hash", {"fn": "WriteBufferedWithChecksum.cold",
                      "start": hex(WBC_COLD_ADDR),
                      "end": hex(WBC_COLD_FDE_END), "size": 363,
                      "sha256": hashes["write_buffered_with_checksum_cold"]})
    add("body_hash", {"fn": "WriteBuffered",
                      "start": hex(WRITE_BUFFERED_ADDR),
                      "end": hex(WRITE_BUFFERED_FDE_END), "size": 3533,
                      "sha256": hashes["write_buffered"]})
    add("body_hash", {"fn": "WriteBuffered.cold",
                      "start": hex(COLD_ADDR),
                      "end": hex(COLD_FDE_END), "size": 285,
                      "sha256": hashes["cold"]})
    add("body_hash", {"fn": "Flush", "start": hex(FLUSH_ADDR),
                      "end": hex(FLUSH_FDE_END), "size": 2908,
                      "sha256": hashes["flush"]})
    add("body_hash", {"fn": "WriteDirect",
                      "start": hex(WRITE_DIRECT_ADDR),
                      "end": hex(WRITE_DIRECT_FDE_END), "size": 3338,
                      "sha256": hashes["write_direct"]})
    add("body_hash", {"fn": "WriteDirectWithChecksum",
                      "start": hex(WRITE_DIRECT_CHECKSUM_ADDR),
                      "end": hex(WRITE_DIRECT_CHECKSUM_FDE_END),
                      "size": 3255,
                      "sha256": hashes["write_direct_checksum"]})
    add("body_hash", {"fn": "RangeSync",
                      "start": hex(RANGE_SYNC_ADDR),
                      "end": hex(RANGE_SYNC_FDE_END), "size": 2155,
                      "sha256": hashes["range_sync"]})
    add("body_hash", {"fn": "Append",
                      "start": hex(APPEND_ADDR),
                      "end": hex(APPEND_FDE_END), "size": 2827,
                      "sha256": hashes["append"]})
    add("body_hash", {"fn": "DecideRateLimiterPriority",
                      "start": hex(DECIDE_PRIORITY_ADDR),
                      "end": hex(DECIDE_PRIORITY_ADDR + 39),
                      "size": 39,
                      "sha256": hashes["decide_priority"]})
    add("body_hash", {"fn": "UpdateFileChecksum",
                      "start": hex(UPDATE_FILE_CHECKSUM_ADDR),
                      "end": hex(UPDATE_FILE_CHECKSUM_ADDR + 33),
                      "size": 33,
                      "sha256": hashes["update_file_checksum"]})
    add("body_hash", {"fn": "crc_value_helper",
                      "start": hex(CRC_VALUE_HELPER_ADDR),
                      "end": hex(CRC_VALUE_HELPER_ADDR + 19),
                      "size": 19,
                      "sha256": hashes["crc_value_helper"]})
    add("body_hash", {"fn": "timer_guard_dtor",
                      "start": hex(TIMER_GUARD_DTOR_ADDR),
                      "end": hex(TIMER_GUARD_DTOR_ADDR + 82),
                      "size": 82,
                      "sha256": hashes["timer_guard_dtor"]})
    census = json.load(open(ROOT / CENSUS_PATH))["records"]
    by_start = {r["start"]: r for r in census}
    for addr, fn in ((WD_COLD_ADDR, "WriteDirect.cold"),
                     (WBC_COLD_ADDR,
                      "WriteBufferedWithChecksum.cold"),
                     (DECIDE_PRIORITY_ADDR,
                      "DecideRateLimiterPriority"),
                     (COPY_STATE_ADDR, "Status::CopyState (two-arg)"),
                     (REQUEST_TOKEN_ADDR,
                      "RateLimiter::RequestToken (base)"),
                     (SYSTEM_CLOCK_DEFAULT_ADDR,
                      "SystemClock::Default"),
                     (GET_FILE_SIZE_TRACING_WRAPPER_ADDR,
                      "FSWritableFileTracingWrapper::GetFileSize"),
                     (UPDATE_FILE_CHECKSUM_ADDR,
                      "UpdateFileChecksum")):
        rec = by_start[addr]
        add("census_fn", {"fn": fn, "start": hex(addr),
                          "target_body_sha256":
                              rec["target_body_sha256"],
                          "source_body_sha256":
                              rec["source_body_sha256"],
                          "raw_equal": rec["raw_equal"],
                          "relocations": rec["relocations"]})
    # Caller census sites (from census.json in the packet).
    pkt_census = json.load(open(PACKET / "census.json"))
    add("caller_census", pkt_census)
    # Vtable slots.
    for slot, name in ((GET_IO_PRIORITY_SLOT, "GetIOPriority"),
                       (FILE_APPEND_SLOT,
                        "FSWritableFile::Append"),
                       (FILE_APPEND_CHECKSUM_SLOT,
                        "FSWritableFile::Append (with checksum)"),
                       (FILE_GET_FILE_SIZE_SLOT,
                        "FSWritableFile::GetFileSize"),
                       (FILE_POSITIONED_APPEND_SLOT,
                        "FSWritableFile::PositionedAppend"),
                       (FILE_POSITIONED_APPEND_CHECKSUM_SLOT,
                        "FSWritableFile::PositionedAppend (with checksum)"),
                       (NOTIFY_WRITE_FINISH_SLOT // 8,
                        "EventListener::OnFileWriteFinish"),
                       (NOTIFY_FLUSH_FINISH_SLOT // 8,
                        "EventListener::OnFileFlushFinish"),
                       (NOTIFY_RANGE_SYNC_FINISH_SLOT // 8,
                        "EventListener::OnFileRangeSyncFinish"),
                       (NOTIFY_FAILURE_SLOT // 8,
                        "EventListener::OnFile* failure")):
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
    # FileOperationType values. The failure type 9 is
    # FileOperationType::kPositionedAppend (v8.1.1
    # listener.h:236-248).
    add("file_op_type", {"name": "kWrite", "value": FILE_OP_WRITE})
    add("file_op_type", {"name": "kAppend", "value": FILE_OP_WRITE_FAILURE})
    add("file_op_type", {"name": "kPositionedAppend",
                         "value": FILE_OP_POSITIONED_APPEND})
    add("file_op_type", {"name": "kFlush", "value": FILE_OP_FLUSH})
    add("file_op_type", {"name": "kRangeSync",
                         "value": FILE_OP_RANGE_SYNC})
    # WriteDirect call-site constants. The three sync-point
    # sites are the loop-head gate (0x6050108), the success-tail
    # gate (0x6050795) and the bytes-add gate (0x60507bd). The
    # pad is inlined at 0x6050a97 (memset) and the refit at
    # 0x6050ad7 (memmove); the checksum arm is the per-chunk
    # Extend(0, src, size) through the 0x604c7e0 helper, gated
    # ONLY on perform_data_verification_; the CPU half of the
    # timer guard is never armed in this FDE.
    add("write_direct_constants",
        {"crc_value_helper": hex(CRC_VALUE_HELPER_ADDR),
         "request_token_base": hex(REQUEST_TOKEN_ADDR),
         "system_clock_default": hex(SYSTEM_CLOCK_DEFAULT_ADDR),
         "sync_point_helper": hex(SYNC_POINT_HELPER_ADDR),
         "sync_point_sites": [hex(s) for s in WD_SYNC_POINT_SITES],
         "gate_site": hex(WD_GATE_ADDR),
         "loop_head_site": hex(WD_LOOP_HEAD_ADDR),
         "pad_site": hex(WD_PAD_SITE),
         "refit_site": hex(WD_REFIT_SITE),
         "timer_guard_dtor": hex(TIMER_GUARD_DTOR_ADDR),
         "copy_state": hex(COPY_STATE_ADDR),
         "hashtable_dtor": hex(HASHTABLE_DTOR_ADDR),
         "extend_thunk": hex(EXTEND_THUNK_ADDR),
         "nanos_counter_tls_off": 0x28,
         "cpu_counter_tls_off": 0x58,
         "iostats_bytes_counter_tls_off": 0x08,
         "iostats_bytes_flag_tls_off": 0x98,
         "rate_limiter_op_write": RATE_LIMITER_OP_WRITE,
         "file_positioned_append_slot": FILE_POSITIONED_APPEND_SLOT,
         "file_positioned_append_checksum_slot":
             FILE_POSITIONED_APPEND_CHECKSUM_SLOT,
         "notify_write_finish_slot": NOTIFY_WRITE_FINISH_SLOT // 8,
         "notify_write_finish_base": hex(NOTIFY_WRITE_FINISH_BASE),
         "notify_failure_slot": NOTIFY_FAILURE_SLOT // 8,
         "notify_failure_base": hex(NOTIFY_FAILURE_BASE)})
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
    # write_zeros unit rows (the buffer-clear step).
    for capacity, cursize, n in ((4096, 0, 100), (4096, 100, 0),
                                 (4096, 4000, 96), (512, 512, 0)):
        buf = AlignedBuffer(4096, capacity=capacity, cursize=cursize,
                            data=bytes([0xAB]) * cursize)
        wrote = buf.write_zeros(n)
        add("aligned_buffer_write_zeros",
            {"capacity": capacity, "cursize_in": cursize, "n": n,
             "wrote": wrote, "cursize_out": buf.cursize,
             "tail_zero": all(b == 0 for b in
                             buf.data[cursize:cursize + n])})
    # Timer-guard thresholds: nanos armed iff perf_level > 2;
    # the CPU half is NEVER armed in this FDE (flag -0x18f is
    # written 0 at 0x605012c and never set; no clock-or-default
    # helper is called), so cpu_armed is False at every level.
    for level in range(6):
        add("timer_guard_armed", {"perf_level": level,
                                  "armed": level > 2})
    for level in range(6):
        add("timer_guard_cpu_armed", {"perf_level": level,
                                      "armed": False})
    # Pad / refit unit rows: pad = Roundup(cursize, alignment) -
    # cursize; file_advance = TruncateToPageBoundary(alignment,
    # cursize); leftover = cursize - file_advance.
    for alignment, cursize in ((4096, 0), (4096, 1), (4096, 4096),
                               (4096, 4097), (4096, 5000),
                               (4096, 8192), (512, 100),
                               (512, 512), (512, 513)):
        buf = AlignedBuffer(alignment, capacity=8192,
                            cursize=cursize,
                            data=bytes([0xAB]) * cursize)
        pad = buf.pad_to_alignment(0)
        add("pad_to_alignment",
            {"alignment": alignment, "cursize_in": cursize,
             "pad": pad, "cursize_out": buf.cursize,
             "file_advance": truncate_to_page(alignment, cursize),
             "leftover_tail": cursize - truncate_to_page(
                 alignment, cursize),
             "tail_zero": all(
                 b == 0 for b in buf.data[cursize:buf.cursize])})
    for alignment, cursize in ((4096, 5000), (4096, 8192),
                               (512, 513), (4096, 4096)):
        buf = AlignedBuffer(alignment, capacity=8192,
                            cursize=cursize,
                            data=bytes(range(256)) * 40)
        advance = truncate_to_page(alignment, cursize)
        leftover = cursize - advance
        tail = bytes(buf.data[advance:advance + leftover])
        buf.refit_tail(advance, leftover)
        add("refit_tail",
            {"alignment": alignment, "cursize_in": cursize,
             "file_advance": advance, "leftover_tail": leftover,
             "cursize_out": buf.cursize,
             "tail_preserved": bytes(buf.data[:leftover]) == tail})
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
    cases.extend(_gen_write_loop(rng))
    cases.extend(_gen_verification(rng))
    cases.extend(_gen_bindings(rng))
    assert len(cases) == 2400, len(cases)
    return cases


def case_outcome(case):
    """The expected outcome for a case: run the model (for the
    three behavioural groups) or evaluate the binding directly."""
    if case["group"] == "bindings":
        return _binding_outcome(case)
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
    if kind == "write_direct_constants":
        return {"ok": True,
                "crc_value_helper": p["crc_value_helper"],
                "request_token_base": p["request_token_base"],
                "system_clock_default": p["system_clock_default"],
                "sync_point_helper": p["sync_point_helper"],
                "sync_point_sites": p["sync_point_sites"],
                "timer_guard_dtor": p["timer_guard_dtor"],
                "copy_state": p["copy_state"],
                "hashtable_dtor": p["hashtable_dtor"],
                "extend_thunk": p["extend_thunk"],
                "nanos_counter_tls_off": p["nanos_counter_tls_off"],
                "cpu_counter_tls_off": p["cpu_counter_tls_off"],
                "iostats_bytes_counter_tls_off":
                    p["iostats_bytes_counter_tls_off"],
                "iostats_bytes_flag_tls_off":
                    p["iostats_bytes_flag_tls_off"],
                "rate_limiter_op_write": p["rate_limiter_op_write"],
                "file_positioned_append_slot":
                    p["file_positioned_append_slot"],
                "file_positioned_append_checksum_slot":
                    p["file_positioned_append_checksum_slot"],
                "notify_write_finish_slot":
                    p["notify_write_finish_slot"],
                "notify_write_finish_base":
                    p["notify_write_finish_base"],
                "notify_failure_slot": p["notify_failure_slot"],
                "notify_failure_base": p["notify_failure_base"],
                "gate_site": p["gate_site"],
                "loop_head_site": p["loop_head_site"],
                "pad_site": p["pad_site"],
                "refit_site": p["refit_site"]}
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
    if kind == "aligned_buffer_write_zeros":
        buf = AlignedBuffer(4096, capacity=p["capacity"],
                            cursize=p["cursize_in"],
                            data=bytes([0xAB]) * p["cursize_in"])
        wrote = buf.write_zeros(p["n"])
        return {"ok": True, "wrote": wrote,
                "cursize_out": buf.cursize,
                "tail_zero": all(b == 0 for b in
                                buf.data[p["cursize_in"]:
                                         p["cursize_in"] + p["n"]])}
    if kind == "timer_guard_armed":
        return {"ok": True, "perf_level": p["perf_level"],
                "armed": p["perf_level"] > 2}
    if kind == "timer_guard_cpu_armed":
        # The CPU half is never armed in WriteDirect.
        return {"ok": True, "perf_level": p["perf_level"],
                "armed": False}
    if kind == "pad_to_alignment":
        buf = AlignedBuffer(p["alignment"], capacity=8192,
                            cursize=p["cursize_in"],
                            data=bytes([0xAB]) * p["cursize_in"])
        pad = buf.pad_to_alignment(0)
        return {"ok": True, "pad": pad,
                "cursize_out": buf.cursize,
                "file_advance": truncate_to_page(p["alignment"],
                                                 p["cursize_in"]),
                "leftover_tail": p["cursize_in"] - truncate_to_page(
                    p["alignment"], p["cursize_in"]),
                "tail_zero": all(
                    b == 0 for b in
                    buf.data[p["cursize_in"]:buf.cursize])}
    if kind == "refit_tail":
        buf = AlignedBuffer(p["alignment"], capacity=8192,
                            cursize=p["cursize_in"],
                            data=bytes(range(256)) * 40)
        advance = truncate_to_page(p["alignment"], p["cursize_in"])
        leftover = p["cursize_in"] - advance
        tail = bytes(buf.data[advance:advance + leftover])
        buf.refit_tail(advance, leftover)
        return {"ok": True, "file_advance": advance,
                "leftover_tail": leftover,
                "cursize_out": buf.cursize,
                "tail_preserved": bytes(buf.data[:leftover]) == tail}
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
    """Drive the model against a REAL file: every positioned_append
    also writes to a tempfile with os.pwrite, and the model's file
    image must equal the real file bytes after each WriteDirect.

    Returns (ok, report dict)."""
    import os

    class RealFile(FakeFile):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.fd, self.path = tempfile.mkstemp(
                prefix="wfw-writedirect-")
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
        # Leg 1: page-pad + positional write on a real file --
        # 5000 bytes, alignment 4096: pad 3192, left 8192,
        # grants [4096, 4096] -> two PositionedAppends at offsets
        # 0 and 4096; flushed_size_ == 8192; next_write_offset_
        # == 4096; buf_ refit to the 904-byte tail.
        data = bytes(range(256)) * 19 + bytes(range(136))
        assert len(data) == 5000
        f = RealFile(io_priority=IO_TOTAL, direct_io=True)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 8192, 5000, data=data),
            max_buffer_size=65536, filesize=0,
            rate_limiter=FakeRateLimiter([4096, 4096]))
        s = write_direct(state, IO_LOW)
        assert s.is_ok(), s
        assert state.wd_grants == [4096, 4096], state.wd_grants
        assert state.wd_positioned_appends == 2
        assert state.wd_pad == 3192
        assert state.wd_file_advance == 4096
        assert state.wd_leftover_tail == 904
        assert state.flushed_size == 8192
        assert state.next_write_offset == 4096
        assert state.buf.cursize == 904
        assert bytes(state.buf.data[:904]) == data[4096:5000]
        assert bytes(f.image) == data + b"\x00" * 3192
        f._check_real()
        report["legs"].append({"leg": "pad_positional_real_file",
                               "bytes": 8192, "ok": True})
        f.close()
        # Leg 2: the verification arm computes a FRESH checksum
        # per chunk -- "hello world" (11 B, alignment 512, pad
        # 501, left 512), grants [5, 6] then the 501-byte tail:
        # chunks b"hello", b" world", 501 zero bytes, each
        # carrying crc32c::Value(chunk) -- NOT the buffered
        # value (0x12345678).
        f = RealFile(io_priority=IO_TOTAL, direct_io=True)
        state = WriterState(
            file=f, buf=AlignedBuffer(512, 1024, 11,
                                      data=b"hello world"),
            max_buffer_size=65536, filesize=0,
            perform_data_verification=True,
            buffered_data_with_checksum=True,
            buffered_data_crc32c_checksum=0x12345678,
            rate_limiter=FakeRateLimiter([5, 6]))
        s = write_direct(state, IO_LOW)
        assert s.is_ok(), s
        assert state.wd_grants == [5, 6, 501], state.wd_grants
        assert state.wd_positioned_appends == 3
        appends = [e for e in f.events
                   if e["op"] == "positioned_append"]
        assert len(appends) == 3, appends
        assert appends[0]["checksum"] == crc32c_value(b"hello")
        assert appends[1]["checksum"] == crc32c_value(b" world")
        assert appends[2]["checksum"] == crc32c_value(b"\x00" * 501)
        assert appends[0]["checksum"] != 0x12345678
        assert bytes(f.image) == b"hello world" + b"\x00" * 501
        # file_advance 0 (11 < 512): the whole buffer is the
        # tail; next_write_offset_ does not move.
        assert state.next_write_offset == 0
        assert state.buf.cursize == 11
        assert bytes(state.buf.data[:11]) == b"hello world"
        report["legs"].append(
            {"leg": "verification_per_chunk_checksum",
             "checksums": [a["checksum"] for a in appends],
             "ok": True})
        f.close()
        # Leg 3: the seen-error gate returns the prev-error
        # status and writes nothing.
        f = RealFile()
        state = WriterState(file=f, buf=AlignedBuffer(4096, 4096, 5,
                                                      data=b"hello"),
                            max_buffer_size=65536, seen_error=True)
        s = write_direct(state, IO_LOW)
        assert not s.is_ok() and s.code == 5, s
        assert s.summary()["state"] == 1
        assert len(f.image) == 0 and state.filesize == 0
        assert state.wd_positioned_appends == 0
        report["legs"].append({"leg": "seen_error_gate", "ok": True})
        f.close()
        # Leg 4: empty buffer -- OK, no PositionedAppend, file
        # unchanged, flushed_size_ unchanged, offsets unchanged.
        f = RealFile()
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 0),
            max_buffer_size=65536, filesize=1000,
            next_write_offset=4096, flushed_size=4096,
            perform_data_verification=True,
            buffered_data_crc32c_checksum=0xDEADBEEF)
        s = write_direct(state, IO_TOTAL)
        assert s.is_ok(), s
        assert state.wd_positioned_appends == 0
        assert state.buf.cursize == 0
        assert state.flushed_size == 4096
        assert state.next_write_offset == 4096
        assert len(f.image) == 0
        report["legs"].append({"leg": "empty_buffer_no_write",
                              "ok": True})
        f.close()
        # Leg 5: failure on the SECOND PositionedAppend --
        # seen_error_ set; cursize_ restored to the ENTRY 5000;
        # flushed_size_ keeps the first chunk (4096);
        # next_write_offset_ NOT advanced; the file holds only
        # the first chunk.
        f = RealFile()
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 8192, 5000, data=data),
            max_buffer_size=65536, filesize=0,
            rate_limiter=FakeRateLimiter([4096, 4096]))
        state.script = {"positioned_append_statuses": [
            {"code": 0, "subcode": 0, "b2": 0, "b3": 0, "b4": 0,
             "b5": 0, "b67": 0, "state": 0}, dict(ERR_IO)]}
        s = write_direct(state, IO_LOW)
        assert not s.is_ok() and s.code == 5, s
        assert state.seen_error
        assert state.wd_grants == [4096, 4096], state.wd_grants
        assert state.wd_positioned_appends == 2
        assert state.flushed_size == 4096
        assert state.buf.cursize == 5000
        assert state.next_write_offset == 0
        assert bytes(f.image) == data[:4096]
        f._check_real()
        report["legs"].append({"leg": "failure_second_chunk",
                              "ok": True})
        f.close()
        # Leg 6: listeners + guards armed (perf 5) -- the finish
        # event fires with type 1, offset = next_write_offset_,
        # nbytes = the padded size; the nanos counter advances
        # by the scripted elapsed time; the CPU counter stays 0
        # (the CPU half is never armed in this FDE); the IOStats
        # bytes counter advances by the padded size.
        f = RealFile(io_priority=IO_TOTAL, direct_io=True)
        pairs = [(1000000 + 1000 * j, 500000 + 700 * j)
                 for j in range(8)]
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 10,
                                      data=b"0123456789"),
            max_buffer_size=65536, filesize=0,
            next_write_offset=4096, flushed_size=4096,
            listeners=["L1"], perf_level=5,
            clock=FakeClock(pairs))
        s = write_direct(state, IO_TOTAL)
        assert s.is_ok(), s
        # Clock reads: nanos start (pair 0), listener pair
        # (pair 1), finish steady (pair 2), nanos stop (pair 3).
        assert state.wd_nanos == 2100, state.wd_nanos
        assert state.wd_cpu_nanos == 0, state.wd_cpu_nanos
        assert state.iostats_bytes_written == 4096
        finishes = [e for e in state.events
                    if e["op"] == "notify_finish"]
        assert len(finishes) == 1, finishes
        assert finishes[0]["type"] == 1
        assert finishes[0]["offset"] == 4096
        assert finishes[0]["nbytes"] == 4096
        assert finishes[0]["elapsed_nanos"] == 700, finishes[0]
        # Positional write at offset 4096 into an empty file:
        # the image is 4096 zero bytes, then the padded chunk.
        assert bytes(f.image) == (b"\x00" * 4096 + b"0123456789"
                                  + b"\x00" * 4086)
        assert state.next_write_offset == 4096
        assert state.buf.cursize == 10
        report["legs"].append({"leg": "listeners_and_guards",
                              "ok": True})
        f.close()
        # Leg 7: a decided IO_TOTAL priority skips the limiter
        # entirely -- one PositionedAppend, no RequestToken call.
        f = RealFile(io_priority=IO_TOTAL, direct_io=True)
        limiter = FakeRateLimiter([1])
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 10,
                                      data=b"0123456789"),
            max_buffer_size=65536, filesize=0,
            rate_limiter=limiter)
        s = write_direct(state, IO_TOTAL)
        assert s.is_ok(), s
        assert limiter.calls == [], limiter.calls
        assert state.wd_grants == []
        assert state.wd_positioned_appends == 1
        assert bytes(f.image) == b"0123456789" + b"\x00" * 4086
        report["legs"].append({"leg": "io_total_skips_limiter",
                              "ok": True})
        f.close()
        # Leg 8: the failure event carries type 9 with the
        # trailing (size, write_offset) u64s, and seen_error_ is
        # set only after the notifications.
        f = RealFile(io_priority=IO_TOTAL, direct_io=True)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 10,
                                      data=b"0123456789"),
            max_buffer_size=65536, filesize=0,
            next_write_offset=777,
            listeners=["L1", "L2"],
            rate_limiter=FakeRateLimiter([4]))
        state.script = {"positioned_append_statuses": [dict(ERR_IO)]}
        s = write_direct(state, IO_LOW)
        assert not s.is_ok() and s.code == 5, s
        assert state.seen_error
        failures = [e for e in state.events
                    if e["op"] == "notify_failure"]
        assert len(failures) == 2, failures  # one per listener
        assert failures[0]["type"] == 9
        assert failures[0]["size"] == 4
        assert failures[0]["write_offset"] == 777
        assert state.flushed_size == 0
        assert state.buf.cursize == 10
        report["legs"].append({"leg": "failure_event_type_9",
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
