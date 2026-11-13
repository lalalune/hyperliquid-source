#!/usr/bin/env python3
"""Node #115 RocksDB WritableFileWriter::Pad: reconstruction.

RE-002 work item. Reconstructs the WAL/SST file writer's pad
routine at 0x60525b0..0x60527a5 (501 B) plus its landing pad
``Pad.cold`` at 0x605257c..0x60525a8 (44 B):

  rocksdb::WritableFileWriter::Pad       0x60525b0 (501 B)
  rocksdb::WritableFileWriter::Pad.cold  0x605257c (44 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
BOTH functions are census-bound (body hashes match
target_body_sha256 exactly; source hashes reproduced by zeroing
the recorded relocations -- see gen_records.py). Symbols come
from the vendor census (member a895f7517936a0f7-writable_file_
writer.o, librocksdb-sys 0.11.0+8.1.1). This is the follow-up to
open PR #6057 (WritableFileWriter::Flush), which took Pad as a
caller (one call site) and left it as the direct follow-up; this
packet supersedes that oracle note with the full body model.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus Pad(uint64_t size, Env::IOPriority priority)
  -- returns by value, so rdi is the hidden 16-byte sret
  out-pointer, rsi is the Writer*, rdx the size, ecx the priority.
  Steps, in binary order:

  1. Seen-error gate (0x60525d5): byte this+0x89 (seen_error_)
     read FIRST. If set, the routine returns at once (0x60526d0):
     sret = {code 5 (kIOError), subcode 0, severity 0, scope 0,
     retryable 0, data_loss 0, state_ = fresh 27-byte "Writer has
     previous error."} -- exactly upstream
     AssertFalseAndGetStatusForPrevError()
     (file/writable_file_writer.h:555-563). The old sret state_
     (when non-null) is delete[]'d first. No other member is
     touched: no zero-fill, no Flush, pending_sync_ NOT set,
     filesize_ unchanged.
  2. Zero-fill loop (0x60525e4..0x60526c4): the entry cursize_
     (this+0x58) is saved at rsp+0x8 -- it is the pad start --
     and the remaining size is filled in chunks of
     min(buf_.capacity_ - buf_.cursize_, remaining): memset
     (buf_.bufstart_ (this+0x60) + buf_.cursize_, 0, chunk),
     cursize_ += chunk, remaining -= chunk. When remaining is
     still non-zero the buffer is full, so the routine calls
     Flush(priority) at 0x6051a20 (0x6052690) with a 16-byte sret
     at rsp+0x10; on a non-OK Flush status it sets seen_error_
     = 1 and returns that status at once (0x6052758, move-assigned
     into the out sret with byte 2 forced to 0 -- pending_sync_
     NOT set, filesize_ NOT advanced, the padded zeros stay
     buffered). On success it delete[]s the Flush sret state_
     when non-null, reloads cursize_/capacity_ and loops. A
     zero-size Pad skips the loop entirely (0x60525fa).
  3. Epilogue (0x605262e): pending_sync_ (this+0x88) = 1;
     filesize_ (this+0x70) += size.
  4. Verification arm (0x6052641..0x605274f): only when
     perform_data_verification_ (this+0xd1) is set,
     buffered_data_crc32c_checksum_ (this+0xd4) =
     crc32c::Extend(checksum, buf_.bufstart_ + ENTRY cursize_,
     size) through the 0x61c25f0 dispatch thunk -- the pointer
     is the SAVED entry cursize, not the final one. When no
     Flush intervened the span is exactly the zeros just
     written; when a Flush DID intervene (size exceeded the
     free space at entry) the span runs past the buffer's
     capacity -- the binary reads heap bytes past the
     allocation, so the resulting checksum is NOT pinned by
     this model (recorded as null with the pointer/length).
     buffered_data_with_checksum_ (this+0xd8) is NOT consulted
     here (unlike Flush's WriteDirectWithChecksum selection).
  5. OK return (0x605264f): sret = {code 0, state_ null}.

  Pad.cold (0x605257c..0x60525a8) is the unwind-only landing
  pad: delete[] the sret state_ when non-null, stack check,
  _Unwind_Resume. It is reached by the single tail jump at
  0x60527a0 (the FDE's exception landing-pad tail).

Sole caller (whole-.text census, Capstone-validated):
``rocksdb::BlockBasedTableBuilder::WriteMaybeCompressedBlock``
0x60e7200..0x60e7844, one call site at 0x60e7649 with priority
IO_TOTAL (4) and size = (block_size - ((offset + 5) %
block_size)) % block_size -- the SST block-alignment pad
(block trailer: 1 type byte + 4 CRC bytes). Pad itself never
computes an alignment; the caller does.

Flush (0x6051a20), WriteBuffered[WithChecksum]
(0x604e140/0x604f080), WriteDirect[WithChecksum]
(0x604fe80/0x6050c80), RangeSync (0x604d7b0) and the file's
Flush/RangeSync are input oracles with the contracts from open
PR #6057 (Flush) and #6041 (Append); their bodies are not
reconstructed here. The Flush oracle is implemented at the
same fidelity as #6057: buffered/direct write step, listener
start times + finish/failure events, IOOptions with
DecideRateLimiterPriority, file_->Flush, and the RangeSync
arm. Direct I/O note: Pad's binary has no use_direct_io()
check (upstream asserts !use_direct_io()); with direct I/O
and pending_sync_ clear, Flush skips the write, the buffer
stays full and the loop makes no progress -- the binary does
not terminate for size > free space in that configuration.
The model raises instead of hanging (see pad()); no
generated case uses direct I/O.

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
temperature_ +0xdc; total 0xe0.

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
          / "re-002-node115-rocksdb-writable-file-writer-pad-115")
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
PAD_ADDR = 0x60525B0
PAD_FDE_END = 0x60527A5
COLD_ADDR = 0x605257C
COLD_FDE_END = 0x60525A8
FLUSH_ADDR = 0x6051A20
FLUSH_FDE_END = 0x605257C
WRITE_BUFFERED_ADDR = 0x604E140
WRITE_BUFFERED_FDE_END = 0x604EF0D
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
# Sole caller: BlockBasedTableBuilder::WriteMaybeCompressedBlock.
CALLER_ADDR = 0x60E7200
CALLER_FDE_END = 0x60E7844
CALLER_SITE = 0x60E7649
USE_DIRECT_IO_SLOT = 12
GET_IO_PRIORITY_SLOT = 16
FILE_FLUSH_SLOT = 8
FILE_RANGE_SYNC_SLOT = 23
GET_IO_PRIORITY_BASE = 0x5DF6E90
TIMER_GUARD_DTOR_ADDR = 0x604C6B6
SYNC_POINT_HELPER_ADDR = 0x606D9F0
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
# Pad's memset PLT target and the Flush call site in Pad.
MEMSET_PLT_ADDR = 0x63F0A90
PAD_FLUSH_CALL_SITE = 0x605269A
# Caller alignment math: pad = (block_size - ((offset + 5)
# % block_size)) % block_size (block trailer: 1 type + 4 CRC).
CALLER_TRAILER_BYTES = 5

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


def caller_pad_size(block_size, offset):
    """The sole caller's pad size (WriteMaybeCompressedBlock,
    0x60e7618..0x60e7649): pad = (block_size - ((offset + 5) %
    block_size)) % block_size, computed with the binary's
    and/subtract sequence (rcx = block_size - 1)."""
    rem = (offset + CALLER_TRAILER_BYTES) & (block_size - 1)
    return (block_size - rem) & (block_size - 1)


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
        # Pad run record (set by pad()): the Extend pointer/length,
        # whether its input is fully inside the buffer, the chunk
        # sizes written, and how many mid-loop Flushes ran.
        self.pad_extend_ptr_offset = None
        self.pad_extend_len = None
        self.pad_extend_input_len = None
        self.pad_extend_pinned = None
        self.pad_flush_calls = 0
        self.pad_chunks = []

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
            "pad_extend_ptr_offset": self.pad_extend_ptr_offset,
            "pad_extend_len": self.pad_extend_len,
            "pad_extend_input_len": self.pad_extend_input_len,
            "pad_extend_pinned": self.pad_extend_pinned,
            "pad_flush_calls": self.pad_flush_calls,
            "pad_chunks": self.pad_chunks,
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


def pad(state, size, priority):
    """rocksdb::WritableFileWriter::Pad, exactly as the FDE at
    0x60525b0 implements it. `size` is the pad length in bytes,
    `priority` is Env::IOPriority. Returns Status.

    The zero-fill loop calls the Flush oracle (0x605269a) each
    time the buffer fills; a failed Flush sets seen_error_ and
    returns at once. The verification Extend reads
    bufstart_ + ENTRY cursize_ for `size` bytes -- when a Flush
    intervened that span runs past the buffer capacity and the
    checksum is heap-dependent; the model records it as null
    (pad_extend_pinned False) instead of inventing bytes.
    """
    s = Status.ok()
    # 1. Seen-error gate (0x60525d5).
    if state.seen_error:
        return Status.io_error(PREV_ERROR_MSG)
    buf = state.buf
    # The entry cursize_ is saved at rsp+0x8 (0x60525f2) -- it is
    # the pad start for the verification Extend below.
    entry_cursize = buf.cursize
    state.pad_extend_ptr_offset = entry_cursize
    state.pad_extend_len = size
    remaining = size
    # 2. Zero-fill loop (0x6052610..0x60526c4). A zero-size Pad
    # skips the loop entirely (0x60525fa).
    guard = 0
    while remaining > 0:
        guard += 1
        if guard > 10000:
            raise ValueError(
                "pad loop exceeded 10000 iterations (size=%d, "
                "capacity=%d, cursize=%d)" % (size, buf.capacity,
                                              buf.cursize))
        free = buf.capacity - buf.cursize
        chunk = min(free, remaining)
        # memset(bufstart_ + cursize_, 0, chunk) (0x6052620, PLT
        # memset at 0x63f0a90); cursize_ += chunk (0x6052625).
        # A 0 chunk is recorded too: it pins the full-buffer-at-
        # entry flush-first iteration.
        state.pad_chunks.append(chunk)
        if chunk > 0:
            buf.write_zeros(chunk)
            state.events.append({"op": "pad_memset",
                                 "offset": buf.cursize - chunk,
                                 "len": chunk,
                                 "callee": hex(MEMSET_PLT_ADDR)})
        remaining -= chunk
        if remaining == 0:
            break
        # The buffer is full: Flush(priority) (0x605269a) with a
        # 16-byte sret at rsp+0x10; code byte checked at 0x605269f.
        cursize_before = buf.cursize
        s = _flush_oracle(state, priority)
        state.pad_flush_calls += 1
        state.events.append({"op": "pad_flush_call",
                             "priority": priority,
                             "n": state.pad_flush_calls,
                             "callee": hex(FLUSH_ADDR),
                             "site": hex(PAD_FLUSH_CALL_SITE),
                             "status": s.summary()})
        if not s.is_ok():
            # 0x6052758: seen_error_ = 1; the Flush status is
            # move-assigned into the out sret with byte 2 = 0.
            state.set_seen_error()
            s.b2 = 0
            return s
        if chunk == 0 and buf.cursize == cursize_before:
            # No progress: the Flush skipped the write (direct I/O
            # with pending_sync_ clear, or a zero-capacity buffer).
            # The binary loops forever here; the model refuses.
            raise ValueError(
                "pad makes no progress: flush skipped the write "
                "(direct_io=%s, pending_sync=%s, capacity=%d, "
                "cursize=%d)" % (state.file.use_direct_io(),
                                 state.pending_sync, buf.capacity,
                                 buf.cursize))
    # 3. Epilogue (0x605262e): pending_sync_ = 1; filesize_ += size.
    state.pending_sync = True
    state.filesize += size
    # 4. Verification arm (0x6052641..0x605274f): only when
    # perform_data_verification_ (this+0xd1) is set,
    # buffered_data_crc32c_checksum_ = Extend(checksum,
    # bufstart_ + ENTRY cursize_, size) via the 0x61c25f0 thunk.
    if state.perform_data_verification:
        end = entry_cursize + size
        avail = bytes(buf.data[entry_cursize:min(end, buf.capacity)])
        pinned = end <= buf.capacity
        state.pad_extend_input_len = len(avail)
        state.pad_extend_pinned = pinned
        state.events.append({"op": "pad_verify_extend",
                             "callee": hex(EXTEND_THUNK_ADDR),
                             "ptr_offset": entry_cursize,
                             "len": size,
                             "input_len": len(avail),
                             "pinned": pinned})
        if pinned:
            state.buffered_data_crc32c_checksum = crc32c_extend(
                state.buffered_data_crc32c_checksum, avail)
        else:
            # The Extend reads past the buffer's capacity: heap
            # bytes the model cannot pin. Record null, not a guess.
            state.buffered_data_crc32c_checksum = None
    else:
        state.pad_extend_input_len = 0
        state.pad_extend_pinned = None
    # 5. OK return (0x605264f): sret = {code 0, state_ null}.
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
        file_name=o.get("file_name", "test.wal"))
    if o.get("file_image_hex"):
        f.image = bytearray(bytes.fromhex(o["file_image_hex"]))
    state.script = {k: [dict(x) for x in v]
                    for k, v in (script or {}).items()}
    return state


def run_case(case):
    """Run one case dict through pad() and return the observed
    outcome dict (status summary + state snapshot)."""
    state = make_writer(case.get("writer"), case.get("file"),
                        case.get("script"))
    s = pad(state, case["size"], case["priority"])
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
    """600 gate cases: seen-error, zero/non-zero size, entry
    cursize/capacity, verification flags, priorities, tracer
    selection, perf level, sync point, clock pairs, flag_d9,
    file names, scripted Flush/file-Flush/RangeSync failures."""
    cases = []
    for i in range(600):
        seen_error = rng.random() < 0.15
        verify = rng.random() < 0.5
        with_cksum = rng.random() < 0.5
        perf = rng.choice([0, 1, 2, 3, 4, 5])
        clock = ([(1000000 + 1000 * j, 500000 + 700 * j)
                  for j in range(6)] if perf > 2 or
                 rng.random() < 0.5 else None)
        tracer = rng.choice([None, {"enabled": False},
                             {"enabled": True}])
        capacity = rng.choice([512, 1024, 4096, 8192])
        cursize = rng.choice([0, 0, 1, 100, min(1000, capacity),
                              capacity - 1, capacity])
        size = rng.choice([0, 1, 7, 100, 1000, 4096, 5000, 9000,
                           20000])
        script = {}
        r = rng.random()
        if r < 0.10:
            script["write_statuses"] = [dict(ERR_IO)]
        if rng.random() < 0.10:
            script["file_flush_statuses"] = [dict(ERR_CORRUPTION)]
        if rng.random() < 0.08:
            script["range_sync_file_statuses"] = [dict(ERR_IO)]
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
            capacity=capacity, cursize=cursize,
            buf_seed=(rng.randrange(2 ** 31)
                      if rng.random() < 0.7 else None),
            pending_sync=rng.random() < 0.5,
            listeners=(["L1", "L2"] if rng.random() < 0.3 else
                       (["L1"] if rng.random() < 0.3 else [])))
        f = {"io_priority": rng.randrange(5),
             "direct_io": False, "tracer": tracer}
        cases.append({
            "group": "gate", "case_id": "gate-%03d" % i,
            "writer": w, "file": f, "script": script,
            "size": size, "priority": rng.randrange(5)})
    return cases


def _gen_pad_paths(rng):
    """600 pad-path cases: the chunking matrix -- size vs the
    free space at entry (below, equal, just over, multi-buffer),
    entry cursize 0/partial/full, capacities 512..8192, scripted
    write/file-Flush failures, the RangeSync arm (filesize >
    1 MiB), rate limiter grants, listeners, clock pairs."""
    cases = []
    for i in range(600):
        capacity = rng.choice([512, 1024, 4096, 8192])
        cursize = rng.choice([0, 1, 100, capacity // 2,
                              capacity - 1, capacity])
        free = capacity - cursize
        size = rng.choice([0, 1, max(0, free - 1), free, free + 1,
                           capacity, 2 * capacity, 2 * capacity + 1,
                           3 * capacity + 7, 20000])
        script = {}
        r = rng.random()
        if r < 0.12:
            script["write_statuses"] = [dict(ERR_IO)]
        if rng.random() < 0.12:
            script["file_flush_statuses"] = [dict(ERR_CORRUPTION)]
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
            perform_data_verification=rng.random() < 0.4,
            buffered_data_with_checksum=rng.random() < 0.5,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            pending_sync=rng.random() < 0.5,
            listeners=(["L1", "L2"] if rng.random() < 0.25 else
                       (["L1"] if rng.random() < 0.25 else [])),
            clock_pairs=[(1000000 + 1000 * j, 500000 + 700 * j)
                         for j in range(8)],
            flag_d9=rng.random() < 0.5,
            perf_level=rng.choice([0, 3]),
            rate_limiter_grants=(
                [100, 1000, 4096] if rng.random() < 0.25 else None))
        f = {"io_priority": rng.randrange(5),
             "direct_io": False,
             "tracer": rng.choice([None, {"enabled": True}])}
        cases.append({
            "group": "pad_paths", "case_id": "pad_paths-%03d" % i,
            "writer": w, "file": f, "script": script,
            "size": size, "priority": rng.randrange(5)})
    return cases


def _gen_verification(rng):
    """600 verification cases: perform_data_verification on/off
    x buffered_data_with_checksum on/off x sizes straddling the
    free-space boundary (flush intervened or not) -- the pinned
    checksum rows vs the unpinned over-read rows -- plus the
    zero-size Extend (checksum unchanged) and entry-checksum
    variety."""
    cases = []
    for i in range(600):
        verify = rng.random() < 0.7
        with_cksum = rng.random() < 0.5
        capacity = rng.choice([512, 1024, 4096])
        cursize = rng.choice([0, 1, capacity // 2, capacity - 1,
                              capacity])
        free = capacity - cursize
        size = rng.choice([0, 1, max(0, free - 1), free, free + 1,
                           free + 100, 2 * capacity, 10000])
        script = {}
        if rng.random() < 0.08:
            script["write_statuses"] = [dict(ERR_IO)]
        w = _base_writer(
            rng, capacity=capacity, cursize=cursize,
            buf_seed=rng.randrange(2 ** 31),
            perform_data_verification=verify,
            buffered_data_with_checksum=with_cksum,
            buffered_data_crc32c_checksum=rng.randrange(2 ** 32),
            listeners=(["L1"] if rng.random() < 0.3 else []),
            clock_pairs=[(1000000 + 1000 * j, 500000 + 700 * j)
                         for j in range(4)],
            flag_d9=rng.random() < 0.5,
            perf_level=rng.choice([0, 3]))
        f = {"io_priority": rng.randrange(5),
             "direct_io": False, "tracer": None}
        cases.append({
            "group": "verification",
            "case_id": "verification-%03d" % i,
            "writer": w, "file": f, "script": script,
            "size": size, "priority": rng.randrange(5)})
    return cases


def _fde_body_hashes():
    """Recompute the FDE body hashes from the binary (the
    bindings group pins them; the packet's gen_records.py is the
    authority, this is a cross-check)."""
    data = open(_bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256
    out = {}
    for start, end, key in ((PAD_ADDR, PAD_FDE_END, "pad"),
                            (COLD_ADDR, COLD_FDE_END, "cold"),
                            (FLUSH_ADDR, FLUSH_FDE_END, "flush"),
                            (WRITE_BUFFERED_ADDR,
                             WRITE_BUFFERED_FDE_END, "write_buffered"),
                            (WRITE_BUFFERED_CHECKSUM_ADDR,
                             WRITE_BUFFERED_CHECKSUM_FDE_END,
                             "write_buffered_checksum"),
                            (WRITE_DIRECT_ADDR, WRITE_DIRECT_FDE_END,
                             "write_direct"),
                            (WRITE_DIRECT_CHECKSUM_ADDR,
                             WRITE_DIRECT_CHECKSUM_FDE_END,
                             "write_direct_checksum"),
                            (RANGE_SYNC_ADDR, RANGE_SYNC_FDE_END,
                             "range_sync"),
                            (APPEND_ADDR, APPEND_FDE_END, "append"),
                            (CALLER_ADDR, CALLER_FDE_END,
                             "write_maybe_compressed_block")):
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
    caller census, the caller's alignment math, vtable slots,
    layout offsets, IOOptions constants, the priority matrix,
    CRC vectors, FileOperationType values, the RangeSync arm
    constants, and direct AlignedBuffer unit rows."""
    cases = []
    idx = 0

    def add(kind, payload):
        nonlocal idx
        cases.append({"group": "bindings",
                      "case_id": "bindings-%03d" % idx,
                      "kind": kind, "payload": payload})
        idx += 1

    hashes = _fde_body_hashes()
    add("body_hash", {"fn": "Pad", "start": hex(PAD_ADDR),
                      "end": hex(PAD_FDE_END), "size": 501,
                      "sha256": hashes["pad"]})
    add("body_hash", {"fn": "Pad.cold", "start": hex(COLD_ADDR),
                      "end": hex(COLD_FDE_END), "size": 44,
                      "sha256": hashes["cold"]})
    add("body_hash", {"fn": "Flush", "start": hex(FLUSH_ADDR),
                      "end": hex(FLUSH_FDE_END), "size": 2908,
                      "sha256": hashes["flush"]})
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
    add("body_hash", {"fn": "RangeSync",
                      "start": hex(RANGE_SYNC_ADDR),
                      "end": hex(RANGE_SYNC_FDE_END), "size": 2155,
                      "sha256": hashes["range_sync"]})
    add("body_hash", {"fn": "Append",
                      "start": hex(APPEND_ADDR),
                      "end": hex(APPEND_FDE_END), "size": 2827,
                      "sha256": hashes["append"]})
    add("body_hash", {"fn": "WriteMaybeCompressedBlock",
                      "start": hex(CALLER_ADDR),
                      "end": hex(CALLER_FDE_END), "size": 1604,
                      "sha256": hashes["write_maybe_compressed_block"]})
    census = json.load(open(ROOT / CENSUS_PATH))["records"]
    by_start = {r["start"]: r for r in census}
    for addr, fn in ((PAD_ADDR, "Pad"), (COLD_ADDR, "Pad.cold")):
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
    # The sole caller's alignment math.
    for block_size in (4096, 8192, 16384, 32768, 65536):
        for offset in (0, 1, 4090, 4091, 4092, 4096, 8191, 12345,
                       100000):
            add("caller_pad_size",
                {"block_size": block_size, "offset": offset,
                 "pad_size": caller_pad_size(block_size, offset)})
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
    # Pad loop constants (call sites pinned in the FDE).
    add("pad_constants",
        {"memset_plt": hex(MEMSET_PLT_ADDR),
         "flush_addr": hex(FLUSH_ADDR),
         "flush_call_site": hex(PAD_FLUSH_CALL_SITE),
         "extend_thunk": hex(EXTEND_THUNK_ADDR),
         "caller_site": hex(CALLER_SITE),
         "caller_trailer_bytes": CALLER_TRAILER_BYTES})
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
    # write_zeros unit rows (Pad's memset step).
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
    cases.extend(_gen_pad_paths(rng))
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
    if kind == "caller_pad_size":
        return {"ok": True, "block_size": p["block_size"],
                "offset": p["offset"],
                "pad_size": caller_pad_size(p["block_size"],
                                            p["offset"])}
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
    if kind == "pad_constants":
        return {"ok": True,
                "memset_plt": p["memset_plt"],
                "flush_addr": p["flush_addr"],
                "flush_call_site": p["flush_call_site"],
                "extend_thunk": p["extend_thunk"],
                "caller_site": p["caller_site"],
                "caller_trailer_bytes": p["caller_trailer_bytes"]}
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
    file image must equal the real file bytes after each Pad.

    Returns (ok, report dict)."""
    import os

    class RealFile(FakeFile):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.fd, self.path = tempfile.mkstemp(prefix="wfw-pad-")
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
        # Leg 1: pad 5000 with capacity 4096, cursize 0 -- a
        # mid-loop Flush writes 4096 zeros to the real file; the
        # 904-byte tail stays buffered; a final Flush writes it.
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 0),
            max_buffer_size=65536, filesize=0)
        s = pad(state, 5000, IO_TOTAL)
        assert s.is_ok(), s
        assert state.pad_flush_calls == 1, state.pad_flush_calls
        assert state.pad_chunks == [4096, 904], state.pad_chunks
        assert len(f.image) == 4096 and bytes(f.image) == b"\x00" * 4096
        assert state.buf.cursize == 904
        assert state.filesize == 5000 and state.pending_sync
        f._check_real()
        s = _flush_oracle(state, IO_TOTAL)
        assert s.is_ok(), s
        assert len(f.image) == 5000 and bytes(f.image) == b"\x00" * 5000
        f._check_real()
        report["legs"].append({"leg": "pad_flush_tail",
                              "bytes": 5000, "ok": True})
        f.close()
        # Leg 2: pad with verification on, no flush -- the checksum
        # is pinned: Extend(entry, zeros) exactly.
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        entry = 0x12345678
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 11,
                                      data=b"hello pad!!"),
            max_buffer_size=65536, filesize=11,
            perform_data_verification=True,
            buffered_data_crc32c_checksum=entry)
        s = pad(state, 100, IO_TOTAL)
        assert s.is_ok(), s
        assert state.pad_flush_calls == 0
        assert state.pad_extend_pinned is True
        assert state.buffered_data_crc32c_checksum == crc32c_extend(
            entry, b"\x00" * 100)
        assert state.filesize == 111
        report["legs"].append({"leg": "pad_verify_pinned",
                              "checksum": state.buffered_data_crc32c_checksum,
                              "ok": True})
        f.close()
        # Leg 3: the seen-error gate returns the prev-error status
        # and writes nothing.
        f = RealFile()
        state = WriterState(file=f, buf=AlignedBuffer(4096, 4096, 5,
                                                      data=b"hello"),
                            max_buffer_size=65536, seen_error=True)
        s = pad(state, 100, IO_TOTAL)
        assert not s.is_ok() and s.code == 5, s
        assert s.summary()["state"] == 1
        assert len(f.image) == 0 and state.filesize == 0
        assert not state.pending_sync
        report["legs"].append({"leg": "seen_error_gate", "ok": True})
        f.close()
        # Leg 4: zero-size pad -- no loop, no flush, pending_sync_
        # set, filesize_ unchanged, checksum unchanged.
        f = RealFile()
        entry = 0xDEADBEEF
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 100,
                                      data=bytes(100)),
            max_buffer_size=65536, filesize=1000,
            perform_data_verification=True,
            buffered_data_crc32c_checksum=entry)
        s = pad(state, 0, IO_TOTAL)
        assert s.is_ok(), s
        assert state.pad_flush_calls == 0 and state.pad_chunks == []
        assert state.pending_sync and state.filesize == 1000
        assert state.buffered_data_crc32c_checksum == entry
        assert state.pad_extend_pinned is True
        report["legs"].append({"leg": "zero_size_pad", "ok": True})
        f.close()
        # Leg 5: flush-intervened pad with verification on -- the
        # file bytes are exact, the checksum is NOT pinned (null).
        f = RealFile(io_priority=IO_TOTAL, direct_io=False)
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 4000,
                                      data=bytes([0xAB]) * 4000),
            max_buffer_size=65536, filesize=4000,
            perform_data_verification=True,
            buffered_data_crc32c_checksum=0x12345678)
        s = pad(state, 1000, IO_TOTAL)
        assert s.is_ok(), s
        assert state.pad_flush_calls == 1
        assert state.pad_chunks == [96, 904], state.pad_chunks
        assert state.pad_extend_pinned is False
        assert state.buffered_data_crc32c_checksum is None
        assert state.filesize == 5000
        s = _flush_oracle(state, IO_TOTAL)
        assert s.is_ok(), s
        assert len(f.image) == 5000
        assert bytes(f.image[:4000]) == bytes([0xAB]) * 4000
        assert bytes(f.image[4000:]) == b"\x00" * 1000
        f._check_real()
        report["legs"].append({"leg": "pad_verify_unpinned",
                              "ok": True})
        f.close()
        # Leg 6: a mid-loop Flush failure -- seen_error_ set,
        # filesize_ NOT advanced, and the failed WriteBuffered
        # clears buf_ (cursize 0) and resets the checksum, per
        # the #6057 contract; the file gains nothing.
        f = RealFile()
        state = WriterState(
            file=f, buf=AlignedBuffer(4096, 4096, 0),
            max_buffer_size=65536, filesize=0,
            perform_data_verification=False)
        state.script = {"write_statuses": [dict(ERR_IO)]}
        s = pad(state, 5000, IO_TOTAL)
        assert not s.is_ok() and s.code == 5, s
        assert state.seen_error and not state.pending_sync
        assert state.filesize == 0
        assert state.buf.cursize == 0
        assert state.buffered_data_crc32c_checksum == 0
        assert len(f.image) == 0
        report["legs"].append({"leg": "flush_failure", "ok": True})
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
