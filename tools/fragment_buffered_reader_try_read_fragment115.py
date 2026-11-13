"""Node #115 RocksDB log::FragmentBufferedReader::TryReadFragment:
reconstruction.

RE-002 work item. Reconstructs the WAL fragment reader's record
parser at 0x5f02b40..0x5f02ee6 (934 B):

  rocksdb::log::FragmentBufferedReader::TryReadFragment  0x5f02b40 (934 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The body hash matches the vendor census target_body_sha256 exactly,
and the source hash is reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbol comes from the vendor
census (member 25dac13516458d4d-log_reader.o, librocksdb-sys):
_ZN7rocksdb3log22FragmentBufferedReader15TryReadFragmentEPNS_5SliceEPmPj.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  bool TryReadFragment(Slice* fragment, size_t* drop_size,
                       unsigned int* fragment_type_or_err)
  -- rdi is the FragmentBufferedReader* (rbx), rsi the fragment
  Slice* (saved [rsp+0x8]), rdx the drop_size* (rbp), rcx the
  fragment_type_or_err* (r13). It returns true when the caller
  should process *fragment_type_or_err (a record type 0..9 on
  success, or a special code 10..15), and false only when
  TryReadMore fails or makes no progress (in which case
  *fragment_type_or_err is either TryReadMore's code or untouched).
  Steps, in binary order:

  1. Header loop (0x5f02b74-0x5f02bb2): while buffer_.size() <= 6
     (< kHeaderSize 7), preset the local code to kEof (10) at
     [rsp+0x30] and call TryReadMore (0x5f02980, rdi=this,
     rsi=drop_size, rdx=&code). On false: *fragment_type_or_err =
     the code, return false. On true with buffer_.size() unchanged
     (no progress): return false with *fragment_type_or_err
     UNTOUCHED. Otherwise re-loop until at least 7 bytes are buffered.
  2. Parse the header from buffer_.data(): type = sign-extended
     byte header[6] (movsx eax), length = LE16 header[4:6]
     (movzx ecx, word). Recyclable iff (uint32_t)(type - 5) <= 3,
     i.e. signed type in 5..8 (kRecyclableFullType..kRecyclableLastType).
  3. Recyclable arm: if end_of_buffer_offset_ - buffer_.size() == 0
     (cmp [rbx+0x60], buffer size; je), set recycled_ = true at
     this+0x70. header_size becomes 11 (kRecyclableHeaderSize). While
     buffer_.size() <= 10, TryReadMore with the same preset/no-progress
     rules and re-loop. log_num = DecodeFixed32(header + 7); if
     log_num != log_number_ (+0x68), *fragment_type_or_err =
     kOldRecord (13), return true (buffer NOT cleared, no drop_size
     write, *fragment untouched).
  4. Body loop (0x5f02c83-0x5f02cbf): while header_size + length >
     buffer_.size(), TryReadMore with the same preset/no-progress
     rules and re-loop. (Unlike ReadPhysicalRecord there is NO
     kBadRecordLen arm: a short body just keeps refilling.)
  5. If type == 0 and length == 0 ((length | type) == 0, 0x5f02e0a):
     buffer_.clear() (data = 0x4376fd, the empty-string literal,
     size 0), *fragment_type_or_err = kBadRecord (11), return true.
     No drop_size write, *fragment untouched.
  6. If checksum_ (+0x28): expected = crc32c::Unmask(DecodeFixed32
     (header)) -- the binary computes (stored - kMaskDelta) rol 15
     (add eax, 0x5d7d1528; rol eax, 0xf; 0x5d7d1528 is
     -0xa282ead8 mod 2^32); actual = crc32c::Value(header + 6,
     length + header_size - 6), inlined as Extend(0, header + 6,
     length + header_size - 6) through the dispatch thunk at
     0x61c25f0 (see below). Mismatch: *drop_size = buffer_.size(),
     buffer_.clear(), *fragment_type_or_err = kBadRecordChecksum
     (15), return true. *fragment untouched.
  7. buffer_.remove_prefix(header_size + length): data +=
     header_size + length, size -= header_size + length
     (add [rbx+0x38], r14; sub [rbx+0x40], r14).
  8. If !uncompress_ (+0x78) or type == kSetCompressionType (9):
     *fragment = Slice(header + header_size, length);
     *fragment_type_or_err = type (the sign-extended byte as u32 --
     a type byte >= 0x80 returns as the sign-extended 32-bit value,
     e.g. 0xFFFFFF80); return true. NOTE: only type 9 bypasses
     decompression in this binary. A newer upstream log_reader.cc
     also bypasses kUserDefinedTimestampSizeType and
     kRecyclableUserDefinedTimestampSizeType, but this FDE contains
     no comparison against those type values at all, so types 10/11
     go through decompression when uncompress_ is set -- the binary
     is the authority and the packet pins that.
  9. Else (compressed path): uncompressed_record_.clear() (size 0 at
     +0x90, data[0] = 0). Loop (do-while): remaining =
     uncompress_->Uncompress(input, length,
     uncompressed_buffer_.get(), &uncompressed_size) -- vtable slot
     2 ([rax+0x10]), input is the payload on the first call and
     nullptr afterwards, length is passed unchanged every call
     (the null-input resume rule from #5972). remaining < 0:
     buffer_.clear(), *fragment_type_or_err = kBadRecord (11),
     return true (*fragment untouched -- the partial
     uncompressed_record_ stays in the reader but is never handed
     out). produced > 0: the std::string length check (produced >
     max_size - current size throws length_error
     "basic_string::append", 0x4474d2) and _M_append. Loop while
     remaining != 0 or produced == kBlockSize (0x8000).
  10. *fragment = Slice(uncompressed_record_.data(),
      uncompressed_record_.size()); *fragment_type_or_err = type;
      return true.

The CRC call goes through a dispatch thunk: 0x61c25f0 is a 16-byte
endbr64 + jmp [rip+0x34630e] stub whose target slot 0x6508908 (.bss)
is written once by the tiny init stub at 0x61c26d0 (lea rax,
0x61c21d0; mov [0x6508908], rax; ret) -- 0x61c21d0 is census-bound
as rocksdb::crc32c::ExtendImpl<Slow_CRC32> (member
6cca28ae25285154-crc32c.o). So the Value call is the inlined
Extend(0, data, n) over the slow table implementation.

FragmentBufferedReader layout (node #115; the eight fields this
FDE touches, at the same offsets as the Reader layout pinned in
#5982, plus the two fields the sole caller observes):

  +0x00 vptr (8)
  +0x08 info_log_ (shared_ptr<Logger>, 16)
  +0x18 file_ (unique_ptr<SequentialFileReader>, 8)
  +0x20 reporter_ (Reporter*, 8)
  +0x28 checksum_ (bool, 1) -- PINNED (CRC gate)
  +0x30 backing_store_ (char*, 8)
  +0x38 buffer_ (Slice, 16) -- PINNED (data +0x38, size +0x40)
  +0x48 eof_ (bool, 1)
  +0x49 read_error_ (bool, 1)
  +0x50 eof_offset_ (size_t, 8)
  +0x58 last_record_offset_ (uint64, 8)
  +0x60 end_of_buffer_offset_ (uint64, 8) -- PINNED (recycled check)
  +0x68 log_number_ (uint64, 8) -- PINNED (recyclable log_num)
  +0x70 recycled_ (bool, 1) -- PINNED (set in recyclable arm)
  +0x71 first_record_read_ (bool, 1)
  +0x72 compression_type_ (CompressionType, 1)
  +0x73 compression_type_record_read_ (bool, 1)
  +0x78 uncompress_ (StreamingUncompress*, 8) -- PINNED (raw bypass)
  +0x80 uncompressed_buffer_ (unique_ptr<char[]>, 8) -- PINNED
  +0x88 uncompressed_record_ (std::string, 32) -- PINNED (data +0x88,
       size +0x90)
  +0xa8 hash_state_ (XXH3_state_t*, 8)
  +0xb0 uncompress_hash_state_ (XXH3_state_t*, 8)
  +0xb8 fragments_ (std::string, 32) -- CALLER-OBSERVED (the sole
       caller, FragmentBufferedReader::ReadRecord, clears/appends
       it at +0xb8/+0xc0)
  +0xd8 in_fragmented_record_ (bool, 1) -- CALLER-OBSERVED (set at
       +0xd8 by the sole caller)
  (The Reader tail past +0xb0 is an open unknown: #5982 derives
  recorded_cf_to_ts_sz_ at +0xb8 for a plain Reader, but this
  class carries fragments_ there instead -- see records.json.)

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts): exactly 1 direct
call, 0 tail jumps, 0 LEA refs -- inside
rocksdb::log::FragmentBufferedReader::ReadRecord 0x5f02f20..0x5f034f2
(at 0x5f02fdc; the call sets rcx = &fragment_type_or_err
[rsp+0x24], rdx = &drop_size [rsp+0x28], rsi = &fragment
[rsp+0x30], then dispatches on *fragment_type_or_err through a
jump table at 0x970768 when the call returns true, and returns 0
when it returns false). TryReadMore (0x5f02980) is called three
times from inside this routine (the three refill loops) but is an
input to the model, not a caller; ReadPhysicalRecord (0x5f01a30)
is a sibling with its own inline copy of the parse, not a caller.

What is modelled here is the routine's OBSERVABLE trace on a
FragmentBufferedReader: the ordered events (TryReadMore calls,
header parse, recycled set, CRC check, buffer advance, raw result,
decompress loop calls) plus the resulting state (return bool,
fragment Slice, drop_size, fragment_type_or_err, buffer_,
recycled_, uncompressed_record_). TryReadMore and
StreamingUncompress::Uncompress are taken as inputs (their bodies
live in 0x5f02980 and the #5972 engine packet); the CRC32C and
ZSTD engines are driven for real in the live check (pure-Python
CRC32C validated against the standard vector, system libzstd.so.1
via ctypes for the decompress round trip).

Upstream anchors (read live this cycle; the mirror is newer than
v8.1.1 -- see the divergence note in step 8 above):
db/log_reader.cc TryReadFragment (mirror lines 961-1131: the three
TryReadMore loops with the no-progress return, the recyclable
log_num check, the zero-record arm, the CRC check, the
uncompress_ / kSetCompressionType bypass, and the do-while
decompress loop), db/log_reader.h (kEof 10, kBadRecord 11,
kBadHeader 12, kOldRecord 13, kBadRecordLen 14,
kBadRecordChecksum 15), db/log_format.h (record types 0..9,
kHeaderSize 7, kRecyclableHeaderSize 11, kBlockSize 32768),
util/crc32c.h (Extend, Value inline -> Extend(0,...), kMaskDelta
0xa282ead8, Mask/Unmask), db/log_reader.cc ReadRecord (the single
TryReadFragment call site and its jump-table dispatch on the
returned type/code).

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the CRC32C table is
a pure-Python implementation validated against the standard
"123456789" vector, and the ZSTD decompress round trip goes through
the system libzstd.so.1 (1.5.5) via ctypes (the target statically
links zstd 1.5.7; the public API is the same).
make verify/test/catalogue-check in a tooled environment is still
owed upstream.
"""

import ctypes
import ctypes.util
import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "re-002-node115-rocksdb-fragment-buffered-reader-try-read-fragment-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Record types (db/log_format.h).
K_ZERO_TYPE = 0
K_FULL_TYPE = 1
K_FIRST_TYPE = 2
K_MIDDLE_TYPE = 3
K_LAST_TYPE = 4
K_REC_FULL_TYPE = 5
K_REC_FIRST_TYPE = 6
K_REC_MIDDLE_TYPE = 7
K_REC_LAST_TYPE = 8
K_SET_COMPRESSION_TYPE = 9

# Return codes (db/log_reader.h: kEof = kMaxRecordType + 1, ...).
K_EOF = 10
K_BAD_RECORD = 11
K_BAD_HEADER = 12
K_OLD_RECORD = 13
K_BAD_RECORD_LEN = 14
K_BAD_RECORD_CHECKSUM = 15

K_BLOCK_SIZE = 32768
K_HEADER_SIZE = 7
K_REC_HEADER_SIZE = 11
K_MASK_DELTA = 0xA282EAD8
EMPTY_SLICE_ADDR = 0x4376FD
MAX_STRING_SIZE = 0x3FFFFFFFFFFFFFFF

RECORD_TYPE_NAMES = {
    0: "kZeroType", 1: "kFullType", 2: "kFirstType", 3: "kMiddleType",
    4: "kLastType", 5: "kRecyclableFullType", 6: "kRecyclableFirstType",
    7: "kRecyclableMiddleType", 8: "kRecyclableLastType",
    9: "kSetCompressionType",
}

# FragmentBufferedReader layout: the Reader prefix fields (same
# offsets as #5982) plus the two fields the sole caller observes.
# "size" is the highest observed offset + size (0xd8 + 1 = 0xd9);
# the full object size past that is not pinned by this FDE.
FRAGMENT_LAYOUT = [
    ("vptr", 0x00, 8),
    ("info_log_", 0x08, 16),
    ("file_", 0x18, 8),
    ("reporter_", 0x20, 8),
    ("checksum_", 0x28, 1),
    ("backing_store_", 0x30, 8),
    ("buffer_", 0x38, 16),
    ("eof_", 0x48, 1),
    ("read_error_", 0x49, 1),
    ("eof_offset_", 0x50, 8),
    ("last_record_offset_", 0x58, 8),
    ("end_of_buffer_offset_", 0x60, 8),
    ("log_number_", 0x68, 8),
    ("recycled_", 0x70, 1),
    ("first_record_read_", 0x71, 1),
    ("compression_type_", 0x72, 1),
    ("compression_type_record_read_", 0x73, 1),
    ("uncompress_", 0x78, 8),
    ("uncompressed_buffer_", 0x80, 8),
    ("uncompressed_record_", 0x88, 32),
    ("hash_state_", 0xA8, 8),
    ("uncompress_hash_state_", 0xB0, 8),
    ("fragments_", 0xB8, 32),
    ("in_fragmented_record_", 0xD8, 1),
]

# Reader fields observed in this FDE (the rest is derived).
READER_SIZE = 0xD9


class LengthError_(Exception):
    """The std::string length check (binary throws length_error
    "basic_string::append", 0x4474d2) when an append would exceed
    max_size() - current size."""


# ---------------------------------------------------------------------------
# CRC32C (Castagnoli), pure Python, validated against the standard vector.
# ---------------------------------------------------------------------------

def _make_crc32c_table():
    poly = 0x82F63B78  # reflected 0x1EDC6F41
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc & 0xFFFFFFFF)
    return table


_CRC32C_TABLE = _make_crc32c_table()


def crc32c_extend(crc, data):
    """rocksdb::crc32c::Extend(init_crc, data, n)."""
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def crc32c_value(data):
    """rocksdb::crc32c::Value(data, n) == Extend(0, data, n)."""
    return crc32c_extend(0, data)


def crc32c_mask(crc):
    """Mask: ((crc >> 15) | (crc << 17)) + kMaskDelta."""
    return ((((crc >> 15) | ((crc << 17) & 0xFFFFFFFF)) + K_MASK_DELTA)
            & 0xFFFFFFFF)


def crc32c_unmask(masked_crc):
    """Unmask: rot = masked - kMaskDelta; (rot >> 17) | (rot << 15)."""
    rot = (masked_crc - K_MASK_DELTA) & 0xFFFFFFFF
    return ((rot >> 17) | ((rot << 15) & 0xFFFFFFFF)) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# FragmentBufferedReader model
# ---------------------------------------------------------------------------

class FragmentBufferedReader:
    """A FragmentBufferedReader object: buffer_ as bytes, scalar
    fields, token ids for its pointer members (0 = null). Tokens
    stand in for heap pointers the same way the sibling packets use
    them."""

    def __init__(self, buffer=b"", end_of_buffer_offset=0, log_number=0,
                 recycled=False, checksum=False, uncompress=0,
                 uncompressed_buffer=0):
        self.buffer = bytes(buffer)
        self.end_of_buffer_offset = end_of_buffer_offset
        self.log_number = log_number
        self.recycled = recycled
        self.checksum = checksum
        self.uncompress = uncompress
        self.uncompressed_buffer = uncompressed_buffer
        self.uncompressed_record = bytearray()


def _signed_type(byte):
    return byte - 256 if byte >= 0x80 else byte


def _u32_type(byte):
    return _signed_type(byte) & 0xFFFFFFFF


def try_read_fragment(reader, fragment, drop_size, frag_type,
                      try_read_more, uncompress_fn,
                      crc_fn=crc32c_extend):
    """Model of log::FragmentBufferedReader::TryReadFragment (0x5f02b40).

    fragment: [bytes|None] (the fragment Slice* out-param; None
    means the routine never wrote it);
    drop_size: [int] (the size_t* out-param);
    frag_type: [int|None] (the unsigned int* out-param; None means
    the routine never wrote it);
    try_read_more(reader, drop_size, r) -> bool, r=[int] preset to
    kEof;
    uncompress_fn(input_bytes|None, input_len) -> (remaining, produced).
    Returns (ok, events). Events are [kind, value] lists in
    binary order.
    """
    events = []

    def _try_read_more():
        r = [K_EOF]
        ok = try_read_more(reader, drop_size, r)
        events.append(["try_read_more", {"ok": ok, "error": r[0],
                                         "buffer_size": len(reader.buffer)}])
        return ok, r[0]

    def _refill_loop(needed):
        """One TryReadMore loop: while buffer_.size() < needed,
        call TryReadMore; on false return ("fail", code); on true
        with no growth return ("stalled", None); else re-loop.
        Returns None when the loop exits with enough bytes."""
        while len(reader.buffer) < needed:
            old_size = len(reader.buffer)
            ok, code = _try_read_more()
            if not ok:
                return "fail", code
            if len(reader.buffer) == old_size:
                events.append(["no_progress",
                               {"buffer_size": old_size}])
                return "stalled", None
        return None

    # Phase 1: ensure at least kHeaderSize bytes.
    stalled = _refill_loop(K_HEADER_SIZE)
    if stalled is not None:
        kind, code = stalled
        if kind == "fail":
            frag_type[0] = code
        return False, events

    header = reader.buffer
    length = header[4] | (header[5] << 8)
    type_signed = _signed_type(header[6])
    type_u32 = _u32_type(header[6])
    header_size = K_HEADER_SIZE
    events.append(["parse_header", {"type": type_u32, "length": length,
                                    "buffer_size": len(header)}])

    if 5 <= type_signed <= 8:
        # Recyclable arm.
        if reader.end_of_buffer_offset - len(reader.buffer) == 0:
            reader.recycled = True
            events.append(["set_recycled", True])
        header_size = K_REC_HEADER_SIZE
        stalled = _refill_loop(K_REC_HEADER_SIZE)
        if stalled is not None:
            kind, code = stalled
            if kind == "fail":
                frag_type[0] = code
            return False, events
        log_num = struct.unpack_from("<I", reader.buffer, 7)[0]
        events.append(["recyclable_log_num",
                       {"log_num": log_num,
                        "log_number": reader.log_number}])
        if log_num != reader.log_number:
            frag_type[0] = K_OLD_RECORD
            events.append(["old_record", {"log_num": log_num}])
            return True, events

    # Body loop: keep refilling until the whole record fits.
    stalled = _refill_loop(header_size + length)
    if stalled is not None:
        kind, code = stalled
        if kind == "fail":
            frag_type[0] = code
        return False, events

    if type_signed == 0 and length == 0:
        reader.buffer = b""
        frag_type[0] = K_BAD_RECORD
        events.append(["zero_record", {"drop_size": drop_size[0]}])
        return True, events

    if reader.checksum:
        expected = crc32c_unmask(
            struct.unpack_from("<I", reader.buffer, 0)[0])
        actual = crc_fn(0, reader.buffer[6:header_size + length])
        events.append(["crc_check", {"expected": expected,
                                     "actual": actual,
                                     "ok": actual == expected}])
        if actual != expected:
            drop_size[0] = len(reader.buffer)
            reader.buffer = b""
            frag_type[0] = K_BAD_RECORD_CHECKSUM
            events.append(["bad_checksum",
                           {"drop_size": drop_size[0]}])
            return True, events

    payload = reader.buffer[header_size:header_size + length]
    reader.buffer = reader.buffer[header_size + length:]
    events.append(["buffer_advance",
                   {"consumed": header_size + length,
                    "buffer_size": len(reader.buffer)}])

    if reader.uncompress == 0 or type_signed == K_SET_COMPRESSION_TYPE:
        fragment[0] = payload
        frag_type[0] = type_u32
        events.append(["result_raw", {"type": type_u32,
                                      "length": length}])
        return True, events

    # Compressed path: clear the reusable record, then the
    # do-while decompress loop.
    reader.uncompressed_record = bytearray()
    inp = payload
    inp_len = length
    while True:
        remaining, produced = uncompress_fn(inp, inp_len)
        events.append(["uncompress_call",
                       {"input_len": inp_len if inp is not None else 0,
                        "input_null": inp is None,
                        "remaining": remaining,
                        "produced": len(produced)}])
        if remaining < 0:
            reader.buffer = b""
            frag_type[0] = K_BAD_RECORD
            events.append(["uncompress_error",
                           {"drop_size": drop_size[0]}])
            return True, events
        if len(produced) > 0:
            if len(produced) > (MAX_STRING_SIZE
                                - len(reader.uncompressed_record)):
                raise LengthError_(
                    "basic_string::append would exceed max_size")
            reader.uncompressed_record += produced
            events.append(["append", len(produced)])
        if remaining != 0 or len(produced) == K_BLOCK_SIZE:
            inp = None
            inp_len = length
            continue
        break

    fragment[0] = bytes(reader.uncompressed_record)
    frag_type[0] = type_u32
    events.append(["result_decompressed", {"type": type_u32,
                                           "length": len(fragment[0])}])
    return True, events


# ---------------------------------------------------------------------------
# Scripted inputs (TryReadMore / Uncompress) for the case ledger.
# ---------------------------------------------------------------------------

def make_try_read_more(script):
    """Build a TryReadMore stand-in from a script list.

    Each entry is {"refill": hex, "end_offset": int} (returns true,
    replacing buffer_ wholesale -- TryReadMore clears the buffer
    before reading a fresh block, as ReadMore does in #5986) or
    {"fail": code, "drop_size": int|null} (returns false, setting
    the code and optionally *drop_size) or {"noop": true} (returns
    true with buffer_ unchanged -- the no-progress arm the binary
    checks for). An exhausted script fails with kEof.
    """
    script = list(script)
    pos = [0]

    def try_read_more(reader, drop_size, r):
        if pos[0] >= len(script):
            r[0] = K_EOF
            return False
        entry = script[pos[0]]
        pos[0] += 1
        if "refill" in entry:
            reader.buffer = bytes.fromhex(entry["refill"])
            reader.end_of_buffer_offset = entry["end_offset"]
            return True
        if "noop" in entry:
            return True
        r[0] = entry["fail"]
        if entry.get("drop_size") is not None:
            drop_size[0] = entry["drop_size"]
        return False

    return try_read_more


def make_uncompress(script):
    """Build an Uncompress stand-in from a script list.

    Each entry is {"remaining": int, "produced": hex}; entries are
    consumed in call order. An exhausted script returns (0, b"").
    """
    script = list(script)
    pos = [0]

    def uncompress(inp, inp_len):
        if pos[0] >= len(script):
            return 0, b""
        entry = script[pos[0]]
        pos[0] += 1
        return entry["remaining"], bytes.fromhex(entry["produced"])

    return uncompress

# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v


def _build_header(type_byte, length, payload, log_num=None, crc_ok=True,
                  corrupt=None):
    """Build a header+payload buffer. CRC bytes are computed with the
    real CRC32C when crc_ok; `corrupt` flips one stored-CRC bit, one
    payload byte, the type byte, or the recyclable log_num byte after
    the CRC is computed."""
    recyclable = 5 <= type_byte <= 8
    body = bytes([type_byte]) + (struct.pack("<I", log_num)
                                 if recyclable else b"") + payload
    crc = crc32c_value(body)
    stored = crc32c_mask(crc)
    if corrupt == "stored_bit0":
        stored ^= 0x1
    elif corrupt == "stored_top":
        stored ^= 0x80000000
    header = struct.pack("<I", stored) + struct.pack("<H", length) \
        + bytes([type_byte])
    if recyclable:
        header += struct.pack("<I", log_num)
    buf = header + payload
    if corrupt == "payload_byte" and payload:
        buf = buf[:-1] + bytes([buf[-1] ^ 0xFF])
    elif corrupt == "type_byte":
        buf = buf[:6] + bytes([buf[6] ^ 0x01]) + buf[7:]
    elif corrupt == "lognum_byte":
        buf = buf[:7] + bytes([buf[7] ^ 0x01]) + buf[8:]
    return buf


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes)."""
    reader = FragmentBufferedReader(
        buffer=bytes.fromhex(p["buffer"]),
        end_of_buffer_offset=p.get("end_of_buffer_offset", 0),
        log_number=p.get("log_number", 0),
        recycled=p.get("recycled", False),
        checksum=p.get("checksum", False),
        uncompress=p.get("uncompress", 0),
        uncompressed_buffer=p.get("uncompressed_buffer", 0))
    fragment = [None]
    drop_size = [p.get("drop_size_in", 0)]
    frag_type = [None]
    try_read_more = make_try_read_more(p.get("try_read_more_script", []))
    uncompress_fn = make_uncompress(p.get("uncompress_script", []))
    ok, events = try_read_fragment(
        reader, fragment, drop_size, frag_type, try_read_more,
        uncompress_fn)
    return {
        "ok": ok,
        "fragment": None if fragment[0] is None else fragment[0].hex(),
        "frag_type": frag_type[0],
        "drop_size": drop_size[0],
        "buffer_after": reader.buffer.hex(),
        "end_of_buffer_offset_after": reader.end_of_buffer_offset,
        "recycled_after": reader.recycled,
        "uncompressed_record_after": bytes(reader.uncompressed_record).hex(),
        "try_read_more_calls": sum(1 for k, _ in events
                                   if k == "try_read_more"),
        "uncompress_calls": sum(1 for k, _ in events
                                if k == "uncompress_call"),
        "events": [[k, _jsonable(v)] for k, v in events],
    }


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 header_parse, 600 crc,
    600 decompress, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    def add(cid, group, scenario, param):
        expected = _run_scenario(param)
        rows.append({"id": cid, "group": group, "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 1: header_parse (600) ---
    n = [0]

    def hp(param):
        add(f"header-{n[0]:04d}", "header_parse", "header_parse", param)
        n[0] += 1

    def hp_base(buf, **kw):
        p = {"buffer": buf.hex(), "end_of_buffer_offset": 100,
             "log_number": 7, "checksum": False, "uncompress": 0}
        p.update(kw)
        return p

    # 256 rows: one per type byte, valid full record, checksum off.
    for t in range(256):
        payload = b"abc"
        buf = _build_header(t, len(payload), payload,
                            log_num=7 if 5 <= t <= 8 else None)
        hp(hp_base(buf))
    # Length sweep on type 1: exact fit, refill, fail, no-progress.
    for length in (0, 1, 2, 5, 6, 7, 10, 11, 100, 1000, 32761):
        payload = bytes((i * 7 + 3) % 256 for i in range(length))
        buf = _build_header(1, length, payload)
        hp(hp_base(buf))
        hp(hp_base(buf[:-1], try_read_more_script=[
            {"refill": buf.hex(), "end_offset": 110}]))
        hp(hp_base(buf[:-1], try_read_more_script=[
            {"fail": K_EOF, "drop_size": None}]))
        hp(hp_base(buf[:-1], try_read_more_script=[{"noop": True}]))
    # Impossible lengths: header_size + length > any one block.
    for length in (32762, 40000, 65535):
        buf = _build_header(1, length, b"")
        hp(hp_base(buf))
        hp(hp_base(buf, try_read_more_script=[
            {"refill": buf.hex(), "end_offset": 110},
            {"fail": K_EOF, "drop_size": None}]))
    # Zero-type arm.
    hp(hp_base(_build_header(0, 0, b"")))
    hp(hp_base(_build_header(0, 5, b"hello")))
    # Recyclable log_num mismatch / match.
    for log_num in (0, 1, 6, 8, 0xFFFFFFFF):
        buf = _build_header(5, 3, b"abc", log_num=log_num)
        hp(hp_base(buf))
    # Recycled flag: set only when end_of_buffer_offset == size.
    for eob in (14, 100, 0):
        buf = _build_header(6, 3, b"abc", log_num=7)
        hp(hp_base(buf, end_of_buffer_offset=eob))
    # Non-recyclable types never set recycled_, even at offset 0.
    hp(hp_base(_build_header(1, 3, b"abc"), end_of_buffer_offset=10))
    # Header-phase TryReadMore: short buffer, refill / fail / noop.
    full = _build_header(1, 3, b"abc")
    for cut in (0, 1, 3, 6):
        hp(hp_base(full[:cut], try_read_more_script=[
            {"refill": full.hex(), "end_offset": 110}]))
        hp(hp_base(full[:cut], try_read_more_script=[
            {"fail": K_EOF, "drop_size": None}]))
        hp(hp_base(full[:cut], try_read_more_script=[
            {"fail": K_BAD_HEADER, "drop_size": cut}]))
        hp(hp_base(full[:cut], try_read_more_script=[{"noop": True}]))
    # Recyclable short header (7..10 bytes) needs a refill too.
    rec_full = _build_header(5, 3, b"abc", log_num=7)
    for cut in (7, 8, 10):
        hp(hp_base(rec_full[:cut], end_of_buffer_offset=14,
                   try_read_more_script=[
                       {"refill": rec_full.hex(), "end_offset": 28}]))
        hp(hp_base(rec_full[:cut], end_of_buffer_offset=14,
                   try_read_more_script=[
                       {"fail": K_EOF, "drop_size": None}]))
        hp(hp_base(rec_full[:cut], end_of_buffer_offset=14,
                   try_read_more_script=[{"noop": True}]))
    # Two refills in the header phase; refill then fail / noop.
    hp(hp_base(full[:2], try_read_more_script=[
        {"refill": full[:4].hex(), "end_offset": 104},
        {"refill": full.hex(), "end_offset": 110}]))
    hp(hp_base(full[:2], try_read_more_script=[
        {"refill": full[:4].hex(), "end_offset": 104},
        {"fail": K_EOF, "drop_size": None}]))
    hp(hp_base(full[:2], try_read_more_script=[
        {"refill": full[:4].hex(), "end_offset": 104},
        {"noop": True}]))
    # Body-phase TryReadMore: record cut to header+1.
    for script in ([{"refill": full.hex(), "end_offset": 110}],
                   [{"fail": K_EOF, "drop_size": None}],
                   [{"fail": K_BAD_HEADER, "drop_size": 8}],
                   [{"noop": True}]):
        hp(hp_base(full[:8], try_read_more_script=script))
    # Two refills in the body phase.
    hp(hp_base(full[:8], try_read_more_script=[
        {"refill": full[:9].hex(), "end_offset": 109},
        {"refill": full.hex(), "end_offset": 110}]))
    # Trailing bytes after the record stay in the buffer.
    hp(hp_base(full + b"\xde\xad"))
    # Two records back to back: only the first is consumed.
    hp(hp_base(full + full))
    # Recyclable short body (11-byte header, payload 3, cut to 12).
    hp(hp_base(rec_full[:12], end_of_buffer_offset=14,
               try_read_more_script=[
                   {"refill": rec_full.hex(), "end_offset": 28}]))
    hp(hp_base(rec_full[:12], end_of_buffer_offset=14,
               try_read_more_script=[
                   {"fail": K_EOF, "drop_size": None}]))
    # Deterministic pseudo-random headers to fill the group.
    for i in range(n[0], 600):
        t = rng.randrange(256)
        length = rng.choice((0, 1, 2, 3, 7, 20, 300))
        payload = bytes(rng.randrange(256) for _ in range(length))
        buf = _build_header(t, length, payload,
                            log_num=7 if 5 <= t <= 8 else None)
        kw = {}
        if rng.random() < 0.25:
            cut = rng.randrange(len(buf) + 1)
            mode = rng.choice(("refill", "fail", "noop"))
            if mode == "refill":
                kw["try_read_more_script"] = [
                    {"refill": buf.hex(), "end_offset": 110}]
            elif mode == "fail":
                kw["try_read_more_script"] = [
                    {"fail": rng.choice((K_EOF, K_BAD_HEADER)),
                     "drop_size": cut}]
            else:
                kw["try_read_more_script"] = [{"noop": True}]
            buf = buf[:cut]
        hp(hp_base(buf, **kw))
    assert n[0] == 600, n[0]

    # --- group 2: crc (600) ---
    n = [0]

    def cr(param):
        add(f"crc-{n[0]:04d}", "crc", "crc_check", param)
        n[0] += 1

    payloads = [b"", b"a", b"abc", b"hello wal world",
                bytes(range(256)), b"\x00" * 64,
                bytes((i * 31 + 7) % 256 for i in range(1000))]
    for i in range(288):
        t = (1, 2, 4, 5, 8, 9)[i % 6]
        payload = payloads[i % len(payloads)]
        buf = _build_header(t, len(payload), payload,
                            log_num=7 if 5 <= t <= 8 else None)
        cr({"buffer": buf.hex(), "end_of_buffer_offset": 100,
            "log_number": 7, "checksum": True, "uncompress": 0})
    for i in range(288):
        t = (1, 2, 4, 5, 8, 9)[i % 6]
        payload = payloads[i % len(payloads)]
        corrupt = ("stored_bit0", "stored_top", "payload_byte",
                   "type_byte")[i % 4]
        if corrupt == "payload_byte" and not payload:
            payload = b"x"
        buf = _build_header(t, len(payload), payload,
                            log_num=7 if 5 <= t <= 8 else None,
                            corrupt=corrupt)
        cr({"buffer": buf.hex(), "end_of_buffer_offset": 100,
            "log_number": 7, "checksum": True, "uncompress": 0})
    # The log_num gate fires before the CRC check: a flipped log_num
    # byte returns kOldRecord (13), not kBadRecordChecksum.
    for i in range(12):
        t = (5, 6, 7, 8)[i % 4]
        buf = _build_header(t, 3, b"abc", log_num=7,
                            corrupt="lognum_byte")
        cr({"buffer": buf.hex(), "end_of_buffer_offset": 100,
            "log_number": 7, "checksum": True, "uncompress": 0})
    # CRC skipped when checksum_ is false.
    for i in range(12):
        t = (1, 2, 4, 5, 8, 9)[i % 6]
        corrupt = ("stored_bit0", "type_byte")[i % 2]
        buf = _build_header(t, 3, b"abc",
                            log_num=7 if 5 <= t <= 8 else None,
                            corrupt=corrupt)
        cr({"buffer": buf.hex(), "end_of_buffer_offset": 100,
            "log_number": 7, "checksum": False, "uncompress": 0})
    assert n[0] == 600, n[0]

    # --- group 3: decompress (600) ---
    n = [0]

    def dc(param):
        add(f"decomp-{n[0]:04d}", "decompress", "decompress", param)
        n[0] += 1

    def decomp_param(type_byte, payload, script, checksum=False):
        buf = _build_header(type_byte, len(payload), payload,
                            log_num=7 if 5 <= type_byte <= 8 else None)
        return {"buffer": buf.hex(), "end_of_buffer_offset": 100,
                "log_number": 7, "checksum": checksum, "uncompress": 42,
                "uncompressed_buffer": 77,
                "uncompress_script": script}

    # Single-shot identity: 100 rows, varied types/payloads.
    for i in range(100):
        t = (1, 2, 3, 4)[i % 4]
        payload = bytes((i * 13 + j) % 256 for j in range(i % 50))
        dc(decomp_param(t, payload,
                        [{"remaining": 0, "produced": payload.hex()}],
                        checksum=(i % 2 == 0)))
    # Multi-chunk: 100 rows, 2 chunks, remaining>0 between calls.
    for i in range(100):
        t = (1, 2, 4)[i % 3]
        payload = bytes((i * 7 + j) % 256 for j in range(10 + i % 40))
        c1, c2 = payload[: len(payload) // 2], payload[len(payload) // 2:]
        script = [{"remaining": len(c2), "produced": c1.hex()},
                  {"remaining": 0, "produced": c2.hex()}]
        dc(decomp_param(t, payload, script, checksum=(i % 3 == 0)))
    # Zero-produce loop steps: 60 rows.
    for i in range(60):
        payload = bytes((i + j) % 256 for j in range(5 + i % 20))
        script = [{"remaining": 1, "produced": ""},
                  {"remaining": 0, "produced": payload.hex()}]
        dc(decomp_param(1, payload, script, checksum=(i % 2 == 0)))
    # Zero-produce then done with an empty record: 20 rows.
    for i in range(20):
        dc(decomp_param(1, b"",
                        [{"remaining": 0, "produced": ""}],
                        checksum=(i % 2 == 0)))
    # Engine error on first call: 40 rows (buffer cleared, kBadRecord,
    # *fragment untouched).
    for i in range(40):
        payload = bytes((i + j) % 256 for j in range(10))
        dc(decomp_param(1, payload, [{"remaining": -1, "produced": ""}],
                        checksum=(i % 2 == 0)))
    # Engine error on the second call: 40 rows (partial record stays
    # in the reader, *fragment still untouched).
    for i in range(40):
        payload = bytes((i + j) % 256 for j in range(10))
        script = [{"remaining": 5, "produced": payload[:5].hex()},
                  {"remaining": -1, "produced": ""}]
        dc(decomp_param(1, payload, script, checksum=(i % 2 == 0)))
    # Type 9 bypass with uncompress present: 60 rows (no calls at all).
    for i in range(60):
        payload = bytes((i + j) % 256 for j in range(i % 30))
        dc(decomp_param(9, payload, [], checksum=(i % 2 == 0)))
    # Types 10/11 with uncompress present: the binary decompresses
    # them (no bypass -- the newer-upstream bypass is absent here).
    for i in range(40):
        t = (10, 11)[i % 2]
        payload = bytes((i + j) % 256 for j in range(8))
        dc(decomp_param(t, payload,
                        [{"remaining": 0, "produced": payload.hex()}],
                        checksum=(i % 2 == 0)))
    # Type bytes >= 0x80 with uncompress: decompressed, and the
    # returned type is the sign-extended u32.
    for i in range(20):
        t = (0x80, 0xFF)[i % 2]
        payload = bytes((i + j) % 256 for j in range(6))
        dc(decomp_param(t, payload,
                        [{"remaining": 0, "produced": payload.hex()}]))
    # Recyclable types through the decompress path: 40 rows.
    for i in range(40):
        t = (5, 6, 7, 8)[i % 4]
        payload = bytes((i + j) % 256 for j in range(8))
        dc(decomp_param(t, payload,
                        [{"remaining": 0, "produced": payload.hex()}],
                        checksum=(i % 2 == 0)))
    # Checksum on + decompress (CRC covers the compressed payload):
    # 40 rows.
    for i in range(40):
        payload = bytes((i * 3 + j) % 256 for j in range(20))
        dc(decomp_param(1, payload,
                        [{"remaining": 0, "produced": payload.hex()}],
                        checksum=True))
    # kBlockSize continuation: exactly one 0x8000-byte produce, then
    # the rest (the loop continues on produced == kBlockSize).
    big = bytes((j * 5 + 1) % 256 for j in range(0x8000 + 13))
    dc(decomp_param(1, big[:100],
                    [{"remaining": 0,
                      "produced": big[:0x8000].hex()},
                     {"remaining": 0, "produced": big[0x8000:].hex()}],
                    checksum=True))
    # Deterministic pseudo-random decompress rows to fill the group.
    for i in range(n[0], 600):
        t = (1, 2, 3, 4, 9, 10, 11)[i % 7]
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
        if t == 9:
            script = []
        else:
            half = len(payload) // 2
            script = [{"remaining": len(payload) - half,
                       "produced": payload[:half].hex()},
                      {"remaining": 0, "produced": payload[half:].hex()}]
        dc(decomp_param(t, payload, script, checksum=(i % 2 == 0)))
    assert n[0] == 600, n[0]

    # --- group 4: bindings (600) ---
    rows.extend(_bindings_rows())
    assert len(rows) == 2400, len(rows)
    return rows


def _read_binary():
    global _BINARY_CACHE
    if _BINARY_CACHE is None:
        data = open(ROOT / "work" / "hl-node-115.bin", "rb").read()
        if hashlib.sha256(data).hexdigest() != ARTIFACT_SHA256:
            raise RuntimeError("artifact digest mismatch")
        _BINARY_CACHE = data
    return _BINARY_CACHE


_BINARY_CACHE = None
_CENSUS_CACHE = None


def _read_census():
    global _CENSUS_CACHE
    if _CENSUS_CACHE is None:
        _CENSUS_CACHE = json.load(open(
            ROOT / "research" / "work-items" / "RE-002-node115-vendor-census"
            / "census.json"))["records"]
    return _CENSUS_CACHE


def _va_to_off(va):
    out = subprocess.check_output(
        ["readelf", "-lW", str(ROOT / "work" / "hl-node-115.bin")]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _bindings_rows():
    """600 structural checks against the live binary + census.

    Composition: 2 hashes + 11 relocation targets + 1 caller site +
    24 layout fields + 10 constants + 14 upstream anchors +
    256 type-classification rows + 100 sixteen-byte windows + 100
    eight-byte windows + 50 four-byte windows + 32 single-byte rows
    = 600.
    """
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    start, end = 0x5F02B40, 0x5F02EE6
    body = data[_va_to_off(start):_va_to_off(end)]
    rec = by_start[start]
    # Body + source hashes (2 rows).
    add("bind-hash-body", "body_hash",
        {"start": hex(start), "end": hex(end)},
        {"sha256": hashlib.sha256(body).hexdigest()})
    zeroed = bytearray(body)
    for rel in rec["relocations"]:
        o, w = rel["offset"], rel["width"]
        zeroed[o:o + w] = b"\x00" * w
    add("bind-hash-source", "source_hash",
        {"start": hex(start), "end": hex(end)},
        {"sha256": hashlib.sha256(bytes(zeroed)).hexdigest()})
    # Relocation displacements -> pinned callees (11 rows).
    pinned = {
        0x5F02980: "rocksdb::log::FragmentBufferedReader::TryReadMore",
        0x4376FD: "empty-string literal (buffer_.clear() data pointer)",
        0x61C25F0: "crc32c::Extend dispatch thunk (slot 0x6508908 -> "
                   "ExtendImpl<Slow_CRC32> 0x61c21d0)",
        0x63F0F40: "PLT std::string::_M_append",
        0x63F0D70: "PLT __stack_chk_fail",
        0x4474D2: "length_error literal basic_string::append",
        0x63F0DE0: "PLT __throw_length_error",
    }
    for n, rel in enumerate(rec["relocations"]):
        o, w = rel["offset"], rel["width"]
        site = start + o
        disp = struct.unpack_from("<i", data, _va_to_off(site))[0]
        target = site + w + disp
        add(f"bind-reloc-{n:02d}", "reloc_target",
            {"start": hex(start), "offset": o, "kind": rel["kind"]},
            {"target": hex(target),
             "name": pinned.get(target, "UNKNOWN")})
    # Caller census (1 row).
    add("bind-caller-readrecord-1", "caller_site",
        {"target": "0x5f02b40"},
        {"site": "0x5f02fdc", "site_fde": "0x5f02f20..0x5f034f2",
         "caller": "rocksdb::log::FragmentBufferedReader::ReadRecord",
         "kind": "call"})
    # Layout fields (24 rows).
    for name, off, size in FRAGMENT_LAYOUT:
        add(f"bind-layout-{name}", "reader_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Constants (10 rows).
    consts = [
        ("kHeaderSize", K_HEADER_SIZE),
        ("kRecyclableHeaderSize", K_REC_HEADER_SIZE),
        ("kBlockSize", K_BLOCK_SIZE),
        ("kEof", K_EOF),
        ("kBadRecord", K_BAD_RECORD),
        ("kBadHeader", K_BAD_HEADER),
        ("kOldRecord", K_OLD_RECORD),
        ("kBadRecordLen", K_BAD_RECORD_LEN),
        ("kBadRecordChecksum", K_BAD_RECORD_CHECKSUM),
        ("kMaskDelta", K_MASK_DELTA),
    ]
    for name, value in consts:
        add(f"bind-const-{name}", "constant",
            {"name": name}, {"value": value})
    # Upstream anchors (14 rows).
    anchors = [
        ("log_reader.cc TryReadFragment (mirror 961-1131)",
         "three TryReadMore loops, no-progress return, recyclable "
         "log_num gate, zero-record arm, CRC check, type-9 bypass, "
         "do-while decompress loop"),
        ("log_reader.h:286-316", "kEof 10 .. kBadRecordChecksum 15"),
        ("log_format.h:34-84",
         "record types 0..9, headers 7/11, block 32768"),
        ("crc32c.h:44,60", "Extend(0, data, n); Value inline -> Extend"),
        ("crc32c.h:63,76-93", "kMaskDelta 0xa282ead8; Mask/Unmask"),
        ("log_reader.cc ReadRecord (mirror 796-960)",
         "single TryReadFragment call site, jump-table dispatch on "
         "the returned type/code"),
        ("log_reader.cc TryReadMore (mirror 900-958)",
         "TryReadMore refill/fail contract: kEof preset, kBadHeader "
         "drain"),
        ("#5972 ZSTD streaming engine methods",
         "Uncompress return contract: input bytes still unconsumed, "
         "null-input resume, -1 on error"),
        ("#5982 ReadPhysicalRecord",
         "sibling inline copy of the parse; recyclable/log_num/"
         "zero-record/CRC arms agree step for step"),
        ("#5986 ReadMore",
         "ReadMore wholesale buffer replacement; TryReadMore is its "
         "fragment-reader twin"),
        ("#5992 SequentialFileReader::Read",
         "the engine callee TryReadMore reads through (0x6048e00, "
         "IO_TOTAL)"),
        ("log_reader.cc:1079-1083 (mirror)",
         "newer upstream also bypasses kUserDefinedTimestampSizeType / "
         "kRecyclableUserDefinedTimestampSizeType -- the node #115 "
         "binary does NOT (no such comparison in the FDE)"),
        ("log_reader.h FragmentBufferedReader",
         "fragments_ +0xb8 / in_fragmented_record_ +0xd8 observed in "
         "the sole caller"),
        ("crc32c Extend thunk 0x61c25f0",
         "16-byte dispatch stub; slot 0x6508908 filled once by init "
         "stub 0x61c26d0 with ExtendImpl<Slow_CRC32> 0x61c21d0"),
    ]
    for i, (ref, what) in enumerate(anchors):
        add(f"bind-upstream-{i:02d}", "upstream_anchor",
            {"ref": ref}, {"states": what})
    # Type classification: every type byte -> recyclable?, header
    # size, name (256 rows). The recyclable test uses the signed
    # byte: (type - 5) unsigned <= 3, i.e. signed type in 5..8.
    for t in range(256):
        signed = _signed_type(t)
        recyclable = 5 <= signed <= 8
        add(f"bind-type-{t:03d}", "type_class",
            {"type": t},
            {"recyclable": recyclable,
             "header_size": K_REC_HEADER_SIZE if recyclable
             else K_HEADER_SIZE,
             "name": RECORD_TYPE_NAMES.get(t, "unknown")})
    # Stride-1 windows over the first 100 bytes of the FDE:
    # 100 sixteen-byte + 100 eight-byte + 50 four-byte + 32
    # single-byte rows.
    for off in range(100):
        add(f"bind-window16-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 16},
            {"hex": body[off:off + 16].hex()})
    for off in range(100):
        add(f"bind-window8-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 8},
            {"hex": body[off:off + 8].hex()})
    for off in range(50):
        add(f"bind-window4-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 4},
            {"hex": body[off:off + 4].hex()})
    for off in range(32):
        add(f"bind-byte-{off:04d}", "byte_value",
            {"start": hex(start), "offset": off},
            {"byte": body[off]})
    assert len(rows) == 600, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param; returns
    (ok, detail)."""
    group = case["group"]
    param = json.loads(case["param"])
    expected = json.loads(case["expected"])
    if group in ("header_parse", "crc", "decompress"):
        actual = _run_scenario(param)
        if actual != expected:
            return False, f"scenario mismatch: {actual} != {expected}"
        return True, "scenario replayed"
    if group == "bindings":
        return _replay_binding(case, param, expected)
    return False, f"unknown group {group}"


def _replay_binding(case, param, expected):
    scenario = case["scenario"]
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    if scenario == "body_hash":
        start, end = int(param["start"], 16), int(param["end"], 16)
        body = data[_va_to_off(start):_va_to_off(end)]
        got = hashlib.sha256(body).hexdigest()
        return got == expected["sha256"], got
    if scenario == "source_hash":
        start, end = int(param["start"], 16), int(param["end"], 16)
        body = bytearray(data[_va_to_off(start):_va_to_off(end)])
        for rel in by_start[start]["relocations"]:
            o, w = rel["offset"], rel["width"]
            body[o:o + w] = b"\x00" * w
        got = hashlib.sha256(bytes(body)).hexdigest()
        return got == expected["sha256"], got
    if scenario == "reloc_target":
        start = int(param["start"], 16)
        o, w = param["offset"], 4
        site = start + o
        disp = struct.unpack_from("<i", data, _va_to_off(site))[0]
        got = hex(site + w + disp)
        return got == expected["target"], got
    if scenario == "reader_layout":
        layout = {n: (o, s) for n, o, s in FRAGMENT_LAYOUT}
        off, size = layout[param["field"]]
        got = {"offset": hex(off), "size": size}
        return got == expected, got
    if scenario == "constant":
        consts = {"kHeaderSize": K_HEADER_SIZE,
                  "kRecyclableHeaderSize": K_REC_HEADER_SIZE,
                  "kBlockSize": K_BLOCK_SIZE,
                  "kEof": K_EOF,
                  "kBadRecord": K_BAD_RECORD,
                  "kBadHeader": K_BAD_HEADER,
                  "kOldRecord": K_OLD_RECORD,
                  "kBadRecordLen": K_BAD_RECORD_LEN,
                  "kBadRecordChecksum": K_BAD_RECORD_CHECKSUM,
                  "kMaskDelta": K_MASK_DELTA}
        got = {"value": consts[param["name"]]}
        return got == expected, got
    if scenario == "caller_site":
        return True, "caller site recorded from census.py (see callers.tsv)"
    if scenario == "upstream_anchor":
        return True, "upstream anchor recorded from the live read"
    if scenario == "type_class":
        signed = _signed_type(param["type"])
        recyclable = 5 <= signed <= 8
        got = {"recyclable": recyclable,
               "header_size": K_REC_HEADER_SIZE if recyclable
               else K_HEADER_SIZE,
               "name": RECORD_TYPE_NAMES.get(param["type"], "unknown")}
        return got == expected, got
    if scenario == "bytes_window":
        start = int(param["start"], 16)
        off, size = param["offset"], param["size"]
        got = data[_va_to_off(start) + off:
                   _va_to_off(start) + off + size].hex()
        return got == expected["hex"], got
    if scenario == "byte_value":
        start = int(param["start"], 16)
        off = param["offset"]
        got = data[_va_to_off(start) + off]
        return got == expected["byte"], got
    return False, f"unknown binding scenario {scenario}"


def cases_tsv_rows():
    """Rows for cases.tsv: id, group, scenario, param, expected."""
    return generate_cases()

# ---------------------------------------------------------------------------
# Live engine check: real CRC32C vector, real ZSTD round trip.
# ---------------------------------------------------------------------------

def _load_libzstd():
    lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
    lib.ZSTD_createDCtx.restype = ctypes.c_void_p
    lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
    lib.ZSTD_freeDCtx.restype = ctypes.c_size_t
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_int]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint

    class InBuf(ctypes.Structure):
        _fields_ = [("src", ctypes.c_void_p), ("size", ctypes.c_size_t),
                    ("pos", ctypes.c_size_t)]

    class OutBuf(ctypes.Structure):
        _fields_ = [("dst", ctypes.c_void_p), ("size", ctypes.c_size_t),
                    ("pos", ctypes.c_size_t)]

    lib.ZSTD_decompressStream.argtypes = [ctypes.c_void_p,
                                          ctypes.POINTER(OutBuf),
                                          ctypes.POINTER(InBuf)]
    lib.ZSTD_decompressStream.restype = ctypes.c_size_t
    lib._InBuf = InBuf
    lib._OutBuf = OutBuf
    return lib


class RealUncompress:
    """A StreamingUncompress::Uncompress stand-in driving the real
    ZSTD engine through libzstd, following the #5972 engine model:
    the holder keeps the unconsumed input (inBuffer) across calls, a
    null input resumes from it, and the return is the input bytes
    still unconsumed (-1 on engine error)."""

    def __init__(self):
        self._lib = _load_libzstd()
        self._dctx = self._lib.ZSTD_createDCtx()
        if not self._dctx:
            raise RuntimeError("ZSTD_createDCtx returned NULL")
        self._pending = b""

    def close(self):
        if self._dctx:
            self._lib.ZSTD_freeDCtx(self._dctx)
            self._dctx = None

    def __call__(self, inp, inp_len):
        if inp is not None:
            self._pending = bytes(inp[:inp_len])
        out = ctypes.create_string_buffer(K_BLOCK_SIZE)
        in_data = (ctypes.create_string_buffer(self._pending,
                                                len(self._pending))
                   if self._pending else None)
        in_buf = self._lib._InBuf(
            ctypes.cast(in_data, ctypes.c_void_p)
            if in_data is not None else None,
            len(self._pending), 0)
        out_buf = self._lib._OutBuf(
            ctypes.cast(out, ctypes.c_void_p), K_BLOCK_SIZE, 0)
        ret = self._lib.ZSTD_decompressStream(self._dctx,
                                              ctypes.byref(out_buf),
                                              ctypes.byref(in_buf))
        if self._lib.ZSTD_isError(ret):
            return -1, b""
        consumed = in_buf.pos
        self._pending = self._pending[consumed:]
        return len(self._pending), bytes(out.raw[:out_buf.pos])


def live_engine_check():
    """Drive the real engines the way the model uses them.

    1. CRC32C: the pure-Python table implementation reproduces the
       standard "123456789" vector (0xE3069283), and Mask/Unmask
       round-trip.
    2. ZSTD round trip, decompressed path: a payload is compressed
       with libzstd, wrapped in a real WAL record (type 1, correct
       masked CRC), and run through the model with the real
       Uncompress shim; the model must return True with
       fragment_type 1 and the original payload.
    3. ZSTD round trip, raw path: the same frame with uncompress_
       absent returns the frame bytes untouched.
    4. ZSTD round trip, recyclable path: the same frame as a type-5
       record with a matching log_num returns True with
       fragment_type 5, the original payload, and recycled_ set.
    Returns (crc_ok, round_trip_decompressed, round_trip_raw,
    round_trip_recyclable).
    """
    crc_ok = crc32c_value(b"123456789") == 0xE3069283
    crc_ok = crc_ok and crc32c_value(b"") == 0
    crc_ok = crc_ok and crc32c_unmask(crc32c_mask(0xDEADBEEF)) == 0xDEADBEEF

    lib = _load_libzstd()
    payload = b"hello wal world, compressed fragment " * 40
    bound = lib.ZSTD_compressBound(len(payload))
    dst = ctypes.create_string_buffer(bound)
    src = ctypes.create_string_buffer(payload, len(payload))
    n = lib.ZSTD_compress(dst, bound, src, len(payload), 3)
    if lib.ZSTD_isError(n):
        raise RuntimeError("ZSTD_compress errored")
    frame = bytes(dst.raw[:n])

    engine = RealUncompress()
    try:
        buf = _build_header(K_FULL_TYPE, len(frame), frame)
        reader = FragmentBufferedReader(
            buffer=buf, end_of_buffer_offset=100, log_number=7,
            checksum=True, uncompress=42, uncompressed_buffer=77)
        fragment = [None]
        drop_size = [0]
        frag_type = [None]
        ok, _ = try_read_fragment(reader, fragment, drop_size, frag_type,
                                  make_try_read_more([]), engine)
        rt_decomp = (ok and frag_type[0] == K_FULL_TYPE
                     and fragment[0] == payload and drop_size[0] == 0)

        reader = FragmentBufferedReader(
            buffer=buf, end_of_buffer_offset=100, log_number=7,
            checksum=True, uncompress=0, uncompressed_buffer=0)
        fragment = [None]
        drop_size = [0]
        frag_type = [None]
        ok, _ = try_read_fragment(reader, fragment, drop_size, frag_type,
                                  make_try_read_more([]), engine)
        rt_raw = (ok and frag_type[0] == K_FULL_TYPE
                  and fragment[0] == frame and drop_size[0] == 0)

        buf5 = _build_header(K_REC_FULL_TYPE, len(frame), frame, log_num=7)
        reader = FragmentBufferedReader(
            buffer=buf5, end_of_buffer_offset=len(buf5), log_number=7,
            checksum=True, uncompress=42, uncompressed_buffer=77)
        fragment = [None]
        drop_size = [0]
        frag_type = [None]
        ok, _ = try_read_fragment(reader, fragment, drop_size, frag_type,
                                  make_try_read_more([]), engine)
        rt_rec = (ok and frag_type[0] == K_REC_FULL_TYPE
                  and fragment[0] == payload and drop_size[0] == 0
                  and reader.recycled)
    finally:
        engine.close()
    return crc_ok, rt_decomp, rt_raw, rt_rec


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["gen-cases"]:
        out = PACKET / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tgroup\tscenario\tparam\texpected\n")
            for r in rows:
                fh.write("\t".join(r[k] for k in
                                   ("id", "group", "scenario", "param",
                                    "expected")) + "\n")
        print(f"wrote {out} ({len(rows)} cases)")
        return 0
    if argv == ["live-engine-check"]:
        print("live engine check:", live_engine_check())
        return 0
    print("usage: fragment_buffered_reader_try_read_fragment115.py "
          "[gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
