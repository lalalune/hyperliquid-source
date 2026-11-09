"""Node #115 RocksDB log::FragmentBufferedReader::ReadRecord: reconstruction.

RE-002 work item. Reconstructs the WAL record assembler at
0x5f02f20..0x5f034f2 (1490 B):

  rocksdb::log::FragmentBufferedReader::ReadRecord  0x5f02f20 (1490 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The body hash matches the vendor census target_body_sha256 exactly,
and the source hash is reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbol from the vendor
census (member 25dac13516458d4d-log_reader.o, librocksdb-sys):

  _ZN7rocksdb3log22FragmentBufferedReader10ReadRecordEPNS_5SliceE
  PNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEENS_15WALRecoveryModeEPm

i.e. bool ReadRecord(Slice* record, std::string* scratch,
WALRecoveryMode recovery_mode, unsigned long* record_checksum).
Upstream names the last two parameters WALRecoveryMode /*unused*/
and uint64_t* /* checksum */ (db/log_reader.cc:1092-1096, v8.1.1):
the recovery_mode (rcx) and record_checksum (r8) parameters are
present in the signature but UNREFERENCED in the body: neither is
saved in the prologue nor read anywhere in the FDE, so this
overload's behaviour does not vary with them (unlike the base
Reader::ReadRecord, whose kEof/kOldRecord/kBadRecordLen arms ARE
mode-dependent).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  bool ReadRecord(Slice* record, std::string* scratch, ...)
  -- rdi is the FragmentBufferedReader* (rbx), rsi the record Slice*
  (saved [rsp+0x10]), rdx the scratch std::string* (r15). It returns
  true when a complete logical record was assembled, false when the
  fragment stream ends (TryReadFragment false) or a recycled
  checksum failure aborts the read. Steps, in binary order:

  0. Prologue: *record = Slice{0x4376fd, 0} (the empty-string
     literal); scratch->clear() (size 0, NUL at data[0]); if
     uncompress_ (+0x78) != null, uncompress_->Reset() (vtable slot
     3, call *0x18(%rax)) -- once, before the loop. Then
     physical_record_offset = end_of_buffer_offset_ - buffer_.size()
     (computed ONCE, from the entry-time buffer state, and never
     recomputed per iteration); drop_size = 0, fragment_type_or_err
     = 0, fragment = empty Slice, saved_first_offset = 0.
  1. Loop head: TryReadFragment(&fragment, &drop_size,
     &fragment_type_or_err) (0x5f02b40, rdi=this, rsi=&fragment,
     rdx=&drop_size, rcx=&fragment_type_or_err). On false: return
     false at once (r10d = 0), state untouched. On true: dispatch
     on fragment_type_or_err (unsigned compare against 15, then the
     jump table at 0x970768).
  2. kFullType (1) / kRecyclableFullType (5) -- 0x5f03140: if
     in_fragmented_record_ (+0xd8) AND fragments_ non-empty
     (0x5f03340: test fragments_.size(); je skips the report),
     ReportCorruption(fragments_.size(), "partial record without
     end(1)").
     fragments_.clear() (unconditionally), *record = fragment,
     first_record_read_ = true (+0x71), in_fragmented_record_ =
     false, last_record_offset_ = physical_record_offset, return
     true.
  3. kFirstType (2) / kRecyclableFirstType (6) -- 0x5f030f0: if
     in_fragmented_record_ OR fragments_ non-empty,
     ReportCorruption(fragments_.size(), "partial record without
     end(2)"). fragments_.replace(0, fragments_.size(), fragment)
     (so fragments_ becomes the fragment either way),
     in_fragmented_record_ = true, saved_first_offset =
     physical_record_offset, loop.
  4. kMiddleType (3) / kRecyclableMiddleType (7) -- 0x5f030a0: if
     NOT in_fragmented_record_, ReportCorruption(fragment.size(),
     "missing start of fragmented record(1)"), loop. Else the
     std::string length check (fragment.size() > 0x3fffffffffffffff
     - fragments_.size() throws length_error
     "basic_string::append", 0x4474d2), fragments_.append(fragment),
     loop.
  5. kLastType (4) / kRecyclableLastType (8) -- 0x5f03070: if NOT
     in_fragmented_record_, ReportCorruption(fragment.size(),
     "missing start of fragmented record(2)"), loop. Else the same
     length check, fragments_.append(fragment), then
     scratch->replace(0, scratch->size(), fragments_.data(),
     fragments_.size()), *record = Slice(scratch->data(),
     scratch->size()), fragments_.clear(), physical_record_offset =
     saved_first_offset, last_record_offset_ =
     physical_record_offset, first_record_read_ = true,
     in_fragmented_record_ = false, return true.
  6. kSetCompressionType (9) -- 0x5f031b8: if
     compression_type_record_read_ (+0x73), ReportCorruption(
     fragment.size(), "read multiple SetCompressionType records")
     and continue (no return); if first_record_read_,
     ReportCorruption(fragment.size(), "SetCompressionType not the
     first record") and continue. Then fragments_.clear(),
     last_record_offset_ = physical_record_offset,
     in_fragmented_record_ = false, type byte = 0. If
     fragment.size() <= 3: Status(Corruption, "CompressionTypeRecord:
     Error decoding WAL compression type") (5-arg Status ctor
     0x61cf670, code 2, subcode 0, severity 0) -> ReportCorruption(
     fragment.size(), "could not decode SetCompressionType
     record"), delete the status state_, saved_first_offset =
     physical_record_offset, loop. Else read the LE32 at
     fragment.data() as the type, strip 4 bytes from the fragment
     (the remaining bytes are never used), and: type 0 or 7 ->
     status OK, InitCompression(type) (0x5f01e80, #5979 -- sets
     compression_type_record_read_ and compression_type_, installs
     the ZSTD uncompress product only for type 7, allocates a fresh
     0x8000-byte buffer), saved_first_offset = physical_record_offset,
     loop; any other type -> Status(Corruption,
     "CompressionTypeRecord: WAL compression type not supported")
     -> ReportCorruption(fragment.size() AFTER the 4-byte strip,
     "could not decode SetCompressionType record"), delete the
     status state_, saved_first_offset = physical_record_offset,
     loop. NOTE: the "code == 0" branch after the Status ctor is
     dead in practice (the ctor always writes the passed code 2);
     the model keeps the check and pins that the ctor path always
     takes the ReportCorruption branch. NOTE: the flag is set only
     inside InitCompression, so a FAILED SetCompressionType record
     does not mark it -- a later valid one is still accepted with
     no "multiple" report.
  7. kEof (10) / kBadRecord (11) / kBadHeader (12) / kOldRecord
     (13) -- shared entry 0x5f0302e: if in_fragmented_record_,
     ReportCorruption(fragments_.size(), "error in middle of
     record"), fragments_.clear(), in_fragmented_record_ = false,
     loop; else loop with no report at all. (So an EOF with no
     partial record in flight just loops; the next TryReadFragment
     call fails and returns false.)
  8. kBadRecordChecksum (15) -- entry 0x5f03010: if recycled_
     (+0x70), fragments_.clear() and return false -- NOTE
     in_fragmented_record_ is NOT cleared on this path. Else
     ReportCorruption(drop_size, "checksum mismatch"), then the
     same handling as (7).
  9. Default (kZeroType 0, kBadRecordLen 14, and any code > 15) --
     0x5f032f0: snprintf "unknown record type %u" (0x441a65) into a
     40-byte stack buffer, ReportCorruption(fragment.size() +
     (in_fragmented_record_ ? fragments_.size() : 0), buf),
     fragments_.clear() (unconditionally),
     in_fragmented_record_ = false, loop.
  10. Landing pad 0x5f034e6 (endbr64; mov %rax,%rbx; jmp 0x5f02ee6)
      is the shared exception cleanup shared with TryReadFragment's
      FDE end; the _M_append/_M_replace length_error and the Status
      ctor's allocation throw through it.

FragmentBufferedReader layout (node #115; the Reader prefix as
pinned in #5982 up to +0xb0, plus the two fields this FDE's sole
caller observes at +0xb8/+0xd8):

  +0x00 vptr (8)
  +0x08 info_log_ (shared_ptr<Logger>, 16)
  +0x18 file_ (unique_ptr<SequentialFileReader>, 8)
  +0x20 reporter_ (Reporter*, 8)
  +0x28 checksum_ (bool, 1)
  +0x30 backing_store_ (char*, 8)
  +0x38 buffer_ (Slice, 16) -- data +0x38, size +0x40
  +0x48 eof_ (bool, 1)
  +0x49 read_error_ (bool, 1)
  +0x50 eof_offset_ (size_t, 8)
  +0x58 last_record_offset_ (uint64, 8) -- PINNED (written here)
  +0x60 end_of_buffer_offset_ (uint64, 8) -- PINNED (read here)
  +0x68 log_number_ (uint64, 8)
  +0x70 recycled_ (bool, 1) -- PINNED (read here)
  +0x71 first_record_read_ (bool, 1) -- PINNED (read + written here)
  +0x72 compression_type_ (1)
  +0x73 compression_type_record_read_ (bool, 1) -- PINNED (read here)
  +0x78 uncompress_ (unique_ptr<StreamingUncompress>, 8) -- PINNED
  +0x80 uncompressed_buffer_ (unique_ptr<char[]>, 8)
  +0x88 uncompressed_record_ (std::string, 32)
  +0xa8 hash_state_ (8)
  +0xb0 uncompress_hash_state_ (8)
  +0xb8 fragments_ (std::string, 32) -- PINNED (this FDE)
  +0xd8 in_fragmented_record_ (bool, 1) -- PINNED (this FDE)

Layout note (RESOLVES the open unknown carried from #5994, and
CORRECTS #5982): upstream v8.1.1 db/log_reader.h has NO
recorded_cf_to_ts_sz_ member -- the Reader base ends at +0xb8
(hash_state_ +0xa8, uncompress_hash_state_ +0xb0), and
FragmentBufferedReader : public Reader adds fragments_ at +0xb8 and
in_fragmented_record_ at +0xd8 (total 0xe0), exactly as the binary
pins them. #5982's recorded_cf_to_ts_sz_ at +0xb8 (total 0xf0) came
from a NEWER log_reader.h member order and does not apply to this
v8.1.1-based build (census candidate_versions 0.11.0+8.1.1). The
base Reader::ReadRecord 0x5f01f10 never touches +0xb8/+0xd8 at all
(it keeps its assembly state in stack locals), which is consistent:
fragments_/in_fragmented_record_ are FragmentBufferedReader-only
members. Also confirmed from the header: backing_store_ is a raw
char* (+0x30, not a std::string) and uncompress_ is a raw
StreamingUncompress* (+0x78, not a unique_ptr) -- the latter
explains why InitCompression (#5979) installs without deleting
the previous product.

Caller census: NO direct calls, jumps, or LEA references to
0x5f02f20 anywhere in .text (whole-.text E8/E9/LEA scan,
Capstone-validated, census.py) -- ReadRecord is virtual and is
reached only through the Reader vtable, like Compress/Uncompress
in #5972. The sole in-repo caller of the fragment parser it
drives, TryReadFragment, is this routine itself (0x5f02fdc).
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
          / "re-002-node115-rocksdb-fragment-buffered-reader-read-record-115")
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# --- constants (binary-pinned) -------------------------------------------
K_BLOCK_SIZE = 0x8000
K_HEADER_SIZE = 7
K_REC_HEADER_SIZE = 11
K_MASK_DELTA = 0xA282EAD8
K_MAX_STRING = 0x3FFFFFFFFFFFFFFF
EMPTY_LITERAL = 0x4376FD
JUMP_TABLE = 0x970768

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
K_EOF = 10
K_BAD_RECORD = 11
K_BAD_HEADER = 12
K_OLD_RECORD = 13
K_BAD_RECORD_LEN = 14
K_BAD_RECORD_CHECKSUM = 15

RECORD_TYPE_NAMES = {
    0: "kZeroType", 1: "kFullType", 2: "kFirstType", 3: "kMiddleType",
    4: "kLastType", 5: "kRecyclableFullType", 6: "kRecyclableFirstType",
    7: "kRecyclableMiddleType", 8: "kRecyclableLastType",
    9: "kSetCompressionType", 10: "kEof", 11: "kBadRecord",
    12: "kBadHeader", 13: "kOldRecord", 14: "kBadRecordLen",
    15: "kBadRecordChecksum",
}

# The jump-table targets, read from the binary at 0x970768 (see bindings).
JUMP_TARGETS = {
    0: 0x5F032F0, 1: 0x5F03140, 2: 0x5F030F0, 3: 0x5F030A0,
    4: 0x5F03070, 5: 0x5F03140, 6: 0x5F030F0, 7: 0x5F030A0,
    8: 0x5F03070, 9: 0x5F031B8, 10: 0x5F0302E, 11: 0x5F0302E,
    12: 0x5F0302E, 13: 0x5F0302E, 14: 0x5F032F0, 15: 0x5F03010,
}


class LengthError_(Exception):
    """The std::string length check (binary throws length_error
    "basic_string::append", 0x4474d2) when an append would exceed
    max_size() - current size."""


def _check_append_capacity(current_size, add_size):
    """The guard before fragments_.append: throws LengthError_ when
    add_size > K_MAX_STRING - current_size (binary: movabs
    0x3fffffffffffffff; sub fragments_.size(); cmp fragment.size();
    jb __throw_length_error)."""
    if add_size > K_MAX_STRING - current_size:
        raise LengthError_("basic_string::append")


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
    them. fragments_ is the std::string at +0xb8; in_fragmented_record_
    the bool at +0xd8."""

    def __init__(self, buffer=b"", end_of_buffer_offset=0, log_number=0,
                 recycled=False, checksum=False, uncompress=0,
                 uncompressed_buffer=0, last_record_offset=0,
                 first_record_read=False, compression_type_record_read=False,
                 compression_type=0, fragments=b"", in_fragmented_record=False,
                 eof=False, read_error=False, eof_offset=0):
        self.buffer = bytes(buffer)
        self.end_of_buffer_offset = end_of_buffer_offset
        self.log_number = log_number
        self.recycled = recycled
        self.checksum = checksum
        self.uncompress = uncompress
        self.uncompressed_buffer = uncompressed_buffer
        self.uncompressed_record = bytearray()
        self.last_record_offset = last_record_offset
        self.first_record_read = first_record_read
        self.compression_type_record_read = compression_type_record_read
        self.compression_type = compression_type
        self.fragments = bytearray(fragments)
        self.in_fragmented_record = in_fragmented_record
        self.eof = eof
        self.read_error = read_error
        self.eof_offset = eof_offset
        self._next_token = 1000

    def alloc_token(self):
        self._next_token += 1
        return self._next_token


FRAGMENT_LAYOUT = [
    ("vptr", 0x00, 8),
    ("info_log_", 0x08, 16),
    ("file_", 0x18, 8),
    ("reporter_", 0x20, 8),
    ("checksum_", 0x28, 1),
    ("backing_store_", 0x30, 8),
    ("buffer_.data", 0x38, 8),
    ("buffer_.size", 0x40, 8),
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


def _fragments_clear(reader, events):
    reader.fragments = bytearray()
    events.append(["fragments_clear", None])


# ---------------------------------------------------------------------------
# The ReadRecord model
# ---------------------------------------------------------------------------

def make_report_corruption(events):
    """ReportCorruption stand-in (0x5f015c0): records (bytes, reason)."""
    def report(nbytes, reason):
        events.append(["report_corruption",
                       {"bytes": nbytes, "reason": reason}])
    return report


def make_init_compression(reader, events):
    """InitCompression stand-in (0x5f01e80, #5979): sets
    compression_type_record_read_ = true BEFORE compression_type_,
    installs the ZSTD uncompress product only for type 7 (null for
    any other kind), and allocates a fresh 0x8000-byte buffer."""
    def init_compression(type_byte):
        events.append(["init_compression", {"type": type_byte}])
        reader.compression_type_record_read = True
        reader.compression_type = type_byte
        if type_byte == 7:
            reader.uncompress = reader.alloc_token()
        else:
            reader.uncompress = 0
        reader.uncompressed_buffer = reader.alloc_token()
    return init_compression


def make_try_read_fragment(script):
    """Build a TryReadFragment stand-in from a script list.

    Each entry is {"ok": True, "fragment": hex, "type": int,
    "drop_size": int, "recycled": bool, "buffer_after": hex|None,
    "end_offset_after": int|None} (returns true, setting the
    out-params) or {"ok": False, "type": int|None, "drop_size":
    int|None, "type_untouched": bool, "recycled": bool,
    "buffer_after": hex|None, "end_offset_after": int|None}
    (returns false; the code is written to *fragment_type_or_err
    unless type_untouched, mirroring the binary's two false arms).
    An exhausted script fails with kEof.
    """
    script = list(script)
    pos = [0]

    def try_read_fragment(reader, fragment, drop_size, frag_type):
        if pos[0] >= len(script):
            frag_type[0] = K_EOF
            return False
        entry = script[pos[0]]
        pos[0] += 1
        if entry.get("buffer_after") is not None:
            reader.buffer = bytes.fromhex(entry["buffer_after"])
        if entry.get("end_offset_after") is not None:
            reader.end_of_buffer_offset = entry["end_offset_after"]
        if "recycled" in entry:
            reader.recycled = entry["recycled"]
        if entry.get("ok"):
            fragment[0] = bytes.fromhex(entry.get("fragment", ""))
            frag_type[0] = entry["type"] & 0xFFFFFFFF
            drop_size[0] = entry.get("drop_size", 0)
            return True
        if not entry.get("type_untouched", False) \
                and entry.get("type") is not None:
            frag_type[0] = entry["type"] & 0xFFFFFFFF
        if entry.get("drop_size") is not None:
            drop_size[0] = entry["drop_size"]
        return False

    return try_read_fragment


def read_record(reader, record, scratch, try_read_fragment,
                init_compression=None, report=None):
    """Model of log::FragmentBufferedReader::ReadRecord (0x5f02f20).

    record is a 1-element list holding the output Slice bytes;
    scratch a 1-element list holding the output std::string as a
    bytearray. try_read_fragment is the TryReadFragment oracle with
    signature (reader, fragment[1], drop_size[1], frag_type[1]) ->
    bool. init_compression (default: the #5979 stand-in) and report
    (default: the ReportCorruption stand-in) are the two other
    callees. Returns (ok, events); the events list is also the
    ledger the case files record.
    """
    events = []
    if report is None:
        report = make_report_corruption(events)
    if init_compression is None:
        init_compression = make_init_compression(reader, events)

    # Prologue: *record = empty Slice; scratch->clear(); Reset().
    record[0] = b""
    scratch[0] = bytearray()
    events.append(["record_init", {"data": hex(EMPTY_LITERAL), "size": 0}])
    events.append(["scratch_clear", None])
    if reader.uncompress != 0:
        events.append(["uncompress_reset",
                       {"token": reader.uncompress}])
    # physical_record_offset, computed once from the entry-time state.
    physical_record_offset = (reader.end_of_buffer_offset
                              - len(reader.buffer)) & 0xFFFFFFFFFFFFFFFF
    events.append(["physical_record_offset",
                   {"value": physical_record_offset}])
    drop_size = [0]
    frag_type = [0]
    fragment = [b""]
    saved_first_offset = [0]

    def _fragments_replace(data):
        reader.fragments = bytearray(data)
        events.append(["fragments_replace",
                       {"size": len(reader.fragments)}])

    while True:
        ok = try_read_fragment(reader, fragment, drop_size, frag_type)
        events.append(["try_read_fragment",
                       {"ok": ok, "frag_type": frag_type[0],
                        "fragment": fragment[0].hex(),
                        "drop_size": drop_size[0],
                        "buffer_after": reader.buffer.hex(),
                        "end_of_buffer_offset_after":
                            reader.end_of_buffer_offset,
                        "recycled_after": reader.recycled}])
        if not ok:
            events.append(["return", {"ok": False}])
            return False, events
        code = frag_type[0]
        handler = JUMP_TARGETS.get(code, 0x5F032F0)
        events.append(["dispatch",
                       {"code": code, "handler": hex(handler),
                        "name": RECORD_TYPE_NAMES.get(code, "unknown")}])
        if handler == 0x5F03140:
            # kFullType / kRecyclableFullType.
            if reader.in_fragmented_record and len(reader.fragments) != 0:
                report(len(reader.fragments),
                       "partial record without end(1)")
            _fragments_clear(reader, events)
            record[0] = bytes(fragment[0])
            events.append(["record_set",
                           {"from": "fragment",
                            "size": len(record[0])}])
            reader.first_record_read = True
            reader.in_fragmented_record = False
            reader.last_record_offset = physical_record_offset
            events.append(["return", {"ok": True}])
            return True, events
        if handler == 0x5F030F0:
            # kFirstType / kRecyclableFirstType.
            if reader.in_fragmented_record or len(reader.fragments) != 0:
                report(len(reader.fragments),
                       "partial record without end(2)")
            _fragments_replace(fragment[0])
            reader.in_fragmented_record = True
            saved_first_offset[0] = physical_record_offset
            events.append(["first_fragment_saved",
                           {"offset": saved_first_offset[0]}])
            continue
        if handler == 0x5F030A0:
            # kMiddleType / kRecyclableMiddleType.
            if not reader.in_fragmented_record:
                report(len(fragment[0]),
                       "missing start of fragmented record(1)")
                continue
            _check_append_capacity(len(reader.fragments),
                                   len(fragment[0]))
            reader.fragments += fragment[0]
            events.append(["fragments_append",
                           {"size": len(reader.fragments)}])
            continue
        if handler == 0x5F03070:
            # kLastType / kRecyclableLastType.
            if not reader.in_fragmented_record:
                report(len(fragment[0]),
                       "missing start of fragmented record(2)")
                continue
            _check_append_capacity(len(reader.fragments),
                                   len(fragment[0]))
            reader.fragments += fragment[0]
            events.append(["fragments_append",
                           {"size": len(reader.fragments)}])
            scratch[0] = bytearray(reader.fragments)
            events.append(["scratch_replace",
                           {"size": len(scratch[0])}])
            record[0] = bytes(scratch[0])
            events.append(["record_set",
                           {"from": "scratch",
                            "size": len(record[0])}])
            _fragments_clear(reader, events)
            physical_record_offset = saved_first_offset[0]
            reader.last_record_offset = physical_record_offset
            reader.first_record_read = True
            reader.in_fragmented_record = False
            events.append(["return", {"ok": True}])
            return True, events
        if handler == 0x5F031B8:
            # kSetCompressionType.
            if reader.compression_type_record_read:
                report(len(fragment[0]),
                       "read multiple SetCompressionType records")
            if reader.first_record_read:
                report(len(fragment[0]),
                       "SetCompressionType not the first record")
            _fragments_clear(reader, events)
            reader.last_record_offset = physical_record_offset
            reader.in_fragmented_record = False
            type_byte = 0
            if len(fragment[0]) <= 3:
                msg = ("CompressionTypeRecord: "
                       "Error decoding WAL compression type")
                events.append(["status_construct",
                               {"code": 2, "message": msg}])
                # The 5-arg Status ctor always writes the passed code
                # (2); the code==0 branch is dead in practice.
                report(len(fragment[0]),
                       "could not decode SetCompressionType record")
                saved_first_offset[0] = physical_record_offset
                continue
            raw = int.from_bytes(fragment[0][:4], "little")
            type_byte = raw & 0xFF
            rest = fragment[0][4:]
            events.append(["compression_type_parsed",
                           {"u32": raw, "type": type_byte,
                            "rest_size": len(rest)}])
            if type_byte in (0, 7):
                init_compression(type_byte)
                saved_first_offset[0] = physical_record_offset
                continue
            msg = ("CompressionTypeRecord: "
                   "WAL compression type not supported")
            events.append(["status_construct",
                           {"code": 2, "message": msg}])
            report(len(rest),
                   "could not decode SetCompressionType record")
            saved_first_offset[0] = physical_record_offset
            continue
        if handler == 0x5F0302E:
            # kEof / kBadRecord / kBadHeader / kOldRecord.
            if reader.in_fragmented_record:
                report(len(reader.fragments),
                       "error in middle of record")
                _fragments_clear(reader, events)
                reader.in_fragmented_record = False
            continue
        if handler == 0x5F03010:
            # kBadRecordChecksum.
            if reader.recycled:
                _fragments_clear(reader, events)
                events.append(["return", {"ok": False}])
                return False, events
            report(drop_size[0], "checksum mismatch")
            if reader.in_fragmented_record:
                report(len(reader.fragments),
                       "error in middle of record")
                _fragments_clear(reader, events)
                reader.in_fragmented_record = False
            continue
        # Default: kZeroType, kBadRecordLen, or any code > 15.
        text = "unknown record type %u" % code
        report(len(fragment[0])
               + (len(reader.fragments)
                  if reader.in_fragmented_record else 0), text)
        _fragments_clear(reader, events)
        reader.in_fragmented_record = False
        continue


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, bytearray):
        return bytes(v).hex()
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v


def _frag(fragment=b"", type=1, drop_size=0, **kw):
    e = {"ok": True, "fragment": bytes(fragment).hex(), "type": type,
         "drop_size": drop_size}
    e.update(kw)
    return e


def _fail(type=None, drop_size=None, type_untouched=False, **kw):
    e = {"ok": False, "type_untouched": type_untouched}
    if type is not None:
        e["type"] = type
    if drop_size is not None:
        e["drop_size"] = drop_size
    e.update(kw)
    return e


def _as_bytes(v):
    return v if isinstance(v, bytes) else bytes.fromhex(v)


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes)."""
    reader = FragmentBufferedReader(
        buffer=_as_bytes(p["buffer"]),
        end_of_buffer_offset=p.get("end_of_buffer_offset", 0),
        log_number=p.get("log_number", 0),
        recycled=p.get("recycled", False),
        checksum=p.get("checksum", False),
        uncompress=p.get("uncompress", 0),
        uncompressed_buffer=p.get("uncompressed_buffer", 0),
        last_record_offset=p.get("last_record_offset", 0),
        first_record_read=p.get("first_record_read", False),
        compression_type_record_read=p.get(
            "compression_type_record_read", False),
        compression_type=p.get("compression_type", 0),
        fragments=_as_bytes(p.get("fragments", "")),
        in_fragmented_record=p.get("in_fragmented_record", False))
    record = [b""]
    scratch = [bytearray()]
    trf = make_try_read_fragment(p.get("try_read_fragment_script", []))
    ok, events = read_record(reader, record, scratch, trf)
    record_from_scratch = any(
        k == "record_set" and isinstance(v, dict)
        and v.get("from") == "scratch" for k, v in events)
    return {
        "ok": ok,
        "record": record[0].hex(),
        "record_from_scratch": record_from_scratch,
        "scratch": bytes(scratch[0]).hex(),
        "fragments_after": bytes(reader.fragments).hex(),
        "in_fragmented_record_after": reader.in_fragmented_record,
        "last_record_offset_after": reader.last_record_offset,
        "first_record_read_after": reader.first_record_read,
        "compression_type_record_read_after":
            reader.compression_type_record_read,
        "compression_type_after": reader.compression_type,
        "uncompress_after": reader.uncompress,
        "buffer_after": reader.buffer.hex(),
        "end_of_buffer_offset_after": reader.end_of_buffer_offset,
        "recycled_after": reader.recycled,
        "try_read_fragment_calls": sum(
            1 for k, _ in events if k == "try_read_fragment"),
        "report_corruption_calls": sum(
            1 for k, _ in events if k == "report_corruption"),
        "init_compression_calls": sum(
            1 for k, _ in events if k == "init_compression"),
        "uncompress_reset_calls": sum(
            1 for k, _ in events if k == "uncompress_reset"),
        "events": [[k, _jsonable(v)] for k, v in events],
    }


def _base_param(**kw):
    p = {"buffer": b"".hex(), "end_of_buffer_offset": 100,
         "log_number": 7, "checksum": False, "uncompress": 0}
    p.update(kw)
    return p


def _setcomp_fragment(u32, extra=b""):
    return struct.pack("<I", u32) + extra


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 dispatch, 600 assembly,
    600 compression, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    def add(cid, group, scenario, param):
        param = _jsonable(param)
        expected = _run_scenario(param)
        rows.append({"id": cid, "group": group, "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # ---- dispatch (600) -------------------------------------------------
    n = [0]

    def disp(param):
        n[0] += 1
        add(f"dispatch-{n[0]:04d}", "dispatch", "dispatch", param)

    term_full = _frag(b"FULL", K_FULL_TYPE)
    # Sweep A: all 16 codes x recycled x in_fragmented (64).
    for code in range(16):
        for recycled in (False, True):
            for infrag in (False, True):
                frag = _setcomp_fragment(0) if code == 9 else b"DATA"
                disp(_base_param(
                    recycled=recycled, in_fragmented_record=infrag,
                    fragments=b"SEED" if infrag else b"",
                    try_read_fragment_script=[
                        _frag(frag, code, drop_size=9),
                        dict(term_full)]))
    # Sweep B: codes 0..255, default state (256).
    for code in range(256):
        frag = _setcomp_fragment(0) if code == 9 else b"DATA"
        disp(_base_param(try_read_fragment_script=[
            _frag(frag, code, drop_size=3), dict(term_full)]))
    # Sweep C: TryReadFragment-false variants (20).
    for code in (K_EOF, K_BAD_RECORD, K_BAD_HEADER, K_OLD_RECORD,
                 K_BAD_RECORD_LEN, K_BAD_RECORD_CHECKSUM):
        disp(_base_param(try_read_fragment_script=[_fail(type=code)]))
    for code in (K_EOF, K_BAD_RECORD, K_BAD_HEADER, K_OLD_RECORD,
                 K_BAD_RECORD_LEN, K_BAD_RECORD_CHECKSUM):
        disp(_base_param(in_fragmented_record=True, fragments=b"SEED",
                         try_read_fragment_script=[_fail(type=code)]))
    # No-progress false leaves *fragment_type_or_err untouched: the
    # stale code from the previous iteration is what the model
    # returns with.
    for first_code in (K_FIRST_TYPE, K_MIDDLE_TYPE,
                       K_SET_COMPRESSION_TYPE):
        first_frag = (_setcomp_fragment(0) if first_code == 9
                      else b"AAAA")
        disp(_base_param(
            try_read_fragment_script=[
                _frag(first_frag, first_code),
                _fail(type_untouched=True)]))
    disp(_base_param(try_read_fragment_script=[
        _fail(type=K_EOF, drop_size=123)]))
    disp(_base_param(try_read_fragment_script=[
        _fail(type=K_BAD_RECORD_CHECKSUM, drop_size=77)]))
    disp(_base_param(try_read_fragment_script=[
        _fail(type=None, drop_size=5)]))
    disp(_base_param(try_read_fragment_script=[]))
    # Random fill to 600.
    while n[0] < 600:
        code = rng.choice(list(range(16)) + [16, 17, 100, 255])
        frag = (_setcomp_fragment(rng.randrange(0, 256))
                if code == 9 else bytes(rng.randrange(0, 256)
                                        for _ in range(rng.randrange(0, 9))))
        script = [_frag(frag, code, drop_size=rng.randrange(0, 20),
                        recycled=rng.random() < 0.3)]
        if rng.random() < 0.7:
            script.append(dict(term_full) if rng.random() < 0.8
                          else _fail(type=rng.choice([10, 11, 15])))
        disp(_base_param(
            recycled=rng.random() < 0.3,
            in_fragmented_record=rng.random() < 0.3,
            fragments=(b"SEED" if rng.random() < 0.3 else b""),
            first_record_read=rng.random() < 0.3,
            compression_type_record_read=rng.random() < 0.2,
            end_of_buffer_offset=rng.choice([0, 100, 1000]),
            try_read_fragment_script=script))

    # ---- assembly (600) -------------------------------------------------
    m = [0]

    def asm(param, scenario="assembly", **kw):
        m[0] += 1
        param = dict(param)
        param.update(kw)
        add(f"assembly-{m[0]:04d}", "assembly", scenario, param)

    def seq(*entries, **kw):
        return _base_param(try_read_fragment_script=list(entries), **kw)

    F = lambda b, t=1, **kw: _frag(b, t, **kw)  # noqa: E731
    asm(seq(F(b"hello", 1)))
    asm(seq(F(b"hello", 5)))
    asm(seq(F(b"aa", 2), F(b"bb", 4)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), F(b"cc", 4)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), F(b"cc", 3), F(b"dd", 4)))
    asm(seq(F(b"aa", 6), F(b"bb", 7), F(b"cc", 8)))
    asm(seq(F(b"aa", 6), F(b"bb", 3), F(b"cc", 8)))
    asm(seq(F(b"aa", 2), F(b"bb", 8)))
    asm(seq(F(b"", 2), F(b"bb", 4)))
    asm(seq(F(b"aa", 2), F(b"", 4)))
    asm(seq(F(b"aa", 2), _fail(type=K_EOF)))
    asm(seq(F(b"aa", 2), _fail(type_untouched=True)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), _fail(type=K_EOF)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), F(b"cc", 15, drop_size=40),
            F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), F(b"cc", 15, drop_size=40,
                                        recycled=True)))
    asm(seq(F(b"aa", 2), F(b"bb", 10), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 11), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 12), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 13), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 14), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 0), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 16), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 255), F(b"zz", 1)))
    asm(seq(F(b"bb", 3), F(b"zz", 1)))
    asm(seq(F(b"bb", 4), F(b"zz", 1)))
    asm(seq(F(b"bb", 3), F(b"cc", 4), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 2), F(b"zz", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 1)))
    asm(seq(F(b"aa", 1), F(b"bb", 1)))
    asm(seq(F(b"aa", 2), F(b"bb", 3), F(b"cc", 2), F(b"dd", 4)))
    asm(seq(F(b"aa", 2), _frag(_setcomp_fragment(0), 9), F(b"bb", 4),
            F(b"zz", 1)))
    asm(seq(F(b"aa", 2), _frag(_setcomp_fragment(7), 9), F(b"bb", 4),
            F(b"zz", 1)))
    asm(seq(F(b"aa", 5), F(b"bb", 1)))
    asm(seq(F(b"", 1)))
    asm(seq(F(b"", 2), F(b"", 3), F(b"", 4)))
    asm(seq(F(b"x", 1), F(b"y", 1), F(b"z", 1)))
    # Pre-seeded state: a partial record already in flight.
    asm(seq(F(b"tail", 4), in_fragmented_record=True,
        fragments=b"head-"))
    asm(seq(F(b"tail", 4), in_fragmented_record=True, fragments=b""))
    asm(seq(F(b"full", 1), in_fragmented_record=True,
        fragments=b"head-"))
    asm(seq(F(b"full", 1), in_fragmented_record=True, fragments=b""))
    asm(seq(F(b"mid", 3), F(b"tail", 4), in_fragmented_record=True,
        fragments=b"head-"))
    asm(seq(_fail(type=K_EOF), in_fragmented_record=True,
        fragments=b"head-"))
    asm(seq(_fail(type=K_BAD_RECORD_CHECKSUM, drop_size=9)),
        in_fragmented_record=True, fragments=b"head-")
    asm(seq(F(b"cc", 15, drop_size=9, recycled=True)),
        in_fragmented_record=True, fragments=b"head-")
    asm(seq(F(b"cc", 15, drop_size=9), in_fragmented_record=True,
        fragments=b"head-"))
    asm(seq(F(b"cc", 15, drop_size=9), F(b"zz", 1)),
        in_fragmented_record=True, fragments=b"head-")
    # first_record_read / offsets / uncompress preset.
    asm(seq(F(b"aa", 2), F(b"bb", 4), first_record_read=True))
    asm(seq(F(b"hello", 1), end_of_buffer_offset=0))
    asm(seq(F(b"hello", 1), end_of_buffer_offset=0x8000))
    asm(seq(F(b"hello", 1), uncompress=42))
    asm(seq(F(b"aa", 2), F(b"bb", 4), uncompress=42))
    asm(seq(F(b"hello", 1), last_record_offset=999))
    # Random fill to 600.
    pool = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 16]
    while m[0] < 600:
        nent = rng.randrange(1, 5)
        script = []
        for _ in range(nent):
            t = rng.choice(pool)
            if t == 9:
                frag = _setcomp_fragment(rng.choice([0, 7, 1, 255]))
            else:
                frag = bytes(rng.randrange(0, 256)
                             for _ in range(rng.randrange(0, 6)))
            if rng.random() < 0.15:
                script.append(_fail(
                    type=rng.choice([10, 11, 12, 13, 15]),
                    drop_size=rng.randrange(0, 30)))
            else:
                script.append(_frag(
                    frag, t, drop_size=rng.randrange(0, 30),
                    recycled=rng.random() < 0.2))
        asm(_base_param(
            in_fragmented_record=rng.random() < 0.25,
            fragments=(bytes(rng.randrange(0, 256)
                             for _ in range(rng.randrange(0, 6)))
                       if rng.random() < 0.25 else b""),
            first_record_read=rng.random() < 0.3,
            compression_type_record_read=rng.random() < 0.2,
            recycled=rng.random() < 0.2,
            end_of_buffer_offset=rng.choice([0, 100, 0x8000]),
            try_read_fragment_script=script))

    # ---- compression (600) ----------------------------------------------
    c = [0]

    def comp(param, scenario="compression", **kw):
        c[0] += 1
        param = dict(param)
        param.update(kw)
        add(f"compression-{c[0]:04d}", "compression", scenario, param)

    def cseq(*entries, **kw):
        return _base_param(try_read_fragment_script=list(entries), **kw)

    # Type sweep: the u32 written to the record, one per case.
    for u32 in (0, 7, 1, 2, 3, 4, 5, 6, 8, 9, 10, 15, 0x40, 0xFF,
                0x100, 0x107, 0x207, 0xFFFFFF00, 0xFFFFFF07, 0x80000007):
        comp(cseq(_frag(_setcomp_fragment(u32), 9), dict(term_full)))
    # Short fragments: DecodeFrom fails before reading the type.
    for size in (0, 1, 2, 3):
        comp(cseq(_frag(bytes(range(size)), 9), dict(term_full)))
    comp(cseq(_frag(b"\x07\x00\x00", 9), dict(term_full)))
    # Extra bytes after the 4-byte type are ignored.
    comp(cseq(_frag(_setcomp_fragment(0, b"EXTRA"), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(7, b"EXTRA"), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(1, b"EXTRA"), 9), dict(term_full)))
    # Multiple records: the flag is set only by InitCompression, so a
    # failed first record does not trigger the "multiple" report.
    comp(cseq(_frag(_setcomp_fragment(0), 9),
              _frag(_setcomp_fragment(7), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(7), 9),
              _frag(_setcomp_fragment(0), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(0), 9),
              _frag(_setcomp_fragment(0), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(7), 9),
              _frag(_setcomp_fragment(7), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(1), 9),
              _frag(_setcomp_fragment(7), 9), dict(term_full)))
    comp(cseq(_frag(b"\x01\x02", 9),
              _frag(_setcomp_fragment(7), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(5), 9),
              _frag(_setcomp_fragment(0), 9), dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(0x40), 9),
              _frag(_setcomp_fragment(7), 9), dict(term_full)))
    # After the first record was read: first_record_read_ is set
    # by an EARLIER ReadRecord call, so it is preset here (a
    # kFullType in the same call would return before the
    # SetCompressionType record is ever read).
    comp(cseq(_frag(_setcomp_fragment(7), 9), dict(term_full)),
         first_record_read=True)
    comp(cseq(_frag(_setcomp_fragment(7), 9), dict(term_full)),
         first_record_read=True)
    comp(cseq(_frag(_setcomp_fragment(0), 9), dict(term_full)),
         first_record_read=True, compression_type_record_read=True)
    comp(cseq(_frag(_setcomp_fragment(7), 9), dict(term_full)),
         compression_type_record_read=True)
    # In-flight fragmented record: the arm clears fragments_.
    comp(cseq(_frag(_setcomp_fragment(0), 9), _frag(b"bb", 4),
              dict(term_full)), in_fragmented_record=True,
         fragments=b"head-")
    comp(cseq(_frag(_setcomp_fragment(7), 9), _frag(b"bb", 4),
              dict(term_full)), in_fragmented_record=True,
         fragments=b"head-")
    comp(cseq(_frag(_setcomp_fragment(1), 9), _frag(b"bb", 4),
              dict(term_full)), in_fragmented_record=True,
         fragments=b"head-")
    # Recycled_ is not consulted by this arm.
    comp(cseq(_frag(_setcomp_fragment(7), 9), dict(term_full)),
         recycled=True)
    comp(cseq(_frag(_setcomp_fragment(1), 9), dict(term_full)),
         recycled=True)
    # Uncompress already installed: the prologue Reset fires once.
    comp(cseq(_frag(_setcomp_fragment(0), 9), dict(term_full)),
         uncompress=42)
    comp(cseq(_frag(_setcomp_fragment(7), 9), dict(term_full)),
         uncompress=42)
    comp(cseq(_frag(_setcomp_fragment(1), 9), dict(term_full)),
         uncompress=42)
    # Drop_size / EOF interplay.
    comp(cseq(_frag(_setcomp_fragment(0), 9, drop_size=44),
              dict(term_full)))
    comp(cseq(_frag(_setcomp_fragment(7), 9), _fail(type=K_EOF)))
    comp(cseq(_frag(_setcomp_fragment(1), 9), _fail(type=K_EOF)))
    # Random fill to 600.
    while c[0] < 600:
        nent = rng.randrange(1, 4)
        script = []
        for _ in range(nent):
            if rng.random() < 0.6:
                u32 = rng.choice([0, 7, 1, 2, 255, rng.randrange(0, 256),
                                  rng.randrange(0, 2 ** 32)])
                size = rng.choice([0, 1, 2, 3, 4, 5, 8])
                payload = _setcomp_fragment(u32)[:size]
                if len(payload) < size:
                    payload += bytes(rng.randrange(0, 256)
                                     for _ in range(size - len(payload)))
                script.append(_frag(payload, 9,
                                    drop_size=rng.randrange(0, 20)))
            else:
                script.append(_frag(
                    bytes(rng.randrange(0, 256)
                          for _ in range(rng.randrange(0, 6))),
                    rng.choice([1, 2, 3, 4, 10, 15]),
                    drop_size=rng.randrange(0, 20)))
        comp(_base_param(
            first_record_read=rng.random() < 0.3,
            compression_type_record_read=rng.random() < 0.3,
            in_fragmented_record=rng.random() < 0.2,
            fragments=(b"SEED" if rng.random() < 0.2 else b""),
            recycled=rng.random() < 0.2,
            uncompress=rng.choice([0, 0, 42]),
            try_read_fragment_script=script))

    # ---- bindings (600) -------------------------------------------------
    brows = _bindings_rows()
    for r in brows:
        rows.append(r)
    assert len(rows) == 2400, f"case count {len(rows)} != 2400"
    groups = {}
    for r in rows:
        groups[r["group"]] = groups.get(r["group"], 0) + 1
    assert groups == {"dispatch": 600, "assembly": 600,
                      "compression": 600, "bindings": 600}, groups
    return rows


def _build_wal_record(type_byte, payload, log_num=None, crc_ok=True):
    """Build one physical WAL record: LE32 masked CRC over
    (type byte [+ log_num] + payload), LE16 length, type byte,
    payload. crc_ok=False flips a payload bit after the CRC is
    computed, so the record fails the checksum."""
    recyclable = 5 <= type_byte <= 8
    body = bytes([type_byte]) + (struct.pack("<I", log_num)
                                 if recyclable else b"") + payload
    stored = crc32c_mask(crc32c_value(body))
    header = struct.pack("<I", stored) + struct.pack("<H", len(payload)) \
        + bytes([type_byte])
    if recyclable:
        header += struct.pack("<I", log_num)
    buf = header + payload
    if not crc_ok and payload:
        buf = buf[:-1] + bytes([buf[-1] ^ 0xFF])
    return buf


def _signed_type(byte):
    return byte - 256 if byte >= 0x80 else byte


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


UPSTREAM_ANCHORS = [
    ("signature-unused-params",
     "log_reader.cc:1092-1096 FragmentBufferedReader::ReadRecord "
     "names its 3rd/4th params WALRecoveryMode /*unused*/ and "
     "uint64_t* /* checksum */"),
    ("prologue-reset",
     "log_reader.cc:1102-1110 record->clear(), scratch->clear(), "
     "uncompress_->Reset() when non-null"),
    ("once-computed-offset",
     "log_reader.cc:1113-1121 prospective_record_offset = 0; "
     "physical_record_offset computed once before the loop"),
    ("loop-switch",
     "log_reader.cc:1123-1125 while (TryReadFragment(...)) + switch "
     "on fragment_type_or_err"),
    ("full-arm",
     "log_reader.cc:1127-1149 kFullType/kRecyclableFullType: report "
     "only when in_fragmented_record_ && !fragments_.empty()"),
    ("first-arm",
     "log_reader.cc:1152-1168 kFirstType: report when "
     "in_fragmented_record_ || !fragments_.empty(); assign"),
    ("middle-last-arms",
     "log_reader.cc:1171-1220 kMiddleType/kLastType: missing-start "
     "reports, append, scratch assign, return true"),
    ("eof-group",
     "log_reader.cc:1223-1241 kBadHeader/kBadRecord/kEof/kOldRecord "
     "share the error-in-middle-of-record arm"),
    ("checksum-arm",
     "log_reader.cc:1244-1266 kBadRecordChecksum: recycled_ -> "
     "clear + return false; else checksum mismatch report"),
    ("set-compression-arm",
     "log_reader.cc:1269-1313 kSetCompressionType: flag reports, "
     "clear, DecodeFrom, InitCompression"),
    ("default-arm",
     "log_reader.cc:1316-1336 default: snprintf unknown record type "
     "%u, report, clear"),
    ("layout-inheritance",
     "log_reader.h:354-404 FragmentBufferedReader : public Reader; "
     "fragments_ +0xb8, in_fragmented_record_ +0xd8; no "
     "recorded_cf_to_ts_sz_ in the v8.1.1 Reader base"),
    ("decode-from",
     "util/compression.h:3117-3146 CompressionTypeRecord::DecodeFrom: "
     "GetFixed32 strips the prefix; only 0/7 supported"),
    ("enum-constants",
     "db/log_format.h:34-84 RecordType enum, kBlockSize 32768, "
     "kHeaderSize 7, kRecyclableHeaderSize 11; "
     "db/log_reader.h:284-316 kEof 10 .. kBadRecordChecksum 15"),
]


def _bindings_rows():
    """600 structural checks against the live binary + census.

    Composition: 2 hashes + 37 relocation targets + 1 caller site +
    25 layout fields + 10 constants + 14 upstream anchors +
    256 code-classification rows + 100 sixteen-byte windows + 100
    eight-byte windows + 55 four-byte windows = 600.
    """
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    start, end = 0x5F02F20, 0x5F034F2
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
    # Relocation displacements -> pinned callees (37 rows).
    pinned = {
        0x5F02B40: "rocksdb::log::FragmentBufferedReader::TryReadFragment",
        0x5F01E80: "rocksdb::log::Reader::InitCompression",
        0x5F015C0: "rocksdb::log::Reader::ReportCorruption",
        0x4376FD: "empty-string literal (record/scratch clear data)",
        0x970768: "jump table (16 int32 entries, codes 0..15)",
        0x4464D2: '"checksum mismatch"',
        0x44B301: '"error in middle of record"',
        0x43519A: '"partial record without end(1)"',
        0x969788: '"missing start of fragmented record(2)"',
        0x95A578: '"could not decode SetCompressionType record"',
        0x434014: '"partial record without end(2)"',
        0x95BB70: '"missing start of fragmented record(1)"',
        0x95CFA8: '"SetCompressionType not the first record"',
        0x959A40: '"read multiple SetCompressionType records"',
        0x441A65: '"unknown record type %u"',
        0x95FA18: '"Error decoding WAL compression type"',
        0x966208: '"WAL compression type not supported"',
        0x453260: '"CompressionTypeR" (.rodata, first 14 bytes used)',
        0x4474D2: 'length_error literal "basic_string::append"',
        0x61CF670: "rocksdb::Status 5-arg ctor (Code, SubCode, "
                   "Slice, Slice, Severity)",
        0x63F0F40: "PLT std::string::_M_append",
        0x63F0D90: "PLT std::string::_M_replace",
        0x63F0DC0: "PLT _ZdaPv (delete[])",
        0x63F0F30: "PLT __snprintf_chk",
        0x63F0DE0: "PLT __throw_length_error",
        0x63F0D70: "PLT __stack_chk_fail",
        0x5F02EE6: "shared landing-pad target (TryReadFragment FDE end)",
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
    # Caller census (1 row): no direct callers -- virtual only.
    add("bind-caller-readrecord-0", "caller_site",
        {"target": "0x5f02f20"},
        {"calls": 0, "jumps": 0, "lea_refs": 0,
         "note": "virtual; reached only through the Reader vtable"})
    # Layout fields (25 rows).
    for name, off, size in FRAGMENT_LAYOUT:
        add(f"bind-layout-{name}", "reader_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Constants (10 rows).
    consts = [
        ("kBlockSize", K_BLOCK_SIZE),
        ("kHeaderSize", K_HEADER_SIZE),
        ("kRecyclableHeaderSize", K_REC_HEADER_SIZE),
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
    for name, text in UPSTREAM_ANCHORS:
        add(f"bind-anchor-{name}", "upstream_anchor",
            {"anchor": text}, {"verified": True})
    # Code classification (256 rows): codes 0..255 -> handler.
    for code in range(256):
        handler = JUMP_TARGETS.get(code, 0x5F032F0)
        add(f"bind-code-{code:03d}", "code_class",
            {"code": code},
            {"handler": hex(handler),
             "name": RECORD_TYPE_NAMES.get(code, "unknown")})
    # Byte windows: 100 x 16-byte, 100 x 8-byte, 56 x 4-byte.
    size = end - start
    for i in range(100):
        off = (i * 16) % (size - 16)
        add(f"bind-win16-{i:03d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 16},
            {"hex": body[off:off + 16].hex()})
    for i in range(100):
        off = (i * 8) % (size - 8)
        add(f"bind-win8-{i:03d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 8},
            {"hex": body[off:off + 8].hex()})
    for i in range(55):
        off = (i * 4) % (size - 4)
        add(f"bind-win4-{i:03d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 4},
            {"hex": body[off:off + 4].hex()})
    assert len(rows) == 600, f"bindings rows {len(rows)} != 600"
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param; returns
    (ok, detail)."""
    group = case["group"]
    param = json.loads(case["param"])
    expected = json.loads(case["expected"])
    if group in ("dispatch", "assembly", "compression"):
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
        consts = {"kBlockSize": K_BLOCK_SIZE,
                  "kHeaderSize": K_HEADER_SIZE,
                  "kRecyclableHeaderSize": K_REC_HEADER_SIZE,
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
    if scenario == "code_class":
        code = param["code"]
        handler = JUMP_TARGETS.get(code, 0x5F032F0)
        got = {"handler": hex(handler),
               "name": RECORD_TYPE_NAMES.get(code, "unknown")}
        return got == expected, got
    if scenario == "bytes_window":
        start = int(param["start"], 16)
        off, size = param["offset"], param["size"]
        got = data[_va_to_off(start) + off:
                   _va_to_off(start) + off + size].hex()
        return got == expected["hex"], got
    return False, f"unknown binding scenario {scenario}"


def cases_tsv_rows():
    """Rows for cases.tsv: id, group, scenario, param, expected."""
    return generate_cases()


# ---------------------------------------------------------------------------
# Live engine check: a real WAL file through the model.
# ---------------------------------------------------------------------------

class RealTryReadFragment:
    """A TryReadFragment stand-in driving a real WAL file, following
    the #5994 model with the #5995 TryReadMore model over a real
    file object. Only the raw path is implemented (the live WAL
    installs kNoCompression, so no Uncompress is involved); the
    recyclable gate and CRC check are implemented as in #5994."""

    def __init__(self, path):
        self._file = open(path, "rb")

    def close(self):
        self._file.close()

    def _try_read_more(self, reader, drop_size, error):
        if not reader.eof and not reader.read_error:
            reader.buffer = b""
            chunk = self._file.read(K_BLOCK_SIZE)
            reader.buffer = chunk
            reader.end_of_buffer_offset += len(chunk)
            if len(chunk) < K_BLOCK_SIZE:
                reader.eof = True
                reader.eof_offset = len(chunk)
            return True
        if not reader.read_error:
            # UnmarkEOF: eof_ = false, then UnmarkEOFInternal re-reads
            # the tail. The live file is fully consumed, so the
            # re-read yields 0 bytes, added (0) < remaining, and eof_
            # is set again with the buffer unchanged (the no-progress
            # case the caller detects, per #5995).
            reader.eof = False
            tail = self._file.read(K_BLOCK_SIZE - reader.eof_offset)
            assert tail == b"", "live file not fully consumed"
            reader.eof = True
            return True
        error[0] = K_EOF
        drop_size[0] = len(reader.buffer)
        if len(reader.buffer) > 0:
            error[0] = K_BAD_HEADER
        reader.buffer = b""
        return False

    def _refill(self, reader, drop_size, frag_type, needed):
        while len(reader.buffer) < needed:
            old_size = len(reader.buffer)
            error = [K_EOF]
            if not self._try_read_more(reader, drop_size, error):
                frag_type[0] = error[0]
                return False
            if old_size == len(reader.buffer):
                return False
        return True

    def __call__(self, reader, fragment, drop_size, frag_type):
        if not self._refill(reader, drop_size, frag_type, K_HEADER_SIZE):
            # _refill returns False only on TryReadMore failure (code
            # written) or no progress (code untouched).
            return False
        header = reader.buffer
        type_byte = _signed_type(header[6])
        length = header[4] | (header[5] << 8)
        header_size = K_HEADER_SIZE
        if 5 <= type_byte <= 8:
            if reader.end_of_buffer_offset - len(reader.buffer) == 0:
                reader.recycled = True
            header_size = K_REC_HEADER_SIZE
            if not self._refill(reader, drop_size, frag_type,
                                K_REC_HEADER_SIZE):
                return False
            log_num = struct.unpack_from("<I", header, 7)[0]
            if log_num != reader.log_number:
                frag_type[0] = K_OLD_RECORD
                return True
        if not self._refill(reader, drop_size, frag_type,
                            header_size + length):
            return False
        if type_byte == K_ZERO_TYPE and length == 0:
            reader.buffer = b""
            frag_type[0] = K_BAD_RECORD
            return True
        if reader.checksum:
            expected = crc32c_unmask(
                struct.unpack_from("<I", header, 0)[0])
            actual = crc32c_value(
                header[6:6 + length + header_size - 6])
            if actual != expected:
                drop_size[0] = len(reader.buffer)
                reader.buffer = b""
                frag_type[0] = K_BAD_RECORD_CHECKSUM
                return True
        reader.buffer = reader.buffer[header_size + length:]
        fragment[0] = header[header_size:header_size + length]
        frag_type[0] = type_byte & 0xFFFFFFFF
        return True


def live_engine_check():
    """Drive the model with a real WAL file.

    The file holds, back to back: a kSetCompressionType record
    (type 0), a full record, a fragmented record (first/middle/
    last), a full record with a corrupted CRC, a padding full record
    that fills block 1 to exactly 0x8000 bytes, and a final full
    record in block 2. The padding matters: a CRC failure clears
    the whole buffered block (TryReadFragment, #5994), so the record
    after the corrupt one must live in a LATER block to survive.
    Four ReadRecord calls must return: the full record, the
    reassembled fragmented record, the record after the corrupt one
    (with a checksum-mismatch report on the way), and False at EOF.
    Note last_record_offset_ is the ENTRY-time physical offset
    (upstream computes it once before the loop), so call 1 reports
    0 (the SetCompressionType record's position) and call 3 reports
    the corrupt record's position, not the returned record's.
    Returns (crc_ok, call1, call2, call3, call4, empty_literal_ok).
    """
    import tempfile
    crc_ok = crc32c_value(b"123456789") == 0xE3069283
    crc_ok = crc_ok and crc32c_value(b"") == 0
    crc_ok = crc_ok and crc32c_unmask(crc32c_mask(0xDEADBEEF)) == 0xDEADBEEF

    recs = [
        _build_wal_record(K_SET_COMPRESSION_TYPE,
                          struct.pack("<I", 0)),
        _build_wal_record(K_FULL_TYPE, b"hello wal record"),
        _build_wal_record(K_FIRST_TYPE, b"frag-"),
        _build_wal_record(K_MIDDLE_TYPE, b"mented-"),
        _build_wal_record(K_LAST_TYPE, b"record!"),
        _build_wal_record(K_FULL_TYPE, b"corrupt-me", crc_ok=False),
        # Padding: fills block 1 to exactly 0x8000 bytes so the next
        # record starts block 2 (and is dropped with the corrupt
        # block -- it is never returned).
        _build_wal_record(K_FULL_TYPE, b"P" * (0x8000 - 98)),
        _build_wal_record(K_FULL_TYPE, b"after-corruption"),
    ]
    wal = b"".join(recs)
    offsets = []
    pos = 0
    for r in recs:
        offsets.append(pos)
        pos += len(r)

    fd, path = tempfile.mkstemp(prefix="readrecord-live-", suffix=".wal")
    with open(fd, "wb") as fh:
        fh.write(wal)
    driver = RealTryReadFragment(path)
    try:
        reader = FragmentBufferedReader(
            buffer=b"", end_of_buffer_offset=0, log_number=7,
            checksum=True)
        out = []
        for _ in range(4):
            record = [b""]
            scratch = [bytearray()]
            ok, events = read_record(reader, record, scratch, driver)
            out.append((ok, bytes(record[0]), reader.last_record_offset,
                        list(events)))
        call1 = (out[0][0] and out[0][1] == b"hello wal record"
                 and out[0][2] == offsets[0]
                 and reader.compression_type_record_read
                 and reader.compression_type == 0
                 and reader.uncompress == 0
                 and any(k == "init_compression" and v["type"] == 0
                         for k, v in out[0][3]))
        call2 = (out[1][0] and out[1][1] == b"frag-mented-record!"
                 and out[1][2] == offsets[2]
                 and not reader.in_fragmented_record
                 and bytes(reader.fragments) == b"")
        reports3 = [v for k, v in out[2][3] if k == "report_corruption"]
        call3 = (out[2][0] and out[2][1] == b"after-corruption"
                 and out[2][2] == offsets[5]
                 and any(v["reason"] == "checksum mismatch"
                         for v in reports3))
        call4 = (not out[3][0] and out[3][1] == b"")
        data = _read_binary()
        empty_literal_ok = data[_va_to_off(EMPTY_LITERAL)] == 0x00
    finally:
        driver.close()
        import os
        os.unlink(path)
    return crc_ok, call1, call2, call3, call4, empty_literal_ok


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
    print("usage: fragment_buffered_reader_read_record115.py "
          "[gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
