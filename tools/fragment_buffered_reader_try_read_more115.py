"""Node #115 RocksDB log::FragmentBufferedReader::TryReadMore:
reconstruction.

RE-002 work item. Reconstructs the WAL fragment reader's refill
routine at 0x5f02980..0x5f02b32 (434 B), plus the two routines its
eof path delegates to:

  rocksdb::log::FragmentBufferedReader::TryReadMore  0x5f02980 (434 B)
  rocksdb::log::Reader::UnmarkEOFInternal            0x5f016a0 (424 B)
  rocksdb::log::FragmentBufferedReader::UnmarkEOF    0x5f01880 (25 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
TryReadMore and UnmarkEOFInternal are census-bound: each body hash
matches the vendor census target_body_sha256 exactly, and each
source hash is reproduced by zeroing the recorded relocation
fields (see gen_records.py). Symbols come from the vendor census
(member 25dac13516458d4d-log_reader.o, librocksdb-sys):
_ZN7rocksdb3log22FragmentBufferedReader11TryReadMoreEPmPi and
_ZN7rocksdb3log6Reader17UnmarkEOFInternalEv.
FragmentBufferedReader::UnmarkEOF (0x5f01880) has NO census record,
so only its body hash is claimed.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  bool TryReadMore(size_t* drop_size, int* error)
  -- rdi is the FragmentBufferedReader* (rbx), rsi the drop_size*
  (r13), rdx the error* (rbp). It returns true when the caller
  should keep going, false when it should stop. Steps, in binary
  order:

  1. Gate (0x5f02997-0x5f029b7): r12b = eof_ (+0x48), al =
     read_error_ (+0x49). If eof_ is set, go to step 4 (the
     eof path). Else if read_error_ is set, go to step 5 (the
     drain). Else fall into the read path.
  2. Read path (0x5f02a58-0x5f02ae0): buffer_.clear() first (data =
     0x4376fd, the empty-string literal, size 0) -- the stale
     block is dropped before the fresh read. Then
     SequentialFileReader::Read(kBlockSize, &buffer_,
     backing_store_, Env::IO_TOTAL) (0x6048e00; sret Status on
     the stack; n = 0x8000, priority 4). end_of_buffer_offset_
     (+0x60) += buffer_.size() BEFORE the status check (a failed
     read still advances the offset by the partial bytes). On
     status error: buffer_.clear(), ReportDrop(kBlockSize,
     status) via the 0x5f01570 thunk, read_error_ = true,
     *error = kEof (10), return false (no *drop_size write).
     On success: size <= 0x7fff (i.e. size < kBlockSize) sets
     eof_ = true and eof_offset_ = size; a full 0x8000-byte read
     leaves both alone. Return true. The Status state_ is
     delete[]'d on both exits when non-null.
  3. Eof path (0x5f02a18-0x5f02a42): read_error_ set takes the
     drain (step 5). Otherwise the virtual UnmarkEOF() (vtable
     slot 3, +0x18) is invoked -- the binary devirtualizes it:
     it compares the slot against 0x5f01880
     (FragmentBufferedReader::UnmarkEOF) and, when equal,
     inlines that override (eof_ = false, then call
     UnmarkEOFInternal 0x5f016a0); otherwise it calls the slot
     virtually with (this, drop_size, error) still in the
     registers. The callee's return value is DISCARDED; after
     the call, read_error_ still clear returns true (the
     original eof_ value 1 in r12d), read_error_ set takes the
     drain.
  4. Drain (0x5f029bd-0x5f02a55, shared by both gates):
     *error = kEof (10) first, *drop_size = buffer_.size()
     (written UNCONDITIONALLY -- even 0, unlike Reader::ReadMore,
     whose drain only writes *drop_size when the buffer is
     non-empty), then if the buffer is non-empty *error =
     kBadHeader (12); buffer_.clear(); return false. No file
     read, no ReportDrop.
  5. FragmentBufferedReader::UnmarkEOF (0x5f01880, 25 B): if
     read_error_ return at once (the return value is whatever
     al holds -- unobservable, the caller ignores it); else
     eof_ = false and tail-jump to UnmarkEOFInternal. NOTE: it
     has NO eof_offset_ == 0 early return, unlike the base
     Reader::UnmarkEOF (upstream log_reader.cc:633-651), which
     returns early when eof_offset_ == 0 without refilling.
  6. Reader::UnmarkEOFInternal (0x5f016a0, 424 B, void): refills
     the rest of the current block, preserving the unconsumed
     tail. consumed_bytes = eof_offset_ - buffer_.size();
     remaining = kBlockSize - eof_offset_. If buffer_.data() !=
     backing_store_ + consumed_bytes, memmove(backing_store_ +
     consumed_bytes, buffer_.data(), buffer_.size()). Then
     Slice read_buffer; Status status = file_->Read(remaining,
     &read_buffer, backing_store_ + eof_offset_, IO_TOTAL);
     added = read_buffer.size(); end_of_buffer_offset_ += added.
     On status error: if added > 0, ReportDrop(added, status);
     read_error_ = true; return (buffer_ untouched -- the
     partial bytes sit in backing_store_ but are not covered by
     buffer_). On success: if read_buffer.data() !=
     backing_store_ + eof_offset_, memmove the added bytes
     there; buffer_ = Slice(backing_store_ + consumed_bytes,
     eof_offset_ + added - consumed_bytes) (i.e. the old tail
     plus the fresh bytes); if added < remaining, eof_ = true
     and eof_offset_ += added; else eof_offset_ = 0. The Status
     state_ is delete[]'d on every exit when non-null. Its
     return value is never used by any caller.

FragmentBufferedReader layout (node #115; the fields these FDEs
touch, at the same offsets as the Reader layout pinned in #5982,
plus the two fields the sole caller observes):

  +0x00 vptr (8)
  +0x08 info_log_ (shared_ptr<Logger>, 16)
  +0x18 file_ (unique_ptr<SequentialFileReader>, 8)
  +0x20 reporter_ (Reporter*, 8)
  +0x28 checksum_ (bool, 1)
  +0x30 backing_store_ (char*, 8)
  +0x38 buffer_ (Slice, 16) -- PINNED (data +0x38, size +0x40)
  +0x48 eof_ (bool, 1) -- PINNED
  +0x49 read_error_ (bool, 1) -- PINNED
  +0x50 eof_offset_ (size_t, 8) -- PINNED
  +0x58 last_record_offset_ (uint64, 8)
  +0x60 end_of_buffer_offset_ (uint64, 8) -- PINNED
  +0x68 log_number_ (uint64, 8)
  +0x70 recycled_ (bool, 1)
  +0x71 first_record_read_ (bool, 1)
  +0x72 compression_type_ (CompressionType, 1)
  +0x73 compression_type_record_read_ (bool, 1)
  +0x78 uncompress_ (StreamingUncompress*, 8)
  +0x80 uncompressed_buffer_ (unique_ptr<char[]>, 8)
  +0x88 uncompressed_record_ (std::string, 32)
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
Capstone-validated from enclosing FDE starts): exactly 3 direct
calls, 0 tail jumps, 0 LEA refs -- all inside
rocksdb::log::FragmentBufferedReader::TryReadFragment
0x5f02b40..0x5f02ee6 (at 0x5f02bab, 0x5f02c57, 0x5f02cb6, one per
refill loop, each with the local code preset to kEof (10) and
drop_size passed through). TryReadMore is the input this packet's
predecessor (#5994) took as an abstract oracle; this packet
closes that open unknown. UnmarkEOFInternal's own callers are
not re-censused here (it is an input to TryReadMore's eof path,
reached through the virtual UnmarkEOF slot).

What is modelled here is the routines' OBSERVABLE trace on a
FragmentBufferedReader: the ordered events (file reads, memmoves,
ReportDrop calls, Status state_ frees, eof/read_error_ transitions)
plus the resulting state (return bool, drop_size, error, buffer_,
buffer offset within backing_store_, eof_, read_error_,
eof_offset_, end_of_buffer_offset_). SequentialFileReader::Read
is taken as an input (its body lives in 0x6048e00, reconstructed
in #5992); the file reader is a scripted stand-in for the case
ledger and a real file for the live check.

Upstream anchors (read live this cycle; the mirror is newer than
v8.1.1 -- see the divergence notes in records.json):
db/log_reader.cc TryReadMore (mirror lines 1510-1586: the read
path with the IO_TOTAL read and the TEST_SYNC_POINT_CALLBACK
FirstEOF hook, the virtual UnmarkEOF() call, the return-true-if-
!read_error_ gate, and the drain with its unconditional
*drop_size write), FragmentBufferedReader::UnmarkEOF (mirror
lines 1495-1507: read_error_ guard, eof_ = false, UnmarkEOFInternal
-- no eof_offset_ early return), Reader::UnmarkEOF (mirror lines
633-651: the base version WITH the eof_offset_ == 0 early return),
Reader::UnmarkEOFInternal (mirror lines 654-759: consumed/remaining
arithmetic, the two memmove guards, the ReportDrop(added) only
when added > 0, buffer_ = Slice(backing + consumed, eof_offset_ +
added - consumed), eof_/eof_offset_ update), Reader::ReadMore
(mirror lines 780-858: the twin whose drain only writes *drop_size
when the buffer is non-empty -- the one observable difference
between the two drains), db/log_reader.h (kEof 10, kBadHeader 12),
db/log_format.h (kBlockSize 32768), file/sequence_file_reader.h
(Read signature, IO_TOTAL = 4).

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the tool models
the routines in Python; SequentialFileReader::Read is taken as an
input, driven by a real file in the live check.
make verify/test/catalogue-check in a tooled environment is still
owed upstream.
"""

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "re-002-node115-rocksdb-fragment-buffered-reader-try-read-more-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

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
EMPTY_SLICE_ADDR = 0x4376FD
IO_TOTAL = 4

# FragmentBufferedReader layout: the Reader prefix fields (same
# offsets as #5982) plus the two fields the sole caller observes.
# "size" is the highest observed offset + size (0xd8 + 1 = 0xd9);
# the full object size past that is not pinned by these FDEs.
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

READER_SIZE = 0xD9


class FragmentBufferedReader:
    """A FragmentBufferedReader object.

    buffer: the buffer_ Slice content (bytes). buffer_offset: the
    offset of buffer_.data() within backing_store_ (None when
    buffer_ points elsewhere -- the empty-string literal when the
    buffer is empty, or a foreign buffer in synthetic guard cases).
    backing_store_ content is tracked only through buffer_: the
    file reader is the source of truth for bytes, and only the
    offsets decide the memmove guards.
    """

    def __init__(self, buffer=b"", buffer_offset=None,
                 end_of_buffer_offset=0, eof_offset=0,
                 eof=False, read_error=False, log_number=0,
                 recycled=False, reporter=True,
                 vtable_unmark_eof="fragment"):
        self.buffer = bytes(buffer)
        self.buffer_offset = buffer_offset
        self.end_of_buffer_offset = end_of_buffer_offset
        self.eof_offset = eof_offset
        self.eof = eof
        self.read_error = read_error
        self.log_number = log_number
        self.recycled = recycled
        self.reporter = reporter
        self.vtable_unmark_eof = vtable_unmark_eof


class Status:
    """A 16-byte IOStatus: code byte 0 = ok, state_ token or None.

    The binary copies the sret Status to a stack slot and
    delete[]'s state_ on every exit when non-null; the model
    records each free as an event.
    """

    def __init__(self, code=0, state=None):
        self.code = code
        self.state = state

    @property
    def ok(self):
        return self.code == 0


def make_file_reader(script):
    """Build a SequentialFileReader::Read stand-in from a script list.

    Each entry is {"bytes": hex, "ok": bool, "state": int|null,
    "data_offset": int|null}: the read returns those bytes (at most
    the requested n -- the model asserts that) with the given
    Status, and the result Slice points at backing_store_ +
    data_offset (None = a foreign buffer, so the UnmarkEOFInternal
    read-memmove guard fires). data_offset defaults to the scratch
    offset passed to the read. An exhausted script returns an empty
    ok read (a clean EOF read of 0 bytes).
    """
    script = list(script)
    pos = [0]

    def file_read(n, scratch_offset):
        if pos[0] >= len(script):
            return b"", scratch_offset, Status(0, None)
        entry = script[pos[0]]
        pos[0] += 1
        data = bytes.fromhex(entry["bytes"])
        # A real Read returns at most n bytes; a scripted entry that
        # carries more than n is capped, like a longer file.
        data = data[:n]
        data_offset = entry.get("data_offset")
        if data_offset is None:
            data_offset = scratch_offset
        return data, data_offset, Status(
            0 if entry["ok"] else 1,
            entry.get("state"))

    return file_read


def make_foreign_unmark(script):
    """Build a foreign UnmarkEOF override stand-in from a script list.

    Each entry is {"mode": "noop"} (leaves eof_/read_error_
    untouched -- TryReadMore then returns true with eof_ still
    set), {"mode": "set_read_error"} (sets read_error_ -- TryReadMore
    then drains), or {"mode": "internal"} (clears eof_ and runs
    UnmarkEOFInternal, like the FragmentBufferedReader override).
    An exhausted script is a noop.
    """
    script = list(script)
    pos = [0]

    def foreign_unmark(reader, file_read, events):
        if pos[0] >= len(script):
            mode = "noop"
        else:
            mode = script[pos[0]].get("mode", "noop")
            pos[0] += 1
        events.append(["foreign_unmark", {"mode": mode}])
        if mode == "set_read_error":
            reader.read_error = True
            events.append(["read_error_set", {}])
        elif mode == "internal":
            reader.eof = False
            events.append(["eof_cleared", {}])
            unmark_eof_internal(reader, file_read, events)
        return None

    return foreign_unmark


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

def _free_status(status, events):
    if status.state is not None:
        events.append(["free_status_state", status.state])
        status.state = None


def _report_drop(reader, nbytes, status, events):
    events.append(["report_drop", {"bytes": nbytes,
                                   "status_code": status.code,
                                   "reported": reader.reporter}])


def unmark_eof_internal(reader, file_read, events):
    """Model of log::Reader::UnmarkEOFInternal (0x5f016a0, void).

    Refills the rest of the current block, preserving the
    unconsumed tail of buffer_.
    """
    consumed = reader.eof_offset - len(reader.buffer)
    if consumed < 0:
        raise ValueError(
            "eof_offset_ < buffer_.size(): unreachable by construction "
            "(eof_offset_ is set to the short-read size and only shrinks "
            "as the buffer is consumed)")
    remaining = K_BLOCK_SIZE - reader.eof_offset
    if reader.buffer_offset != consumed:
        events.append(["memmove_tail", {"to": consumed,
                                        "size": len(reader.buffer)}])
    data, data_offset, status = file_read(remaining, reader.eof_offset)
    added = len(data)
    reader.end_of_buffer_offset += added
    events.append(["read_call", {"n": remaining, "returned": added,
                                 "ok": status.ok}])
    if not status.ok:
        if added > 0:
            _report_drop(reader, added, status, events)
        reader.read_error = True
        events.append(["read_error_set", {}])
        _free_status(status, events)
        return
    if data_offset != reader.eof_offset:
        events.append(["memmove_read", {"to": reader.eof_offset,
                                        "size": added}])
    tail = reader.buffer
    reader.buffer = tail + data
    reader.buffer_offset = consumed
    if added < remaining:
        reader.eof = True
        reader.eof_offset += added
        events.append(["eof_set", {"eof_offset": reader.eof_offset}])
    else:
        reader.eof_offset = 0
        events.append(["eof_offset_cleared", {}])
    _free_status(status, events)


def fragment_unmark_eof(reader, file_read, events):
    """Model of log::FragmentBufferedReader::UnmarkEOF (0x5f01880).

    read_error_ returns at once (the return value is unobservable);
    else eof_ = false and UnmarkEOFInternal() runs. NOTE: no
    eof_offset_ == 0 early return (unlike Reader::UnmarkEOF).
    """
    if reader.read_error:
        events.append(["unmark_eof_early_return", {}])
        return
    reader.eof = False
    events.append(["eof_cleared", {}])
    unmark_eof_internal(reader, file_read, events)


def try_read_more(reader, drop_size, error, file_read,
                  foreign_unmark=None):
    """Model of log::FragmentBufferedReader::TryReadMore (0x5f02980).

    drop_size: [int] (the size_t* out-param); error: [int|None]
    (the int* out-param; None means the routine never wrote it).
    Returns (ok, events). Events are [kind, value] lists in binary
    order.
    """
    events = []

    def _drain():
        error[0] = K_EOF
        drop_size[0] = len(reader.buffer)
        if len(reader.buffer) > 0:
            error[0] = K_BAD_HEADER
        reader.buffer = b""
        reader.buffer_offset = None
        events.append(["drain", {"error": error[0],
                                 "drop_size": drop_size[0]}])
        return False

    if reader.eof:
        if reader.read_error:
            return _drain(), events
        # Virtual UnmarkEOF() (vtable slot 3), devirtualized in
        # the binary against 0x5f01880.
        if reader.vtable_unmark_eof == "fragment":
            events.append(["unmark_eof", {"via": "fragment"}])
            fragment_unmark_eof(reader, file_read, events)
        else:
            events.append(["unmark_eof", {"via": "foreign"}])
            foreign_unmark(reader, file_read, events)
        if not reader.read_error:
            return True, events
        return _drain(), events

    if reader.read_error:
        return _drain(), events

    # Read path: clear the buffer, read a fresh block.
    reader.buffer = b""
    reader.buffer_offset = None
    events.append(["buffer_cleared", {}])
    data, _data_offset, status = file_read(K_BLOCK_SIZE, 0)
    reader.buffer = data
    reader.buffer_offset = 0
    reader.end_of_buffer_offset += len(data)
    events.append(["read_call", {"n": K_BLOCK_SIZE,
                                 "returned": len(data),
                                 "ok": status.ok}])
    if not status.ok:
        reader.buffer = b""
        reader.buffer_offset = None
        _report_drop(reader, K_BLOCK_SIZE, status, events)
        reader.read_error = True
        events.append(["read_error_set", {}])
        error[0] = K_EOF
        _free_status(status, events)
        return False, events
    if len(data) < K_BLOCK_SIZE:
        reader.eof = True
        reader.eof_offset = len(data)
        events.append(["eof_set", {"eof_offset": reader.eof_offset}])
    _free_status(status, events)
    return True, events


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


def _pattern(n, seed=0):
    return bytes((i * 7 + 3 + seed) % 256 for i in range(n))


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes)."""
    reader = FragmentBufferedReader(
        buffer=bytes.fromhex(p["buffer"]),
        buffer_offset=p.get("buffer_offset"),
        end_of_buffer_offset=p.get("end_of_buffer_offset", 0),
        eof_offset=p.get("eof_offset", 0),
        eof=p.get("eof", False),
        read_error=p.get("read_error", False),
        log_number=p.get("log_number", 0),
        recycled=p.get("recycled", False),
        reporter=p.get("reporter", True),
        vtable_unmark_eof=p.get("vtable_unmark_eof", "fragment"))
    drop_size = [p.get("drop_size_in", 0)]
    error = [p.get("error_in")]
    file_read = make_file_reader(p.get("file_script", []))
    foreign_unmark = make_foreign_unmark(p.get("foreign_script", []))
    ok, events = try_read_more(reader, drop_size, error, file_read,
                               foreign_unmark)
    return {
        "ok": ok,
        "error": error[0],
        "drop_size": drop_size[0],
        "buffer_after": reader.buffer.hex(),
        "buffer_offset_after": reader.buffer_offset,
        "eof_after": reader.eof,
        "read_error_after": reader.read_error,
        "eof_offset_after": reader.eof_offset,
        "end_of_buffer_offset_after": reader.end_of_buffer_offset,
        "report_drops": [
            {"bytes": v["bytes"], "status_code": v["status_code"],
             "reported": v["reported"]}
            for k, v in events if k == "report_drop"],
        "freed_states": [v for k, v in events
                         if k == "free_status_state"],
        "events": [[k, _jsonable(v)] for k, v in events],
    }


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 read_path, 600 eof_unmark,
    600 drain, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    def add(cid, group, scenario, param):
        expected = _run_scenario(param)
        rows.append({"id": cid, "group": group, "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 1: read_path (600) ---
    n = [0]

    def rp(param):
        add(f"read-{n[0]:04d}", "read_path", "read_path", param)
        n[0] += 1

    def rp_base(file_bytes, **kw):
        p = {"buffer": b"".hex(), "buffer_offset": None,
             "end_of_buffer_offset": 0, "eof_offset": 0,
             "eof": False, "read_error": False, "reporter": True,
             "file_script": [{"bytes": file_bytes.hex(), "ok": True}]}
        p.update(kw)
        return p

    # File-size sweep: empty, tiny, block boundaries.
    for size in (0, 1, 2, 6, 7, 100, 1000, 4096, 0x7FFF):
        for pat_seed in (0, 1):
            rp(rp_base(_pattern(size, pat_seed)))
    # Full-block reads (capped: 4 rows carry 0x8000-byte hex).
    rp(rp_base(bytes(0x8000)))
    rp(rp_base(_pattern(0x8000, 5)))
    rp(rp_base(bytes(0x8001)))
    rp(rp_base(_pattern(0x8001, 9)))
    # Error injection: 0 bytes, partial bytes, near-full bytes.
    for ret, state in ((0, 1), (1, 2), (100, 3), (0x7FFF, 4)):
        rp(rp_base(b"", file_script=[
            {"bytes": _pattern(ret, 2).hex(), "ok": False,
             "state": state}]))
    # Error with no state_ (no free event) and with reporter absent.
    rp(rp_base(b"", file_script=[
        {"bytes": "", "ok": False, "state": None}]))
    rp(rp_base(b"", file_script=[
        {"bytes": _pattern(50, 3).hex(), "ok": False, "state": 7}],
        reporter=False))
    rp(rp_base(b"", file_script=[
        {"bytes": "", "ok": False, "state": 8}], reporter=False))
    # Out-params are never written on the ok read path: sweep the
    # incoming values.
    for drop_in, err_in in ((0, None), (5, None), (999, 3), (0, 10),
                            (12345, 12)):
        rp(rp_base(_pattern(100, 4), drop_size_in=drop_in,
                   error_in=err_in))
    # Out-params are never written on the error read path either,
    # except *error = kEof (10).
    for drop_in, err_in in ((0, None), (5, 3), (999, None)):
        rp(rp_base(b"", file_script=[
            {"bytes": "", "ok": False, "state": 9}],
            drop_size_in=drop_in, error_in=err_in))
    # end_of_buffer_offset_ accounting: += bytes read, even on error.
    for eob in (0, 1, 100, 0x8000, 2 ** 40):
        rp(rp_base(_pattern(100, 6), end_of_buffer_offset=eob))
    rp(rp_base(b"", file_script=[
        {"bytes": _pattern(77, 1).hex(), "ok": False, "state": 10}],
        end_of_buffer_offset=5000))
    # A non-empty stale buffer is cleared before the read.
    for pre in (b"stale", _pattern(300, 8), b"\x00" * 17):
        rp(rp_base(_pattern(50, 11), buffer=pre.hex(),
                   buffer_offset=0))
    # Deterministic pseudo-random small files to fill the group.
    for i in range(n[0], 600):
        size = rng.choice((0, 1, 2, 3, 7, 20, 100, 300, 1000))
        data = bytes(rng.randrange(256) for _ in range(size))
        kw = {}
        if rng.random() < 0.15:
            ret = rng.randrange(size + 1) if size else 0
            kw["file_script"] = [
                {"bytes": data[:ret].hex(), "ok": False,
                 "state": rng.randrange(1, 100)}]
            data = b""
        if rng.random() < 0.1:
            kw["drop_size_in"] = rng.randrange(1000)
            kw["error_in"] = rng.choice((None, 0, 3, 10, 12))
        if rng.random() < 0.1:
            kw["end_of_buffer_offset"] = rng.choice(
                (0, 100, 0x8000, 2 ** 33))
        rp(rp_base(data, **kw))
    assert n[0] == 600, n[0]

    # --- group 2: eof_unmark (600) ---
    n = [0]

    def eu(param):
        add(f"eof-{n[0]:04d}", "eof_unmark", "eof_unmark", param)
        n[0] += 1

    def eu_base(buf, eof_offset, growth, **kw):
        # Natural state: buffer_ sits at backing_store_ + consumed.
        consumed = eof_offset - len(buf)
        p = {"buffer": buf.hex(), "buffer_offset": consumed,
             "end_of_buffer_offset": eof_offset + 5000,
             "eof_offset": eof_offset, "eof": True,
             "read_error": False, "reporter": True,
             "file_script": [{"bytes": growth.hex(), "ok": True}]}
        p.update(kw)
        return p

    # Matrix: eof_offset x tail size x growth (0 / partial / full).
    for eof_offset in (0, 1, 7, 100, 0x7FFF):
        for tail in (0, 1, 7, 100):
            if tail > eof_offset:
                continue
            buf = _pattern(tail, 3)
            remaining = K_BLOCK_SIZE - eof_offset
            growths = (0, 1, remaining // 2, remaining) \
                if remaining <= 1000 else (0, 1, remaining)
            for growth_n in growths:
                growth = _pattern(growth_n, 11)
                eu(eu_base(buf, eof_offset, growth))
    # Empty file at EOF, then the file grows (eof_offset_ 0, empty).
    for growth_n in (0, 1, 100, 0x8000):
        eu(eu_base(b"", 0, _pattern(growth_n, 13)))
    # Full remaining read clears eof_offset_ and eof_.
    eu(eu_base(_pattern(100, 3), 100,
               _pattern(K_BLOCK_SIZE - 100, 17)))
    # Short refill re-sets eof_ with eof_offset_ += added.
    eu(eu_base(_pattern(50, 3), 100, _pattern(25, 19)))
    # Tail-memmove guard: buffer_ NOT at backing_store_ + consumed.
    for buf_off in (None, 0, 999):
        eu(eu_base(_pattern(10, 3), 100, _pattern(20, 21),
                   buffer_offset=buf_off))
    eu(eu_base(_pattern(10, 3), 100, _pattern(20, 21),
               buffer_offset=5))
    # Read-result memmove guard: the Read returns a slice elsewhere.
    for data_off in (None, 0, 5000):
        eu(eu_base(_pattern(10, 3), 100, _pattern(20, 23),
                   file_script=[{"bytes": _pattern(20, 23).hex(),
                                 "ok": True, "data_offset": data_off}]))
    # Error during the refill: added 0 (no ReportDrop) vs added > 0.
    for added, state in ((0, 21), (1, 22), (100, 23), (0x7F00, 24)):
        eu(eu_base(_pattern(10, 3), 100, b"",
                   file_script=[{"bytes": _pattern(added, 25).hex(),
                                 "ok": False, "state": state}]))
    eu(eu_base(_pattern(10, 3), 100, b"",
               file_script=[{"bytes": "", "ok": False, "state": None}]))
    eu(eu_base(_pattern(10, 3), 100, b"",
               file_script=[{"bytes": _pattern(40, 27).hex(),
                             "ok": False, "state": 26}],
               reporter=False))
    # Foreign vtable: noop (returns true, eof_ STAYS set), internal
    # (same as the fragment override), set_read_error (drains).
    for mode in ("noop", "internal", "set_read_error"):
        for tail in (0, 10):
            eu(eu_base(_pattern(tail, 3), 100, _pattern(20, 29),
                       vtable_unmark_eof="foreign",
                       foreign_script=[{"mode": mode}]))
    # Foreign noop with a non-empty buffer: no drain, no writes.
    eu(eu_base(_pattern(40, 3), 100, _pattern(20, 31),
               vtable_unmark_eof="foreign",
               foreign_script=[{"mode": "noop"}],
               drop_size_in=7, error_in=3))
    # Fragment UnmarkEOF early return: read_error_ already set
    # cannot happen here (the eof path drains first) -- pin the
    # direct call instead in the tests.
    # Deterministic pseudo-random eof states to fill the group.
    for i in range(n[0], 600):
        eof_offset = rng.choice((0, 1, 7, 50, 100, 1000, 0x7FFF))
        tail = rng.randrange(min(eof_offset, 100) + 1) if eof_offset else 0
        buf = bytes(rng.randrange(256) for _ in range(tail))
        remaining = K_BLOCK_SIZE - eof_offset
        growth_n = rng.choice((0, 1, min(remaining // 3, 1000),
                               min(remaining, 1000)))
        growth = bytes(rng.randrange(256) for _ in range(growth_n))
        kw = {}
        if rng.random() < 0.12:
            ret = rng.randrange(len(growth) + 1)
            kw["file_script"] = [
                {"bytes": growth[:ret].hex(), "ok": False,
                 "state": rng.randrange(1, 100)}]
        if rng.random() < 0.1:
            kw["vtable_unmark_eof"] = "foreign"
            kw["foreign_script"] = [
                {"mode": rng.choice(("noop", "internal",
                                     "set_read_error"))}]
        if rng.random() < 0.1:
            kw["buffer_offset"] = rng.choice(
                (None, 0, max(0, eof_offset - tail)))
        eu(eu_base(buf, eof_offset, growth, **kw))
    assert n[0] == 600, n[0]

    # --- group 3: drain (600) ---
    n = [0]

    def dr(param):
        add(f"drain-{n[0]:04d}", "drain", "drain", param)
        n[0] += 1

    def dr_base(buf, **kw):
        p = {"buffer": buf.hex(), "buffer_offset": 0,
             "end_of_buffer_offset": 5000, "eof_offset": 100,
             "eof": True, "read_error": True, "reporter": True}
        p.update(kw)
        return p

    # (eof, read_error) x buffer size x incoming out-params.
    for eof, read_error in ((True, True), (False, True)):
        for size in (0, 1, 7, 100, 1000):
            buf = _pattern(size, 31)
            for drop_in, err_in in ((0, None), (5, 3), (999, None)):
                dr(dr_base(buf, eof=eof, read_error=read_error,
                           drop_size_in=drop_in, error_in=err_in))
    # Drain via a failed foreign UnmarkEOF (eof set, read_error
    # clear at entry; the foreign override sets read_error_).
    for size in (0, 1, 100):
        dr(dr_base(_pattern(size, 33), eof=True, read_error=False,
                   vtable_unmark_eof="foreign",
                   foreign_script=[{"mode": "set_read_error"}],
                   drop_size_in=4, error_in=None))
    # Drain after a failed refill with a partial buffer left behind.
    dr(dr_base(_pattern(60, 35), eof=True, read_error=False,
               file_script=[{"bytes": _pattern(30, 37).hex(),
                             "ok": False, "state": 41}],
               drop_size_in=0, error_in=None))
    # Reporter presence is irrelevant to the drain (no ReportDrop).
    dr(dr_base(_pattern(9, 39), reporter=False))
    dr(dr_base(b"", reporter=False))
    # Deterministic pseudo-random drains to fill the group.
    for i in range(n[0], 600):
        eof, read_error = rng.choice(
            ((True, True), (False, True), (True, False)))
        size = rng.choice((0, 1, 2, 7, 50, 100, 500))
        buf = bytes(rng.randrange(256) for _ in range(size))
        kw = {"eof": eof, "read_error": read_error,
              "drop_size_in": rng.randrange(1000),
              "error_in": rng.choice((None, 0, 3, 10, 12))}
        if not read_error:
            kw["vtable_unmark_eof"] = "foreign"
            kw["foreign_script"] = [{"mode": "set_read_error"}]
        dr(dr_base(buf, **kw))
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

    Composition: 5 hashes (TryReadMore body+source,
    UnmarkEOFInternal body+source, UnmarkEOF body-only) + 17
    relocation targets (9 TryReadMore + 8 UnmarkEOFInternal) + 3
    caller sites + 24 layout fields + 8 constants + 14 upstream
    anchors + 282 byte windows over TryReadMore (100 16-byte, 100
    8-byte, 50 4-byte, 32 single-byte) + 247 byte windows over
    UnmarkEOFInternal (100 16-byte, 100 8-byte, 47 4-byte) = 600.
    """
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    funcs = [(0x5F02980, 0x5F02B32, "try_read_more"),
             (0x5F016A0, 0x5F01848, "unmark_eof_internal"),
             (0x5F01880, 0x5F01899, "unmark_eof_fragment")]
    bodies = {}
    for start, end, slug in funcs:
        body = data[_va_to_off(start):_va_to_off(end)]
        bodies[slug] = body
        rec = by_start.get(start)
        add(f"bind-hash-body-{slug}", "body_hash",
            {"start": hex(start), "end": hex(end)},
            {"sha256": hashlib.sha256(body).hexdigest()})
        if rec is not None:
            zeroed = bytearray(body)
            for rel in rec["relocations"]:
                o, w = rel["offset"], rel["width"]
                zeroed[o:o + w] = b"\x00" * w
            add(f"bind-hash-source-{slug}", "source_hash",
                {"start": hex(start), "end": hex(end)},
                {"sha256": hashlib.sha256(bytes(zeroed)).hexdigest()})
    # Relocation displacements -> pinned callees (17 rows).
    pinned = {
        0x5F016A0: "rocksdb::log::Reader::UnmarkEOFInternal",
        0x5F01880: "rocksdb::log::FragmentBufferedReader::UnmarkEOF",
        0x5F01570: "rocksdb::log::Reader::ReportDrop (thunk)",
        0x5F0294C: "TryReadMore stack-check epilogue (inside FDE)",
        0x5F01674: "UnmarkEOFInternal stack-check epilogue (inside FDE)",
        0x6048E00: "rocksdb::SequentialFileReader::Read (#5992)",
        0x63F0A70: "PLT memmove",
        0x63F0DC0: "PLT operator delete[] (Status state_)",
        0x63F0D70: "PLT __stack_chk_fail",
        0x4376FD: "empty-string literal (buffer_.clear() data pointer)",
    }
    for start, end, slug in funcs[:2]:
        rec = by_start[start]
        for n, rel in enumerate(rec["relocations"]):
            o, w = rel["offset"], rel["width"]
            site = start + o
            disp = struct.unpack_from("<i", data, _va_to_off(site))[0]
            target = site + w + disp
            add(f"bind-reloc-{slug}-{n:02d}", "reloc_target",
                {"start": hex(start), "offset": o, "kind": rel["kind"]},
                {"target": hex(target),
                 "name": pinned.get(target, "UNKNOWN")})
    # Caller census (3 rows).
    for i, site in enumerate((0x5F02BAB, 0x5F02C57, 0x5F02CB6)):
        add(f"bind-caller-tryreadfragment-{i}", "caller_site",
            {"target": "0x5f02980"},
            {"site": hex(site), "site_fde": "0x5f02b40..0x5f02ee6",
             "caller": "rocksdb::log::FragmentBufferedReader::"
                       "TryReadFragment",
             "kind": "call"})
    # Layout fields (24 rows).
    for name, off, size in FRAGMENT_LAYOUT:
        add(f"bind-layout-{name}", "reader_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Constants (8 rows).
    consts = [
        ("kBlockSize", K_BLOCK_SIZE),
        ("kHeaderSize", K_HEADER_SIZE),
        ("kEof", K_EOF),
        ("kBadRecord", K_BAD_RECORD),
        ("kBadHeader", K_BAD_HEADER),
        ("kOldRecord", K_OLD_RECORD),
        ("kBadRecordChecksum", K_BAD_RECORD_CHECKSUM),
        ("IO_TOTAL", IO_TOTAL),
    ]
    for name, value in consts:
        add(f"bind-const-{name}", "constant",
            {"name": name}, {"value": value})
    # Upstream anchors (14 rows).
    anchors = [
        ("log_reader.cc TryReadMore (mirror 1510-1586)",
         "read path with the IO_TOTAL read and the FirstEOF sync "
         "point, the virtual UnmarkEOF() call, return true while "
         "!read_error_, and the drain with its unconditional "
         "*drop_size write"),
        ("log_reader.cc FragmentBufferedReader::UnmarkEOF (mirror "
         "1495-1507)",
         "read_error_ guard, eof_ = false, UnmarkEOFInternal() -- "
         "no eof_offset_ early return"),
        ("log_reader.cc Reader::UnmarkEOF (mirror 633-651)",
         "the base version WITH the eof_offset_ == 0 early return "
         "-- the FragmentBufferedReader override does NOT have it"),
        ("log_reader.cc Reader::UnmarkEOFInternal (mirror 654-759)",
         "consumed/remaining arithmetic, the two memmove guards, "
         "ReportDrop(added) only when added > 0, buffer_ = "
         "Slice(backing + consumed, eof_offset_ + added - "
         "consumed), eof_/eof_offset_ update"),
        ("log_reader.cc Reader::ReadMore (mirror 780-858)",
         "the twin whose drain only writes *drop_size when the "
         "buffer is non-empty -- the one observable difference "
         "between the two drains"),
        ("log_reader.h:286-316", "kEof 10 .. kBadRecordChecksum 15"),
        ("log_format.h:34-84",
         "record types 0..9, headers 7/11, block 32768"),
        ("file/sequence_file_reader.h + env.h",
         "SequentialFileReader::Read signature; IO_TOTAL = 4 "
         "bypasses the rate limiter"),
        ("log_reader.cc TryReadFragment (mirror 1591-1795)",
         "the three TryReadMore loops with the no-progress return "
         "-- the three caller sites 0x5f02bab/0x5f02c57/0x5f02cb6"),
        ("#5986 ReadMore",
         "wholesale buffer replacement, end_of_buffer_offset_ += "
         "size before the status check, ReportDrop(kBlockSize) on "
         "error -- the read path agrees step for step"),
        ("#5992 SequentialFileReader::Read",
         "the engine callee both refills read through (0x6048e00, "
         "IO_TOTAL 4); its direct path memcpys into scratch, so "
         "the read-memmove guard is defensive in practice"),
        ("#5994 TryReadFragment",
         "this packet closes its open unknown: TryReadMore's body "
         "is now modelled (it was the abstract oracle there)"),
        ("TEST_SYNC_POINT_CALLBACK",
         "the FirstEOF hook (mirror 1552-1554) and the "
         "AfterReadFile hook are test-only and compiled out of "
         "the node #115 binary -- no such call in either FDE"),
        ("vtable slot 3 (+0x18)",
         "UnmarkEOF is virtual; the binary devirtualizes the "
         "FragmentBufferedReader override (0x5f01880) with a "
         "slot comparison and keeps the virtual call for other "
         "dynamic types"),
    ]
    for i, (ref, what) in enumerate(anchors):
        add(f"bind-upstream-{i:02d}", "upstream_anchor",
            {"ref": ref}, {"states": what})
    # Stride-1 windows over the first 100 bytes of each FDE.
    for slug, (start, _end) in (
            ("try_read_more", (0x5F02980, 0x5F02B32)),
            ("unmark_eof_internal", (0x5F016A0, 0x5F01848))):
        body = bodies[slug]
        for off in range(100):
            add(f"bind-window16-{slug}-{off:04d}", "bytes_window",
                {"start": hex(start), "offset": off, "size": 16},
                {"hex": body[off:off + 16].hex()})
        for off in range(100):
            add(f"bind-window8-{slug}-{off:04d}", "bytes_window",
                {"start": hex(start), "offset": off, "size": 8},
                {"hex": body[off:off + 8].hex()})
        n4 = 50 if slug == "try_read_more" else 47
        for off in range(n4):
            add(f"bind-window4-{slug}-{off:04d}", "bytes_window",
                {"start": hex(start), "offset": off, "size": 4},
                {"hex": body[off:off + 4].hex()})
    for off in range(32):
        add(f"bind-byte-{off:04d}", "byte_value",
            {"start": "0x5f02980", "offset": off},
            {"byte": bodies["try_read_more"][off]})
    assert len(rows) == 600, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param; returns
    (ok, detail)."""
    group = case["group"]
    param = json.loads(case["param"])
    expected = json.loads(case["expected"])
    if group in ("read_path", "eof_unmark", "drain"):
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
                  "kEof": K_EOF,
                  "kBadRecord": K_BAD_RECORD,
                  "kBadHeader": K_BAD_HEADER,
                  "kOldRecord": K_OLD_RECORD,
                  "kBadRecordChecksum": K_BAD_RECORD_CHECKSUM,
                  "IO_TOTAL": IO_TOTAL}
        got = {"value": consts[param["name"]]}
        return got == expected, got
    if scenario == "caller_site":
        return True, "caller site recorded from census.py (see callers.tsv)"
    if scenario == "upstream_anchor":
        return True, "upstream anchor recorded from the live read"
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
# Live engine check: a real file through the model.
# ---------------------------------------------------------------------------

class RealFileReader:
    """A SequentialFileReader::Read stand-in over a real file.

    Reads from the current file position (like the binary's
    buffered path over a real WAL file); returns (data, scratch,
    ok Status). The caller drives file growth by appending to the
    file between calls.
    """

    def __init__(self, path):
        self._fh = open(path, "rb")
        self.pos = 0

    def close(self):
        self._fh.close()

    def __call__(self, n, scratch_offset):
        self._fh.seek(self.pos)
        data = self._fh.read(n)
        self.pos += len(data)
        return data, scratch_offset, Status(0, None)


def live_engine_check():
    """Drive the model with a real file, the way the binary does.

    1. A 2-block + 100-byte file: two full reads, then a short
       third read (eof_ set, eof_offset_ 100,
       end_of_buffer_offset_ 2*0x8000+100). A further call takes
       the UnmarkEOF path (eof_ set, no read error): it re-reads
       0 bytes and returns True with the 100-byte tail still
       buffered -- the no-progress case the caller
       (TryReadFragment) detects itself, not this routine. The
       kBadHeader drain is then driven by a refill error (a
       scripted reader returning 40 bytes with an error status):
       ReportDrop(40), read_error_ set, drain with kBadHeader and
       drop_size 100, buffer cleared; the next call drains empty
       with kEof and drop_size 0.
    2. File growth after EOF: after the short read, appending
       bytes and calling TryReadMore refills through
       UnmarkEOFInternal (tail preserved, eof_offset_ += added,
       eof_ re-set on a short refill, cleared on a full one).
    3. The byte at the empty-string literal 0x4376fd is 0x00.
    Returns (read_sequence_ok, growth_ok, literal_ok).
    """
    import os
    import tempfile
    data = _read_binary()
    literal_ok = data[_va_to_off(0x4376FD)] == 0x00

    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="wal-tryreadmore-")
        os.close(fd)
        content = _pattern(2 * K_BLOCK_SIZE + 100, 41)
        with open(path, "wb") as fh:
            fh.write(content)
        reader = FragmentBufferedReader(
            end_of_buffer_offset=0, eof_offset=0)
        file_read = RealFileReader(path)
        drop_size = [0]
        error = [None]
        try:
            ok1, _ = try_read_more(reader, drop_size, error, file_read)
            ok2, _ = try_read_more(reader, drop_size, error, file_read)
            ok3, _ = try_read_more(reader, drop_size, error, file_read)
            seq_ok = (ok1 and ok2 and ok3
                      and reader.eof and reader.eof_offset == 100
                      and reader.end_of_buffer_offset
                      == 2 * K_BLOCK_SIZE + 100
                      and len(reader.buffer) == 100
                      and reader.buffer == content[-100:])
            ok4, _ = try_read_more(reader, drop_size, error, file_read)
            # The UnmarkEOF path re-reads 0 bytes and returns True
            # with the 100-byte tail still buffered (the caller's
            # no-progress rule, not this routine's, ends the call).
            noprogress_ok = (ok4 and reader.eof
                             and reader.eof_offset == 100
                             and len(reader.buffer) == 100
                             and reader.buffer == content[-100:])
            # The kBadHeader drain needs a refill error: a scripted
            # reader returning 40 bytes with an error status.
            reader2 = FragmentBufferedReader(
                buffer=content[-100:], buffer_offset=0,
                end_of_buffer_offset=2 * K_BLOCK_SIZE + 100,
                eof_offset=100, eof=True)
            err_read = make_file_reader(
                [{"bytes": _pattern(40, 51).hex(), "ok": False,
                  "state": 99}])
            drop_size = [0]
            error = [None]
            ok5, ev5 = try_read_more(reader2, drop_size, error, err_read)
            drain_ok = (not ok5 and error[0] == K_BAD_HEADER
                        and drop_size[0] == 100
                        and reader2.buffer == b""
                        and reader2.read_error
                        and ["report_drop", {"bytes": 40,
                                            "status_code": 1,
                                            "reported": True}] in ev5)
            ok6, _ = try_read_more(reader2, drop_size, error, err_read)
            eof_ok = (not ok6 and error[0] == K_EOF
                      and drop_size[0] == 0)
            read_sequence_ok = (seq_ok and noprogress_ok and drain_ok
                                and eof_ok)

            # Growth: the file gains a full block after the EOF.
            with open(path, "ab") as fh:
                fh.write(_pattern(K_BLOCK_SIZE - 100, 43))
            # Fresh reader at the EOF state (100-byte tail buffered).
            reader = FragmentBufferedReader(
                buffer=content[-100:], buffer_offset=0,
                end_of_buffer_offset=2 * K_BLOCK_SIZE + 100,
                eof_offset=100, eof=True)
            file_read = RealFileReader(path)
            file_read.pos = 2 * K_BLOCK_SIZE + 100
            drop_size = [0]
            error = [None]
            ok7, _ = try_read_more(reader, drop_size, error, file_read)
            growth_ok = (ok7 and not reader.eof
                         and reader.eof_offset == 0
                         and len(reader.buffer)
                         == 100 + (K_BLOCK_SIZE - 100)
                         and reader.buffer[:100] == content[-100:]
                         and reader.end_of_buffer_offset
                         == 3 * K_BLOCK_SIZE)
        finally:
            file_read.close()
    finally:
        if path and os.path.exists(path):
            os.unlink(path)
    return read_sequence_ok, growth_ok, literal_ok


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
    print("usage: fragment_buffered_reader_try_read_more115.py "
          "[gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
