"""Node #115 RocksDB log::Reader::ReadMore: reconstruction.

RE-002 work item. Reconstructs the WAL reader's block refill at
0x5f018d0..0x5f01a30 (352 B):

  rocksdb::log::Reader::ReadMore  0x5f018d0 (352 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The body hash matches the vendor census target_body_sha256 exactly,
and the source hash is reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbol comes from the vendor
census (member 25dac13516458d4d-log_reader.o, librocksdb-sys):
_ZN7rocksdb3log6Reader8ReadMoreEPmPi.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  bool ReadMore(size_t* drop_size, int* error)
  -- rdi is the Reader* (rbx), rsi the drop_size* (r12 = rdx on
  entry, moved to r12), rdx the error* (r12). Returns true when a
  fresh block was read, false otherwise. Steps, in binary order:

  1. Gate (0x5f018f4): if eof_ (+0x48) is set, or read_error_
     (+0x49) is set, take the drain path (step 4). Otherwise take
     the read path (steps 2-3). The gate is `!eof_ && !read_error_`
     (upstream db/log_reader.cc:732).
  2. Read path: buffer_.clear() first -- size 0 at +0x40
     (0x5f0196f), data = 0x4376fd, the empty-string literal
     (0x5f0197f). Then call SequentialFileReader::Read(kBlockSize,
     &buffer_, backing_store_, Env::IO_TOTAL) at 0x5f01997 (rdi =
     sret Status* at rsp+0x10, rsi = file_ (+0x18), rdx = 0x8000,
     rcx = &buffer_, r8 = backing_store_ (+0x30), r9 = 4 =
     IO_TOTAL). The 16-byte Status lands at rsp+0x10 and is copied
     to the local at rsp+0x00.
  3. After the read: end_of_buffer_offset_ (+0x60) += buffer_.size()
     (0x5f019b7-0x5f019bb) -- this runs BEFORE the status check, so
     a failed read still advances the offset by the bytes actually
     read. If the Status code byte (rsp+0x10) is non-zero: the error
     path (0x5f019f0): buffer_.clear() again (data 0x4376fd, size 0),
     ReportDrop(kBlockSize, status) -- the 0x5f01570 thunk (rdi =
     this, rsi = 0x8000, rdx = &status), which calls
     reporter_->Corruption(bytes, reason) when reporter_ (+0x20)
     is non-null -- then read_error_ = true (0x5f01a0c),
     *error = kEof (10) (0x5f01a15), and return false. If the
     Status is ok: if buffer_.size() < kBlockSize (cmp $0x7fff;
     ja skips), eof_ = true and eof_offset_ (+0x50) =
     buffer_.size() (0x5f019ce-0x5f019d2). Return true.
     On BOTH read-path exits the local Status is destroyed: its
     state_ pointer (rsp+0x08) is delete[]'d when non-null
     (0x5f019db-0x5f019e4, _ZdaPv PLT 0x63f0dc0).
  4. Drain path (0x5f01903): the buffer holds a truncated header
     (or nothing) at the end of the file. If buffer_.size() > 0:
     *drop_size = buffer_.size(), buffer_.clear() (data 0x4376fd,
     size 0), *error = kBadHeader (12), return false. If the buffer
     is empty: buffer_.clear() (data 0x4376fd; size already 0, so no
     size write), *error = kEof (10), return false. No file read,
     no ReportDrop on this path.

  The exception landing pad (0x5f01a24-0x5f01a2b, jumping to the
  shared pad at 0x5f0189a) frees the local Status state_ (delete[]
  when non-null), checks the stack canary, and resumes unwinding
  (_Unwind_Resume). It is not modelled as an observable event: the
  model never throws.

Reader layout (node #115, the pinned fields from the field
accesses, the rest derived from the member order in upstream
db/log_reader.h with natural alignment -- same layout as #5979 /
#5982):

  +0x00 vptr (8)
  +0x08 info_log_ (shared_ptr<Logger>, 16)
  +0x18 file_ (unique_ptr<SequentialFileReader>, 8) -- PINNED (Read)
  +0x20 reporter_ (Reporter*, 8) -- PINNED (ReportDrop thunk)
  +0x28 checksum_ (bool, 1)
  +0x30 backing_store_ (char*, 8) -- PINNED (Read scratch)
  +0x38 buffer_ (Slice, 16) -- PINNED (data +0x38, size +0x40)
  +0x48 eof_ (bool, 1) -- PINNED (gate)
  +0x49 read_error_ (bool, 1) -- PINNED (gate + error path)
  +0x50 eof_offset_ (size_t, 8) -- PINNED (short-read arm)
  +0x58 last_record_offset_ (uint64, 8)
  +0x60 end_of_buffer_offset_ (uint64, 8) -- PINNED (advance)
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
  +0xb8 recorded_cf_to_ts_sz_ (UnorderedMap, 56)
  total 0xf0

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts, cross-checked by a
second raw scan): exactly 1 direct call, 0 tail jumps, 0 LEA refs
-- the loop-head call at 0x5f01aab inside
rocksdb::log::Reader::ReadPhysicalRecord 0x5f01a30..0x5f01e7d.
Both the short-buffer and the recyclable-short-header paths in
ReadPhysicalRecord `continue` back to that one loop head, so one
site serves both. FragmentBufferedReader::TryReadMore is a
separate routine (its own read), not a caller.

What is modelled here is the routine's OBSERVABLE trace on a
Reader: the ordered events (gate decision, buffer clear, file
read, offset advance, eof set, ReportDrop call, state_ free,
drain drop) plus the resulting state (return value, *error,
*drop_size, buffer_, eof_, read_error_, eof_offset_,
end_of_buffer_offset_). SequentialFileReader::Read and
Reporter::Corruption are taken as inputs (their bodies live in
0x6048e00 and the reporter's vtable); the live check drives a
real file through the same Read contract the engine callee
implements.

Upstream anchors (RocksDB v8.1.1, read live this cycle):
db/log_reader.cc:730-808 (ReadMore, step for step -- the
!eof_ && !read_error_ gate, buffer_.clear() before the read,
file_->Read(kBlockSize, &buffer_, backing_store_, Env::IO_TOTAL),
end_of_buffer_offset_ += buffer_.size() before the status check,
the error arm with buffer_.clear() + ReportDrop(kBlockSize,
status) + read_error_ = true + *error = kEof, the short-read arm
with eof_ = true and eof_offset_ = buffer_.size(), and the drain
arm with kBadHeader/kEof),
db/log_reader.cc:719-727 (ReportDrop: reporter_ != nullptr ->
reporter_->Corruption(bytes, reason), no other guard),
db/log_reader.h:207-231 (member order: file_ +0x18, reporter_
+0x20, checksum_ +0x28, backing_store_ +0x30, buffer_ +0x38,
eof_ +0x48, read_error_ +0x49, eof_offset_ +0x50,
end_of_buffer_offset_ +0x60),
db/log_reader.h:286-316 (kEof 10, kBadRecord 11, kBadHeader 12,
kOldRecord 13, kBadRecordLen 14, kBadRecordChecksum 15),
file/sequence_file_reader.h:190-192 (Read(size_t n, Slice*
result, char* scratch, Env::IOPriority rate_limiter_priority)),
file/sequence_file_reader.cc:69-265 (the Read body: the buffered
path bumps scratch[0] first, loops file_->Read into scratch,
*result = Slice(scratch, read); IO_TOTAL bypasses the rate
limiter),
include/rocksdb/env.h:809 (IO_TOTAL = 4),
db/log_reader.cc:811-835 (ReadPhysicalRecord loop head: the one
ReadMore call site at 0x5f01aab, r preset to kEof).

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the tool models
the routine in Python; SequentialFileReader::Read and
Reporter::Corruption are taken as inputs, and the live check reads
a real file through the same Read contract. make
verify/test/catalogue-check in a tooled environment is still owed
upstream.
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
          / "re-002-node115-rocksdb-log-reader-read-more-115")
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
EMPTY_SLICE_ADDR = 0x4376FD

# Full derived Reader layout: (field, offset, size).
READER_LAYOUT = [
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
    ("recorded_cf_to_ts_sz_", 0xB8, 56),
    ("size", 0x00, 0xF0),
]

# Reader fields observed in this FDE (the rest is derived).
READER_SIZE = 0xF0


# ---------------------------------------------------------------------------
# Reader model
# ---------------------------------------------------------------------------

class Reader:
    """A Reader object: buffer_ as bytes, scalar fields, token ids for
    its pointer members (0 = null). Tokens stand in for heap pointers
    the same way the sibling packets use them."""

    def __init__(self, buffer=b"", eof=False, read_error=False,
                 eof_offset=0, end_of_buffer_offset=0, file_=0,
                 reporter_=0, backing_store=0):
        self.buffer = bytes(buffer)
        # buffer_data: "empty" (data == 0x4376fd, the empty-string
        # literal after clear()) or "backing_store" (data points into
        # the kBlockSize scratch after a successful read).
        self.buffer_data = "empty" if not buffer else "backing_store"
        self.eof = eof
        self.read_error = read_error
        self.eof_offset = eof_offset
        self.end_of_buffer_offset = end_of_buffer_offset
        self.file_ = file_
        self.reporter_ = reporter_
        self.backing_store = backing_store

    def clear_buffer(self):
        """Slice::clear(): data = 0x4376fd (empty-string literal),
        size = 0."""
        self.buffer = b""
        self.buffer_data = "empty"


def read_more(reader, drop_size, error, read_fn, report_drop):
    """Model of log::Reader::ReadMore (0x5f018d0).

    drop_size: [int] (the size_t* out-param);
    error: [int] (the int* out-param, r);
    read_fn(reader, n, scratch) -> (ok, result_bytes, state):
        the SequentialFileReader::Read stand-in. ok is the Status
        code byte (True == kOk); result_bytes are the bytes the
        engine put in buffer_ (at most n); state is None (Status
        state_ null) or a bytes object (the heap state_ the Status
        destructor delete[]'s).
    report_drop(bytes, state): the ReportDrop stand-in; called with
        (kBlockSize, status state) on the error path only.
    Returns (return_value, events). Events are [kind, value] lists
    in binary order.
    """
    events = []
    if not reader.eof and not reader.read_error:
        events.append(["gate", {"eof": False, "read_error": False,
                                "path": "read"}])
        # buffer_.clear() before the read.
        reader.clear_buffer()
        events.append(["buffer_clear", {"data": hex(EMPTY_SLICE_ADDR),
                                        "size": 0}])
        # file_->Read(kBlockSize, &buffer_, backing_store_, IO_TOTAL).
        ok, result, state = read_fn(reader, K_BLOCK_SIZE,
                                    reader.backing_store)
        reader.buffer = bytes(result[:K_BLOCK_SIZE])
        reader.buffer_data = "backing_store"
        # end_of_buffer_offset_ += buffer_.size() -- BEFORE the
        # status check, so a failed read still advances it.
        reader.end_of_buffer_offset += len(reader.buffer)
        events.append(["file_read",
                       {"ok": ok, "bytes": len(reader.buffer),
                        "state_present": state is not None,
                        "end_of_buffer_offset":
                            reader.end_of_buffer_offset}])
        if not ok:
            reader.clear_buffer()
            events.append(["buffer_clear", {"data": hex(EMPTY_SLICE_ADDR),
                                            "size": 0}])
            report_drop(K_BLOCK_SIZE, state)
            events.append(["report_drop", {"bytes": K_BLOCK_SIZE,
                                           "state_present":
                                               state is not None}])
            reader.read_error = True
            error[0] = K_EOF
            events.append(["set_read_error", True])
            if state is not None:
                # The local Status destructor: delete[] state_.
                events.append(["status_state_freed", True])
            return False, events
        if len(reader.buffer) < K_BLOCK_SIZE:
            reader.eof = True
            reader.eof_offset = len(reader.buffer)
            events.append(["eof_set", {"eof_offset": reader.eof_offset}])
        if state is not None:
            events.append(["status_state_freed", True])
        return True, events
    # Drain path: eof_ or read_error_ is set.
    events.append(["gate", {"eof": reader.eof,
                            "read_error": reader.read_error,
                            "path": "drain"}])
    if len(reader.buffer) > 0:
        drop_size[0] = len(reader.buffer)
        reader.clear_buffer()
        error[0] = K_BAD_HEADER
        events.append(["drop_truncated_header",
                       {"drop_size": drop_size[0]}])
        return False, events
    reader.clear_buffer()
    error[0] = K_EOF
    events.append(["eof_empty", True])
    return False, events


# ---------------------------------------------------------------------------
# Scripted inputs (SequentialFileReader::Read / ReportDrop) for the case
# ledger.
# ---------------------------------------------------------------------------

def make_file_read(script):
    """Build a SequentialFileReader::Read stand-in from a script list.

    Each entry is {"ok": bool, "bytes": hex, "state": hex|null}.
    "bytes" are the bytes the engine put in buffer_ (capped at
    kBlockSize); "state" is the Status state_ (None == null). An
    exhausted script returns (True, b"", None) -- an empty read at
    EOF.
    """
    script = list(script)
    pos = [0]

    def read_fn(reader, n, scratch):
        if pos[0] >= len(script):
            return True, b"", None
        entry = script[pos[0]]
        pos[0] += 1
        result = bytes.fromhex(entry.get("bytes", ""))
        state = (None if entry.get("state") is None
                 else bytes.fromhex(entry["state"]))
        return bool(entry.get("ok", True)), result, state

    return read_fn


def make_report_drop(sink=None):
    """Build a ReportDrop stand-in. Calls are appended to `sink`
    (a list) as (bytes, state-or-None)."""
    calls = [] if sink is None else sink

    def report_drop(nbytes, state):
        calls.append((nbytes, None if state is None else bytes(state)))

    report_drop.calls = calls
    return report_drop


def _jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v

# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes).

    "calls" (default 1) runs read_more() that many times in a row,
    sharing one Reader and one scripted read; each call gets fresh
    drop_size/error out-params. The per-call outcomes are listed in
    "calls_out"; the remaining fields describe the final state.
    """
    reader = Reader(
        buffer=bytes.fromhex(p.get("buffer", "")),
        eof=p.get("eof", False),
        read_error=p.get("read_error", False),
        eof_offset=p.get("eof_offset", 0),
        end_of_buffer_offset=p.get("end_of_buffer_offset", 0),
        file_=p.get("file_", 0),
        reporter_=p.get("reporter_", 0),
        backing_store=p.get("backing_store", 0))
    # A non-empty initial buffer points into backing_store_ (the
    # previous block); an empty one points at the empty literal.
    if p.get("buffer"):
        reader.buffer_data = "backing_store"
    read_fn = make_file_read(p.get("read_script", []))
    drops = []
    report_drop = make_report_drop(drops)
    calls_out = []
    all_events = []
    for _ in range(p.get("calls", 1)):
        drop_size = [p.get("drop_size_in", 0)]
        error = [p.get("error_in", 0)]
        ret, events = read_more(reader, drop_size, error, read_fn,
                                report_drop)
        calls_out.append({"return": ret, "error": error[0],
                          "drop_size": drop_size[0],
                          "buffer_after": reader.buffer.hex(),
                          "buffer_data_after": reader.buffer_data})
        all_events.extend(events)
    return {
        "calls_out": calls_out,
        "buffer_after": reader.buffer.hex(),
        "buffer_data_after": reader.buffer_data,
        "eof_after": reader.eof,
        "read_error_after": reader.read_error,
        "eof_offset_after": reader.eof_offset,
        "end_of_buffer_offset_after": reader.end_of_buffer_offset,
        "report_drop_calls": [[n, None if s is None else s.hex()]
                              for n, s in drops],
        "events": [[k, _jsonable(v)] for k, v in all_events],
    }


def _bytes(n, seed=0):
    return bytes((i * 7 + seed) % 256 for i in range(n))


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 read_path, 600 drain_path,
    600 sequences, 600 bindings."""
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

    # Full-block reads: 8 rows, sizes exactly kBlockSize, varied
    # content and starting offsets. No eof_ set, offset advances by
    # 0x8000, buffer holds the block. (Capped at 8: each full-block
    # row carries 64 KiB of hex twice, in param and in expected, and
    # cases.tsv must stay under GitHub's 100 MB file limit.)
    for i in range(8):
        rp({"buffer": "", "end_of_buffer_offset": i * K_BLOCK_SIZE,
            "read_script": [{"ok": True,
                             "bytes": _bytes(K_BLOCK_SIZE, i).hex(),
                             "state": None}]})
    # Short reads: every length 0..32767 sampled (0, 1, 2, 7, 100,
    # 1000, 0x7ffe, 0x7fff) + a sweep: eof_ set, eof_offset_ = size.
    for size in (0, 1, 2, 7, 100, 1000, 0x7FFE, 0x7FFF):
        for off in (0, K_BLOCK_SIZE):
            rp({"buffer": "", "end_of_buffer_offset": off,
                "read_script": [{"ok": True,
                                 "bytes": _bytes(size, size).hex(),
                                 "state": None}]})
    for size in range(0, 0x1001, 997):  # 5 rows across 0..0x1000
        rp({"buffer": "", "end_of_buffer_offset": 0,
            "read_script": [{"ok": True,
                             "bytes": _bytes(size, size).hex(),
                             "state": None}]})
    # Mid-range sizes (the top end is pinned by the 0x7fff rows).
    for size in (0x2000, 0x4000, 0x6000):
        rp({"buffer": "", "end_of_buffer_offset": 0,
            "read_script": [{"ok": True,
                             "bytes": _bytes(size, size).hex(),
                             "state": None}]})
    # Exact-boundary: 0x7fff sets eof, 0x8000 does not (8 rows each
    # side of the boundary, deterministic pseudo-random offsets).
    for i in range(8):
        rp({"buffer": "", "end_of_buffer_offset": rng.randrange(0, 1 << 20),
            "read_script": [{"ok": True,
                             "bytes": _bytes(0x7FFF, i).hex(),
                             "state": None}]})
        rp({"buffer": "", "end_of_buffer_offset": rng.randrange(0, 1 << 20),
            "read_script": [{"ok": True,
                             "bytes": _bytes(0x8000, i).hex(),
                             "state": None}]})
    # Failed reads: ok=False with a partial byte count (0, 1, 100,
    # 0x7fff) and with/without a Status state_. Buffer cleared,
    # read_error_ set, *error = kEof, ReportDrop(kBlockSize), and
    # end_of_buffer_offset_ still advances by the partial bytes.
    for size in (0, 1, 100, 0x7FFF):
        for state in (None, "deadbeef", "00"):
            rp({"buffer": "", "end_of_buffer_offset": K_BLOCK_SIZE,
                "read_script": [{"ok": False,
                                 "bytes": _bytes(size, size).hex(),
                                 "state": state}]})
    # Failed reads with a full block already in the buffer: the old
    # block is cleared first (buffer_.clear() before the read), so
    # the failure leaves an empty buffer, not the old block.
    for size in (0, 500):
        rp({"buffer": _bytes(1000, 3).hex(),
            "end_of_buffer_offset": K_BLOCK_SIZE,
            "read_script": [{"ok": False,
                             "bytes": _bytes(size, size).hex(),
                             "state": "aabbccdd"}]})
    # Successful reads with a non-null Status state_: the state_ is
    # delete[]'d (status_state_freed event) on the success path too.
    for i in range(20):
        rp({"buffer": "", "end_of_buffer_offset": 0,
            "read_script": [{"ok": True,
                             "bytes": _bytes(100 + i, i).hex(),
                             "state": "01020304"}]})
    # The read replaces the buffer wholesale: a stale 500-byte buffer
    # is gone after a short read (10 bytes), and after a full read.
    rp({"buffer": _bytes(500, 9).hex(), "end_of_buffer_offset": 1000,
        "read_script": [{"ok": True, "bytes": _bytes(10, 1).hex(),
                         "state": None}]})
    rp({"buffer": _bytes(500, 9).hex(), "end_of_buffer_offset": 1000,
        "read_script": [{"ok": True,
                         "bytes": _bytes(K_BLOCK_SIZE, 2).hex(),
                         "state": None}]})
    # Deterministic pseudo-random read_path rows to fill the group
    # (sizes capped at 1000: the boundary rows above already pin
    # 0x7fff/0x8000, and full-block hex is 64 KiB per row).
    for i in range(n[0], 600):
        size = rng.choice((0, 1, 7, 100, 1000))
        ok = rng.random() < 0.85
        state = None if rng.random() < 0.7 else "%08x" % rng.randrange(1 << 32)
        rp({"buffer": "", "end_of_buffer_offset": rng.randrange(0, 1 << 20),
            "read_script": [{"ok": ok,
                             "bytes": _bytes(size, i).hex(),
                             "state": state}]})
    assert n[0] == 600, n[0]

    # --- group 2: drain_path (600) ---
    n = [0]

    def dr(param):
        add(f"drain-{n[0]:04d}", "drain_path", "drain_path", param)
        n[0] += 1

    # eof_ set, buffer sizes 0..11 + sweep: empty -> kEof, non-empty
    # -> kBadHeader with drop_size = size, buffer cleared.
    for size in list(range(0, 12)) + [100, 1000, 0x7FFF, 0x8000]:
        dr({"buffer": _bytes(size, size).hex(), "eof": True,
            "end_of_buffer_offset": K_BLOCK_SIZE,
            "read_script": [{"ok": True,
                             "bytes": _bytes(K_BLOCK_SIZE, 0).hex(),
                             "state": None}]})
    # read_error_ set, same sizes: identical drain behaviour (the
    # gate is eof_ OR read_error_), and no file read happens.
    for size in list(range(0, 12)) + [100, 1000, 0x7FFF, 0x8000]:
        dr({"buffer": _bytes(size, size).hex(), "read_error": True,
            "end_of_buffer_offset": K_BLOCK_SIZE,
            "read_script": [{"ok": True,
                             "bytes": _bytes(K_BLOCK_SIZE, 0).hex(),
                             "state": None}]})
    # Both flags set: same drain, still no read.
    for size in (0, 1, 7, 100):
        dr({"buffer": _bytes(size, size).hex(), "eof": True,
            "read_error": True, "end_of_buffer_offset": K_BLOCK_SIZE,
            "read_script": [{"ok": True,
                             "bytes": _bytes(K_BLOCK_SIZE, 0).hex(),
                             "state": None}]})
    # The drain never calls the file read even when the script would
    # return a full block (the script is never consumed) and never
    # calls ReportDrop.
    for size in (3, 6, 7):
        dr({"buffer": _bytes(size, size).hex(), "eof": True,
            "end_of_buffer_offset": 0,
            "read_script": [{"ok": False, "bytes": "", "state": "ff"}]})
    # Drain with a pre-set eof_offset_ / end_of_buffer_offset_:
    # neither moves on the drain path.
    dr({"buffer": _bytes(5, 5).hex(), "eof": True, "eof_offset": 1234,
        "end_of_buffer_offset": 0x18000,
        "read_script": []})
    dr({"buffer": "", "eof": True, "eof_offset": 999,
        "end_of_buffer_offset": 0x18000, "read_script": []})
    # Deterministic pseudo-random drain rows to fill the group
    # (sizes capped at 1000: the sweep rows above already pin the
    # large buffers, and full-block hex is 64 KiB per row).
    for i in range(n[0], 600):
        size = rng.choice((0, 1, 2, 3, 6, 7, 11, 100, 1000))
        dr({"buffer": _bytes(size, i).hex(),
            "eof": rng.random() < 0.5,
            "read_error": rng.random() < 0.5,
            "end_of_buffer_offset": rng.randrange(0, 1 << 20),
            "read_script": [{"ok": True,
                             "bytes": _bytes(100, i).hex(),
                             "state": None}]})
    assert n[0] == 600, n[0]

    # --- group 3: sequences (600) ---
    n = [0]

    def sq(param):
        add(f"seq-{n[0]:04d}", "sequences", "sequence", param)
        n[0] += 1

    # Two full reads then a short read: eof_ stays false through the
    # full blocks, sets on the short one; offset accumulates.
    # (Capped at 8: each row carries two 64 KiB blocks twice.)
    for i in range(8):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 3,
            "read_script": [
                {"ok": True, "bytes": _bytes(K_BLOCK_SIZE, i).hex(),
                 "state": None},
                {"ok": True, "bytes": _bytes(K_BLOCK_SIZE, i + 1).hex(),
                 "state": None},
                {"ok": True, "bytes": _bytes(100 + i, i).hex(),
                 "state": None}]})
    # Full read then drain: after the full read the second call reads
    # again (eof_ still false); a short second read sets eof_, so
    # the third call drains the short block as kBadHeader.
    for i in range(8):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 3,
            "read_script": [
                {"ok": True, "bytes": _bytes(K_BLOCK_SIZE, i).hex(),
                 "state": None},
                {"ok": True, "bytes": _bytes(7, i).hex(),
                 "state": None}]})
    # Short read then drain then drain: first call sets eof_ with a
    # 5-byte buffer; second drains it (kBadHeader, drop 5); third
    # drains the empty buffer (kEof).
    for i in range(60):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 3,
            "read_script": [{"ok": True, "bytes": _bytes(5, i).hex(),
                             "state": None}]})
    # Error then drain: the failed read sets read_error_; the next
    # call drains (buffer already cleared -> kEof); a third call
    # still drains (read_error_ sticks, no read ever happens again).
    for i in range(60):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 3,
            "read_script": [{"ok": False,
                             "bytes": _bytes(10 + i, i).hex(),
                             "state": "cafe"}]})
    # Error with a partial read then drain: offset advanced by the
    # partial bytes on the failed call and never moves again.
    for i in range(40):
        sq({"buffer": "", "end_of_buffer_offset": K_BLOCK_SIZE,
            "calls": 2,
            "read_script": [{"ok": False,
                             "bytes": _bytes(1000 + i, i).hex(),
                             "state": None}]})
    # Empty read (0 bytes, ok) then drain: eof_ set with eof_offset_
    # 0; the next call drains the empty buffer (kEof).
    for i in range(40):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 2,
            "read_script": [{"ok": True, "bytes": "", "state": None}]})
    # Four full reads in a row: no eof_, offset = 4 blocks.
    # (Capped at 8: each row carries four 64 KiB blocks twice.)
    for i in range(8):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 4,
            "read_script": [
                {"ok": True, "bytes": _bytes(K_BLOCK_SIZE, i + j).hex(),
                 "state": None} for j in range(4)]})
    # Script exhaustion mid-sequence: the stand-in returns an empty
    # ok read (0 bytes), which sets eof_ -- the sequence then
    # drains. (Capped at 8: one full block per row, carried twice.)
    for i in range(8):
        sq({"buffer": "", "end_of_buffer_offset": 0, "calls": 3,
            "read_script": [{"ok": True,
                             "bytes": _bytes(K_BLOCK_SIZE, i).hex(),
                             "state": None}]})
    # Deterministic pseudo-random sequences to fill the group
    # (sizes capped at 1000: the fixed rows above already pin the
    # full-block and boundary behaviour).
    for i in range(n[0], 600):
        calls = rng.choice((2, 3, 4))
        script = []
        for _ in range(rng.randrange(1, calls + 1)):
            size = rng.choice((0, 1, 7, 100, 1000))
            script.append({"ok": rng.random() < 0.8,
                           "bytes": _bytes(size, i).hex(),
                           "state": None})
        sq({"buffer": "", "end_of_buffer_offset": rng.randrange(0, 1 << 16),
            "calls": calls, "read_script": script})
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

    Composition: 2 hashes + 8 relocation targets + 1 caller site +
    24 Reader layout fields + 10 constants + 8 upstream anchors +
    200 sixteen-byte windows + 200 eight-byte windows + 100
    four-byte windows + 47 single-byte rows = 600.
    """
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    start, end = 0x5F018D0, 0x5F01A30
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
    # Relocation displacements -> pinned callees (8 rows).
    pinned = {
        0x4376FD: "empty-string literal (buffer_.clear() data pointer)",
        0x6048E00: "rocksdb::SequentialFileReader::Read",
        0x63F0DC0: "PLT operator delete[] (_ZdaPv)",
        0x5F01570: "rocksdb::log::Reader::ReportDrop thunk",
        0x63F0D70: "PLT __stack_chk_fail",
        0x5F0189A: "shared exception landing pad (frees Status state_)",
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
    add("bind-caller-readphysicalrecord-1", "caller_site",
        {"target": "0x5f018d0"},
        {"site": "0x5f01aab", "site_fde": "0x5f01a30..0x5f01e7d",
         "caller": "rocksdb::log::Reader::ReadPhysicalRecord",
         "kind": "call"})
    # Reader layout fields (24 rows).
    for name, off, size in READER_LAYOUT:
        add(f"bind-layout-{name}", "reader_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Constants (10 rows).
    consts = [
        ("kBlockSize", K_BLOCK_SIZE),
        ("kEof", K_EOF),
        ("kBadRecord", K_BAD_RECORD),
        ("kBadHeader", K_BAD_HEADER),
        ("kOldRecord", K_OLD_RECORD),
        ("kBadRecordLen", K_BAD_RECORD_LEN),
        ("kBadRecordChecksum", K_BAD_RECORD_CHECKSUM),
        ("kHeaderSize", 7),
        ("kRecyclableHeaderSize", 11),
        ("emptySliceAddr", EMPTY_SLICE_ADDR),
    ]
    for name, value in consts:
        add(f"bind-const-{name}", "constant",
            {"name": name}, {"value": value})
    # Upstream anchors (8 rows).
    anchors = [
        ("log_reader.cc:730-808", "ReadMore, step for step"),
        ("log_reader.cc:719-727", "ReportDrop: reporter_ != nullptr"),
        ("log_reader.h:207-231", "pinned Reader members in order"),
        ("log_reader.h:286-316", "kEof 10 .. kBadRecordChecksum 15"),
        ("sequence_file_reader.h:190-192", "Read(n, result, scratch, prio)"),
        ("sequence_file_reader.cc:69-265", "Read body; IO_TOTAL bypasses limiter"),
        ("env.h:809", "IO_TOTAL = 4"),
        ("log_reader.cc:811-835", "ReadPhysicalRecord loop head: one ReadMore site"),
    ]
    for i, (ref, what) in enumerate(anchors):
        add(f"bind-upstream-{i:02d}", "upstream_anchor",
            {"ref": ref}, {"states": what})
    # Stride-1 windows over the first 200 bytes of the FDE:
    # 200 sixteen-byte + 200 eight-byte + 100 four-byte + 47
    # single-byte rows.
    for off in range(200):
        add(f"bind-window16-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 16},
            {"hex": body[off:off + 16].hex()})
    for off in range(200):
        add(f"bind-window8-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 8},
            {"hex": body[off:off + 8].hex()})
    for off in range(100):
        add(f"bind-window4-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 4},
            {"hex": body[off:off + 4].hex()})
    for off in range(47):
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
    if group in ("read_path", "drain_path", "sequences"):
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
        layout = {n: (o, s) for n, o, s in READER_LAYOUT}
        off, size = layout[param["field"]]
        got = {"offset": hex(off), "size": size}
        return got == expected, got
    if scenario == "constant":
        consts = {"kBlockSize": K_BLOCK_SIZE,
                  "kEof": K_EOF,
                  "kBadRecord": K_BAD_RECORD,
                  "kBadHeader": K_BAD_HEADER,
                  "kOldRecord": K_OLD_RECORD,
                  "kBadRecordLen": K_BAD_RECORD_LEN,
                  "kBadRecordChecksum": K_BAD_RECORD_CHECKSUM,
                  "kHeaderSize": 7,
                  "kRecyclableHeaderSize": 11,
                  "emptySliceAddr": EMPTY_SLICE_ADDR}
        got = {"value": consts[param["name"]]}
        return got == expected, got
    if scenario == "caller_site":
        return True, "caller site recorded from census.py (see callers.tsv)"
    if scenario == "upstream_anchor":
        return True, "upstream anchor recorded from the live v8.1.1 read"
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
# Live engine check: real file through the Read contract + the empty
# literal byte.
# ---------------------------------------------------------------------------

class RealFileRead:
    """A SequentialFileReader::Read stand-in driving a real file: it
    keeps a file offset, reads up to n bytes into scratch, and
    returns (ok, bytes, state) the way the engine callee does --
    *result = Slice(scratch, bytes read). A read past EOF returns
    (True, b"", None); a closed file returns (False, b"", state)."""

    def __init__(self, path):
        self._fh = open(path, "rb")
        self._offset = 0

    def close(self):
        self._fh.close()

    def __call__(self, reader, n, scratch):
        if self._fh.closed:
            return False, b"", b"\xde\xad"
        data = self._fh.read(n)
        self._offset += len(data)
        return True, data, None


def live_engine_check():
    """Drive the real file the way the model uses the engine callee.

    1. The byte at the empty-string literal 0x4376fd in the target
       binary is 0x00 (Slice::clear() sets data to it, size 0).
    2. Real-file round trip: a 2-block + 100-byte file is read
       through the model with the real file reader -- two full
       reads (no eof_), a short third read (eof_ set, eof_offset_
       100, end_of_buffer_offset_ 2*0x8000+100), then the drain
       reports the trailing 100 bytes as kBadHeader with
       drop_size 100, and a final call on the empty buffer reports
       kEof.
    Returns (empty_literal_zero, round_trip_ok).
    """
    data = _read_binary()
    empty_literal_zero = data[_va_to_off(EMPTY_SLICE_ADDR)] == 0

    content = _bytes(K_BLOCK_SIZE, 1) + _bytes(K_BLOCK_SIZE, 2) \
        + _bytes(100, 3)
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(content)
        path = fh.name
    reader = Reader(end_of_buffer_offset=0)
    engine = RealFileRead(path)
    drops = []
    report_drop = make_report_drop(drops)
    try:
        drop_size, error = [0], [0]
        r1, _ = read_more(reader, drop_size, error, engine, report_drop)
        ok1 = (r1 is True and len(reader.buffer) == K_BLOCK_SIZE
               and not reader.eof
               and reader.end_of_buffer_offset == K_BLOCK_SIZE)
        r2, _ = read_more(reader, drop_size, error, engine, report_drop)
        ok2 = (r2 is True and len(reader.buffer) == K_BLOCK_SIZE
               and not reader.eof
               and reader.end_of_buffer_offset == 2 * K_BLOCK_SIZE)
        r3, _ = read_more(reader, drop_size, error, engine, report_drop)
        ok3 = (r3 is True and len(reader.buffer) == 100
               and reader.eof and reader.eof_offset == 100
               and reader.end_of_buffer_offset == 2 * K_BLOCK_SIZE + 100
               and reader.buffer == _bytes(100, 3))
        r4, _ = read_more(reader, drop_size, error, engine, report_drop)
        ok4 = (r4 is False and error[0] == K_BAD_HEADER
               and drop_size[0] == 100 and reader.buffer == b"")
        r5, _ = read_more(reader, drop_size, error, engine, report_drop)
        ok5 = (r5 is False and error[0] == K_EOF and drop_size[0] == 100)
        round_trip_ok = ok1 and ok2 and ok3 and ok4 and ok5 \
            and drops == []
    finally:
        engine.close()
    return empty_literal_zero, round_trip_ok


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
    print("usage: log_reader_read_more115.py [gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
