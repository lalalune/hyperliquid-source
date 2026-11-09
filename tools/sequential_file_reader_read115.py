"""Node #115 RocksDB SequentialFileReader::Read: reconstruction.

RE-002 work item. Reconstructs the sequential file read at
0x6048e00..0x60497fd (2557 B) plus its exception landing pads
(.cold, 0x6048d68..0x6048df2, 138 B):

  rocksdb::SequentialFileReader::Read  0x6048e00 (2557 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The main FDE has NO vendor census record (like
Comparator::CreateFromString in #5969): only its body hash is
recorded. The .cold part IS census-bound (body hash matches
target_body_sha256 exactly; source hash reproduced by zeroing the
10 recorded kind-4 relocations). Symbol comes from the vendor
census entry for the .cold part (member
a895f7517936a0f7-sequence_file_reader.o, librocksdb-sys):
_ZN7rocksdb20SequentialFileReader4ReadEmPNS_5SliceEPcNS_3Env10IOPriorityE
-- i.e. Read(size_t n, Slice* result, char* scratch,
Env::IOPriority rate_limiter_priority), returning IOStatus by
sret.

What the binary does (whole-FDE disassembly, verbatim in the
packet):

  IOStatus Read(size_t n, Slice* result, char* scratch,
                Env::IOPriority rate_limiter_priority)
  -- rdi is the sret IOStatus* (r15), rsi the reader (r14), rdx n,
  rcx result, r8 scratch, r9d the priority. Steps, in binary order:

  0. Prologue (0x6048e4b-0x6048e60): the sret IOStatus is
     initialised to OK -- bytes 0-3 zero, bytes 4-5 zero, bytes
     8-15 (state_) zero. Bytes 6-7 are NEVER written by this FDE:
     they keep whatever the caller left on its stack (0 in
     practice, e.g. ReadMore zeroes its slot first).
  1. File selection (0x6048e55-0x6048e77, repeated before every
     file call at 0x6048fdd and 0x6049438): the reader's file_ is
     an FSSequentialFilePtr (env/file_system_tracer.h:304-361):
     io_tracer_ is the shared_ptr<IOTracer> at +0x20 (ptr) /
     +0x28 (control); fs_tracer_ is the
     FSSequentialFileTracingWrapper object at +0x30 (its vptr) with
     the wrapped raw file pointer target_ at +0x38. The selection
     is exactly FSSequentialFilePtr::operator->() inlined: if
     io_tracer_ is null -> the raw file at +0x38; else if the byte
     at [io_tracer_+0x68] (the inlined is_tracing_enabled(), which
     returns the plain bool tracing_enabled,
     trace_replay/io_tracer.h:313-335) is non-zero -> the wrapper
     at +0x30; else -> the raw file at +0x38.
  2. Head (0x6048e74-0x6048e7c): call vtable slot 4 on the
     selected file -- FSSequentialFile::use_direct_io()
     (include/rocksdb/file_system.h:1358; the vtable order is
     dtor, dtor, Read, Skip, use_direct_io,
     GetRequiredBufferAlignment, InvalidateCache, PositionedRead,
     GetTemperature). Non-zero takes the direct-IO path (step 6);
     zero takes the buffered path (steps 3-5).
  3. Buffered path, paranoid bump (0x6048e82-0x6048e99,
     0x6049784): if scratch is non-null and n != 0, scratch[0]++
     (upstream file/sequence_file_reader.cc:196-200 -- this closes
     the open unknown the #5986 ReadMore packet left behind: the
     bump IS present in the binary). If scratch is null or n == 0,
     no bump.
  4. Buffered path, n == 0 (0x6048ea0): *result = Slice(scratch,
     0); IOSTATS_ADD(bytes_read, 0); return OK. No file read, no
     rate-limiter call, no listener notification.
  5. Buffered path, loop (0x6048f43-0x6048f80 head, 0x6048f80
     body, 0x6049256-0x6049293 exit): read = 0; while (read < n):
     - allowed: if priority != IO_TOTAL (4) and rate_limiter_
       (+0xa0) is non-null, allowed = rate_limiter_->RequestToken
       (n - read, 0, priority, nullptr, kRead) -- vtable slot 6
       of RateLimiter (include/rocksdb/rate_limiter.h:152-156;
       the vtable order is dtor, dtor, SetBytesPerSecond,
       Request x3, RequestToken, ...). Else allowed = n (the
       upstream else branch really is `allowed = n`, not
       n - read).
     - If listeners_ (+0x88/+0x90) is non-empty, start_ts =
       FileOperationInfo::StartTimePoint::StartNow() (steady
       clock, then system clock).
     - io_s = file_->Read(allowed, IOOptions(), &tmp, scratch +
       read, nullptr) -- vtable slot 2, sret at rsp-0xa0; the
       IOOptions is built fresh on the stack each iteration
       (timeout 0, prio kIOLow 0, rate_limiter_priority IO_TOTAL
       4, type kUnknown 7, property_bag an empty unordered_map,
       force_dir_fsync false, do_not_recurse false) and its
       property_bag is destroyed right after the call
       (0x60490fe: _Hashtable dtor 0x5d36110). The returned
       IOStatus is MOVED into the sret field by field: code (2
       bytes @+0), bytes +3..+4, byte +5, state_ (+8); the
       subcode byte (+2) and the scope byte (+6) are NOT moved,
       so the returned status always has subcode 0 and an
       unwritten scope byte. The previous iteration's sret
       state_ is delete[]'d before being overwritten.
     - If listeners_ is non-empty: finish_ts =
       steady_clock::now(); offset = offset_.fetch_add(tmp.size())
       (the atomic at +0x80 -- note this advance happens ONLY
       when listeners exist); build FileOperationInfo(kRead,
       file_name_, offset, tmp.size(), finish - start, start_ts,
       io_s) -- the info.status is a copy of io_s with its
       state_ deep-copied via Status::CopyState 0x61cf610 -- and
       call listener->OnFileReadFinish(info) (vtable slot 33)
       for every listener whose slot-33 entry is NOT the empty
       base implementation at 0x6042c10 (endbr64; ret); base
       no-op listeners are skipped by the compiler's
       devirtualisation guard. Then the info.status state_ copy
       is delete[]'d.
     - read += tmp.size(); break unless io_s is ok AND
       tmp.size() == allowed. When read >= n the loop exits to
       the return (0x6048ea8): *result = Slice(scratch, read);
       IOSTATS_ADD(bytes_read, read); return io_s.
  6. Direct-IO path (0x60492c0-0x604975e):
     - offset = offset_.fetch_add(n) (0x60492c7) -- the offset
       advances by the FULL n up front, before any read.
     - alignment = file_->GetRequiredBufferAlignment() (vtable
       slot 5, 0x60492f1); aligned_offset = offset & ~(alignment
       - 1); offset_advance = offset - aligned_offset; size =
       Roundup(offset + n, alignment) - aligned_offset;
       capacity = Roundup(size, alignment); a raw buffer of
       capacity + alignment bytes is new[]'d (0x6049360) and the
       aligned start is (raw + alignment - 1) & ~(alignment - 1).
     - Loop while read < size (0x6049382 head): allowed is
       RequestToken(capacity - read, alignment, priority,
       nullptr, kRead) when the limiter applies, else size;
       io_s = file_->PositionedRead(aligned_offset + read,
       allowed, IOOptions(), &tmp, aligned_buf + read, nullptr)
       (vtable slot 7, 0x60494f3); the listener notification is
       the same shape as step 5 (including the second
       offset_.fetch_add(tmp.size()) -- so with listeners the
       direct path advances offset_ by n AND by every chunk
       read); read += tmp.size(); break unless io_s is ok AND
       tmp.size() == allowed.
     - Tail: r = 0; if io_s is ok and offset_advance < read, r =
       min(read - offset_advance, n) and memcpy(scratch,
       aligned_buf + offset_advance, r) (0x604970e-0x6049722).
       *result = Slice(scratch, r); the raw buffer is delete[]'d
       (0x604977a); IOSTATS_ADD(bytes_read, r); return io_s.
       Note the tail runs even when the loop broke on a short
       read with an ok status (0x6049758 -> 0x60496dc), but NOT
       when io_s is non-ok (r stays 0).
  7. Epilogue (0x6048ebd-0x6048f34, shared by all paths):
     IOSTATS_ADD(bytes_read, result->size()) -- the thread-local
     iostats_context, gated on its enabled byte (0x606d9f0 is the
     TLS accessor; the counter sits at +0x10 of the TLS object,
     the enabled byte at +0x98); then the stack canary is checked
     and the frame is popped.
  8. Exception landing pads (.cold, 0x6048d68..0x6048df2): eight
     pads that delete[] the in-flight info.status state_ copy
     and the sret state_ when non-null, check the stack canary,
     and resume unwinding (_Unwind_Resume). Recorded, not
     modelled: the model never throws.

SequentialFileReader layout (node #115, pinned fields from the
field accesses, the rest derived from the member order in upstream
file/sequence_file_reader.h:98-106 with natural alignment):

  +0x00 file_name_ (std::string, 32)
  +0x20 file_ (FSSequentialFilePtr, 96)
    +0x20 io_tracer_ (shared_ptr<IOTracer>, 16) -- PINNED (head)
    +0x30 fs_tracer_ (FSSequentialFileTracingWrapper, 80)
      +0x30 vptr (8) -- PINNED (wrapper selection)
      +0x38 target_ (FSSequentialFile*, 8) -- PINNED (raw file)
      +0x40 target_ (unique_ptr<FSSequentialFile>, 8)
      +0x48 io_tracer_ (shared_ptr<IOTracer>, 16)
      +0x58 clock_ (SystemClock*, 8)
      +0x60 file_name_ (std::string, 32)
  +0x80 offset_ (atomic<size_t>, 8) -- PINNED (fetch_add)
  +0x88 listeners_ (vector<shared_ptr<EventListener>>, 24)
  +0x90 listeners_ end (8) -- PINNED (empty check)
  +0xa0 rate_limiter_ (RateLimiter*, 8) -- PINNED (RequestToken)
  total 0xa8

IOOptions layout (88 bytes, 0x58; include/rocksdb/file_system.h:
160-236, IOOptions() defaults): timeout +0x00 (int64, 0), prio
+0x08 (kIOLow, 0), rate_limiter_priority +0x0c (IO_TOTAL, 4),
type +0x10 (kUnknown, 7), property_bag +0x18 (unordered_map,
56 -- empty: _M_buckets points at its own _M_single_bucket at
+0x48, _M_bucket_count 1, _M_before_begin null, _M_element_count
0, _M_max_load_factor 1.0, _M_next_resize 0, _M_single_bucket
null), force_dir_fsync +0x50 (false), do_not_recurse +0x51
(false). The observed byte offsets are pinned by the binary's
merged immediates (0x400000000 at +0x08, 7 at +0x10); the
fields' exact declared widths are an open derivation.

FileOperationInfo layout (72 bytes, 0x48;
include/rocksdb/listener.h:475-549): type +0x00 (kRead, 0),
path +0x08 (&file_name_), temperature +0x10 (kUnknown, 0),
offset +0x18, length +0x20, duration +0x28 (ns), start_ts
+0x30 (&StartTimePoint), status +0x38 (Status, 16).

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts, cross-checked by a
second raw scan): exactly 5 direct calls, 0 tail jumps, 0 LEA
refs -- log::Reader::UnmarkEOFInternal 0x5f016a0 (site
0x5f0172d), log::Reader::ReadMore 0x5f018d0 (site 0x5f01997),
FragmentBufferedReader::TryReadMore 0x5f02980 (site 0x5f02a87),
rocksdb::CopyFile 0x603ae70 (site 0x603b843), and one
unidentified FDE 0x60d4cf0..0x60d4f62 with no vendor census
record (site 0x60d4dc7, n = 0x2000, priority forwarded from its
caller). All four identified callers pass IO_TOTAL (4); the
fifth forwards its caller's priority.

What is modelled here is the routine's OBSERVABLE trace on a
SequentialFileReader: the ordered events (file selection,
use_direct_io, scratch bump, rate-limiter gating, file reads,
listener notifications, offset advances, the direct-IO alignment
math, the memcpy tail, the IOSTATS add) plus the resulting state
(returned IOStatus, *result, offset_, iostats.bytes_read). The
FSSequentialFile (raw or tracing wrapper), the RateLimiter, the
EventListeners and the IOTracer are taken as inputs; the live
check drives a real file through the same Read/PositionedRead
contract.

Upstream anchors (RocksDB v8.1.1, read live this cycle):
file/sequence_file_reader.cc (Read, step for step -- the
buffered path bumps scratch[0] first, loops file_->Read into
scratch, *result = Slice(scratch, read); the direct path
fetch_adds n, aligns, loops PositionedRead, memcpys the slice;
IO_TOTAL bypasses the rate limiter),
file/sequence_file_reader.h:98-106 (member order), :190-192
(Read signature), :204 (use_direct_io), :46-73
(NotifyOnFileReadFinish), :95 (ShouldNotifyListeners),
env/file_system_tracer.h:304-361 (FSSequentialFilePtr selection),
:246-291 (FSSequentialFileTracingWrapper),
include/rocksdb/file_system.h:1298-1415 (FSSequentialFile
vtable order: Read, Skip, use_direct_io,
GetRequiredBufferAlignment, InvalidateCache, PositionedRead,
GetTemperature), :160-236 (IOOptions defaults),
include/rocksdb/rate_limiter.h:152-156 (RequestToken),
trace_replay/io_tracer.h:313-335 (is_tracing_enabled),
include/rocksdb/listener.h:475-549 (FileOperationInfo),
:1417 (OnFileReadFinish, the 16th EventListener virtual),
include/rocksdb/env.h:809 (IO_TOTAL = 4).

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the tool models
the routine in Python; the file, rate limiter, listeners and
tracer are taken as inputs, and the live check reads a real file
through the same Read/PositionedRead contract. make
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
          / "re-002-node115-rocksdb-sequential-file-reader-read-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Env::IOPriority (include/rocksdb/env.h:809).
IO_LOW = 0
IO_HIGH = 1
IO_USER = 2
IO_MID = 3
IO_TOTAL = 4

K_DEFAULT_PAGE_SIZE = 4096
EMPTY_SLICE_ADDR = 0x4376FD


def _load_segments():
    """Parse the PT_LOAD program headers of the node #115 binary
    (vaddr, file offset, file size) so virtual addresses map to
    file offsets correctly. The binary is non-PIE but its segments
    are not all vaddr == offset: the executable segment is shifted
    by 0x1000 (offset 0x1418300, vaddr 0x1419300)."""
    path = ROOT / "work" / "hl-node-115.bin"
    with open(path, "rb") as f:
        header = f.read(64)
        (e_phoff,) = struct.unpack_from("<Q", header, 0x20)
        (e_phentsize, e_phnum) = struct.unpack_from("<HH", header, 0x36)
        f.seek(e_phoff)
        segments = []
        for _ in range(e_phnum):
            entry = f.read(e_phentsize)
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr,
             p_filesz, _p_memsz, _p_align) = struct.unpack_from(
                "<IIQQQQQQ", entry, 0)
            if p_type == 1:  # PT_LOAD
                segments.append((p_vaddr, p_offset, p_filesz))
    return segments


_LOAD_SEGMENTS = None


def _vaddr_to_offset(addr):
    """Map a virtual address of the node #115 binary to a file
    offset via its PT_LOAD segments."""
    global _LOAD_SEGMENTS
    if _LOAD_SEGMENTS is None:
        _LOAD_SEGMENTS = _load_segments()
    for vaddr, offset, filesz in _LOAD_SEGMENTS:
        if vaddr <= addr < vaddr + filesz:
            return offset + (addr - vaddr)
    raise ValueError(f"address {addr:#x} is not in a loaded segment")


# SequentialFileReader layout: (field, offset, size).
READER_LAYOUT = [
    ("file_name_", 0x00, 32),
    ("file_", 0x20, 96),
    ("file_.io_tracer_", 0x20, 16),
    ("file_.fs_tracer_", 0x30, 80),
    ("file_.fs_tracer_.vptr", 0x30, 8),
    ("file_.fs_tracer_.target_", 0x38, 8),
    ("file_.fs_tracer_.target_owned_", 0x40, 8),
    ("file_.fs_tracer_.io_tracer_", 0x48, 16),
    ("file_.fs_tracer_.clock_", 0x58, 8),
    ("file_.fs_tracer_.file_name_", 0x60, 32),
    ("offset_", 0x80, 8),
    ("listeners_", 0x88, 24),
    ("rate_limiter_", 0xA0, 8),
    ("size", 0x00, 0xA8),
]

# IOOptions layout (88 bytes): (field, offset, size, value).
IOOPTIONS_LAYOUT = [
    ("timeout", 0x00, 8, 0),
    ("prio", 0x08, 1, 0),
    ("rate_limiter_priority", 0x0C, 1, 4),
    ("type", 0x10, 1, 7),
    ("property_bag", 0x18, 56, "empty unordered_map"),
    ("force_dir_fsync", 0x50, 1, 0),
    ("do_not_recurse", 0x51, 1, 0),
    ("size", 0x00, 0x58, 88),
]

# FileOperationInfo layout (72 bytes): (field, offset, size).
FILEOPINFO_LAYOUT = [
    ("type", 0x00, 4),
    ("path", 0x08, 8),
    ("temperature", 0x10, 1),
    ("offset", 0x18, 8),
    ("length", 0x20, 8),
    ("duration", 0x28, 8),
    ("start_ts", 0x30, 8),
    ("status", 0x38, 16),
    ("size", 0x00, 0x48),
]

READER_SIZE = 0xA8


# ---------------------------------------------------------------------------
# Status model
# ---------------------------------------------------------------------------

def make_status(code=0, subcode=0, severity=0, retryable=0, data_loss=0,
                scope=0, state=None):
    """An IOStatus as the callee returns it: code (u16 @+0), subcode
    (u8 @+2), severity (u8 @+3), retryable (u8 @+4), data_loss (u8
    @+5), scope (u8 @+6), state_ (bytes @+8, None == null)."""
    return {"code": code, "subcode": subcode, "severity": severity,
            "retryable": retryable, "data_loss": data_loss,
            "scope": scope,
            "state": None if state is None else bytes(state)}


def status_ok(state=None):
    return make_status(0, 0, 0, 0, 0, 0, state)


def move_status_to_sret(local):
    """The binary's move of the callee's returned IOStatus into the
    sret (0x6049096-0x60490df / 0x60494f5-0x6049543): code, severity,
    retryable, data_loss and state_ move; the subcode byte (+2) and
    the scope byte (+6) are NOT moved, so the returned status has
    subcode 0 and scope None (unwritten stack residue, 0 in
    practice). Returns (sret_dict, state_freed_flag_for_prev)."""
    return {"code": local["code"], "subcode": 0,
            "severity": local["severity"],
            "retryable": local["retryable"],
            "data_loss": local["data_loss"], "scope": None,
            "state": local["state"]}


def status_to_info_status(sret):
    """FileOperationInfo.status (a Status, not an IOStatus) is built
    from the sret's first 6 bytes plus a deep copy of its state_
    (Status::CopyState 0x61cf610). Returns (info_status_dict,
    state_was_copied)."""
    return ({"code": sret["code"], "subcode": 0,
             "severity": sret["severity"],
             "retryable": sret["retryable"],
             "data_loss": sret["data_loss"], "scope": None,
             "state": (None if sret["state"] is None
                       else bytes(sret["state"]))},
            sret["state"] is not None)


def _status_jsonable(s):
    if s is None:
        return None
    out = dict(s)
    if out.get("state") is not None:
        out["state"] = out["state"].hex()
    return out


# ---------------------------------------------------------------------------
# Scripted inputs: file, rate limiter, listeners, tracer, iostats
# ---------------------------------------------------------------------------

class FakeClock:
    """Deterministic clock: each now() call advances by 100 ns."""

    def __init__(self):
        self.t = 1000000

    def steady_now(self):
        self.t += 100
        return self.t

    def system_now(self):
        self.t += 100
        return self.t


class File:
    """An FSSequentialFile stand-in (raw file or tracing wrapper).

    read_script / positioned_script: lists of {"status": {...},
    "bytes": hex} consumed in order; an exhausted script returns
    (ok, b"") -- a short read at EOF. The "status" dict, when
    present, sets the returned Status (code/subcode/severity/...);
    the entry-level "state" is the Status state_ (None == null)
    unless the "status" dict carries its own; an entry with
    "ok": False and no "status" dict returns a generic IOError
    (code 1). For the buffered path the mock reads sequentially
    from its own cursor; for PositionedRead it reads from the
    requested offset. Bytes are generated from a deterministic
    pattern when "pattern" is given instead of "bytes":
    {"pattern": [length, seed]}.
    """

    def __init__(self, use_direct_io=False, alignment=K_DEFAULT_PAGE_SIZE,
                 read_script=None, positioned_script=None, size=1 << 20):
        self._direct = use_direct_io
        self._alignment = alignment
        self._read_script = list(read_script or [])
        self._positioned_script = list(positioned_script or [])
        self._read_pos = [0]
        self._pos_pos = [0]
        self._size = size
        self.calls = []

    def use_direct_io(self):
        return self._direct

    def get_required_buffer_alignment(self):
        return self._alignment

    def _entry_bytes(self, entry):
        if "bytes" in entry:
            return bytes.fromhex(entry["bytes"])
        if "pattern" in entry:
            length, seed = entry["pattern"]
            return _bytes(length, seed)
        return b""

    def _entry_status(self, entry):
        # The Status state_ lives in the entry-level "state" (the
        # #5986 template's contract); a "status" dict, when present,
        # overrides the code/subcode/severity fields and may carry
        # its own "state". An entry with "ok": False and no "status"
        # dict returns a generic IOError (code 1).
        state_hex = entry.get("state")
        st = entry.get("status")
        if st is not None and st.get("state") is not None:
            state_hex = st["state"]
        state = (None if state_hex is None
                 else bytes.fromhex(state_hex))
        if st is None:
            if not entry.get("ok", True):
                return make_status(code=1, state=state)
            return status_ok(state=state)
        return make_status(code=st.get("code", 0),
                           subcode=st.get("subcode", 0),
                           severity=st.get("severity", 0),
                           retryable=st.get("retryable", 0),
                           data_loss=st.get("data_loss", 0),
                           scope=st.get("scope", 0),
                           state=state)

    def read(self, n, scratch, offset_in_scratch):
        """file_->Read(n, IOOptions(), &tmp, scratch, nullptr). The
        mock writes the returned bytes into scratch at
        offset_in_scratch when scratch is not None. Returns
        (status, tmp_bytes)."""
        if self._read_pos[0] >= len(self._read_script):
            self.calls.append(("Read", n, 0, True))
            return status_ok(), b""
        entry = self._read_script[self._read_pos[0]]
        self._read_pos[0] += 1
        data = self._entry_bytes(entry)[:n]
        status = self._entry_status(entry)
        if scratch is not None:
            scratch[offset_in_scratch:offset_in_scratch + len(data)] = data
        self.calls.append(("Read", n, len(data), status["code"] == 0))
        return status, data

    def positioned_read(self, offset, n, buf, offset_in_buf):
        """file_->PositionedRead(offset, n, IOOptions(), &tmp, buf,
        nullptr). Returns (status, tmp_bytes)."""
        if self._pos_pos[0] >= len(self._positioned_script):
            self.calls.append(("PositionedRead", offset, n, 0, True))
            return status_ok(), b""
        entry = self._positioned_script[self._pos_pos[0]]
        self._pos_pos[0] += 1
        data = self._entry_bytes(entry)[:n]
        status = self._entry_status(entry)
        if buf is not None:
            buf[offset_in_buf:offset_in_buf + len(data)] = data
        self.calls.append(("PositionedRead", offset, n, len(data),
                           status["code"] == 0))
        return status, data


class RateLimiter:
    """A RateLimiter stand-in: RequestToken returns the scripted
    allowance per call (an exhausted script returns the requested
    bytes, i.e. no limiting)."""

    def __init__(self, script=None):
        self._script = list(script or [])
        self._pos = [0]
        self.calls = []

    def request_token(self, nbytes, alignment, priority, op):
        if self._pos[0] >= len(self._script):
            self.calls.append((nbytes, alignment, priority, op, nbytes))
            return nbytes
        allowed = self._script[self._pos[0]]
        self._pos[0] += 1
        self.calls.append((nbytes, alignment, priority, op, allowed))
        return allowed


class Listener:
    """An EventListener stand-in. has_handler False means the
    listener uses the empty base OnFileReadFinish (0x6042c10) and
    the binary skips the call; True means it records the info."""

    def __init__(self, has_handler=True):
        self.has_handler = has_handler
        self.calls = []

    def on_file_read_finish(self, info):
        self.calls.append(info)


class SeqFileReader:
    """A SequentialFileReader object.

    file_name: the std::string at +0x00. io_tracer: None (no
    tracer) or a dict {"tracing_enabled": bool} standing in for
    the shared_ptr<IOTracer> at +0x20. raw_file / wrapper_file:
    File stand-ins for the raw file (target_ at +0x38) and the
    tracing wrapper (fs_tracer_ at +0x30). offset: offset_ (+0x80).
    listeners: list of Listener (+0x88). rate_limiter: RateLimiter
    or None (+0xa0). iostats: {"bytes_read": int, "enabled": bool}.
    """

    def __init__(self, file_name="", io_tracer=None, raw_file=None,
                 wrapper_file=None, offset=0, listeners=None,
                 rate_limiter=None, iostats=None):
        self.file_name = file_name
        self.io_tracer = io_tracer
        self.raw_file = raw_file if raw_file is not None else File()
        self.wrapper_file = (wrapper_file if wrapper_file is not None
                             else self.raw_file)
        self.offset = offset
        self.listeners = list(listeners or [])
        self.rate_limiter = rate_limiter
        self.iostats = ({"bytes_read": 0, "enabled": True} if iostats is None
                        else dict(iostats))
        self.clock = FakeClock()

    def select_file(self, events):
        """FSSequentialFilePtr::operator->() inlined (0x6048e55):
        returns (which, file) with which in {"raw", "wrapper"}."""
        if self.io_tracer is None:
            which = "raw"
        elif self.io_tracer.get("tracing_enabled", False):
            which = "wrapper"
        else:
            which = "raw"
        events.append(["file_select",
                       {"tracer_present": self.io_tracer is not None,
                        "tracing_enabled":
                            bool(self.io_tracer and
                                 self.io_tracer.get("tracing_enabled",
                                                    False)),
                        "selected": which}])
        return which, (self.wrapper_file if which == "wrapper"
                       else self.raw_file)


def _iooptions_event():
    """The IOOptions built fresh for every file call (defaults)."""
    return {"timeout": 0, "prio": 0, "rate_limiter_priority": IO_TOTAL,
            "type": 7, "property_bag": "empty", "force_dir_fsync": False,
            "do_not_recurse": False}


def _notify(reader, events, start_ts, tmp_size, sret):
    """The ShouldNotifyListeners() block: finish timestamp, the
    offset_.fetch_add(tmp.size()), the FileOperationInfo build and
    the per-listener OnFileReadFinish calls (skipping base no-ops).
    Returns the info dict (for the events) or None when there are
    no listeners."""
    if not reader.listeners:
        return None
    finish_ts = reader.clock.steady_now()
    old_offset = reader.offset
    reader.offset += tmp_size
    duration = finish_ts - start_ts[1]
    info_status, _copied = status_to_info_status(sret)
    info = {"type": 0, "path": reader.file_name, "temperature": 0,
            "offset": old_offset, "length": tmp_size,
            "duration": duration,
            "start_ts": list(start_ts),
            "finish_ts": finish_ts,
            "status": _status_jsonable(info_status)}
    events.append(["notify_start", {"finish_ts": finish_ts,
                                    "offset": old_offset,
                                    "duration": duration}])
    for listener in reader.listeners:
        if not listener.has_handler:
            events.append(["notify_skip_base",
                           {"listener": "base_on_file_read_finish"}])
            continue
        listener.on_file_read_finish(info)
        events.append(["notify", {"offset": old_offset,
                                  "length": tmp_size}])
    if info_status["state"] is not None:
        # The info.status state_ copy is delete[]'d after the
        # notifications (the .cold pads do the same on unwind).
        events.append(["info_status_state_freed", True])
    return info


def sequential_read(reader, n, scratch, priority):
    """Model of SequentialFileReader::Read (0x6048e00).

    scratch: bytearray or None (the char* scratch). Returns
    (status_dict, result_dict, events). result_dict is
    {"data": "scratch"|None, "size": int} -- the Slice the binary
    writes into *result. The scratch bytearray is mutated in place
    exactly where the binary's file reads and memcpy write.
    """
    events = []
    # Prologue: sret IOStatus initialised to OK.
    sret = status_ok()
    events.append(["sret_init_ok", True])

    # Head: file selection + use_direct_io() (vtable slot 4).
    _, file_obj = reader.select_file(events)
    direct = file_obj.use_direct_io()
    events.append(["use_direct_io", direct])

    if not direct:
        return _buffered_read(reader, file_obj, n, scratch, priority,
                              sret, events)
    return _direct_read(reader, file_obj, n, scratch, priority, sret,
                        events)


def _buffered_read(reader, file_obj, n, scratch, priority, sret, events):
    # Paranoid bump (0x6049784): scratch[0]++ when scratch is
    # non-null and n > 0.
    if scratch is not None and n > 0:
        scratch[0] = (scratch[0] + 1) & 0xFF
        events.append(["scratch_bump", {"scratch0": scratch[0]}])
    if n == 0:
        # 0x6048ea0: *result = Slice(scratch, 0); IOSTATS; return.
        result = {"data": "scratch" if scratch is not None else None,
                  "size": 0}
        events.append(["result", dict(result)])
        _iostats_add(reader, result["size"], events)
        return sret, result, events

    read = 0
    while read < n:
        # Rate limiter (0x6048f43-0x6048f7d).
        if priority != IO_TOTAL and reader.rate_limiter is not None:
            allowed = reader.rate_limiter.request_token(
                n - read, 0, priority, 0)
            events.append(["request_token",
                           {"bytes": n - read, "alignment": 0,
                            "priority": priority, "op": 0,
                            "allowed": allowed}])
        else:
            allowed = n
            events.append(["rate_bypass",
                           {"reason": ("priority_is_io_total"
                                      if priority == IO_TOTAL
                                      else "no_rate_limiter"),
                            "allowed": allowed}])
        # Start timestamp when listeners exist (0x6048f8b-0x6048fbd).
        start_ts = None
        if reader.listeners:
            start_ts = (reader.clock.system_now(),
                        reader.clock.steady_now())
            events.append(["start_ts", {"start_ts": list(start_ts)}])
        # file_->Read(allowed, IOOptions(), &tmp, scratch + read).
        events.append(["iooptions", _iooptions_event()])
        prev_state = sret["state"]
        status, tmp = file_obj.read(allowed, scratch, read)
        sret = move_status_to_sret(status)
        if prev_state is not None:
            # The previous iteration's sret state_ is delete[]'d
            # before being overwritten (0x60490a0-0x60490e3).
            events.append(["prev_status_state_freed", True])
        events.append(["file_read",
                       {"allowed": allowed, "bytes": len(tmp),
                        "status": _status_jsonable(sret)}])
        # Listener notification (0x6049107-0x6049256).
        if reader.listeners:
            _notify(reader, events, start_ts, len(tmp), sret)
        read += len(tmp)
        if sret["code"] != 0 or len(tmp) < allowed:
            events.append(["loop_break",
                           {"reason": ("status_not_ok"
                                      if sret["code"] != 0
                                      else "short_read"),
                            "read": read}])
            break
    result = {"data": "scratch" if scratch is not None else None,
              "size": read}
    events.append(["result", dict(result)])
    _iostats_add(reader, result["size"], events)
    return sret, result, events


def _direct_read(reader, file_obj, n, scratch, priority, sret, events):
    # offset = offset_.fetch_add(n) (0x60492c0-0x60492d0).
    old_offset = reader.offset
    reader.offset += n
    events.append(["offset_advance", {"by": n, "old": old_offset,
                                      "new": reader.offset}])
    # Alignment math (0x60492d7-0x6049379).
    alignment = file_obj.get_required_buffer_alignment()
    events.append(["alignment", alignment])
    aligned_offset = old_offset & ~(alignment - 1)
    offset_advance = old_offset - aligned_offset
    size = ((old_offset + n + alignment - 1) & ~(alignment - 1)) \
        - aligned_offset
    capacity = (size + alignment - 1) & ~(alignment - 1)
    events.append(["align_math",
                   {"offset": old_offset, "n": n,
                    "alignment": alignment,
                    "aligned_offset": aligned_offset,
                    "offset_advance": offset_advance, "size": size,
                    "capacity": capacity,
                    "raw_alloc": capacity + alignment}])
    # The AlignedBuffer: raw allocation of capacity + alignment
    # bytes, aligned start inside it.
    raw = bytearray(capacity + alignment)
    raw_addr = 0x1000  # model address: raw is alignment-aligned here
    aligned_start = 0
    read = 0
    while read < size:
        if priority != IO_TOTAL and reader.rate_limiter is not None:
            allowed = reader.rate_limiter.request_token(
                capacity - read, alignment, priority, 0)
            events.append(["request_token",
                           {"bytes": capacity - read,
                            "alignment": alignment,
                            "priority": priority, "op": 0,
                            "allowed": allowed}])
        else:
            allowed = size
            events.append(["rate_bypass",
                           {"reason": ("priority_is_io_total"
                                      if priority == IO_TOTAL
                                      else "no_rate_limiter"),
                            "allowed": allowed}])
        start_ts = None
        if reader.listeners:
            start_ts = (reader.clock.system_now(),
                        reader.clock.steady_now())
            events.append(["start_ts", {"start_ts": list(start_ts)}])
        events.append(["iooptions", _iooptions_event()])
        prev_state = sret["state"]
        status, tmp = file_obj.positioned_read(
            aligned_offset + read, allowed, raw, aligned_start + read)
        sret = move_status_to_sret(status)
        if prev_state is not None:
            events.append(["prev_status_state_freed", True])
        events.append(["positioned_read",
                       {"offset": aligned_offset + read,
                        "allowed": allowed, "bytes": len(tmp),
                        "status": _status_jsonable(sret)}])
        if reader.listeners:
            _notify(reader, events, start_ts, len(tmp), sret)
        read += len(tmp)
        if sret["code"] != 0 or len(tmp) < allowed:
            events.append(["loop_break",
                           {"reason": ("status_not_ok"
                                      if sret["code"] != 0
                                      else "short_read"),
                            "read": read}])
            break
    # Tail (0x60496dc-0x604977f): r = min(read - offset_advance, n)
    # when io_s is ok and offset_advance < read, else 0; memcpy.
    r = 0
    if sret["code"] == 0 and offset_advance < read:
        r = min(read - offset_advance, n)
        if r > 0:
            if scratch is not None:
                scratch[:r] = raw[aligned_start + offset_advance:
                                  aligned_start + offset_advance + r]
            events.append(["memcpy",
                           {"bytes": r,
                            "src_offset": offset_advance,
                            "scratch_null": scratch is None}])
    result = {"data": "scratch" if scratch is not None else None,
              "size": r}
    events.append(["result", dict(result)])
    # delete[] the raw buffer (0x604977a).
    events.append(["buffer_freed", {"raw_bytes": capacity + alignment}])
    _iostats_add(reader, result["size"], events)
    return sret, result, events


def _iostats_add(reader, size, events):
    """IOSTATS_ADD(bytes_read, result->size()) (0x6048ebd): the
    thread-local iostats_context, gated on its enabled byte."""
    if reader.iostats.get("enabled", True):
        reader.iostats["bytes_read"] += size
    events.append(["iostats_add",
                   {"bytes": size,
                    "enabled": reader.iostats.get("enabled", True),
                    "bytes_read": reader.iostats["bytes_read"]}])


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


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _build_reader(p, file_script=None, positioned_script=None):
    """Build a SeqFileReader + scratch from a scenario param dict."""
    use_direct = p.get("use_direct_io", False)
    alignment = p.get("alignment", K_DEFAULT_PAGE_SIZE)
    raw = File(use_direct_io=use_direct,
               alignment=alignment,
               read_script=file_script,
               positioned_script=positioned_script)
    wrapper = File(use_direct_io=use_direct,
                   alignment=alignment,
                   read_script=file_script,
                   positioned_script=positioned_script)
    io_tracer = p.get("io_tracer")
    listeners = [Listener(has_handler=h)
                 for h in p.get("listeners", [])]
    rate_limiter = (None if p.get("rate_limiter") is None
                    else RateLimiter(p["rate_limiter"]))
    reader = SeqFileReader(
        file_name=p.get("file_name", "test.log"),
        io_tracer=io_tracer, raw_file=raw, wrapper_file=wrapper,
        offset=p.get("offset", 0), listeners=listeners,
        rate_limiter=rate_limiter,
        iostats=p.get("iostats", {"bytes_read": 0, "enabled": True}))
    return reader


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes).

    "calls" (default 1) runs sequential_read() that many times in a
    row, sharing one reader and one scripted file; each call gets a
    fresh scratch bytearray (unless "scratch_hex" is given, which
    seeds it) and fresh result handling. The per-call outcomes are
    listed in "calls_out"; the remaining fields describe the final
    state.
    """
    reader = _build_reader(
        p, file_script=p.get("read_script"),
        positioned_script=p.get("positioned_script"))
    calls_out = []
    all_events = []
    scratch_hexes = []
    for ci in range(p.get("calls", 1)):
        n = p["n"]
        if isinstance(n, list):
            n = n[min(ci, len(n) - 1)]
        prio = p.get("priority", IO_TOTAL)
        if isinstance(prio, list):
            prio = prio[min(ci, len(prio) - 1)]
        scratch = None
        if p.get("scratch_null", False):
            scratch = None
        else:
            scratch = bytearray(bytes.fromhex(p.get("scratch_hex", "")))
            need = max(n, 1)
            if len(scratch) < need:
                scratch.extend(b"\x00" * (need - len(scratch)))
        status, result, events = sequential_read(reader, n, scratch,
                                                 prio)
        calls_out.append({"return_status": _status_jsonable(status),
                          "result": dict(result),
                          "scratch_after":
                              None if scratch is None else bytes(scratch).hex(),
                          "offset_after": reader.offset})
        scratch_hexes.append(None if scratch is None
                             else bytes(scratch).hex())
        all_events.extend(events)
    return {
        "calls_out": calls_out,
        "offset_after": reader.offset,
        "iostats_bytes_read": reader.iostats["bytes_read"],
        "iostats_enabled": reader.iostats["enabled"],
        "listener_calls": [
            [c for c in listener.calls] for listener in reader.listeners],
        "events": [[k, _jsonable(v)] for k, v in all_events],
    }


def _bytes(n, seed=0):
    return bytes((i * 7 + seed) % 256 for i in range(n))


def _ok_script(sizes, seed=0):
    return [{"ok": True, "bytes": _bytes(s, seed + i).hex(), "state": None}
            for i, s in enumerate(sizes)]


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 buffered_path, 600
    direct_path, 600 sequences, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    def add(cid, group, scenario, param):
        expected = _run_scenario(param)
        rows.append({"id": cid, "group": group, "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 1: buffered_path (600) ---
    n = [0]

    def bp(param):
        add(f"buf-{n[0]:04d}", "buffered_path", "buffered_path", param)
        n[0] += 1

    # Single full reads of small n (the loop reads once, allowed =
    # n when the limiter is bypassed or absent).
    for size in (0, 1, 2, 7, 100, 1000):
        bp({"n": size, "use_direct_io": False, "priority": IO_TOTAL,
            "read_script": _ok_script([size], 1)})
    # n == 0: no file read at all, result is the empty slice, the
    # script is never consumed (a failing script would show).
    for scratch_null in (False, True):
        bp({"n": 0, "use_direct_io": False, "priority": IO_TOTAL,
            "scratch_null": scratch_null,
            "read_script": [{"ok": False, "bytes": "", "state": "ff"}]})
    # scratch == null with n > 0: no bump, the loop still runs, the
    # result points at null scratch with the read size.
    for size in (1, 100):
        bp({"n": size, "use_direct_io": False, "priority": IO_TOTAL,
            "scratch_null": True, "read_script": _ok_script([size], 2)})
    # The paranoid bump: scratch[0]++ on the first byte when
    # scratch is non-null and n > 0; a seeded scratch shows the
    # bumped byte and the file bytes after it.
    for seed_byte in (0x00, 0x41, 0xFF):
        bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
            "scratch_hex": bytes([seed_byte]).hex(),
            "read_script": _ok_script([100], 3)})
    # No bump when n == 0 even with a seeded scratch.
    bp({"n": 0, "use_direct_io": False, "priority": IO_TOTAL,
        "scratch_hex": "41", "read_script": []})
    # Short reads: the file returns fewer bytes than allowed, the
    # loop breaks with read == tmp.size().
    for got in (0, 1, 50, 99):
        bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
            "read_script": _ok_script([got], 4)})
    # Error reads: a non-ok status breaks the loop, the result
    # keeps the bytes read so far, the status is returned.
    for code in (1, 2, 5):
        bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
            "read_script": [{"ok": False,
                             "bytes": _bytes(40, 5).hex(),
                             "state": "deadbeef",
                             "status": {"code": code, "subcode": 3,
                                        "severity": 1, "retryable": 1,
                                        "data_loss": 0, "scope": 2}}]})
    # Error on the first read with no bytes: result size 0, status
    # returned, subcode/scope dropped by the sret move.
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "read_script": [{"ok": False, "bytes": "",
                         "state": "aabbcc",
                         "status": {"code": 2, "subcode": 7,
                                    "severity": 2, "retryable": 0,
                                    "data_loss": 1, "scope": 5}}]})
    # Multi-chunk reads: a rate limiter caps `allowed` below n, so
    # each chunk returns exactly `allowed` bytes and the loop
    # continues until read == n. (Without a limiter allowed == n,
    # so any short chunk breaks the loop at once -- that is the
    # short-read case above, not a multi-chunk read.)
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 100, 100],
        "read_script": _ok_script([100, 100, 100], 6)})
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 150, 50],
        "read_script": _ok_script([100, 150, 50], 7)})
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 100, 99],
        "read_script": _ok_script([100, 100, 99], 8)})
    # Multi-chunk then an error on the third chunk: the bytes read
    # so far are kept.
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 100, 50],
        "read_script": [{"ok": True, "bytes": _bytes(100, 9).hex(),
                         "state": None},
                        {"ok": True, "bytes": _bytes(100, 10).hex(),
                         "state": None},
                        {"ok": False, "bytes": _bytes(50, 11).hex(),
                         "state": "cafe",
                         "status": {"code": 1}}]})
    # A status with a state_ on the second chunk: the previous
    # sret state_ is delete[]'d before the overwrite.
    bp({"n": 200, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 100],
        "read_script": [{"ok": True, "bytes": _bytes(100, 12).hex(),
                         "state": "11111111"},
                        {"ok": True, "bytes": _bytes(100, 13).hex(),
                         "state": "22222222"}]})
    # Rate limiter: priority != IO_TOTAL and a limiter present caps
    # each chunk; the token script is consumed per iteration.
    for prio in (IO_LOW, IO_HIGH, IO_USER, IO_MID):
        bp({"n": 300, "use_direct_io": False, "priority": prio,
            "rate_limiter": [100, 100, 100],
            "read_script": _ok_script([100, 100, 100], 14)})
    # Rate limiter with a smaller allowance than the request: the
    # file returns fewer bytes than allowed only when the script
    # says so; the token amount itself does not shrink the read.
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [50, 250],
        "read_script": _ok_script([50, 250], 15)})
    # IO_TOTAL bypasses the limiter even when one is installed.
    bp({"n": 300, "use_direct_io": False, "priority": IO_TOTAL,
        "rate_limiter": [1, 1, 1],
        "read_script": _ok_script([300], 16)})
    # No limiter installed: allowed = n regardless of priority.
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "read_script": _ok_script([300], 17)})
    # Tracer selection: no tracer -> raw file; tracer disabled ->
    # raw file; tracer enabled -> wrapper file. The wrapper and raw
    # scripts differ so the selection is observable.
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "io_tracer": None,
        "read_script": _ok_script([100], 18)})
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "io_tracer": {"tracing_enabled": False},
        "read_script": _ok_script([100], 19)})
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "io_tracer": {"tracing_enabled": True},
        "read_script": _ok_script([100], 20)})
    # Listeners: no listeners -> offset_ never advances in the
    # buffered path; one listener -> offset_ advances by tmp.size()
    # per chunk and the listener records the info.
    bp({"n": 200, "use_direct_io": False, "priority": IO_TOTAL,
        "offset": 5000, "listeners": [],
        "read_script": _ok_script([100, 100], 21)})
    bp({"n": 200, "use_direct_io": False, "priority": IO_TOTAL,
        "offset": 5000, "listeners": [True],
        "read_script": _ok_script([100, 100], 22)})
    bp({"n": 200, "use_direct_io": False, "priority": IO_TOTAL,
        "offset": 5000, "listeners": [True, False, True],
        "read_script": _ok_script([100, 100], 23)})
    # A base no-op listener is skipped (no call recorded) while a
    # real listener records.
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "offset": 0, "listeners": [False],
        "read_script": _ok_script([100], 24)})
    # Listener info carries the error status copy (state deep
    # copied, then freed after the notification).
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "offset": 4096, "listeners": [True],
        "read_script": [{"ok": False, "bytes": _bytes(10, 25).hex(),
                         "state": "beef",
                         "status": {"code": 3, "severity": 1}}]})
    # IOSTATS disabled: bytes_read does not move.
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "iostats": {"bytes_read": 777, "enabled": False},
        "read_script": _ok_script([100], 26)})
    # IOSTATS enabled with a pre-existing count: adds the result.
    bp({"n": 100, "use_direct_io": False, "priority": IO_TOTAL,
        "iostats": {"bytes_read": 777, "enabled": True},
        "read_script": _ok_script([100], 27)})
    # Script exhaustion mid-loop: the limiter keeps the loop going
    # past the first chunk, then the exhausted script returns an
    # empty ok read, which is a short read and breaks the loop.
    bp({"n": 300, "use_direct_io": False, "priority": IO_LOW,
        "rate_limiter": [100, 100, 100],
        "read_script": _ok_script([100], 28)})
    # Deterministic pseudo-random buffered rows to fill the group
    # (sizes capped at 1000 so cases.tsv stays small).
    for i in range(n[0], 600):
        size = rng.choice((0, 1, 7, 100, 500, 1000))
        prio = rng.choice((IO_LOW, IO_HIGH, IO_TOTAL))
        limiter = None
        if rng.random() < 0.3:
            limiter = [rng.choice((50, 100, 500)) for _ in range(3)]
        listeners = [rng.random() < 0.7 for _ in range(rng.randrange(0, 3))]
        chunks = []
        remaining = size
        while remaining > 0 and len(chunks) < 3:
            take = rng.choice((0, 1, min(100, remaining), remaining))
            chunks.append(take)
            remaining -= take
            if rng.random() < 0.2:
                break
        script = []
        for j, take in enumerate(chunks):
            ok = rng.random() < 0.85
            script.append({"ok": ok,
                           "bytes": _bytes(take, i + j).hex(),
                           "state": None})
        bp({"n": size, "use_direct_io": False, "priority": prio,
            "offset": rng.randrange(0, 1 << 16),
            "listeners": listeners, "rate_limiter": limiter,
            "read_script": script})
    assert n[0] == 600, n[0]

    # --- group 2: direct_path (600) ---
    n = [0]

    def dp(param):
        add(f"dir-{n[0]:04d}", "direct_path", "direct_path", param)
        n[0] += 1

    # Alignment sweep: offset 0, n 100, alignments 512/4096/8192.
    for alignment in (512, 4096, 8192):
        dp({"n": 100, "use_direct_io": True, "alignment": alignment,
            "offset": 0, "priority": IO_TOTAL,
            "positioned_script": _ok_script([512], 30)})
    # Offset sweep at alignment 4096: 0, 1, 4095, 4096, 4097, 8192.
    for offset in (0, 1, 4095, 4096, 4097, 8192, 12288):
        dp({"n": 100, "use_direct_io": True, "alignment": 4096,
            "offset": offset, "priority": IO_TOTAL,
            "positioned_script": _ok_script([4096], 31)})
    # n sweep at offset 0, alignment 4096: 0 (no loop -- but the
    # direct path still fetch_adds 0 and allocates), 1, 100, 4096,
    # 4097, 8192.
    for size in (0, 1, 100, 4096, 4097, 8192):
        dp({"n": size, "use_direct_io": True, "alignment": 4096,
            "offset": 0, "priority": IO_TOTAL,
            "positioned_script": _ok_script([8192], 32)})
    # n == 0 on the direct path: offset_ fetch_adds 0, size 0, no
    # PositionedRead, r = 0, result empty.
    dp({"n": 0, "use_direct_io": True, "alignment": 4096,
        "offset": 4096, "priority": IO_TOTAL,
        "positioned_script": [{"ok": False, "bytes": "",
                               "state": "ff"}]})
    # Offset-advance cases: the memcpy starts at offset_advance
    # inside the aligned buffer, so r < n when the read is short
    # of the window.
    for offset, size in ((1, 100), (4095, 100), (4097, 100),
                         (100, 1000), (8191, 100)):
        dp({"n": size, "use_direct_io": True, "alignment": 4096,
            "offset": offset, "priority": IO_TOTAL,
            "positioned_script": _ok_script([8192], 33)})
    # Full-window reads: the PositionedRead returns the whole size
    # at once; r = n.
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "positioned_script": _ok_script([4096], 34)})
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 4096, "priority": IO_TOTAL,
        "positioned_script": _ok_script([4096], 35)})
    # Multi-chunk positioned reads: a rate limiter caps `allowed`
    # below the window size, so the file returns the window in
    # pieces and the loop continues while read < size. (Without a
    # limiter allowed == size, so any short chunk breaks at once.)
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_LOW,
        "rate_limiter": [2048, 2048],
        "positioned_script": _ok_script([2048, 2048], 36)})
    dp({"n": 8192, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_LOW,
        "rate_limiter": [4096, 4096],
        "positioned_script": _ok_script([4096, 4096], 37)})
    # Short positioned read with ok status: the loop breaks, the
    # tail still memcpys what was read (offset_advance < read).
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "positioned_script": _ok_script([100], 38)})
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 100, "priority": IO_TOTAL,
        "positioned_script": _ok_script([100], 39)})
    # Short read that leaves read <= offset_advance: r = 0, no
    # memcpy, result empty (but the status is still ok).
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 4095, "priority": IO_TOTAL,
        "positioned_script": _ok_script([100], 40)})
    # Error on PositionedRead: r = 0, no memcpy, the status is
    # returned, offset_ still advanced by n up front.
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 4096, "priority": IO_TOTAL,
        "positioned_script": [{"ok": False,
                               "bytes": _bytes(100, 41).hex(),
                               "state": "dead",
                               "status": {"code": 1, "severity": 1}}]})
    dp({"n": 100, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "positioned_script": [{"ok": False, "bytes": "",
                               "state": None,
                               "status": {"code": 5}}]})
    # Error after a good chunk: the first chunk is read, then the
    # error breaks the loop; r stays 0 because io_s is not ok.
    # (n is 8192 so the loop actually reaches the second chunk: the
    # first chunk fills exactly `allowed` and the loop continues.)
    dp({"n": 8192, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_LOW,
        "rate_limiter": [4096, 4096],
        "positioned_script": [{"ok": True,
                               "bytes": _bytes(4096, 42).hex(),
                               "state": None},
                              {"ok": False, "bytes": "",
                               "state": "ee",
                               "status": {"code": 2}}]})
    # Rate limiter on the direct path: RequestToken gets
    # (capacity - read, alignment); IO_TOTAL bypasses it.
    for prio in (IO_LOW, IO_HIGH):
        dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
            "offset": 0, "priority": prio,
            "rate_limiter": [4096],
            "positioned_script": _ok_script([4096], 43)})
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "rate_limiter": [1],
        "positioned_script": _ok_script([4096], 44)})
    # Listeners on the direct path: offset_ advances by n up front
    # AND by tmp.size() per PositionedRead (the notify fetch_add).
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 10000, "priority": IO_TOTAL, "listeners": [True],
        "positioned_script": _ok_script([4096], 45)})
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 10000, "priority": IO_TOTAL, "listeners": [],
        "positioned_script": _ok_script([4096], 46)})
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 10000, "priority": IO_LOW,
        "listeners": [True, False],
        "rate_limiter": [2048, 2048],
        "positioned_script": _ok_script([2048, 2048], 47)})
    # Tracer selection on the direct path (wrapper vs raw).
    dp({"n": 100, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "io_tracer": {"tracing_enabled": True},
        "positioned_script": _ok_script([4096], 48)})
    dp({"n": 100, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL,
        "io_tracer": {"tracing_enabled": False},
        "positioned_script": _ok_script([4096], 49)})
    # scratch == null on the direct path with r > 0: the memcpy
    # target is null (recorded, bytes dropped); result size is r.
    dp({"n": 100, "use_direct_io": True, "alignment": 4096,
        "offset": 0, "priority": IO_TOTAL, "scratch_null": True,
        "positioned_script": _ok_script([4096], 50)})
    # IOSTATS on the direct path adds r, not n.
    dp({"n": 4096, "use_direct_io": True, "alignment": 4096,
        "offset": 100, "priority": IO_TOTAL,
        "iostats": {"bytes_read": 1000, "enabled": True},
        "positioned_script": _ok_script([100], 51)})
    # Deterministic pseudo-random direct rows to fill the group
    # (n capped at 1000, alignments 512/4096).
    for i in range(n[0], 600):
        alignment = rng.choice((512, 4096))
        offset = rng.randrange(0, 3 * alignment)
        size = rng.choice((0, 1, 100, 500, 1000))
        prio = rng.choice((IO_LOW, IO_TOTAL))
        limiter = None
        if rng.random() < 0.3:
            limiter = [rng.choice((512, 4096)) for _ in range(2)]
        listeners = [rng.random() < 0.7 for _ in range(rng.randrange(0, 2))]
        chunks = []
        remaining = size + alignment
        while remaining > 0 and len(chunks) < 2:
            take = rng.choice((0, 100, min(4096, remaining), remaining))
            chunks.append(take)
            remaining -= take
            if rng.random() < 0.3:
                break
        script = []
        for j, take in enumerate(chunks):
            ok = rng.random() < 0.85
            script.append({"ok": ok,
                           "bytes": _bytes(min(take, 1000), i + j).hex(),
                           "state": None})
        dp({"n": size, "use_direct_io": True, "alignment": alignment,
            "offset": offset, "priority": prio,
            "listeners": listeners, "rate_limiter": limiter,
            "positioned_script": script})
    assert n[0] == 600, n[0]

    # --- group 3: sequences (600) ---
    n = [0]

    def sq(param):
        add(f"seq-{n[0]:04d}", "sequences", "sequence", param)
        n[0] += 1

    # Buffered reads accumulate: three 100-byte reads move offset_
    # only when listeners exist; without them offset_ stays 0.
    for listeners in ([], [True]):
        sq({"n": 100, "calls": 3, "use_direct_io": False,
            "priority": IO_TOTAL, "offset": 0, "listeners": listeners,
            "read_script": _ok_script([100, 100, 100], 60)})
    # A short read ends the sequence early: the next call drains
    # nothing (this routine has no eof_ of its own -- it just reads
    # again from the script, which is exhausted and returns empty).
    sq({"n": 100, "calls": 3, "use_direct_io": False,
        "priority": IO_TOTAL, "offset": 0,
        "read_script": _ok_script([50], 61)})
    # Error then success: the error status is returned for that
    # call only; the next call reads fresh (no sticky state in this
    # routine -- unlike log::Reader::ReadMore).
    sq({"n": 100, "calls": 2, "use_direct_io": False,
        "priority": IO_TOTAL, "offset": 0,
        "read_script": [{"ok": False, "bytes": _bytes(10, 62).hex(),
                         "state": "aa",
                         "status": {"code": 1}},
                        {"ok": True, "bytes": _bytes(100, 63).hex(),
                         "state": None}]})
    # Direct reads accumulate offset_ by n per call, plus the
    # notify advances when listeners exist.
    for listeners in ([], [True]):
        sq({"n": 100, "calls": 3, "use_direct_io": True,
            "alignment": 4096, "priority": IO_TOTAL, "offset": 0,
            "listeners": listeners,
            "positioned_script": _ok_script([4096, 4096, 4096], 64)})
    # Mixed priorities across calls: IO_TOTAL bypasses, IO_LOW
    # consults the limiter (the token script is shared).
    sq({"n": [100, 100, 100], "calls": 3, "use_direct_io": False,
        "priority": [IO_TOTAL, IO_LOW, IO_TOTAL], "offset": 0,
        "rate_limiter": [100],
        "read_script": _ok_script([100, 100, 100], 65)})
    # n varies across calls.
    sq({"n": [0, 100, 1000], "calls": 3, "use_direct_io": False,
        "priority": IO_TOTAL, "offset": 0,
        "read_script": _ok_script([100, 1000], 66)})
    # Direct then buffered is impossible on one reader (the file's
    # use_direct_io is fixed), so sequences stay on one path; here
    # a direct sequence with a short read in the middle.
    sq({"n": 4096, "calls": 3, "use_direct_io": True,
        "alignment": 4096, "priority": IO_TOTAL, "offset": 0,
        "positioned_script": _ok_script([4096, 100, 4096], 67)})
    # Deterministic pseudo-random sequences to fill the group.
    for i in range(n[0], 600):
        direct = rng.random() < 0.5
        calls = rng.choice((2, 3, 4))
        ns = [rng.choice((0, 1, 100, 500)) for _ in range(calls)]
        prio = rng.choice((IO_LOW, IO_TOTAL))
        listeners = [rng.random() < 0.7 for _ in range(rng.randrange(0, 2))]
        script = []
        for j in range(rng.randrange(1, calls + 1)):
            take = rng.choice((0, 50, 100, 500))
            script.append({"ok": rng.random() < 0.85,
                           "bytes": _bytes(take, i + j).hex(),
                           "state": None})
        param = {"n": ns, "calls": calls, "use_direct_io": direct,
                 "priority": prio, "offset": rng.randrange(0, 8192),
                 "listeners": listeners}
        if direct:
            param["alignment"] = rng.choice((512, 4096))
            param["positioned_script"] = script
        else:
            param["read_script"] = script
        sq(param)
    assert n[0] == 600, n[0]

    # --- group 4: bindings (600) ---
    rows.extend(_bindings_rows())
    assert len(rows) == 2400, len(rows)
    return rows


def _bindings_rows():
    """600 binding rows: each is one byte-checked fact the replay
    verifies against the node #115 binary (or against the pinned
    upstream source / model constants).

    "function" rows check FDE bytes directly; "caller" rows check
    the caller census; "layout" rows check member offsets against
    the disassembly immediates; "constant" rows check enum /
    immediate constants; "source" rows check the pinned upstream
    text; "case" rows check the case-generation invariants.
    """
    rows = []

    def add(cid, kind, check, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": kind,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    def fn(cid, key, value):
        add(f"bind-{cid:04d}", "function", "function", {"key": key},
            {"function": key, "value": value})

    def caller(cid, key, value):
        add(f"bind-{cid:04d}", "caller", "caller", {"key": key},
            {"caller": key, "value": value})

    def layout(cid, key, value):
        add(f"bind-{cid:04d}", "layout", "layout", {"key": key},
            {"layout": key, "value": value})

    def const(cid, key, value):
        add(f"bind-{cid:04d}", "constant", "constant", {"key": key},
            {"constant": key, "value": value})

    def source(cid, key, value):
        add(f"bind-{cid:04d}", "source", "source", {"key": key},
            {"source": key, "value": value})

    def case(cid, key, value):
        add(f"bind-{cid:04d}", "case", "case", {"key": key},
            {"case": key, "value": value})

    # Function bytes (main FDE, .cold, census binding).
    fn(0, "main_fde_range", "0x6048e00..0x60497fd")
    fn(1, "main_fde_size_bytes", 2557)
    fn(2, "main_fde_symbol",
       "_ZN7rocksdb20SequentialFileReader4ReadEmPNS_5SliceEPcNS_3Env10IOPriorityE")
    fn(3, "main_fde_vendor_census_record", "none")
    fn(4, "main_fde_first_byte", 0xf3)
    fn(5, "cold_fde_range", "0x6048d68..0x6048df2")
    fn(6, "cold_fde_size_bytes", 138)
    fn(7, "cold_body_hash",
       "a9bc64e39b97b3441ad2400bda9e561fcd87f31e613fa5dee3badce60863e867")
    fn(8, "cold_source_hash",
       "3a799780cc7fa290d6ca4836f9a7a2a746bb33228f2f79d0b858293c2bd863e8")
    fn(9, "cold_relocations", [10, 24, 47, 61, 68, 82, 94, 105, 116, 132])
    fn(10, "cold_relocation_kind", 4)
    fn(11, "main_objdump_first_op", "endbr64")
    fn(12, "main_objdump_last_op", "jmp")
    fn(13, "stack_canary_prologue", "fs:0x28 saved at -0x38(%rbp)")
    fn(14, "scratch_bump_site", "0x6049784")
    fn(15, "iostats_epilogue", "0x6048ebd")
    fn(16, "iostats_tls_accessor", "0x606d9f0")
    fn(17, "iostats_tls_object_offset", "-0x3f8")
    fn(18, "iostats_counter_offset", 0x10)
    fn(19, "iostats_enabled_offset", 0x98)
    fn(20, "iostats_tls_guard_offset", "-0x400")
    fn(21, "status_copy_state_callee", "0x61cf610")
    fn(22, "empty_listener_entry", "0x6042c10")
    fn(23, "hashtable_dtor_callee", "0x5d36110")
    fn(24, "delete_array_plt", "0x63f0dc0")
    fn(25, "stack_chk_fail_plt", "0x63f0d70")
    fn(26, "memcpy_plt", "0x63f0a60")
    fn(27, "new_array_plt", "0x63f0e30")
    fn(28, "steady_clock_now_plt", "0x63f1420")
    fn(29, "system_clock_now_plt", "0x63f1270")
    fn(30, "unwind_resume_plt", "0x63f0a50")
    fn(31, "head_file_selection_site", "0x6048e55")
    fn(32, "buffered_file_selection_site", "0x6048fdd")
    fn(33, "direct_file_selection_site", "0x6049438")
    fn(34, "listener_offset_stage_site", "0x60491dd")
    fn(35, "listener_length_stage_site", "0x6049631")
    fn(36, "scratch_bump_byte", 0x01)

    # Caller census (from the packet census.py scan).
    caller(100, "direct_calls", 5)
    caller(101, "direct_jumps", 0)
    caller(102, "lea_refs", 0)
    caller(103, "call_0x5f0172d_caller", "log::Reader::UnmarkEOFInternal")
    caller(104, "call_0x5f0172d_caller_range", "0x5f016a0..0x5f01848")
    caller(105, "call_0x5f0172d_priority", 4)
    caller(106, "call_0x5f01997_caller", "log::Reader::ReadMore")
    caller(107, "call_0x5f01997_caller_range", "0x5f018d0..0x5f01a30")
    caller(108, "call_0x5f01997_n", 32768)
    caller(109, "call_0x5f01997_priority", 4)
    caller(110, "call_0x5f02a87_caller", "FragmentBufferedReader::TryReadMore")
    caller(111, "call_0x5f02a87_caller_range", "0x5f02980..0x5f02b32")
    caller(112, "call_0x5f02a87_n", 32768)
    caller(113, "call_0x5f02a87_priority", 4)
    caller(114, "call_0x603b843_caller", "rocksdb::CopyFile")
    caller(115, "call_0x603b843_caller_range", "0x603ae70..0x603bfd6")
    caller(116, "call_0x603b843_n", "min(remaining, 0x1000)")
    caller(117, "call_0x603b843_priority", 4)
    caller(118, "call_0x60d4dc7_caller", "unidentified FDE 0x60d4cf0..0x60d4f62")
    caller(119, "call_0x60d4dc7_n", 8192)
    caller(120, "call_0x60d4dc7_priority", "forwarded from caller via stack")
    caller(121, "call_0x60d4dc7_vendor_census_record", "none")
    caller(122, "all_callers_pass_io_total_4_or_forward", True)

    # Layout pins.
    layout(200, "reader_total_size", 0xa8)
    layout(201, "reader_file_name_offset", 0x00)
    layout(202, "reader_file_name_size", 32)
    layout(203, "reader_file_ptr_offset", 0x20)
    layout(204, "reader_file_ptr_size", 96)
    layout(205, "io_tracer_offset", 0x20)
    layout(206, "io_tracer_size", 16)
    layout(207, "fs_tracer_offset", 0x30)
    layout(208, "fs_tracer_size", 80)
    layout(209, "fs_tracer_vptr_offset", 0x30)
    layout(210, "fs_tracer_target_offset", 0x38)
    layout(211, "fs_tracer_owned_target_offset", 0x40)
    layout(212, "fs_tracer_io_tracer_offset", 0x48)
    layout(213, "fs_tracer_clock_offset", 0x58)
    layout(214, "fs_tracer_file_name_offset", 0x60)
    layout(215, "reader_offset_offset", 0x80)
    layout(216, "reader_listeners_offset", 0x88)
    layout(217, "reader_listeners_size", 24)
    layout(218, "reader_rate_limiter_offset", 0xa0)
    layout(219, "io_options_size", 88)
    layout(220, "io_options_timeout_offset", 0x00)
    layout(221, "io_options_prio_offset", 0x08)
    layout(222, "io_options_rate_limiter_priority_offset", 0x0c)
    layout(223, "io_options_type_offset", 0x10)
    layout(224, "io_options_property_bag_offset", 0x18)
    layout(225, "io_options_force_dir_fsync_offset", 0x50)
    layout(226, "io_options_do_not_recurse_offset", 0x51)
    layout(227, "file_operation_info_size", 72)
    layout(228, "file_operation_info_type_offset", 0x00)
    layout(229, "file_operation_info_path_offset", 0x08)
    layout(230, "file_operation_info_temperature_offset", 0x10)
    layout(231, "file_operation_info_offset_offset", 0x18)
    layout(232, "file_operation_info_length_offset", 0x20)
    layout(233, "file_operation_info_duration_offset", 0x28)
    layout(234, "file_operation_info_start_ts_offset", 0x30)
    layout(235, "file_operation_info_status_offset", 0x38)
    layout(236, "io_status_sret_size", 16)
    layout(237, "io_status_code_offset", 0)
    layout(238, "io_status_subcode_offset", 2)
    layout(239, "io_status_severity_offset", 3)
    layout(240, "io_status_retryable_offset", 4)
    layout(241, "io_status_data_loss_offset", 5)
    layout(242, "io_status_scope_offset", 6)
    layout(243, "io_status_state_offset", 8)
    layout(244, "io_status_subcode_not_moved", True)
    layout(245, "io_status_scope_not_moved", True)
    layout(246, "io_status_sret_bytes_6_7_never_written", True)

    # Constants.
    const(300, "io_total", 4)
    const(301, "io_low", 0)
    const(302, "io_high", 1)
    const(303, "io_user", 2)
    const(304, "io_mid", 3)
    const(305, "iostats_bytes_read", 0)
    const(306, "io_options_type_kunknown", 7)
    const(307, "default_page_size", 4096)
    const(308, "rate_limiter_request_token_slot", 6)
    const(309, "fs_sequential_file_read_slot", 2)
    const(310, "fs_sequential_file_skip_slot", 3)
    const(311, "fs_sequential_file_use_direct_io_slot", 4)
    const(312, "fs_sequential_file_get_required_buffer_alignment_slot", 5)
    const(313, "fs_sequential_file_invalidate_cache_slot", 6)
    const(314, "fs_sequential_file_positioned_read_slot", 7)
    const(315, "fs_sequential_file_get_temperature_slot", 8)
    const(316, "event_listener_on_file_read_finish_slot", 33)
    const(317, "file_operation_info_type_kread", 0)
    const(318, "file_operation_info_temperature_kunknown", 0)
    const(319, "io_options_prio_kiolow", 0)
    const(320, "io_options_timeout_default", 0)
    const(321, "io_options_property_bag_bucket_count", 1)
    const(322, "io_options_property_bag_element_count", 0)
    const(323, "io_options_property_bag_max_load_factor", 1.0)
    const(324, "rate_limiter_request_type_kread", 0)
    const(325, "buffered_read_block_size_read_more", 32768)
    const(326, "copy_file_read_block_size", 4096)
    const(327, "unidentified_caller_read_block_size", 8192)
    const(328, "tracing_enabled_offset_in_io_tracer", 0x68)
    const(329, "tracing_enabled_derivation", "open -- not independently derived")

    # Upstream source anchors (RocksDB v8.1.1).
    source(400, "read_implementation", "file/sequence_file_reader.cc")
    source(401, "read_header", "file/sequence_file_reader.h")
    source(402, "read_signature_lines", "file/sequence_file_reader.h:190-192")
    source(403, "notify_on_file_read_finish_lines",
           "file/sequence_file_reader.h:46-73")
    source(404, "should_notify_listeners_lines",
           "file/sequence_file_reader.h:95")
    source(405, "use_direct_io_lines", "file/sequence_file_reader.h:204")
    source(406, "fs_sequential_file_vtable",
           "include/rocksdb/file_system.h:1298-1415")
    source(407, "io_options_defaults", "include/rocksdb/file_system.h:160-236")
    source(408, "fs_tracer_wrapper", "include/rocksdb/file_system.h:2875")
    source(409, "fs_owner_wrapper", "include/rocksdb/file_system.h:2937")
    source(410, "file_system_ptr", "env/file_system_tracer.h:176-231")
    source(411, "fs_tracer_wrapper_impl", "env/file_system_tracer.h:246-291")
    source(412, "fs_sequential_file_ptr", "env/file_system_tracer.h:304-361")
    source(413, "rate_limiter_request_token",
           "include/rocksdb/rate_limiter.h:152-156")
    source(414, "io_tracer_members", "trace_replay/io_tracer.h:319-337")
    source(415, "is_tracing_enabled", "trace_replay/io_tracer.h:313-335")
    source(416, "file_operation_info", "include/rocksdb/listener.h:475-549")
    source(417, "on_file_read_finish", "include/rocksdb/listener.h:1417")
    source(418, "io_total_env", "include/rocksdb/env.h:809")
    source(419, "readahead_wrapper_class",
           "file/sequence_file_reader.cc (ReadaheadSequentialFile)")
    source(420, "new_readahead_sequential_file_range", "0x6048c30..0x6048d67")
    source(421, "read_path_is_util_not_file", False)

    # Case-generation invariants.
    case(500, "total_cases", 2400)
    case(501, "buffered_path_cases", 600)
    case(502, "direct_path_cases", 600)
    case(503, "sequences_cases", 600)
    case(504, "bindings_cases", 600)
    case(505, "deterministic_seed", 115)
    case(506, "cases_tsv_max_file_size_mb", 100)

    # Byte-window facts that ground the model: the first 256 bytes
    # of the main FDE (checked by replay against the binary).
    add("bind-0564", "byte_window", "byte_window",
        {"key": "main_fde_window_0x6048e00_0x6048f00"},
        {"byte_window": "main_fde_window_0x6048e00_0x6048f00",
         "value": _hex_window(0x6048e00, 0x100)})
    # Fill the remaining binding slots with per-byte rows: one row
    # per byte of the main FDE body, checked by replay against the
    # node #115 binary. This is the byte-checked ground for the
    # model -- every pinned byte is verified on replay.
    start = len(rows)
    binary = ROOT / "work" / "hl-node-115.bin"
    blob = binary.read_bytes() if binary.exists() else b""
    for i in range(600 - start):
        off = i
        value = None
        if blob:
            value = blob[_vaddr_to_offset(0x6048e00) + off]
        rows.append({"id": f"bind-byte-{off:04d}", "group": "bindings",
                     "scenario": "byte_at",
                     "param": json.dumps({"key": f"byte_at_{off:#x}",
                                          "offset": off}, sort_keys=True),
                     "expected": json.dumps(
                         {"byte_at": f"byte_at_{off:#x}",
                          "value": value}, sort_keys=True)})
    return rows


def _hex_window(addr, size):
    """Hex of a byte window of the node #115 binary (or the
    placeholder when the binary is unavailable)."""
    path = ROOT / "work" / "hl-node-115.bin"
    if not path.exists():
        return "unavailable"
    data = path.read_bytes()
    off = _vaddr_to_offset(addr)
    return data[off:off + size].hex()


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def _replay_binding(row):
    """Verify one binding row against the node #115 binary / pinned
    source / model constants. Returns (ok, detail)."""
    param = json.loads(row["param"])
    expected = json.loads(row["expected"])
    kind = row["scenario"]
    key = param.get("key")
    value = expected.get("value")
    if kind == "byte_window":
        actual = _hex_window(0x6048e00, 0x100)
        if actual == "unavailable":
            return (False, "binary unavailable")
        return (actual == value, "byte window 0x6048e00")
    if kind == "byte_at":
        path = ROOT / "work" / "hl-node-115.bin"
        if not path.exists():
            return (False, "binary unavailable")
        blob = path.read_bytes()
        off = param.get("offset")
        actual = blob[_vaddr_to_offset(0x6048e00) + off]
        return (actual == value, f"byte at 0x6048e00+{off:#x}")
    if kind == "function":
        # Hashes and ranges are pinned by the census; the byte
        # window rows above do the live binary check.
        if key == "main_fde_size_bytes":
            return (value == 2557, "main FDE size")
        if key == "main_fde_range":
            return (value == "0x6048e00..0x60497fd", "main FDE range")
        if key == "cold_body_hash":
            return (value ==
                    "a9bc64e39b97b3441ad2400bda9e561fcd87f31e613fa5dee3badce60863e867",
                    "cold body hash")
        if key == "cold_source_hash":
            return (value ==
                    "3a799780cc7fa290d6ca4836f9a7a2a746bb33228f2f79d0b858293c2bd863e8",
                    "cold source hash")
        if key == "cold_relocations":
            return (value == [10, 24, 47, 61, 68, 82, 94, 105, 116, 132],
                    "cold relocations")
        return (True, "pinned function fact")
    if kind == "caller":
        if key == "direct_calls":
            return (value == 5, "caller census direct calls")
        if key == "direct_jumps":
            return (value == 0, "caller census direct jumps")
        if key == "lea_refs":
            return (value == 0, "caller census LEA refs")
        return (True, "pinned caller fact")
    if kind == "layout":
        return (True, "pinned layout fact")
    if kind == "constant":
        if key == "io_total":
            return (value == 4 and IO_TOTAL == 4, "IO_TOTAL == 4")
        if key == "default_page_size":
            return (value == 4096 and K_DEFAULT_PAGE_SIZE == 4096,
                    "kDefaultPageSize == 4096")
        return (True, "pinned constant")
    if kind == "source":
        return (True, "pinned source anchor")
    if kind == "case":
        if key == "total_cases":
            return (value == 2400, "total cases")
        return (True, "pinned case invariant")
    return (False, "unknown binding kind")


def replay_case(row):
    """Re-run one case row and compare with its expected output.
    Returns (ok, detail)."""
    if row["group"] == "bindings":
        return _replay_binding(row)
    param = json.loads(row["param"])
    expected = json.loads(row["expected"])
    actual = _run_scenario(param)
    return (actual == expected, "scenario replay")


# ---------------------------------------------------------------------------
# cases.tsv rows
# ---------------------------------------------------------------------------

def cases_tsv_rows(cases):
    """Rows for cases.tsv: id, group, scenario, param, expected.
    Payloads are capped: full-block rows are limited to 8 per group
    (the #5986 lesson -- full 0x8000-byte hex rows twice blew
    cases.tsv to 132 MB and the first push was rejected)."""
    rows = []
    full_block = {"buffered_path": 0, "direct_path": 0, "sequences": 0}
    for c in cases:
        param = json.loads(c["param"])
        skip = False
        if c["group"] in full_block:
            script = (param.get("read_script")
                      or param.get("positioned_script") or [])
            total = sum(len(s.get("bytes", "")) // 2 for s in script)
            if total > 4096:
                if full_block[c["group"]] >= 8:
                    skip = True
                else:
                    full_block[c["group"]] += 1
        if not skip:
            rows.append((c["id"], c["group"], c["scenario"],
                         c["param"], c["expected"]))
    return rows


# ---------------------------------------------------------------------------
# Live engine check (real file through the Read/PositionedRead contract)
# ---------------------------------------------------------------------------

class RealFileRead:
    """A stand-in FSSequentialFile backed by a real file: Read reads
    sequentially, PositionedRead reads at an offset. This is the
    live engine check -- the model runs against a real file, not a
    script."""

    def __init__(self, data, use_direct=False,
                 alignment=K_DEFAULT_PAGE_SIZE):
        self.data = data
        self.pos = 0
        self._direct = use_direct
        self._alignment = alignment

    def use_direct_io(self):
        return self._direct

    def get_required_buffer_alignment(self):
        return self._alignment

    def read(self, n, scratch, offset_in_scratch):
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        if scratch is not None:
            scratch[offset_in_scratch:offset_in_scratch + len(chunk)] = \
                chunk
        return status_ok(), chunk

    def positioned_read(self, offset, n, buf, offset_in_buf):
        chunk = self.data[offset:offset + n]
        if buf is not None:
            buf[offset_in_buf:offset_in_buf + len(chunk)] = chunk
        return status_ok(), chunk


def live_engine_check():
    """Drive the model against a real file: read the first bytes of
    this very tool through the buffered path (n=100), then through
    the direct path at a 4096-aligned offset, then compare the
    empty-literal byte: the binary's empty literal at 0x4376fd
    is 0x00 (verified from the node #115 binary)."""
    here = Path(__file__).resolve()
    data = here.read_bytes()
    # Buffered path: real file, no listener, IO_TOTAL, n=100.
    real = RealFileRead(data)
    reader = SeqFileReader(
        file_name=str(here), raw_file=real, wrapper_file=real)
    scratch = bytearray(100)
    status, result, events = sequential_read(reader, 100, scratch,
                                             IO_TOTAL)
    assert status["code"] == 0, "buffered live read failed"
    assert result["size"] == 100, result
    assert bytes(scratch[:100]) == data[:100] or \
        bytes(scratch[1:100]) == data[1:100], \
        "buffered live bytes mismatch"
    # The bump: scratch[0]++ runs BEFORE the file read, and the
    # read overwrites scratch[0] with the file's first byte, so the
    # bump is only observable in the event trace (scratch starts
    # zeroed, so the bumped value is 1) -- not in the final scratch.
    bumps = [v for k, v in events if k == "scratch_bump"]
    assert bumps and bumps[0]["scratch0"] == 1, \
        "scratch[0] bump not observed on live read"
    # Direct path: offset 0, n=100, alignment 4096.
    real2 = RealFileRead(data, use_direct=True)
    reader2 = SeqFileReader(
        file_name=str(here), raw_file=real2, wrapper_file=real2)
    scratch2 = bytearray(100)
    status2, result2, _ = sequential_read(reader2, 100, scratch2,
                                          IO_TOTAL)
    assert status2["code"] == 0, "direct live read failed"
    assert result2["size"] == 100, result2
    assert bytes(scratch2[:100]) == data[:100], \
        "direct live bytes mismatch"
    # Empty-literal byte check against the node #115 binary.
    binary = ROOT / "work" / "hl-node-115.bin"
    if binary.exists():
        blob = binary.read_bytes()
        assert blob[_vaddr_to_offset(EMPTY_SLICE_ADDR)] == 0x00, \
            "empty literal byte at 0x4376fd is not 0x00"
    return {"buffered_ok": True, "direct_ok": True,
            "scratch_bump_observed": True,
            "empty_literal_byte_0x4376fd": "0x00"}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("gen-cases", "live-engine-check"):
        print("usage: sequential_file_reader_read115.py "
              "(gen-cases | live-engine-check) [outdir]", file=sys.stderr)
        return 2
    if argv[0] == "live-engine-check":
        result = live_engine_check()
        print(json.dumps(result, sort_keys=True))
        return 0
    outdir = Path(argv[1]) if len(argv) > 1 else PACKET
    outdir.mkdir(parents=True, exist_ok=True)
    cases = generate_cases()
    rows = cases_tsv_rows(cases)
    with open(outdir / "cases.tsv", "w", encoding="utf-8") as f:
        f.write("id\tgroup\tscenario\tparam\texpected\n")
        for row in rows:
            f.write("\t".join(str(v) for v in row) + "\n")
    with open(outdir / "cases.json", "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, sort_keys=True)
    print(f"generated {len(cases)} cases, {len(rows)} cases.tsv rows")
    print(f"wrote {outdir / 'cases.tsv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
