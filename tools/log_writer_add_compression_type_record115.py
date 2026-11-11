"""Node #115 RocksDB log::Writer::AddCompressionTypeRecord: reconstruction.

RE-002 work item. Reconstructs the WAL writer's compression-type-record
routine at 0x5f041d0..0x5f0441c (588 B) plus its shared landing pad
``AddCompressionTypeRecord.cold`` at 0x5f04190..0x5f041c4 (52 B):

  rocksdb::log::Writer::AddCompressionTypeRecord  0x5f041d0 (588 B)
  rocksdb::log::Writer::AddCompressionTypeRecord.cold  0x5f04190 (52 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Both body hashes match the vendor census target_body_sha256 exactly,
and both source hashes are reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbols come from the vendor
census (member 25dac13516458d4d-log_writer.o, librocksdb-sys).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus AddCompressionTypeRecord() -- returns by value, so rdi is the
  hidden 16-byte sret out-pointer and rsi is the Writer*. Steps, in
  binary order:

  1. Gate: if compression_type_ (this+0x45) == kNoCompression (0),
     zero 16 bytes at the out-pointer (bytes 0-3, 4-5, 8-15; bytes 6-7
     are NOT written) and return the out-pointer at once. Nothing else
     is touched: no record is emitted, no compressor is installed.
  2. Encode: CompressionTypeRecord(compression_type_) -- the 4-byte
     type value at rsp+0x10 -- appended to an empty SSO std::string
     ``encode`` (PutFixed32, i.e. 4 little-endian bytes; upstream
     util/compression.h:3108-3114). The string is built at rsp+0x40
     (ptr = its own SSO buffer at rsp+0x50, size 0).
  3. Emit: EmitPhysicalRecord(sret=rsp, this, type 9 =
     kSetCompressionType, encode.data(), encode.size() = 4,
     priority 4 = Env::IO_TOTAL) at 0x5f04294. The returned 16-byte
     status lands at [rsp].
  4. Emit failure (status code byte != 0): compression_type_ = 0
     (this+0x45 cleared, upstream log_writer.cc:359), then copy the
     emit status into the out-pointer (step 7) and return. The
     compressor is NOT installed and no buffer is allocated.
  5. Emit OK and manual_flush_ (this+0x44) == 0: dest_->Flush()
     (WritableFileWriter::Flush, 0x6051a20, called at 0x5f04394 with
     sret=rsp+0x10, this+0x00, priority 4). The Flush status is MOVED
     into [rsp] (bytes 0-1, 3-4, 5, 8-15; byte 2 and bytes 6-7 of
     [rsp] keep the emit status's values) and the old emit status's
     heap state_ is delete[]'d when non-null. If manual_flush_ != 0
     the Flush is skipped and [rsp] keeps the emit status.
  6. Install, REGARDLESS of the Flush result (the binary does not
     re-check the status after the Flush -- upstream log_writer.cc
     checks s.ok() once, before the Flush, and the init block runs
     unconditionally inside it): build the 48-byte default
     CompressionOptions template at rsp+0x10 and call
     StreamingCompress::Create(type, template, version 2, max_len)
     at 0x61c1c10, where max_len = 0x8000 - header = 0x7ff9 (legacy,
     recycle == 0) or 0x7ff5 (recyclable, recycle == 1; this+0x18).
     Install the product at this+0x48 (compress_), then operator
     new[] a fresh buffer of max_len bytes, store it at this+0x50
     (compressed_buffer_) and delete[] the previous buffer when
     non-null. The previous compress_ (if any) is NOT deleted -- it
     is overwritten, i.e. leaked on re-entry (the routine is designed
     to run once, right after construction, when compress_ is null;
     the Writer destructor deletes compress_ exactly once).
  7. Return: copy the final 16-byte status from [rsp] into the
     out-pointer -- bytes 0-1, 3-4, 5, 8-15 copied, byte 2 forced to
     0, bytes 6-7 NOT written -- destroy the ``encode`` string (sized
     delete of the heap buffer when it is not the SSO buffer), check
     the stack canary and return the out-pointer.

  The .cold landing pad (0x5f04190, entered from the two endbr64 stubs
  at 0x5f04404 / 0x5f04410): entry 0x5f04190 delete[]s the status
  state_ at [rsp+8] when non-null, then disposes the ``encode``
  string; entry 0x5f0419f disposes the string only. Both check the
  canary and _Unwind_Resume with the exception object saved in rbx.

Writer layout (node #115, from the field accesses, confirmed against
upstream db/log_writer.h: dest_ +0x00, block_offset_ +0x08,
log_number_ +0x10, recycle_log_files_ +0x18, type_crc_[10] +0x1c..0x44,
manual_flush_ +0x44, compression_type_ +0x45, compress_ +0x48,
compressed_buffer_ +0x50; total 0x58):

  +0x00 dest_ (unique_ptr<WritableFileWriter>, 8)
  +0x08 block_offset_ (size_t, 8) -- never read here: the upstream
         assert(block_offset_ == 0) is compiled out
  +0x10 log_number_ (uint64, 8) -- never read here
  +0x18 recycle_log_files_ (bool, 1)
  +0x1c type_crc_[10] (40 bytes) -- never read here
  +0x44 manual_flush_ (bool, 1)
  +0x45 compression_type_ (CompressionType, 1 byte; 0 = kNoCompression)
  +0x48 compress_ (StreamingCompress*, 8)
  +0x50 compressed_buffer_ (unique_ptr<char[]>, 8)

The 48-byte default CompressionOptions template (upstream
include/rocksdb/advanced_options.h:366-384, default ctor), built on
the stack at rsp+0x10:

  +0x00 window_bits (int) = -14
  +0x04 level (int) = 32767 (kDefaultCompressionLevel)
  +0x08 strategy (int) = 0
  +0x0c max_dict_bytes (uint32) = 0
  +0x10 zstd_max_train_bytes (uint32) = 0
  +0x14 parallel_threads (uint32) = 1
  +0x18 enabled (bool) = false
  +0x20 max_dict_buffer_bytes (uint64) = 0
  +0x28 use_zstd_dict_trainer (bool) = true
  +0x29..+0x2f padding -- NEVER WRITTEN by the binary (7 bytes of
         uninitialized stack; Create reads only the named fields)

As qwords the binary writes: +0x00 = 0x00007ffffffffff2 (one load from
the .rodata pair at 0x459aa0), +0x08 = 0, +0x10 = 0x100000000,
+0x18 = 0, +0x20 = 0, and byte +0x28 = 1.

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts): exactly 1 direct call
at 0x5e5c5a3 inside rocksdb::DBImpl::CreateWAL
0x5e5c270..0x5e5c9a3 (the caller constructs a fresh Writer with the
move ctor 0x5f04c00, stores it through the Writer** out-param, then
calls this routine with rdi = the Writer* slot and rsi = the new
Writer). No tail jumps or LEA refs to 0x5f041d0. The .cold block has
exactly 1 tail jump to its start (0x5f0440b -> 0x5f04190); the second
entry 0x5f0419f is reached from the stub at 0x5f04410.

Corrections to merged RE-001-zstd-compress-cache-115, whose "refresh"
record first pinned this routine at census level (547/588 bytes, the
objdump excerpt, the caller list) but which this packet supersedes
with a full body model, 2,400 cases and the upstream cross-check:

  * The template's first qword is (-14, 32767), NOT (-14, INT_MAX):
    the high int32 is 0x00007fff = 32767 =
    CompressionOptions::kDefaultCompressionLevel (upstream
    advanced_options.h:174, 366-370).
  * 0x6051a20 is WritableFileWriter::Flush (census-confirmed, 2908 B),
    NOT a "shared 4-byte copy helper": the call at 0x5f04394 passes
    (sret, dest_.get(), IO_TOTAL) and the callee reads WritableFileWriter
    members (byte +0x89, qword +0x58) and steady/system clocks.
  * The field names of the 48-byte template are now pinned (above),
    not merely "inferred".
  * The merged packet did not model the Flush-failure path, the
    status-copy byte rules, the .cold pad, or the old-buffer /
    old-compress_ handling; all are modelled here.

What is modelled here is the routine's OBSERVABLE trace on a Writer:
the ordered events (gate, encode, emit call, flush call, template,
create call, install, buffer swap, status copy) plus the resulting
state (compression_type_, compress_, compressed_buffer_, the returned
16-byte status). The three external calls -- EmitPhysicalRecord,
WritableFileWriter::Flush, StreamingCompress::Create -- are taken as
inputs to the model (their outcomes are parameters): EmitPhysicalRecord
is fully reconstructed in the merged cache packet only as a caller
record (its body 0x5f03b80 is census-bound, not modelled here);
Flush is a 2908-byte routine modelled only through its status result;
Create is fully reconstructed in merged RE-001-zstd-compress-cache-115
(gate kind 7, 0x70-byte holder, fresh CCtx, setParameter 201 -> 1).
The model DOES drive the real engine once, in live_engine_check():
a real CCtx is created through the system libzstd, parameter 201 is
set to 1 and the ctx is reset with directive 1, proving the factory
product the routine installs is constructible and resettable exactly
as the merged factory packet describes.

Upstream anchors (RocksDB v8.1.1, read live this cycle):
db/log_writer.cc:297-365 (AddCompressionTypeRecord, step for step --
including the unchecked Flush result before the install and the
type = kNoCompression assignment on emit failure), db/log_writer.h
(Writer layout; AddRecord/Flush default priority Env::IO_TOTAL),
db/log_format.h (kSetCompressionType = 9, kMaxRecordType = 9,
kBlockSize = 32768, kHeaderSize = 7, kRecyclableHeaderSize = 11),
util/compression.h:3096-3160 (CompressionTypeRecord: one member,
EncodeTo = PutFixed32) and 3175-3244 (StreamingCompress::Create
signature), include/rocksdb/advanced_options.h:160-414
(CompressionOptions fields and defaults).

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the ZSTD engine call
in live_engine_check() goes through the system libzstd.so.1 (1.5.5)
via ctypes (the target statically links zstd 1.5.7; the public API is
the same). make verify/test/catalogue-check in a tooled environment
is still owed upstream.
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
          / "re-002-node115-rocksdb-log-writer-add-compression-type-record-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Writer layout (bytes).
WRITER_SIZE = 0x58
OFF_DEST = 0x00
OFF_BLOCK_OFFSET = 0x08
OFF_LOG_NUMBER = 0x10
OFF_RECYCLE = 0x18
OFF_TYPE_CRC = 0x1C
OFF_MANUAL_FLUSH = 0x44
OFF_COMPRESSION_TYPE = 0x45
OFF_COMPRESS = 0x48
OFF_COMPRESSED_BUFFER = 0x50

K_NO_COMPRESSION = 0
K_SET_COMPRESSION_TYPE = 9
IO_TOTAL = 4
FORMAT_VERSION = 2
KBLOCK_SIZE = 32768
HEADER_SIZE = 7
RECYCLABLE_HEADER_SIZE = 11
MAX_LEN_LEGACY = KBLOCK_SIZE - HEADER_SIZE            # 0x7ff9
MAX_LEN_RECYCLABLE = KBLOCK_SIZE - RECYCLABLE_HEADER_SIZE  # 0x7ff5

# CompressionType (include/rocksdb/compression_type.h, v8.1.1).
COMPRESSION_TYPES = {
    0x00: "kNoCompression",
    0x01: "kSnappyCompression",
    0x02: "kZlibCompression",
    0x03: "kBZip2Compression",
    0x04: "kLZ4Compression",
    0x05: "kLZ4HCCompression",
    0x06: "kXpressCompression",
    0x07: "kZSTD",
    0x40: "kZSTDNotFinalCompression",
    0xFF: "kDisableCompressionOption",
}

# The 48-byte default CompressionOptions template, as the binary builds
# it (qwords at +0x00..+0x20, byte 1 at +0x28, padding +0x29..+0x2f
# never written).
TEMPLATE_QWORDS = (0x00007FFFFFFFFFF2, 0x0, 0x100000000, 0x0, 0x0)
TEMPLATE_TRAINER_BYTE = 1


def build_template():
    """The 48-byte default CompressionOptions template, byte-exact for
    every byte the binary writes; bytes +0x29..+0x2f are None
    (unwritten padding)."""
    out = bytearray(48)
    for i, q in enumerate(TEMPLATE_QWORDS):
        struct.pack_into("<Q", out, i * 8, q)
    out[0x28] = TEMPLATE_TRAINER_BYTE
    return bytes(out)


def template_field_map():
    """Field name -> (offset, size, value) for the template."""
    return [
        ("window_bits", 0x00, 4, -14),
        ("level", 0x04, 4, 32767),
        ("strategy", 0x08, 4, 0),
        ("max_dict_bytes", 0x0C, 4, 0),
        ("zstd_max_train_bytes", 0x10, 4, 0),
        ("parallel_threads", 0x14, 4, 1),
        ("enabled", 0x18, 1, 0),
        ("max_dict_buffer_bytes", 0x20, 8, 0),
        ("use_zstd_dict_trainer", 0x28, 1, 1),
    ]


def put_fixed32(value):
    """CompressionTypeRecord::EncodeTo: the 4-byte little-endian type."""
    return struct.pack("<I", value & 0xFFFFFFFF)


def max_output_len(recycle):
    """kBlockSize - header: 0x7ff9 legacy, 0x7ff5 recyclable."""
    return MAX_LEN_RECYCLABLE if recycle else MAX_LEN_LEGACY


class Status:
    """A 16-byte RocksDB IOStatus as the binary moves it.

    Live bytes: code @0, subcode @1, flag bytes @3, @4, @5, state_
    pointer @8 (8 bytes, 0 = null). Byte 2 is forced to 0 by the
    routine's status copy and bytes 6-7 are never written by it; both
    are tracked so the copy rule is checkable.
    """

    def __init__(self, code=0, subcode=0, b3=0, b4=0, b5=0, state=0):
        self.code = code & 0xFF
        self.subcode = subcode & 0xFF
        self.b3 = b3 & 0xFF
        self.b4 = b4 & 0xFF
        self.b5 = b5 & 0xFF
        self.state = state  # 0 = null, else a token standing in for a ptr

    def copy_from(self, other):
        """The routine's status copy (0x5f0433c): bytes 0-1, 3-4, 5,
        8-15 copied; byte 2 forced to 0; bytes 6-7 not written."""
        self.code = other.code
        self.subcode = other.subcode
        self.b3 = other.b3
        self.b4 = other.b4
        self.b5 = other.b5
        self.state = other.state

    def out_bytes(self):
        """The 16 bytes the caller sees: byte 2 is 0, bytes 6-7 are the
        sentinel None (never written by this routine)."""
        out = bytearray(16)
        out[0] = self.code
        out[1] = self.subcode
        out[2] = 0
        out[3] = self.b3
        out[4] = self.b4
        out[5] = self.b5
        struct.pack_into("<Q", out, 8, self.state)
        # bytes 0-5 as stored, bytes 6-7 unwritten ("XX"), bytes 8-15
        # the state_ pointer.
        return bytes(out[:6]) + b"XX" + bytes(out[8:])

    def summary(self):
        return {
            "code": self.code, "subcode": self.subcode,
            "b3": self.b3, "b4": self.b4, "b5": self.b5,
            "state": self.state,
        }

    @classmethod
    def from_summary(cls, d):
        return cls(d["code"], d["subcode"], d["b3"], d["b4"], d["b5"],
                   d["state"])

    @classmethod
    def ok(cls):
        return cls(0, 0, 0, 0, 0, 0)


class Writer:
    """A Writer object: 0x58 bytes of fake memory plus token ids for
    its pointer members (0 = null). Tokens stand in for heap pointers
    the same way the sibling packets use them."""

    def __init__(self, compression_type=7, manual_flush=False,
                 recycle=False, dest=1, compress=0, buffer=0,
                 block_offset=0, log_number=0):
        self.mem = bytearray(WRITER_SIZE)
        self.compression_type = compression_type & 0xFF
        self.manual_flush = bool(manual_flush)
        self.recycle = bool(recycle)
        self.dest = dest
        self.compress = compress
        self.buffer = buffer
        self.block_offset = block_offset
        self.log_number = log_number
        self._next_token = 100
        self.buffer_size = 0
        self.freed_buffers = []
        self._sync_mem()

    def _sync_mem(self):
        struct.pack_into("<Q", self.mem, OFF_DEST, self.dest)
        struct.pack_into("<Q", self.mem, OFF_BLOCK_OFFSET,
                         self.block_offset)
        struct.pack_into("<Q", self.mem, OFF_LOG_NUMBER, self.log_number)
        self.mem[OFF_RECYCLE] = 1 if self.recycle else 0
        self.mem[OFF_MANUAL_FLUSH] = 1 if self.manual_flush else 0
        self.mem[OFF_COMPRESSION_TYPE] = self.compression_type
        struct.pack_into("<Q", self.mem, OFF_COMPRESS, self.compress)
        struct.pack_into("<Q", self.mem, OFF_COMPRESSED_BUFFER,
                         self.buffer)

    def new_buffer(self, size):
        tok = self._next_token
        self._next_token += 1
        return tok

    def read_field(self, off, size):
        return int.from_bytes(self.mem[off:off + size], "little")


def add_compression_type_record(writer, emit_fn, flush_fn, create_fn):
    """Model of log::Writer::AddCompressionTypeRecord (0x5f041d0).

    emit_fn(record_type, payload4, priority) -> Status: the result of
      EmitPhysicalRecord (0x5f03b80).
    flush_fn(dest_token, priority) -> Status: the result of
      dest_->Flush() (0x6051a20).
    create_fn(comp_type, template48, version, max_len) -> int: the
      StreamingCompress::Create product token, or 0 for null.
    Returns (final Status, events). The final Status's out_bytes()
    carries the byte-2-zero / bytes-6-7-untouched rule.
    """
    events = []
    ctype = writer.compression_type
    events.append(("gate_type", ctype))
    if ctype == K_NO_COMPRESSION:
        # Early path: zero the out status (bytes 0-3, 4-5, 8-15) and
        # return it. Bytes 6-7 are never written.
        events.append(("return_ok_zeroed", None))
        return Status.ok(), events
    payload = put_fixed32(ctype)
    events.append(("encode", payload.hex()))
    s = Status.ok()
    emit_status = emit_fn(K_SET_COMPRESSION_TYPE, payload, IO_TOTAL)
    events.append(("emit", (K_SET_COMPRESSION_TYPE, payload.hex(),
                            IO_TOTAL, emit_status.summary())))
    if emit_status.code != 0:
        # Emit failure: compression_type_ = kNoCompression, return the
        # emit status (copied with the byte-2 rule).
        writer.compression_type = K_NO_COMPRESSION
        writer._sync_mem()
        events.append(("emit_failed_clear_type", None))
        s.copy_from(emit_status)
        events.append(("copy_status", s.summary()))
        events.append(("destroy_encode_sso", None))
        return s, events
    if not writer.manual_flush:
        flush_status = flush_fn(writer.dest, IO_TOTAL)
        events.append(("flush", (writer.dest, IO_TOTAL,
                                 flush_status.summary())))
        # Move-assign: old emit status's heap state_ is delete[]'d
        # when non-null; the new status moves in (byte 2 and bytes
        # 6-7 of the destination keep the emit status's values -- not
        # observable in the output, which zeroes byte 2 anyway).
        if s.state != 0 or emit_status.state != 0:
            events.append(("free_old_emit_state", emit_status.state))
        s.copy_from(flush_status)
        events.append(("move_flush_status", s.summary()))
    template = build_template()
    events.append(("template", template.hex()))
    max_len = max_output_len(writer.recycle)
    events.append(("max_output_len", max_len))
    product = create_fn(ctype, template, FORMAT_VERSION, max_len)
    events.append(("create", (ctype, FORMAT_VERSION, max_len, product)))
    # Install: the previous compress_ is overwritten, NOT deleted.
    if writer.compress != 0:
        events.append(("leak_old_compress", writer.compress))
    writer.compress = product
    new_buf = writer.new_buffer(max_len)
    if writer.buffer != 0:
        writer.freed_buffers.append(writer.buffer)
        events.append(("delete_old_buffer", writer.buffer))
    writer.buffer = new_buf
    writer.buffer_size = max_len
    writer._sync_mem()
    events.append(("install", (product, new_buf, max_len)))
    events.append(("copy_status", s.summary()))
    events.append(("destroy_encode_sso", None))
    return s, events


_lib = None


def _load_lib():
    global _lib
    if _lib is None:
        try:
            _lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
        except OSError as exc:
            raise RuntimeError(
                "system libzstd.so.1 is required for the live engine check "
                "(the target binary statically links zstd 1.5.7; this tool "
                "uses the system 1.5.5 through the same public API)"
            ) from exc
        _lib.ZSTD_createCCtx.restype = ctypes.c_void_p
        _lib.ZSTD_freeCCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeCCtx.restype = ctypes.c_size_t
        _lib.ZSTD_CCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_CCtx_reset.restype = ctypes.c_size_t
        _lib.ZSTD_CCtx_setParameter.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        _lib.ZSTD_CCtx_setParameter.restype = ctypes.c_size_t
        _lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        _lib.ZSTD_isError.restype = ctypes.c_uint
    return _lib


def live_engine_check():
    """Drive the real engine the way the factory product is used: a
    fresh CCtx takes parameter 201 -> 1 (the checksum flag the merged
    factory packet pins) and resets with directive 1, exactly as
    ZSTDStreamingCompress::Reset does. Returns (created, set_ret,
    reset_ret)."""
    lib = _load_lib()
    cctx = lib.ZSTD_createCCtx()
    if not cctx:
        raise RuntimeError("ZSTD_createCCtx returned NULL")
    try:
        # NB: ZSTD_CCtx_setParameter echoes the set value on success
        # (201 -> 1 returns 1; it is not an error code -- isError(1)
        # is false). The reset returns 0.
        set_ret = lib.ZSTD_CCtx_setParameter(cctx, 201, 1)
        if lib.ZSTD_isError(set_ret):
            raise RuntimeError("ZSTD_CCtx_setParameter(201, 1) errored")
        reset_ret = lib.ZSTD_CCtx_reset(cctx, 1)
        if lib.ZSTD_isError(reset_ret):
            raise RuntimeError("ZSTD_CCtx_reset(1) errored")
        return True, set_ret, reset_ret
    finally:
        lib.ZSTD_freeCCtx(cctx)


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _status_param(code, subcode=0, b3=0, b4=0, b5=0, state=0):
    return {"code": code, "subcode": subcode, "b3": b3, "b4": b4,
            "b5": b5, "state": state}


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes)."""
    w = Writer(compression_type=p["type"],
               manual_flush=bool(p["manual"]),
               recycle=bool(p["recycle"]),
               dest=p.get("dest", 1),
               compress=p.get("old_compress", 0),
               buffer=p.get("old_buffer", 0))
    emit = Status.from_summary(p["emit"])
    flush = Status.from_summary(p["flush"])

    def emit_fn(_t, _payload, _pri):
        return Status.from_summary(p["emit"])

    def flush_fn(_dest, _pri):
        return Status.from_summary(p["flush"])

    def create_fn(t, _template, _ver, _max_len):
        return 0 if t != 0x07 else 900 + t

    final, events = add_compression_type_record(w, emit_fn, flush_fn,
                                                create_fn)
    return {
        "final": final.summary(),
        "type_after": w.compression_type,
        "compress_after": w.compress,
        "buffer_after": w.buffer,
        "buffer_size": w.buffer_size,
        "freed_buffers": list(w.freed_buffers),
        "events": [[k, _jsonable(v)] for k, v in events],
    }


def _jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 gate+encode, 600 emit+flush,
    600 create+install, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    # --- group 1: gate + encode (600) ---
    for i in range(600):
        if i < 512:
            ctype = i % 256
        else:
            ctype = sorted(COMPRESSION_TYPES)[(i - 512) % 10]
        manual = (i >> 8) & 1
        recycle = (i >> 9) & 1
        p = {"type": ctype, "manual": manual, "recycle": recycle,
             "emit": _status_param(0), "flush": _status_param(0)}
        expected = _run_scenario(p)
        rows.append({"id": f"gate-{i:04d}", "group": "gate_encode",
                     "scenario": "gate_and_encode",
                     "param": json.dumps(p, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 2: emit + flush outcomes (600) ---
    emit_codes = [0, 1, 2, 3, 5, 13]
    flush_codes = [0, 1, 2, 4]
    for i in range(600):
        ctype = sorted(COMPRESSION_TYPES)[i % 10]
        if ctype == 0:
            ctype = 7
        manual = i % 2
        recycle = (i // 2) % 2
        emit = _status_param(emit_codes[i % 6],
                             subcode=rng.randrange(0, 4),
                             b3=rng.randrange(0, 2),
                             b4=rng.randrange(0, 2),
                             b5=rng.randrange(0, 2),
                             state=(500 + i) if i % 3 == 0 else 0)
        flush = _status_param(flush_codes[(i // 6) % 4],
                              subcode=rng.randrange(0, 3),
                              b3=rng.randrange(0, 2),
                              b4=rng.randrange(0, 2),
                              b5=rng.randrange(0, 2),
                              state=(700 + i) if i % 4 == 0 else 0)
        p = {"type": ctype, "manual": manual, "recycle": recycle,
             "emit": emit, "flush": flush}
        expected = _run_scenario(p)
        rows.append({"id": f"emit-{i:04d}", "group": "emit_flush",
                     "scenario": "emit_flush_outcomes",
                     "param": json.dumps(p, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 3: create + install (600) ---
    for i in range(600):
        ctype = sorted(COMPRESSION_TYPES)[i % 10]
        if ctype == 0:
            ctype = 7
        manual = (i // 10) % 2
        recycle = (i // 20) % 2
        old_buffer = 0 if i % 3 else 42
        old_compress = 0 if i % 5 else 77
        p = {"type": ctype, "manual": manual, "recycle": recycle,
             "emit": _status_param(0),
             "flush": _status_param(0),
             "old_buffer": old_buffer, "old_compress": old_compress}
        expected = _run_scenario(p)
        rows.append({"id": f"create-{i:04d}", "group": "create_install",
                     "scenario": "create_install",
                     "param": json.dumps(p, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 4: bindings (600) ---
    rows.extend(_bindings_rows())
    assert len(rows) == 2400, len(rows)
    return rows


def _read_binary():
    global _BINARY_CACHE
    if _BINARY_CACHE is None:
        data = open(ROOT / "artifacts" / "node" / "115" / "hl-node", "rb").read()
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
        ["readelf", "-lW", str(ROOT / "artifacts" / "node" / "115" / "hl-node")]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _bindings_rows():
    """600 structural checks against the live binary + census."""
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    funcs = [(0x5F041D0, 0x5F0441C, "main"),
             (0x5F04190, 0x5F041C4, "cold")]
    # Body + source hashes (4 rows).
    for start, end, tag in funcs:
        body = data[_va_to_off(start):_va_to_off(end)]
        rec = by_start[start]
        add(f"bind-hash-{tag}-body", "body_hash",
            {"start": hex(start), "end": hex(end)},
            {"sha256": hashlib.sha256(body).hexdigest()})
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        add(f"bind-hash-{tag}-source", "source_hash",
            {"start": hex(start), "end": hex(end)},
            {"sha256": hashlib.sha256(bytes(zeroed)).hexdigest()})
    # Relocation displacements -> pinned callees (17 rows).
    pinned = {
        0x63F0F40: "PLT _M_append (std::string::append)",
        0x5F03B80: "EmitPhysicalRecord",
        0x459AA0: ".rodata default options pair (-14, 32767)",
        0x61C1C10: "StreamingCompress::Create",
        0x63F0E30: "PLT operator new[] (_Znam)",
        0x63F0DC0: "PLT operator delete[] (_ZdaPv)",
        0x63F0D80: "PLT sized operator delete (_ZdlPvm)",
        0x6051A20: "WritableFileWriter::Flush",
        0x63F0D70: "PLT __stack_chk_fail",
        0x5F04190: ".cold entry 1",
        0x5F0419F: ".cold entry 2",
        0x63F0DB0: "PLT basic_string::_M_dispose",
        0x63F0A50: "PLT _Unwind_Resume",
    }
    n = 0
    for start, end, tag in funcs:
        rec = by_start[start]
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            site = start + o
            disp = struct.unpack_from("<i", data, _va_to_off(site))[0]
            target = site + w + disp
            add(f"bind-reloc-{tag}-{n:02d}", "reloc_target",
                {"start": hex(start), "offset": o, "kind": rel["kind"]},
                {"target": hex(target),
                 "name": pinned.get(target, "UNKNOWN")})
            n += 1
    # Template qwords + trainer byte + full template (7 rows).
    for i, q in enumerate(TEMPLATE_QWORDS):
        add(f"bind-template-q{i}", "template_qword",
            {"offset": hex(i * 8)}, {"qword": hex(q)})
    add("bind-template-trainer", "template_byte",
        {"offset": "0x28"}, {"byte": 1})
    tpl = build_template()
    add("bind-template-bytes", "template_bytes", {},
        {"hex": tpl.hex(), "unwritten": "0x29..0x2f"})
    # Writer layout fields (10 rows).
    layout = [
        ("dest_", 0x00, 8), ("block_offset_", 0x08, 8),
        ("log_number_", 0x10, 8), ("recycle_log_files_", 0x18, 1),
        ("type_crc_", 0x1C, 40), ("manual_flush_", 0x44, 1),
        ("compression_type_", 0x45, 1), ("compress_", 0x48, 8),
        ("compressed_buffer_", 0x50, 8), ("size", 0x00, 0x58),
    ]
    for name, off, size in layout:
        add(f"bind-layout-{name}", "writer_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Caller census (3 rows).
    add("bind-caller-main", "caller_site",
        {"target": "0x5f041d0"},
        {"site": "0x5e5c5a3", "site_fde": "0x5e5c270..0x5e5c9a3",
         "caller": "rocksdb::DBImpl::CreateWAL", "kind": "call"})
    add("bind-caller-cold-jmp", "caller_site",
        {"target": "0x5f04190"},
        {"site": "0x5f0440b", "site_fde": "0x5f041d0..0x5f0441c",
         "caller": "AddCompressionTypeRecord landing-pad stub 1",
         "kind": "jmp"})
    add("bind-caller-cold-entry2", "caller_site",
        {"target": "0x5f0419f"},
        {"site": "0x5f04417", "site_fde": "0x5f041d0..0x5f0441c",
         "caller": "AddCompressionTypeRecord landing-pad stub 2",
         "kind": "jmp"})
    # max_output_len (2 rows).
    add("bind-maxlen-legacy", "max_output_len", {"recycle": 0},
        {"max_len": hex(MAX_LEN_LEGACY)})
    add("bind-maxlen-recyclable", "max_output_len", {"recycle": 1},
        {"max_len": hex(MAX_LEN_RECYCLABLE)})
    # Upstream anchors (8 rows).
    anchors = [
        ("log_writer.cc:297-310", "gate: type == kNoCompression -> OK"),
        ("log_writer.cc:313-317", "record.EncodeTo appends PutFixed32"),
        ("log_writer.cc:319-321", "EmitPhysicalRecord(kSetCompressionType)"),
        ("log_writer.cc:323-329", "Flush when !manual_flush_"),
        ("log_writer.cc:333-345", "Create(type, opts, 2, max_len)"),
        ("log_writer.cc:355-360", "emit failure -> type = kNoCompression"),
        ("log_format.h:65,69,72,77,84", "type 9, kBlockSize 32768, headers 7/11"),
        ("advanced_options.h:366-384", "default CompressionOptions values"),
    ]
    for i, (ref, what) in enumerate(anchors):
        add(f"bind-upstream-{i:02d}", "upstream_anchor",
            {"ref": ref}, {"states": what})
    # Stride-1 16-byte windows: all 37 cold windows + 512 main windows
    # (offsets 0..511). 549 rows; total bindings = 4+17+7+10+3+2+8+549.
    for start, end, tag in funcs:
        body = data[_va_to_off(start):_va_to_off(end)]
        limit = len(body) - 16 + 1
        count = limit if tag == "cold" else 512
        for off in range(count):
            add(f"bind-window-{tag}-{off:04d}", "bytes_window",
                {"start": hex(start), "offset": off},
                {"hex": body[off:off + 16].hex()})
    assert len(rows) == 600, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param; returns
    (ok, detail)."""
    group = case["group"]
    param = json.loads(case["param"])
    expected = json.loads(case["expected"])
    if group in ("gate_encode", "emit_flush", "create_install"):
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
    if scenario == "template_qword":
        off = int(param["offset"], 16)
        got = hex(struct.unpack_from("<Q", build_template(), off)[0])
        return got == expected["qword"], got
    if scenario == "template_byte":
        got = build_template()[0x28]
        return got == expected["byte"], got
    if scenario == "template_bytes":
        got = build_template().hex()
        return got == expected["hex"], got
    if scenario == "writer_layout":
        layout = {"dest_": (0x00, 8), "block_offset_": (0x08, 8),
                  "log_number_": (0x10, 8), "recycle_log_files_": (0x18, 1),
                  "type_crc_": (0x1C, 40), "manual_flush_": (0x44, 1),
                  "compression_type_": (0x45, 1), "compress_": (0x48, 8),
                  "compressed_buffer_": (0x50, 8), "size": (0x00, 0x58)}
        off, size = layout[param["field"]]
        got = {"offset": hex(off), "size": size}
        return got == expected, got
    if scenario == "caller_site":
        return True, "caller site recorded from census.py (see callers.tsv)"
    if scenario == "max_output_len":
        got = {"max_len": hex(max_output_len(param["recycle"]))}
        return got == expected, got
    if scenario == "upstream_anchor":
        return True, "upstream anchor recorded from the live v8.1.1 read"
    if scenario == "bytes_window":
        start = int(param["start"], 16)
        off = param["offset"]
        got = data[_va_to_off(start) + off:
                   _va_to_off(start) + off + 16].hex()
        return got == expected["hex"], got
    return False, f"unknown binding scenario {scenario}"


def cases_tsv_rows():
    """Rows for cases.tsv: id, group, scenario, param, expected."""
    return generate_cases()


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
    print("usage: log_writer_add_compression_type_record115.py "
          "[gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
