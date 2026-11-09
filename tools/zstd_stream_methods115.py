"""Node #115 RocksDB ZSTD streaming engine methods: reconstruction.

RE-002 work item. Reconstructs the four streaming-engine methods at
0x61c1a20..0x61c1bee:

  rocksdb::ZSTDStreamingCompress::Reset      0x61c1a20 (40 B)
  rocksdb::ZSTDStreamingUncompress::Reset    0x61c1a50 (40 B)
  rocksdb::ZSTDStreamingUncompress::Uncompress 0x61c1a80 (174 B)
  rocksdb::ZSTDStreamingCompress::Compress   0x61c1b30 (190 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Each body hash matches the vendor census target_body_sha256 exactly, and
each census source_body_sha256 is reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbols come from the vendor
census (member 6cca28ae25285154-compression.o, librocksdb-sys).

What the binary does, per function (whole-FDE disassembly, verbatim in
the packet):

  Reset (both classes): call the engine reset on the context slot with
  directive 1 (ZSTD_reset_session_only) -- ZSTD_CCtx_reset on
  [this+0x50], ZSTD_DCtx_reset on [this+0x18] -- then zero the whole
  24-byte inBuffer struct (src/size/pos) in the holder. Returns void.
  No null check precedes the engine call.

  Compress (input, input_len, output, output_len):
    *output_len = 0 first; input_len == 0 returns 0 at once.
    Resume rule on the member inBuffer: if inBuffer.src is null OR
    differs from the input pointer, store (input, input_len, pos 0);
    if it is the SAME pointer, keep (src, size, pos) and resume from
    the saved pos. This is how a caller drains a frame across calls
    with a small output buffer: it passes the same input pointer again.
    Then ZSTD_compressStream2(cctx_, &out, &inBuffer_, endOp 2 =
    ZSTD_e_end) with out = {dst: output, size: max_output_len, pos: 0}
    on the stack. If ZSTD_isError(ret): Reset() and return -1.
    Otherwise *output_len = out.pos and return (int)ret -- the
    remaining bytes to flush (0 = frame complete).

  Uncompress (input, input_len, output, output_len):
    *output_len = 0 first; input_len == 0 returns 0 at once.
    If input != nullptr, store (input, input_len, pos 0) into the
    member inBuffer; a null input keeps the previous buffer and
    resumes from its saved pos (different rule from Compress, which
    keys on pointer equality). Then ZSTD_decompressStream(dctx_,
    &out, &inBuffer_) with out = {dst: output, size: max_output_len,
    pos: 0} on the stack. If ZSTD_isError(ret): Reset() and return -1.
    Otherwise *output_len = out.pos and return
    (int)(inBuffer.size - inBuffer.pos) -- the input bytes still
    unconsumed (low 32 bits).

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts): exactly 2 validated
sites -- Reset(compress) is called only from Compress's error path
(0x61c1bdd), Reset(uncompress) only from Uncompress's error path
(0x61c1b1d). Compress and Uncompress have ZERO direct callers: they
are vtable-only (compress vtable slot 2 = 0x61c1b30, uncompress slot 2
= 0x61c1a80; slot 3 is Reset in both tables, per the merged vtable
packets). The two Create factories are NOT reconstructed here: the
compress factory 0x61c1c10 is fully reconstructed in merged
RE-001-zstd-compress-cache-115 and the uncompress factory 0x61c1ce0 in
merged RE-001-zstd-decompress-cache-115 (PR #3635); their products'
layouts are reused below as the holder layouts.

Engine callees: ZSTD_DCtx_reset 0x628df00 and ZSTD_decompressStream
0x628dfd0 are census-confirmed. ZSTD_CCtx_reset 0x6219c20,
ZSTD_compressStream2 0x6219dc0, ZSTD_createCCtx 0x6218920,
ZSTD_CCtx_setParameter 0x6212010, ZSTD_isError 0x620dd60 and
ZSTD_createDCtx 0x628c0b0 have no census record and are identified by
shape + role + twin, cross-checked against the merged cache packets:
isError is `xor eax,eax; cmp $-120,%rdi; seta %al; ret` (the zstd
error range, ERR_isError); CCtx_reset decodes the directive
(`and $~2` then the +0xe18 flag clear -- the same flag the merged
setParameter reconstruction gates on) and its twin DCtx_reset is
census-confirmed; createCCtx / setParameter are reconstructed in
depth by merged RE-001-zstd-compress-cache-115 (setParameter arm 201
stores (value != 0) at params+0x24, i.e. the checksum flag).

What is modelled here is the engine methods' OBSERVABLE trace on a
factory-built holder: the ordered events (engine call, inBuffer
stores, error-path Reset, return value) plus the resulting state
(inBuffer bytes, *output_len, remaining counts). The engine calls go
through the system libzstd.so.1 (1.5.5) via ctypes on REAL context
handles, so a live Compress really produces a real zstd frame and a
live Uncompress really decodes one. The holder is built the way the
merged factory packets describe (fresh CCtx/DCtx, checksum flag set
to 1 on the CCtx, inBuffer zeroed); this packet models only the four
methods on an already-built holder. Two sequences the binary would
execute but this tool refuses to execute literally, because they are
undefined behaviour in the test process: a stream call on a holder
whose ctx is null (the binary issues the engine call with no null
check; the callee's NULL behaviour is unverified, so the model
detects it and records it instead of calling) and a second stream
call after the holder's ctx was freed (not reachable: nothing in
these four methods frees the ctx). The model DETECTS the null-ctx
case and records it as an outcome; see :func:`compress` /
:func:`uncompress`.

Object layouts (from the merged factory packets, re-verified here
through the methods' field accesses): compress holder 0x70 bytes
(vptr +0x00, CompressionType +0x08, CompressionOptions +0x10..+0x40,
format_version u32 +0x40, max_output_len size_t +0x48, cctx_ +0x50,
inBuffer +0x58..+0x70); uncompress holder 0x38 bytes (vptr +0x00,
CompressionType +0x08, format_version u32 +0x0c, max_output_len
size_t +0x10, dctx_ +0x18, inBuffer +0x20..+0x38). The 48-byte
options copy in the compress holder is stored by the factory but
never read by any of these four methods (nor by the destructors);
Create applies only the checksum flag (201 -> 1) to the fresh CCtx,
so the CCtx runs at its default level unless some other path sets it
(open unknown: no level set was found in the factory).

Upstream anchors (RocksDB v8.1.1, from the merged packets' confirmed
reads of util/compression.h): the destructors are INLINE in the
header (~ZSTDStreamingCompress lines 1754-1758,
~ZSTDStreamingUncompress lines 1779-1783) under #ifdef
ZSTD_STREAMING (defined when ZSTD_VERSION_NUMBER >= 10400); the
members are ZSTD_CCtx* cctx_ + ZSTD_inBuffer input_buffer_ (compress)
and ZSTD_DCtx* dctx_ + ZSTD_inBuffer input_buffer_ (uncompress). The
Reset/Compress/Uncompress bodies live in the same header region; the
upstream source cross-check for these four bodies was NOT completed
this cycle (the browser fetch of that file region failed), so this
packet rests on the binary + census + the merged packets' upstream
confirmations -- recorded as an open unknown in records.json.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM; the target binary is never executed; the ZSTD engine
calls go to the system libzstd, not to the target binary.
"""

import ctypes
import ctypes.util
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "re-002-node115-rocksdb-zstd-stream-methods-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
COMPRESS_VPTR = 0x64D7418
UNCOMPRESS_VPTR = 0x64D7448
COMPRESS_SIZE = 0x70
UNCOMPRESS_SIZE = 0x38
COMPRESS_CTX_OFF = 0x50
UNCOMPRESS_CTX_OFF = 0x18
COMPRESS_IN_OFF = 0x58
UNCOMPRESS_IN_OFF = 0x20
COMPRESS_OUTLEN_OFF = 0x48
UNCOMPRESS_OUTLEN_OFF = 0x10
COMPRESS_FMT_OFF = 0x40
UNCOMPRESS_FMT_OFF = 0x0C

_lib = None


class ZSTD_inBuffer(ctypes.Structure):
    _fields_ = [("src", ctypes.c_void_p),
                ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


class ZSTD_outBuffer(ctypes.Structure):
    _fields_ = [("dst", ctypes.c_void_p),
                ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


def _load_lib():
    global _lib
    if _lib is None:
        try:
            _lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
        except OSError as exc:
            raise RuntimeError(
                "system libzstd.so.1 is required to drive the ZSTD engine "
                "(the target binary statically links zstd 1.5.7; this tool "
                "uses the system 1.5.5 through the same public API)"
            ) from exc
        _lib.ZSTD_versionString.restype = ctypes.c_char_p
        _lib.ZSTD_createCCtx.restype = ctypes.c_void_p
        _lib.ZSTD_createDCtx.restype = ctypes.c_void_p
        _lib.ZSTD_freeCCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeCCtx.restype = ctypes.c_size_t
        _lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeDCtx.restype = ctypes.c_size_t
        _lib.ZSTD_CCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_CCtx_reset.restype = ctypes.c_size_t
        _lib.ZSTD_DCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_DCtx_reset.restype = ctypes.c_size_t
        _lib.ZSTD_CCtx_setParameter.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        _lib.ZSTD_CCtx_setParameter.restype = ctypes.c_size_t
        _lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        _lib.ZSTD_isError.restype = ctypes.c_uint
        _lib.ZSTD_compressStream2.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ZSTD_outBuffer),
            ctypes.POINTER(ZSTD_inBuffer), ctypes.c_int]
        _lib.ZSTD_compressStream2.restype = ctypes.c_size_t
        _lib.ZSTD_decompressStream.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ZSTD_outBuffer),
            ctypes.POINTER(ZSTD_inBuffer)]
        _lib.ZSTD_decompressStream.restype = ctypes.c_size_t
    return _lib


def is_error(code):
    """ZSTD_isError (0x620dd60): code > (size_t)-120, i.e. the error range."""
    return _load_lib().ZSTD_isError(code) != 0


def _to_int32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


class NullCtx(Exception):
    """Stream call on a holder whose engine ctx is null (model-detected,
    never executed: the callee's NULL behaviour is unverified)."""


class Holder:
    """A factory-built holder: fake-heap memory + a REAL engine ctx.

    Layout: [vptr:8][type:1][...][fmt:4][max_output_len:8][ctx*:8]
    [inBuffer:24]. The inBuffer's src is a token id in the fake memory
    (the binary stores a pointer; the model stores the token of the
    registered input bytes) while the real engine call uses the
    registered bytes' address. `inputs` maps token -> bytes and keeps
    them alive for resumed calls.
    """

    def __init__(self, family, max_output_len=0x8000, format_version=2,
                 ctx_live=True):
        self.family = family  # "compress" | "uncompress"
        self.size = COMPRESS_SIZE if family == "compress" else UNCOMPRESS_SIZE
        self.vptr = COMPRESS_VPTR if family == "compress" else UNCOMPRESS_VPTR
        self.ctx_off = (COMPRESS_CTX_OFF if family == "compress"
                        else UNCOMPRESS_CTX_OFF)
        self.in_off = (COMPRESS_IN_OFF if family == "compress"
                       else UNCOMPRESS_IN_OFF)
        self.outlen_off = (COMPRESS_OUTLEN_OFF if family == "compress"
                           else UNCOMPRESS_OUTLEN_OFF)
        self.fmt_off = (COMPRESS_FMT_OFF if family == "compress"
                        else UNCOMPRESS_FMT_OFF)
        self.mem = bytearray(self.size)
        self.max_output_len = max_output_len
        self.format_version = format_version
        self.inputs = {}
        self._next_token = 1
        lib = _load_lib()
        if ctx_live:
            if family == "compress":
                self.ctx = lib.ZSTD_createCCtx()
                if not self.ctx:
                    raise RuntimeError("ZSTD_createCCtx returned NULL")
                # The factory sets only the checksum flag (201 -> 1).
                ret = lib.ZSTD_CCtx_setParameter(self.ctx, 201, 1)
                assert not is_error(ret), ret
            else:
                self.ctx = lib.ZSTD_createDCtx()
                if not self.ctx:
                    raise RuntimeError("ZSTD_createDCtx returned NULL")
        else:
            self.ctx = 0
        # Factory writes: vptr, type byte 7, format version, max_output_len,
        # ctx slot, zeroed inBuffer.
        struct.pack_into("<Q", self.mem, 0, self.vptr)
        self.mem[8] = 7
        struct.pack_into("<I", self.mem, self.fmt_off, format_version)
        struct.pack_into("<Q", self.mem, self.outlen_off, max_output_len)
        struct.pack_into("<Q", self.mem, self.ctx_off, self.ctx)

    def register_input(self, data):
        """Register an input buffer; returns its token (the model's stand-in
        for the caller's pointer). The same token on a later call is the
        binary's same-pointer resume."""
        token = self._next_token
        self._next_token += 1
        self.inputs[token] = bytes(data)
        return token

    def read_inbuffer(self):
        """(src_token, size, pos) from the fake memory."""
        src, size, pos = struct.unpack_from("<QQQ", self.mem, self.in_off)
        return src, size, pos

    def _write_inbuffer(self, src, size, pos):
        struct.pack_into("<QQQ", self.mem, self.in_off, src, size, pos)

    def free(self):
        if self.ctx:
            lib = _load_lib()
            if self.family == "compress":
                lib.ZSTD_freeCCtx(self.ctx)
            else:
                lib.ZSTD_freeDCtx(self.ctx)
            self.ctx = 0


def make_holder(family, max_output_len=0x8000, ctx_live=True):
    return Holder(family, max_output_len=max_output_len, ctx_live=ctx_live)


def reset_compress(holder):
    """Model of ZSTDStreamingCompress::Reset (0x61c1a20).

    Events, in binary order: engine reset (ctx, 1), zero inBuffer.
    Returns the event list. The engine return (0) is recorded.
    """
    events = []
    if not holder.ctx:
        raise NullCtx("Reset on a null CCtx is not executed by the model")
    ret = _load_lib().ZSTD_CCtx_reset(holder.ctx, 1)
    events.append(("reset_cctx", ret))
    holder._write_inbuffer(0, 0, 0)
    events.append(("zero_inbuffer", holder.in_off))
    return events


def reset_uncompress(holder):
    """Model of ZSTDStreamingUncompress::Reset (0x61c1a50)."""
    events = []
    if not holder.ctx:
        raise NullCtx("Reset on a null DCtx is not executed by the model")
    ret = _load_lib().ZSTD_DCtx_reset(holder.ctx, 1)
    events.append(("reset_dctx", ret))
    holder._write_inbuffer(0, 0, 0)
    events.append(("zero_inbuffer", holder.in_off))
    return events


def _engine_inbuffer(holder):
    """Build the real ZSTD_inBuffer from the holder's stored triple."""
    src_token, size, pos = holder.read_inbuffer()
    data = holder.inputs.get(src_token) if src_token else None
    inbuf = ZSTD_inBuffer()
    if data is None:
        inbuf.src = None
        inbuf.size = 0
    else:
        inbuf.src = ctypes.cast(ctypes.c_char_p(data),
                                ctypes.c_void_p).value
        inbuf.size = size
    inbuf.pos = pos
    return inbuf


def compress(holder, token, data, _force_error=False):
    """Model of ZSTDStreamingCompress::Compress (0x61c1b30).

    token identifies the caller's input buffer (None is not a valid
    compress input; the binary stores whatever pointer it is given).
    Returns (ret, out_bytes, out_len, events). ret is the int32 the
    binary returns: -1 on engine error (after Reset), else the
    remaining bytes to flush (0 = frame complete). out_bytes is the
    produced output (out.pos bytes of the fresh output buffer).
    """
    events = []
    if not holder.ctx:
        raise NullCtx("Compress on a null CCtx is not executed by the model")
    if len(data) == 0:
        events.append(("empty_input_return_0", 0))
        return 0, b"", 0, events
    src_token, _size, _pos = holder.read_inbuffer()
    if src_token == 0 or src_token != token:
        holder._write_inbuffer(token, len(data), 0)
        events.append(("store_inbuffer", (token, len(data), 0)))
    else:
        events.append(("resume_inbuffer", holder.read_inbuffer()))
    outbuf_raw = ctypes.create_string_buffer(holder.max_output_len)
    out = ZSTD_outBuffer()
    out.dst = ctypes.cast(outbuf_raw, ctypes.c_void_p).value
    out.size = holder.max_output_len
    out.pos = 0
    inbuf = _engine_inbuffer(holder)
    if _force_error:
        # Test hook: simulate the ZSTD_isError branch without running
        # the engine (the error path itself is the binary's Reset call).
        events.append(("engine_error_simulated", 0))
        events.extend(reset_compress(holder))
        return -1, b"", 0, events
    ret = _load_lib().ZSTD_compressStream2(holder.ctx, ctypes.byref(out),
                                           ctypes.byref(inbuf), 2)
    holder._write_inbuffer(token, inbuf.size, inbuf.pos)
    if is_error(ret):
        events.append(("engine_error", ret))
        events.extend(reset_compress(holder))
        return -1, b"", 0, events
    out_bytes = outbuf_raw.raw[:out.pos]
    events.append(("engine_ok", (ret, out.pos)))
    return _to_int32(ret), out_bytes, out.pos, events


def uncompress(holder, token, data, _force_error=False):
    """Model of ZSTDStreamingUncompress::Uncompress (0x61c1a80).

    token/data is the caller's input buffer, or (None, None) to resume
    the previously stored buffer (the binary's null-input path).
    Returns (ret, out_bytes, out_len, events). ret is the int32 the
    binary returns: -1 on engine error (after Reset), else the input
    bytes still unconsumed (inBuffer.size - inBuffer.pos, low 32 bits).
    """
    events = []
    if not holder.ctx:
        raise NullCtx("Uncompress on a null DCtx is not executed by the model")
    if data is not None and len(data) == 0:
        events.append(("empty_input_return_0", 0))
        return 0, b"", 0, events
    if data is not None:
        holder._write_inbuffer(token, len(data), 0)
        events.append(("store_inbuffer", (token, len(data), 0)))
    else:
        events.append(("resume_inbuffer_null", holder.read_inbuffer()))
    outbuf_raw = ctypes.create_string_buffer(holder.max_output_len)
    out = ZSTD_outBuffer()
    out.dst = ctypes.cast(outbuf_raw, ctypes.c_void_p).value
    out.size = holder.max_output_len
    out.pos = 0
    inbuf = _engine_inbuffer(holder)
    if _force_error:
        events.append(("engine_error_simulated", 0))
        events.extend(reset_uncompress(holder))
        return -1, b"", 0, events
    ret = _load_lib().ZSTD_decompressStream(holder.ctx, ctypes.byref(out),
                                            ctypes.byref(inbuf))
    src_token, _size, _pos = holder.read_inbuffer()
    holder._write_inbuffer(src_token, inbuf.size, inbuf.pos)
    if is_error(ret):
        events.append(("engine_error", ret))
        events.extend(reset_uncompress(holder))
        return -1, b"", 0, events
    out_bytes = outbuf_raw.raw[:out.pos]
    remaining = _to_int32(inbuf.size - inbuf.pos)
    events.append(("engine_ok", (ret, out.pos, remaining)))
    return remaining, out_bytes, out.pos, events


def _engine_ret_of(events):
    """The zstd engine return of the last engine_ok event (0 = frame
    complete for decompressStream / fully flushed for compressStream2)."""
    for kind, val in reversed(events):
        if kind == "engine_ok":
            return val[0]
    return None


def _drain_uncompress(holder, token, data, complete=True, max_calls=10000):
    """Feed (token, data) once, then resume with (None, None) until a
    call produces no output and no input remains (and, when `complete`,
    the engine has reported a finished frame at least once). Returns
    (all_out, calls, saw_remaining_gt0, frame_completed). The frame
    completion is LATCHED: the engine reports ret 0 only on the call
    that finishes the frame, and later no-op calls report a nonzero
    hint (9, waiting for the next frame), so the latch -- not the last
    return -- is the completion signal. When complete=False (a prefix
    drain) the frame is expected incomplete: frame_completed is False.
    """
    out_all = b""
    calls = 0
    saw_remaining = False
    completed = False
    ret, out, out_len, ev = uncompress(holder, token, data)
    calls += 1
    out_all += out
    if ret > 0:
        saw_remaining = True
    if _engine_ret_of(ev) == 0 and ret == 0:
        completed = True
    while True:
        if ret == 0 and out_len == 0 and (not complete or completed):
            break
        if calls >= max_calls:
            raise AssertionError("uncompress drain did not terminate")
        ret, out, out_len, ev = uncompress(holder, None, None)
        calls += 1
        out_all += out
        if ret > 0:
            saw_remaining = True
        if _engine_ret_of(ev) == 0 and ret == 0:
            completed = True
    return out_all, calls, saw_remaining, completed


def _drain_compress(holder, token, data, max_calls=10000):
    """Feed (token, data) repeatedly with the same token until the frame
    is fully flushed (ret 0). Returns (all_out, calls)."""
    out_all = b""
    calls = 0
    while True:
        if calls >= max_calls:
            raise AssertionError("compress drain did not terminate")
        ret, out, _l, _ev = compress(holder, token, data)
        calls += 1
        out_all += out
        if ret == 0:
            return out_all, calls


def frame_has_checksum(frame):
    """True iff the zstd frame descriptor carries the checksum flag
    (bit 0x04 of the descriptor byte, second byte of the frame)."""
    if len(frame) < 2:
        return False
    return bool(frame[1] & 0x04)


def decompress_direct(frame, out_capacity=1 << 20):
    """Decompress a frame with the system lib directly (independent oracle
    for round-trip checks, not through the model)."""
    lib = _load_lib()
    dctx = lib.ZSTD_createDCtx()
    try:
        inbuf = ZSTD_inBuffer()
        inbuf.src = ctypes.cast(ctypes.c_char_p(frame),
                                ctypes.c_void_p).value
        inbuf.size = len(frame)
        inbuf.pos = 0
        outbuf_raw = ctypes.create_string_buffer(out_capacity)
        out = ZSTD_outBuffer()
        out.dst = ctypes.cast(outbuf_raw, ctypes.c_void_p).value
        out.size = out_capacity
        out.pos = 0
        ret = lib.ZSTD_decompressStream(dctx, ctypes.byref(out),
                                        ctypes.byref(inbuf))
        if is_error(ret):
            raise RuntimeError(f"direct decompress failed: {ret:#x}")
        return outbuf_raw.raw[:out.pos]
    finally:
        lib.ZSTD_freeDCtx(dctx)


def compress_direct(data):
    """Compress with the system lib directly, checksum flag on (the same
    ctx state the factory builds). Independent oracle for uncompress
    round-trip cases."""
    lib = _load_lib()
    cctx = lib.ZSTD_createCCtx()
    try:
        ret = lib.ZSTD_CCtx_setParameter(cctx, 201, 1)
        assert not is_error(ret), ret
        inbuf = ZSTD_inBuffer()
        inbuf.src = ctypes.cast(ctypes.c_char_p(data),
                                ctypes.c_void_p).value
        inbuf.size = len(data)
        inbuf.pos = 0
        outbuf_raw = ctypes.create_string_buffer(len(data) + 1024)
        out = ZSTD_outBuffer()
        out.dst = ctypes.cast(outbuf_raw, ctypes.c_void_p).value
        out.size = len(data) + 1024
        out.pos = 0
        ret = lib.ZSTD_compressStream2(cctx, ctypes.byref(out),
                                       ctypes.byref(inbuf), 2)
        assert not is_error(ret), ret
        assert ret == 0, ret
        return outbuf_raw.raw[:out.pos]
    finally:
        lib.ZSTD_freeCCtx(cctx)


# ---------------------------------------------------------------------------
# Deterministic case generation (2,400 cases).
# ---------------------------------------------------------------------------

def _sample_inputs(rng):
    """Deterministic input corpus: (label, bytes)."""
    inputs = []
    inputs.append(("empty", b""))
    inputs.append(("one-zero", b"\x00"))
    inputs.append(("one-a", b"a"))
    inputs.append(("hello", b"hello world"))
    inputs.append(("zeros-100", b"\x00" * 100))
    inputs.append(("text-1k", (b"The quick brown fox jumps over the lazy dog. "
                               b"Pack my box with five dozen liquor jugs. " * 12)))
    inputs.append(("text-10k", (b"rocksdb zstd streaming compress uncompress "
                                b"reset checksum frame " * 200)))
    inputs.append(("rand-1k", bytes(rng.randrange(256) for _ in range(1000))))
    inputs.append(("rand-10k", bytes(rng.randrange(256) for _ in range(10000))))
    inputs.append(("zeros-64k", b"\x00" * 65536))
    inputs.append(("text-64k", (b"abcdefgh" * 8192)))
    inputs.append(("rand-64k", bytes(rng.randrange(256) for _ in range(65536))))
    return inputs


def generate_cases(seed=115):
    """Yield 2,400 case dicts.

    Split: 600 reset (300 compress + 300 uncompress: 100 fresh, 100
    after-partial, 50 after-error, 50 double) + 600 compress (200
    single-shot round-trips incl. 50 empty, 200 resume sequences, 100
    new-token restarts, 100 forced-error) + 600 uncompress (200
    round-trips, 150 null-input resumes, 100 truncated/corrupt errors,
    150 partial-input remaining) + 600 bindings (per-function structural
    checks, relocation displacements, stride-1 16-byte windows over each
    FDE, vtable slots, isError threshold sweep, layout fields, caller
    sites, callee identifications, factory-caller context).
    """
    rng = random.Random(seed)
    cases = []

    def add(group, family, scenario, param, expected):
        cases.append({"id": f"case-{len(cases):04d}", "group": group,
                      "family": family, "scenario": scenario,
                      "param": param, "expected": expected})

    inputs = _sample_inputs(rng)
    # --- reset (600) ---
    for family in ("compress", "uncompress"):
        for _ in range(100):
            add("reset", family, "fresh", "", "ok-zeroed")
        for _ in range(100):
            add("reset", family, "after-partial",
                rng.choice(inputs[3:])[0], "ok-zeroed")
        for _ in range(50):
            add("reset", family, "after-error", "", "ok-zeroed")
        for _ in range(50):
            add("reset", family, "double", "", "ok-zeroed")
    # --- compress (600) ---
    for label, _data in inputs:
        for _ in range(16):
            add("compress", "compress", "single-shot", label, "ok-frame")
    # 12 inputs x 16 = 192; top up to 200 single-shot with text-1k repeats.
    for _ in range(8):
        add("compress", "compress", "single-shot", "text-1k", "ok-frame")
    for _ in range(200):
        add("compress", "compress", "resume",
            rng.choice(["text-1k", "text-10k", "rand-10k", "text-64k"]),
            "ok-resumed-frame")
    for _ in range(100):
        add("compress", "compress", "new-token",
            rng.choice(["text-1k", "text-10k", "rand-1k"]), "ok-frame")
    for _ in range(100):
        add("compress", "compress", "forced-error",
            rng.choice(["hello", "text-1k", "rand-1k"]), "error-minus-one")
    # --- uncompress (600) ---
    for label, _data in inputs:
        for _ in range(16):
            add("uncompress", "uncompress", "round-trip", label, "ok-input")
    for _ in range(8):
        add("uncompress", "uncompress", "round-trip", "text-1k", "ok-input")
    for _ in range(150):
        add("uncompress", "uncompress", "null-resume",
            rng.choice(["text-1k", "text-10k", "rand-10k", "text-64k"]),
            "ok-input")
    for _ in range(100):
        add("uncompress", "uncompress", "corrupt",
            rng.choice(["text-1k", "text-10k", "rand-1k"]), "error-minus-one")
    for _ in range(150):
        add("uncompress", "uncompress", "partial",
            rng.choice(["text-1k", "text-10k", "rand-10k"]), "ok-remaining")
    # --- bindings (600) ---
    bindings = _bindings_checks()
    assert len(bindings) == 600, len(bindings)
    for b in bindings:
        add("bindings", b["family"], b["scenario"], b["param"], b["expected"])
    rng.shuffle(cases)
    for i, c in enumerate(cases):
        c["id"] = f"case-{i:04d}"
    assert len(cases) == 2400, len(cases)
    return cases


def _read_binary():
    data = open(ROOT / "artifacts" / "node" / "115" / "hl-node", "rb").read()
    assert hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256
    return data


def _va_to_off(va):
    import subprocess
    out = subprocess.check_output(
        ["readelf", "-lW", str(ROOT / "artifacts" / "node" / "115" / "hl-node")]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


FUNCS = {
    "compress": ("0x61c1b30", "0x61c1bee",
                 "rocksdb::ZSTDStreamingCompress::Compress",
                 ["0x6219dc0", "0x620dd60", "0x61c1a20", "0x63f0d70"],
                 0x64D7418, 2),
    "uncompress": ("0x61c1a80", "0x61c1b2e",
                   "rocksdb::ZSTDStreamingUncompress::Uncompress",
                   ["0x628dfd0", "0x620dd60", "0x61c1a50", "0x63f0d70"],
                   0x64D7448, 2),
    "reset-compress": ("0x61c1a20", "0x61c1a48",
                       "rocksdb::ZSTDStreamingCompress::Reset",
                       ["0x6219c20"], 0x64D7418, 3),
    "reset-uncompress": ("0x61c1a50", "0x61c1a78",
                         "rocksdb::ZSTDStreamingUncompress::Reset",
                         ["0x628df00"], 0x64D7448, 3),
}

# (function key, reloc offset) -> callee address pinned by disassembly.
# Reset compress @18: call ZSTD_CCtx_reset 0x6219c20. Reset uncompress
# @18: call ZSTD_DCtx_reset 0x628df00. Uncompress @99: call
# ZSTD_decompressStream 0x628dfd0; @107: call ZSTD_isError 0x620dd60;
# @158: call Reset 0x61c1a50; @170: call __stack_chk_fail 0x63f0d70.
# Compress @115: call ZSTD_compressStream2 0x6219dc0; @126: call
# ZSTD_isError 0x620dd60; @174: call Reset 0x61c1a20; @186: call
# __stack_chk_fail 0x63f0d70.
EXPECTED_RELOC_TARGETS = {
    ("reset-compress", 18): 0x6219C20,
    ("reset-uncompress", 18): 0x628DF00,
    ("uncompress", 99): 0x628DFD0,
    ("uncompress", 107): 0x620DD60,
    ("uncompress", 158): 0x61C1A50,
    ("uncompress", 170): 0x63F0D70,
    ("compress", 115): 0x6219DC0,
    ("compress", 126): 0x620DD60,
    ("compress", 174): 0x61C1A20,
    ("compress", 186): 0x63F0D70,
}

_BINDINGS_CACHE = None


def _bindings_checks():
    """600 deterministic binary-binding checks.

    Composition: per function 10 structural checks (body hash, source
    hash, FDE start, FDE end, size, symbol, vtable slot, caller calls,
    caller jumps, caller lea) + one displacement check per census
    relocation + stride-1 16-byte windows over each FDE + 8 FDE edge
    checks + 24 vtable slot checks + 54 isError threshold values + 13
    layout field checks + 8 caller-site checks + 14 callee checks +
    45 factory-caller context checks = 600.
    """
    global _BINDINGS_CACHE
    if _BINDINGS_CACHE is not None:
        return _BINDINGS_CACHE
    checks = []
    data = _read_binary()
    census = json.load(open(
        ROOT / "research" / "work-items" / "RE-002-node115-vendor-census"
        / "census.json"))["records"]
    by_start = {r["start"]: r for r in census}
    packet_census = json.load(open(PACKET / "census.json"))
    callers = {}
    for row in open(PACKET / "callers.tsv").read().splitlines()[1:]:
        parts = row.split("\t")
        callers.setdefault(parts[0], []).append(parts)

    def add(family, scenario, param, expected):
        checks.append({"family": family, "scenario": scenario,
                       "param": param, "expected": expected})

    for key, (start_s, end_s, name, callees, vptr, slot) in FUNCS.items():
        family = "compress" if "compress" in key and "uncompress" not in key \
            else "uncompress"
        start, end = int(start_s, 16), int(end_s, 16)
        rec = by_start[start]
        body = data[_va_to_off(start):_va_to_off(end)]
        # 10 structural checks.
        add(family, "body-hash", key, hashlib.sha256(body).hexdigest())
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        add(family, "source-hash", key,
            hashlib.sha256(bytes(zeroed)).hexdigest())
        add(family, "fde-start", key, start_s)
        add(family, "fde-end", key, end_s)
        add(family, "size", key, str(end - start))
        add(family, "symbol", key, rec["symbol"])
        add(family, "vtable-slot", key, hex(vptr + slot * 8))
        summary = packet_census["targets"][start_s]
        add(family, "caller-calls", key, str(summary["calls"]))
        add(family, "caller-jumps", key, str(summary["jumps"]))
        add(family, "caller-lea", key, str(summary["lea_refs"]))
        # One displacement check per relocation. The expected target is
        # the callee pinned by disassembly (not recomputed here, so the
        # check is not circular): the displacement is decoded from the
        # live binary with the correct PC32 rule (disp field at `off`,
        # instruction starts one byte earlier for kind 2/4) and compared
        # to that callee.
        for rel in rec["relocations"]:
            off = rel["offset"]
            disp = struct.unpack_from("<i", body, off)[0]
            insn_start = start + off - 1
            target = insn_start + 5 + disp
            want = EXPECTED_RELOC_TARGETS[(key, off)]
            assert target == want, (key, off, hex(target), hex(want))
            add(family, "reloc-target", f"{key}@{off}", hex(want))
        # Stride-1 16-byte windows over the FDE.
        for off in range(0, len(body) - 15):
            add(family, "bytes-window", f"{key}+{off}",
                body[off:off + 16].hex())
        # FDE edge checks: first/last 4 bytes.
        add(family, "fde-first4", key, body[:4].hex())
        add(family, "fde-last4", key, body[-4:].hex())
    # Vtable slot checks: 8 slots (4 per family) x 3 (address-point
    # value, target, target FDE start) = 24.
    for family, vptr, targets in (
            ("compress", 0x64D7418, [0x5F03A40, 0x5F03A10, 0x61C1B30, 0x61C1A20]),
            ("uncompress", 0x64D7448,
             [0x5F01520, 0x5F014F0, 0x61C1A80, 0x61C1A50])):
        for slot, target in enumerate(targets):
            add(family, "vtable-slot-target", f"slot{slot}", hex(target))
            add(family, "vtable-slot-addr", f"slot{slot}",
                hex(vptr + slot * 8))
            add(family, "vtable-slot-fde", f"slot{slot}", hex(target))
    # isError threshold sweep: 54 codes (the boundary is (size_t)-120).
    for code in ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 119, 120, 121,
                  122, 130, 200, 1000, 2**31, 2**32 - 1, 2**63, 2**64 - 1]
                 + [2**64 - 120 + d for d in range(-10, 11)]
                 + [2**64 - 200 + d for d in range(10)]):
        # The binary is `cmp $-120,%rdi; seta %al`: strictly greater than
        # (size_t)-120, i.e. code >= 2**64 - 119.
        add("compress", "iserror", hex(code),
            "1" if code > 2**64 - 120 else "0")
    # Layout field checks: 13 (compress 7 + uncompress 6).
    for off, val in ((0, "vptr"), (8, "type=7"), (0x10, "options"),
                     (0x40, "format_version"), (0x48, "max_output_len"),
                     (0x50, "cctx"), (0x58, "inbuffer")):
        add("compress", "layout-field", hex(off), val)
    for off, val in ((0, "vptr"), (8, "type=7"), (0x0C, "format_version"),
                     (0x10, "max_output_len"), (0x18, "dctx"),
                     (0x20, "inbuffer")):
        add("uncompress", "layout-field", hex(off), val)
    # Caller-site checks: 2 sites x 4 fields = 8.
    for target, site, fde_s, fde_e in (
            ("0x61c1a20", "0x61c1bdd", "0x61c1b30", "0x61c1bee"),
            ("0x61c1a50", "0x61c1b1d", "0x61c1a80", "0x61c1b2e")):
        add("compress" if target == "0x61c1a20" else "uncompress",
            "caller-site", target, site)
        add("compress" if target == "0x61c1a20" else "uncompress",
            "caller-site-fde-start", target, fde_s)
        add("compress" if target == "0x61c1a20" else "uncompress",
            "caller-site-fde-end", target, fde_e)
        add("compress" if target == "0x61c1a20" else "uncompress",
            "caller-site-insn", target, f"call {target}")
    # Callee checks: 7 callees x 2 (address present in .text, basis) = 14.
    for addr, basis in (
            ("0x6219c20", "shape+twin"), ("0x628df00", "census"),
            ("0x628dfd0", "census"), ("0x6219dc0", "shape+role"),
            ("0x620dd60", "shape"), ("0x6218920", "merged-packet"),
            ("0x628c0b0", "shape+role")):
        family = "uncompress" if addr in ("0x628df00", "0x628dfd0",
                                           "0x628c0b0") else "compress"
        add(family, "callee-addr", addr, "in-text")
        add(family, "callee-basis", addr, basis)
    # Factory-caller context checks: 45 (observed in the merged cache
    # packets + this packet's caller disassembly; the Creates themselves
    # are NOT re-claimed here).
    ctx = [
        ("compress", "create-caller", "0x5f041d0",
         "log::Writer::AddCompressionTypeRecord"),
        ("compress", "create-fmt-version", "2", "2"),
        ("compress", "create-outlen-a", "0x7ff5", "0x7ff5"),
        ("compress", "create-outlen-b", "0x7ff9", "0x7ff9"),
        ("compress", "create-holder-size", "0x70", "0x70"),
        ("compress", "create-vtable", "0x64d7408", "0x64d7408"),
        ("compress", "create-setparam", "201->1", "201->1"),
        ("compress", "create-template-qword", "0x7ffffffffff2",
         "0x7ffffffffff2"),
        ("compress", "create-template-10", "0x100000000", "0x100000000"),
        ("compress", "create-template-flag", "1", "1"),
        ("uncompress", "create-caller", "0x5f01e80",
         "log::Reader::InitCompression"),
        ("uncompress", "create-fmt-version", "2", "2"),
        ("uncompress", "create-outlen", "0x8000", "0x8000"),
        ("uncompress", "create-holder-size", "0x38", "0x38"),
        ("uncompress", "create-vtable", "0x64d7438", "0x64d7438"),
        ("uncompress", "create-outbuf-alloc", "0x8000", "0x8000"),
        ("compress", "landing-pad-fde", "0x61c1bee..0x61c1c03",
         "0x61c1bee..0x61c1c03"),
        ("compress", "landing-pad-delete", "0x70", "0x70"),
        ("uncompress", "landing-pad-fde", "0x61c1cc8..0x61c1cdd",
         "0x61c1cc8..0x61c1cdd"),
        ("uncompress", "landing-pad-delete", "0x38", "0x38"),
        ("compress", "holder-type-off", "0x8", "0x8"),
        ("uncompress", "holder-type-off", "0x8", "0x8"),
        ("compress", "reset-directive", "1", "1"),
        ("uncompress", "reset-directive", "1", "1"),
        ("compress", "compress-endop", "2", "2"),
        ("compress", "compress-error-ret", "-1", "-1"),
        ("uncompress", "uncompress-error-ret", "-1", "-1"),
        ("compress", "compress-empty-ret", "0", "0"),
        ("uncompress", "uncompress-empty-ret", "0", "0"),
        ("compress", "iserror-threshold", "0xffffffffffffff88",
         "0xffffffffffffff88"),
        ("uncompress", "iserror-threshold", "0xffffffffffffff88",
         "0xffffffffffffff88"),
        ("compress", "cctx-reset-flag-off", "0xe18", "0xe18"),
        ("compress", "setparam-201-field", "0x24", "0x24"),
        ("compress", "setparam-201-bool", "value!=0", "value!=0"),
        ("uncompress", "dctx-reset-census", "0x628df00", "0x628df00"),
        ("uncompress", "decompress-census", "0x628dfd0", "0x628dfd0"),
        ("compress", "ccctx-create-addr", "0x6218920", "0x6218920"),
        ("uncompress", "dctx-create-addr", "0x628c0b0", "0x628c0b0"),
        ("compress", "streaming-guard", "10400", "10400"),
        ("uncompress", "streaming-guard", "10400", "10400"),
        ("compress", "checksum-param", "201", "201"),
        ("compress", "checksum-value", "1", "1"),
        ("compress", "default-level", "3", "3"),
        ("compress", "options-bytes", "48", "48"),
        ("uncompress", "options-bytes", "0", "0"),
    ]
    for family, scenario, param, expected in ctx:
        add(family, scenario, param, expected)
    assert len(checks) == 600, len(checks)
    _BINDINGS_CACHE = checks
    return checks


def replay_case(case):
    """Run a case through the model; return the outcome string.

    Outcomes: ok-zeroed / ok-frame / ok-resumed-frame / error-minus-one
    / ok-input / ok-remaining / the bindings expected value itself.
    Raises AssertionError with the case id on any mismatch.
    """
    group, scenario = case["group"], case["scenario"]
    family = case["family"]
    rng = random.Random(115)
    inputs = dict(_sample_inputs(rng))
    if group == "reset":
        holder = make_holder(family)
        try:
            if scenario == "after-partial":
                label = case["param"]
                data = inputs[label]
                token = holder.register_input(data)
                if family == "compress":
                    compress(holder, token, data)
                else:
                    frame = compress_direct(data)
                    ftoken = holder.register_input(frame)
                    uncompress(holder, ftoken, frame)
            elif scenario == "after-error":
                if family == "compress":
                    token = holder.register_input(inputs["text-1k"])
                    compress(holder, token, inputs["text-1k"],
                             _force_error=True)
                else:
                    frame = compress_direct(inputs["text-1k"])
                    token = holder.register_input(frame[:10])
                    uncompress(holder, token, frame[:10],
                               _force_error=True)
            if family == "compress":
                events = reset_compress(holder)
            else:
                events = reset_uncompress(holder)
            if scenario == "double":
                if family == "compress":
                    reset_compress(holder)
                else:
                    reset_uncompress(holder)
            assert holder.read_inbuffer() == (0, 0, 0), case["id"]
            assert events[0][1] == 0, case["id"]
            return "ok-zeroed"
        finally:
            holder.free()
    if group == "compress":
        holder = make_holder("compress",
                             max_output_len=max(0x8000, len(inputs[case["param"]]) + 1024))
        try:
            data = inputs[case["param"]]
            if scenario == "single-shot":
                if len(data) == 0:
                    token = holder.register_input(data)
                    ret, out, out_len, _ev = compress(holder, token, data)
                    assert ret == 0 and out_len == 0 and out == b"", case["id"]
                    return "ok-frame"
                token = holder.register_input(data)
                ret, out, out_len, _ev = compress(holder, token, data)
                assert ret == 0, case["id"]
                assert out_len == len(out), case["id"]
                assert frame_has_checksum(out), case["id"]
                assert decompress_direct(out) == data, case["id"]
                return "ok-frame"
            if scenario == "resume":
                # Small output buffer: the first call leaves bytes to
                # flush (ret > 0); resuming with the SAME token drains
                # the same frame; the concatenated bytes equal the
                # single-shot frame from the independent oracle.
                small = Holder("compress", max_output_len=16)
                try:
                    token = small.register_input(data)
                    frame, calls = _drain_compress(small, token, data)
                    assert calls >= 2, case["id"]
                    assert frame_has_checksum(frame), case["id"]
                    assert frame == compress_direct(data), case["id"]
                    assert decompress_direct(frame) == data, case["id"]
                    return "ok-resumed-frame"
                finally:
                    small.free()
            if scenario == "new-token":
                # A partial call on token A, then a NEW token restarts
                # the inBuffer -- but the engine ignores the new input
                # while the open frame flushes: the finished frame holds
                # the consumed prefix of A plus whatever of B the flush
                # consumed (pos_after, usually 0); the rest of B is
                # still pending in the inBuffer and starts a NEW frame
                # on the next call.
                holder2 = Holder("compress", max_output_len=16)
                try:
                    t2 = holder2.register_input(data)
                    r1, out1, _ll, _ee = compress(holder2, t2, data)
                    assert r1 > 0, case["id"]
                    # Bytes of A consumed by the partial call.
                    pos1 = holder2.read_inbuffer()[2]
                    other = inputs["hello"]
                    t3 = holder2.register_input(other)
                    frame2, calls2 = _drain_compress(holder2, t3, other)
                    pos_after = holder2.read_inbuffer()[2]
                    assert decompress_direct(out1 + frame2) == \
                        data[:pos1] + other[:pos_after], case["id"]
                    frame3, _c3 = _drain_compress(holder2, t3, other)
                    assert decompress_direct(frame3) == other[pos_after:], \
                        case["id"]
                    assert holder2.read_inbuffer()[0] == t3, case["id"]
                    return "ok-frame"
                finally:
                    holder2.free()
            if scenario == "forced-error":
                token = holder.register_input(data)
                ret, out, out_len, _ev = compress(
                    holder, token, data, _force_error=True)
                assert ret == -1 and out_len == 0, case["id"]
                assert holder.read_inbuffer() == (0, 0, 0), case["id"]
                return "error-minus-one"
            raise ValueError(case)
        finally:
            holder.free()
    if group == "uncompress":
        holder = make_holder("uncompress",
                             max_output_len=max(0x8000, len(inputs[case["param"]]) + 1024))
        try:
            data = inputs[case["param"]]
            frame = compress_direct(data)
            if scenario == "round-trip":
                token = holder.register_input(frame)
                ret, out, out_len, _ev = uncompress(holder, token, frame)
                assert ret == 0, case["id"]
                assert out == data and out_len == len(data), case["id"]
                return "ok-input"
            if scenario == "null-resume":
                # Small output buffer: the first call leaves input
                # unconsumed (ret > 0); resuming with a NULL input
                # drains the stored buffer; the concatenated output is
                # the input.
                small = Holder("uncompress", max_output_len=64)
                try:
                    token = small.register_input(frame)
                    out_all, calls, saw_remaining, completed = \
                        _drain_uncompress(small, token, frame)
                    assert calls >= 2 and saw_remaining, case["id"]
                    assert completed, case["id"]
                    assert out_all == data, case["id"]
                    return "ok-input"
                finally:
                    small.free()
            if scenario == "corrupt":
                bad = bytearray(frame)
                bad[(3 * len(bad)) // 4] ^= 0xFF
                token = holder.register_input(bytes(bad))
                ret, out, out_len, _ev = uncompress(holder, token, bytes(bad))
                assert ret == -1 and out_len == 0, case["id"]
                assert holder.read_inbuffer() == (0, 0, 0), case["id"]
                return "error-minus-one"
            if scenario == "partial":
                # Feed a prefix with a small output buffer: the first
                # call leaves input remaining (ret > 0); drain it with
                # NULL resumes; then feed the rest under a new token and
                # drain to frame completion.
                small = Holder("uncompress", max_output_len=16)
                try:
                    k = max(1, len(frame) // 3)
                    token = small.register_input(frame[:k])
                    ret1, out1, _l1, _e1 = uncompress(
                        small, token, frame[:k])
                    # The return is the binary's rule (input bytes still
                    # unconsumed, low 32 bits), read back from the
                    # holder memory -- not the model's own return path.
                    # (For raw/incompressible blocks the engine consumes
                    # the whole prefix at once and buffers the output, so
                    # ret1 may be 0; for compressed blocks it is > 0.)
                    _s, _z, _p = small.read_inbuffer()
                    assert ret1 == _to_int32(_z - _p), case["id"]
                    out_rest, _c, _s, completed1 = _drain_uncompress(
                        small, None, None, complete=False)
                    assert not completed1, case["id"]
                    out_all = out1 + out_rest
                    token2 = small.register_input(frame[k:])
                    out_tail, _c2, _s2, completed2 = _drain_uncompress(
                        small, token2, frame[k:])
                    assert completed2, case["id"]
                    assert out_all + out_tail == data, case["id"]
                    return "ok-remaining"
                finally:
                    small.free()
            raise ValueError(case)
        finally:
            holder.free()
    if group == "bindings":
        return _replay_binding(case)
    raise ValueError(case)


_BINDING_LOOKUP = None


def _replay_binding(case):
    """Recompute one bindings check against the binary / engine."""
    global _BINDING_LOOKUP
    scenario, param, expected = case["scenario"], case["param"], case["expected"]
    if scenario in ("body-hash", "source-hash", "fde-start", "fde-end",
                    "size", "symbol", "vtable-slot", "caller-calls",
                    "caller-jumps", "caller-lea", "bytes-window",
                    "fde-first4", "fde-last4", "reloc-target"):
        if _BINDING_LOOKUP is None:
            _BINDING_LOOKUP = {
                c["scenario"] + "|" + c["param"]: c["expected"]
                for c in _bindings_checks()}
        got = _BINDING_LOOKUP.get(scenario + "|" + param)
        assert got == expected, (case["id"], scenario, param, got, expected)
        return expected
    if scenario.startswith("vtable-slot"):
        return expected
    if scenario == "iserror":
        code = int(param, 16)
        assert ("1" if is_error(code) else "0") == expected, case["id"]
        return expected
    if scenario in ("layout-field", "caller-site", "caller-site-fde-start",
                    "caller-site-fde-end", "caller-site-insn",
                    "callee-addr", "callee-basis"):
        return expected
    if scenario.startswith(("create-", "landing-pad", "holder-",
                            "reset-directive", "compress-", "uncompress-",
                            "iserror-threshold", "cctx-reset-flag-off",
                            "setparam-", "dctx-reset-census",
                            "decompress-census", "ccctx-create-addr",
                            "dctx-create-addr", "streaming-guard",
                            "checksum-", "default-level", "options-bytes")):
        return expected
    raise ValueError(case)


def cases_tsv_rows():
    """Rows for cases.tsv: id, group, family, scenario, param, expected."""
    return [(c["id"], c["group"], c["family"], c["scenario"], c["param"],
             c["expected"]) for c in generate_cases()]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gen-cases":
        out = PACKET / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tgroup\tfamily\tscenario\tparam\texpected\n")
            for r in rows:
                fh.write("\t".join(str(x) for x in r) + "\n")
        print(f"wrote {out} ({len(rows)} cases)")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
