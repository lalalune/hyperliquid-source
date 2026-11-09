"""Node #115 RocksDB ZSTD streaming compress/uncompress: wrapper reconstruction.

RE-002 work item. Reconstructs the six functions at 0x61c1a20..0x61c1d5a:

  rocksdb::StreamingCompress::Create      0x61c1c10 (184 B)
  rocksdb::ZSTDStreamingCompress::Compress 0x61c1b30 (190 B)
  rocksdb::ZSTDStreamingCompress::Reset    0x61c1a20 (40 B)
  rocksdb::StreamingUncompress::Create    0x61c1ce0 (122 B)
  rocksdb::ZSTDStreamingUncompress::Uncompress 0x61c1a80 (174 B)
  rocksdb::ZSTDStreamingUncompress::Reset 0x61c1a50 (40 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Each body hash matches the vendor census target_body_sha256 exactly, and
each census source_body_sha256 is reproduced by zeroing the recorded
relocation fields (the two factories additionally need the kind-42
mov<-lea restoration at the vtable load; see records.json).

What is reconstructed here is the WRAPPER: object layout, the Create
gate and field init, the input-buffer refresh rules, the early returns,
the error path (Reset + return -1) and the return-value arithmetic.
The ZSTD streaming engine itself (ZSTD_compressStream2 /
ZSTD_decompressStream and friends) is the linked dependency: the target
statically links zstd 1.5.7, and this tool drives the same public API
through the system libzstd.so.1 (1.5.5) via ctypes. Frame BYTES are
therefore not claimed byte-identical to the target's output; what is
claimed is the wrapper behaviour plus frame validity (magic, checksum
flag, one-shot decode back to the input). The engine calls are thin
passthroughs in :func:`compress_stream2` / :func:`decompress_stream`;
all wrapper logic lives in :class:`StreamingCompress` /
:class:`StreamingUncompress` and is what the tests exercise.

Upstream anchors (RocksDB v8.1.1, util/compression.{h,cc}):
  * Create takes (type, options, compress_format_version: u32,
    max_output_len: size_t); only kZSTD (7) builds an object.
  * The compress ctor creates a CCtx and sets ZSTD_c_checksumFlag (201)
    to 1; no compression level is applied. The uncompress ctor creates
    a DCtx. The binary has no ZSTD_Streaming_Supported() call: the
    source's check folds away with ZSTD_STREAMING defined.
  * Compress: *output_pos = 0; empty input returns 0; a new input
    pointer restocks the input buffer, the same pointer keeps the old
    size/pos; compressStream2(..., ZSTD_e_end=2); error -> Reset, -1;
    else *output_pos = out.pos and the return is (int)remaining.
  * Uncompress: *output_pos = 0; empty input returns 0; a non-null
    input REPLACES the buffer unconditionally (same pointer included);
    a null input keeps the stored buffer, so continuation after a full
    output buffer passes nullptr; decompressStream; error -> Reset, -1;
    else *output_pos = out.pos and the return is
    (int)(in.size - in.pos).

Object layouts (offsets verified against the binary):
  StreamingCompress base: +0x00 vptr, +0x08 type byte (7),
    +0x10..+0x40 options (48 bytes, opaque copy),
    +0x40 format_version (u32), +0x48 max_output_len (size_t).
  ZSTDStreamingCompress adds +0x50 CCtx*, +0x58..+0x70 inBuffer
    {src, size, pos}. Total 0x70 bytes.
  StreamingUncompress base: +0x00 vptr, +0x08 type byte (7),
    +0x0c format_version (u32), +0x10 max_output_len (size_t).
  ZSTDStreamingUncompress adds +0x18 DCtx*, +0x20..+0x38 inBuffer.
    Total 0x38 bytes.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra on
this VM; the target binary is never executed; the ZSTD engine calls go
to the system libzstd, not to the target binary.
"""

import ctypes
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
ZSTD_KIND = 7
ZSTD_C_CHECKSUM_FLAG = 201
ZSTD_RESET_SESSION_ONLY = 1
ZSTD_E_END = 2
ZSTD_ERROR_MAX_CODE = 120  # ZSTD_isError: code > (size_t)-120

# ---------------------------------------------------------------------------
# Thin ctypes passthrough to the system libzstd (the linked engine).
# No wrapper logic lives here on purpose: the tests stub these two
# functions to exercise the error branches.
# ---------------------------------------------------------------------------

_lib = None


def _load_lib():
    global _lib
    if _lib is None:
        try:
            _lib = ctypes.CDLL("libzstd.so.1")
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
        _lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_CCtx_setParameter.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        _lib.ZSTD_CCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_DCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_compressStream2.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_compressStream2.restype = ctypes.c_size_t
        _lib.ZSTD_decompressStream.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        _lib.ZSTD_decompressStream.restype = ctypes.c_size_t
        _lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        _lib.ZSTD_isError.restype = ctypes.c_uint
        _lib.ZSTD_decompress.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        _lib.ZSTD_decompress.restype = ctypes.c_size_t
        _lib.ZSTD_getFrameContentSize.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t]
        _lib.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
    return _lib


class _InBuf(ctypes.Structure):
    _fields_ = [("src", ctypes.c_void_p),
                ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


class _OutBuf(ctypes.Structure):
    _fields_ = [("dst", ctypes.c_void_p),
                ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


def is_error(code):
    """ZSTD_isError, exactly as the binary implements it at 0x620dd60:
    ``code > (size_t)-120`` (cmp rdi, -0x78; seta)."""
    return code > (2 ** 64 - ZSTD_ERROR_MAX_CODE)


def compress_stream2(cctx, out_buf, in_buf, in_pos, end_op=ZSTD_E_END):
    """Passthrough: ZSTD_compressStream2(cctx, &out, &in, end_op).

    ``out_buf`` is a writable buffer, ``in_buf`` bytes, ``in_pos`` the
    starting input position. Returns (ret, out_pos, in_pos)."""
    lib = _load_lib()
    src = ctypes.create_string_buffer(bytes(in_buf), len(in_buf))
    dst = ctypes.create_string_buffer(len(out_buf))
    ib = _InBuf(ctypes.addressof(src), len(in_buf), in_pos)
    ob = _OutBuf(ctypes.addressof(dst), len(out_buf), 0)
    ret = lib.ZSTD_compressStream2(cctx, ctypes.byref(ob),
                                   ctypes.byref(ib), end_op)
    out_buf[:ob.pos] = dst.raw[:ob.pos]
    return ret, ob.pos, ib.pos


def decompress_stream(dctx, out_buf, in_buf, in_pos):
    """Passthrough: ZSTD_decompressStream(dctx, &out, &in).
    Returns (ret, out_pos, in_pos)."""
    lib = _load_lib()
    src = ctypes.create_string_buffer(bytes(in_buf), len(in_buf))
    dst = ctypes.create_string_buffer(len(out_buf))
    ib = _InBuf(ctypes.addressof(src), len(in_buf), in_pos)
    ob = _OutBuf(ctypes.addressof(dst), len(out_buf), 0)
    ret = lib.ZSTD_decompressStream(dctx, ctypes.byref(ob),
                                    ctypes.byref(ib))
    out_buf[:ob.pos] = dst.raw[:ob.pos]
    return ret, ob.pos, ib.pos


def one_shot_decompress(frame, capacity):
    """Independent validity check: ZSTD_decompress (one-shot).
    Returns the decompressed bytes, or None when the frame is invalid."""
    lib = _load_lib()
    src = ctypes.create_string_buffer(bytes(frame), len(frame))
    dst = ctypes.create_string_buffer(capacity)
    ret = lib.ZSTD_decompress(ctypes.addressof(dst), capacity,
                              ctypes.addressof(src), len(frame))
    if is_error(ret):
        return None
    return dst.raw[:ret]


def frame_has_checksum(frame):
    """True when the zstd frame header carries the content-checksum flag
    (descriptor byte bit 0x04). Single-segment frames have no descriptor
    byte layout change; the magic is 0xFD2FB528 little-endian."""
    if len(frame) < 5 or frame[:4] != b"\x28\xb5\x2f\xfd":
        return False
    return bool(frame[4] & 0x04)


def _to_int32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


# ---------------------------------------------------------------------------
# Wrapper reconstruction.
# ---------------------------------------------------------------------------

class StreamingCompress:
    """rocksdb::ZSTDStreamingCompress (0x70 bytes).

    Fields mirror the binary layout; ``_in_data`` holds the input bytes
    object whose identity the binary compares by pointer, and ``_in_size``
    / ``_in_pos`` are the stored ZSTD_inBuffer size/pos.
    """

    __slots__ = ("compression_type", "options", "format_version",
                 "max_output_len", "_cctx", "_in_data", "_in_size",
                 "_in_pos", "_closed")

    def __init__(self, options, format_version, max_output_len):
        lib = _load_lib()
        self.compression_type = ZSTD_KIND
        self.options = bytes(options)  # opaque 48-byte copy, +0x10..+0x40
        self.format_version = format_version & 0xFFFFFFFF
        self.max_output_len = max_output_len
        self._cctx = lib.ZSTD_createCCtx()
        if not self._cctx:
            raise RuntimeError("ZSTD_createCCtx returned NULL")
        # Binary ignores the return value; the cache packet pins param 201
        # as the boolean checksumFlag arm, value 1 enables it.
        lib.ZSTD_CCtx_setParameter(self._cctx, ZSTD_C_CHECKSUM_FLAG, 1)
        self._in_data = None
        self._in_size = 0
        self._in_pos = 0
        self._closed = False

    @classmethod
    def create(cls, compression_type, options, format_version,
               max_output_len):
        """rocksdb::StreamingCompress::Create (0x61c1c10).

        Non-ZSTD kinds return None; no ZSTD_Streaming_Supported() call
        exists in the binary (the source check folds away)."""
        if len(options) != 48:
            raise ValueError("CompressionOptions is a 48-byte blob here")
        if compression_type != ZSTD_KIND:
            return None
        return cls(options, format_version, max_output_len)

    def reset(self):
        """ZSTDStreamingCompress::Reset (0x61c1a20):
        ZSTD_CCtx_reset(cctx, session_only) + zero the input buffer."""
        lib = _load_lib()
        lib.ZSTD_CCtx_reset(self._cctx, ZSTD_RESET_SESSION_ONLY)
        self._in_data = None
        self._in_size = 0
        self._in_pos = 0

    def in_buffer(self):
        """Debug accessor for the stored input buffer: (has_src, size, pos)."""
        return (self._in_data is not None, self._in_size, self._in_pos)

    def compress(self, input_data, input_size, output):
        """ZSTDStreamingCompress::Compress (0x61c1b30).

        ``output`` is a bytearray of at least ``max_output_len`` bytes;
        the binary uses max_output_len as the out-buffer size. Returns
        (ret, output_pos): ret is (int)remaining-to-flush, -1 on error,
        0 for empty input."""
        output_pos = 0
        if input_size == 0:
            return 0, 0
        if self._in_data is None or input_data is not self._in_data:
            # New input pointer: restock, pos = 0. The same pointer keeps
            # the stored size AND pos (the binary never re-reads size).
            self._in_data = input_data
            self._in_size = input_size
            self._in_pos = 0
        out = bytearray(self.max_output_len)
        remaining, produced, new_pos = compress_stream2(
            self._cctx, out, self._in_data[:self._in_size], self._in_pos)
        self._in_pos = new_pos
        if is_error(remaining):
            self.reset()
            return -1, 0
        output[:produced] = out[:produced]
        return _to_int32(remaining), produced

    def close(self):
        if not self._closed:
            _load_lib().ZSTD_freeCCtx(self._cctx)
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class StreamingUncompress:
    """rocksdb::ZSTDStreamingUncompress (0x38 bytes)."""

    __slots__ = ("compression_type", "format_version",
                 "max_output_len", "_dctx", "_in_data", "_in_size",
                 "_in_pos", "_closed")

    def __init__(self, format_version, max_output_len):
        lib = _load_lib()
        self.compression_type = ZSTD_KIND
        self.format_version = format_version & 0xFFFFFFFF
        self.max_output_len = max_output_len
        self._dctx = lib.ZSTD_createDCtx()
        if not self._dctx:
            raise RuntimeError("ZSTD_createDCtx returned NULL")
        self._in_data = None
        self._in_size = 0
        self._in_pos = 0
        self._closed = False

    @classmethod
    def create(cls, compression_type, format_version, max_output_len):
        """rocksdb::StreamingUncompress::Create (0x61c1ce0)."""
        if compression_type != ZSTD_KIND:
            return None
        return cls(format_version, max_output_len)

    def reset(self):
        """ZSTDStreamingUncompress::Reset (0x61c1a50):
        ZSTD_DCtx_reset(dctx, session_only) + zero the input buffer."""
        lib = _load_lib()
        lib.ZSTD_DCtx_reset(self._dctx, ZSTD_RESET_SESSION_ONLY)
        self._in_data = None
        self._in_size = 0
        self._in_pos = 0

    def in_buffer(self):
        return (self._in_data is not None, self._in_size, self._in_pos)

    def uncompress(self, input_data, input_size, output):
        """ZSTDStreamingUncompress::Uncompress (0x61c1a80).

        ``input_data`` None means "continue with the stored buffer"
        (the documented continuation after a full output buffer).
        Returns (ret, output_pos): ret is (int)(in.size - in.pos),
        -1 on error, 0 for empty input."""
        if input_size == 0:
            return 0, 0
        if input_data is not None:
            # Any non-null input REPLACES the buffer, same pointer included.
            self._in_data = input_data
            self._in_size = input_size
            self._in_pos = 0
        if self._in_data is None:
            # Null input with no stored buffer: nothing to consume.
            # The binary would pass a null inBuffer to decompressStream;
            # treat it as an empty feed that leaves the state untouched.
            return 0, 0
        out = bytearray(self.max_output_len)
        ret, produced, new_pos = decompress_stream(
            self._dctx, out, self._in_data[:self._in_size], self._in_pos)
        self._in_pos = new_pos
        if is_error(ret):
            self.reset()
            return -1, 0
        output[:produced] = out[:produced]
        return _to_int32(self._in_size - self._in_pos), produced

    def close(self):
        if not self._closed:
            _load_lib().ZSTD_freeDCtx(self._dctx)
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# ---------------------------------------------------------------------------
# Deterministic case generation (seeded; 2,400 cases total).
# ---------------------------------------------------------------------------

def _rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def _sample_input(rng):
    kind = rng.randrange(6)
    if kind == 0:
        return b""
    if kind == 1:
        return _rand_bytes(rng, rng.randrange(1, 64))
    if kind == 2:
        return (b"abcdefgh" * rng.randrange(1, 200))[:rng.randrange(1, 1500)]
    if kind == 3:
        return _rand_bytes(rng, rng.randrange(1, 5000))
    if kind == 4:
        # highly compressible, crosses block boundaries
        unit = _rand_bytes(rng, rng.randrange(1, 32))
        return (unit * rng.randrange(200, 3000))[:rng.randrange(1000, 70000)]
    return (b"The quick brown fox jumps over the lazy dog. " * 500)[
        :rng.randrange(1, 20000)]


def generate_cases(seed=20261109):
    """Return the 2,400 cases: 400 create, 400 reset, 800 compress,
    800 uncompress. Each case is a dict of inputs only; the expected
    outcomes are the stable wrapper-level values the tests assert."""
    rng = random.Random(seed)
    cases = []
    for i in range(400):
        cases.append({
            "id": f"create-{i}",
            "op": "create",
            "type": rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 8, 9, 255]),
            "options": _rand_bytes(rng, 48),
            "format_version": rng.choice([0, 1, 2, 2, 3, 0xFFFFFFFF]),
            "max_output_len": rng.choice(
                [0, 1, 16, 64, 0x7FF5, 0x7FF9, 0x8000, 65536]),
        })
    for i in range(400):
        cases.append({
            "id": f"reset-{i}",
            "op": "reset",
            "side": rng.choice(["compress", "uncompress"]),
            "data": _sample_input(rng),
            "max_output_len": rng.choice([64, 0x7FF5, 0x8000, 65536]),
        })
    for i in range(800):
        cases.append({
            "id": f"compress-{i}",
            "op": "compress",
            "data": _sample_input(rng),
            "max_output_len": rng.choice([16, 64, 256, 0x7FF5, 0x8000, 65536]),
            "continuation": rng.choice(["same-object", "new-object",
                                        "same-object-new-size", "none"]),
        })
    for i in range(800):
        cases.append({
            "id": f"uncompress-{i}",
            "op": "uncompress",
            "data": _sample_input(rng),
            "max_output_len": rng.choice([16, 64, 256, 0x7FF5, 0x8000, 65536]),
            "feed": rng.choice(["whole", "chunks-null",
                                "chunks-repassed", "corrupt", "garbage"]),
        })
    return cases


def case_ledger(cases):
    """Run the cases through the model and record the stable outcomes
    (return values, output positions, round-trip hashes) for cases.tsv.
    Frame bytes are deliberately NOT frozen: they depend on the system
    libzstd version, while the recorded values do not."""
    rows = []
    for case in cases:
        op = case["op"]
        if op == "create":
            obj = StreamingCompress.create(
                case["type"], case["options"], case["format_version"],
                case["max_output_len"])
            rows.append((case["id"], op,
                         hashlib.sha256(case["options"]).hexdigest()[:16],
                         case["type"], case["format_version"],
                         case["max_output_len"],
                         "object" if obj is not None else "null", "", ""))
            if obj is not None:
                obj.close()
            continue
        if op == "reset":
            rows.append(_ledger_reset(case))
            continue
        if op == "compress":
            rows.append(_ledger_compress(case))
            continue
        rows.append(_ledger_uncompress(case))
    return rows


def _ledger_reset(case):
    data = case["data"]
    if case["side"] == "compress":
        with StreamingCompress.create(7, bytes(48), 2,
                                      case["max_output_len"]) as obj:
            out = bytearray(case["max_output_len"])
            if data:
                obj.compress(data, len(data), out)
            obj.reset()
            cleared = obj.in_buffer() == (False, 0, 0)
            # a fresh frame after reset decompresses to the input alone
            fresh_ok = False
            if data:
                out2 = bytearray(case["max_output_len"])
                ret, pos = obj.compress(data, len(data), out2)
                dec = one_shot_decompress(bytes(out2[:pos]),
                                          max(len(data), 1))
                fresh_ok = (ret == 0 and dec == data)
            return (case["id"], "reset", hashlib.sha256(data).hexdigest()[:16],
                    case["side"], case["max_output_len"], "",
                    "cleared" if cleared else "NOT-CLEARED",
                    "fresh-frame-ok" if fresh_ok else "fresh-frame-FAIL", "")
    with StreamingUncompress.create(7, 2, case["max_output_len"]) as obj:
        obj.reset()
        cleared = obj.in_buffer() == (False, 0, 0)
        return (case["id"], "reset", hashlib.sha256(data).hexdigest()[:16],
                case["side"], case["max_output_len"], "",
                "cleared" if cleared else "NOT-CLEARED", "", "")


def _ledger_compress(case):
    data = case["data"]
    with StreamingCompress.create(7, bytes(48), 2,
                                  case["max_output_len"]) as obj:
        out = bytearray(case["max_output_len"])
        ret, pos = obj.compress(data, len(data), out)
        frame = bytes(out[:pos])
        dec = one_shot_decompress(frame, max(len(data), 1)) if frame else b""
        # continuation: same object again must finish the frame (ret 0)
        frame2 = frame
        if ret != 0:
            out2 = bytearray(case["max_output_len"])
            ret2, pos2 = obj.compress(data, len(data), out2)
            frame2 = frame + bytes(out2[:pos2])
            ret = ret2
            dec = one_shot_decompress(frame2, max(len(data), 1))
        ok = (ret == 0 and dec == data and frame_has_checksum(frame2))
        return (case["id"], "compress",
                hashlib.sha256(data).hexdigest()[:16], len(data),
                case["max_output_len"], case["continuation"],
                f"ret={ret}", f"produced={len(frame2)}",
                "roundtrip-ok" if ok else "roundtrip-FAIL")


def _ledger_uncompress(case):
    data = case["data"]
    with StreamingCompress.create(7, bytes(48), 2, 65536) as enc:
        out = bytearray(65536)
        ret, pos = enc.compress(data, len(data), out)
        frame = bytes(out[:pos])
        while ret != 0:
            out2 = bytearray(65536)
            ret, pos2 = enc.compress(data, len(data), out2)
            frame += bytes(out2[:pos2])
    with StreamingUncompress.create(7, 2, case["max_output_len"]) as obj:
        out = bytearray(case["max_output_len"])
        if case["feed"] in ("garbage",):
            ret, produced = obj.uncompress(_rand_bytes(random.Random(7), 32),
                                           32, out)
            return (case["id"], "uncompress",
                    hashlib.sha256(data).hexdigest()[:16], len(data),
                    case["max_output_len"], case["feed"], f"ret={ret}",
                    f"produced={produced}",
                    "error-reset" if ret == -1 else "NO-ERROR")
        if case["feed"] == "corrupt" and len(frame) > 20:
            bad = bytearray(frame)
            bad[len(bad) // 2] ^= 0xFF
            ret, produced = obj.uncompress(bytes(bad), len(bad), out)
            # The checksum is only checked at the end of the frame, so
            # drain with nullptr continuation until the error surfaces.
            while ret > 0:
                out2 = bytearray(case["max_output_len"])
                ret, produced = obj.uncompress(None, 1, out2)
            return (case["id"], "uncompress",
                    hashlib.sha256(data).hexdigest()[:16], len(data),
                    case["max_output_len"], case["feed"], f"ret={ret}",
                    f"produced={produced}",
                    "error-reset" if ret == -1 else "NO-ERROR")
        if case["feed"] == "chunks-repassed":
            # Re-passing restarts only at a frame boundary (a mid-frame
            # re-pass corrupts the stream; see the targeted test). Drain
            # fully first, then re-pass for a fresh decompression.
            ret, produced = obj.uncompress(frame, len(frame), out)
            got = bytearray(out[:produced])
            while ret > 0:
                out2 = bytearray(case["max_output_len"])
                ret, produced = obj.uncompress(None, 1, out2)
                got += out2[:produced]
            first_ok = (ret == 0 and bytes(got) == data)
            ret, produced = obj.uncompress(frame, len(frame), out)
            got = bytearray(out[:produced])
            while ret > 0:
                out2 = bytearray(case["max_output_len"])
                ret, produced = obj.uncompress(None, 1, out2)
                got += out2[:produced]
            ok = first_ok and ret == 0 and bytes(got) == data
            return (case["id"], "uncompress",
                    hashlib.sha256(data).hexdigest()[:16], len(data),
                    case["max_output_len"], case["feed"], f"ret={ret}",
                    f"produced={len(got)}",
                    "roundtrip-ok" if ok else "roundtrip-FAIL")
        got = bytearray()
        ret, produced = obj.uncompress(frame, len(frame), out)
        got += out[:produced]
        while ret > 0:
            out2 = bytearray(case["max_output_len"])
            ret, produced = obj.uncompress(None, 1, out2)
            got += out2[:produced]
        ok = (ret == 0 and bytes(got) == data)
        return (case["id"], "uncompress",
                hashlib.sha256(data).hexdigest()[:16], len(data),
                case["max_output_len"], case["feed"], f"ret={ret}",
                f"produced={len(got)}",
                "roundtrip-ok" if ok else "roundtrip-FAIL")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-cases", default=None,
                    help="write cases.tsv ledger to this path")
    ap.add_argument("--verify-artifact", action="store_true",
                    help="check the node #115 artifact digest and exit")
    args = ap.parse_args(argv)
    if args.verify_artifact:
        for cand in (ROOT / "artifacts" / "node" / "115" / "hl-node",
                     ROOT / "work" / "hl-node-115.bin"):
            if cand.exists():
                digest = hashlib.sha256(cand.read_bytes()).hexdigest()
                print(f"{cand}: {digest}")
                if digest == ARTIFACT_SHA256:
                    print("artifact digest matches")
                    return 0
        print("no materialized artifact with the expected digest found")
        return 1
    if args.write_cases:
        rows = case_ledger(generate_cases())
        with open(args.write_cases, "w") as fh:
            fh.write("case_id\top\tinput_sha256_16\tinput_len_or_type\t"
                     "max_output_len_or_side\tmode\toutcome\t"
                     "produced\tverdict\n")
            for row in rows:
                fh.write("\t".join(str(c) for c in row) + "\n")
        print(f"wrote {len(rows)} cases to {args.write_cases}")
        return 0
    print("libzstd:", _load_lib().ZSTD_versionString().decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
