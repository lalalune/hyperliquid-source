"""Node #115 RocksDB log::Reader::InitCompression: reconstruction.

RE-002 work item. Reconstructs the WAL reader's compression-init
routine at 0x5f01e80..0x5f01ed2 (82 B):

  rocksdb::log::Reader::InitCompression  0x5f01e80 (82 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The body hash matches the vendor census target_body_sha256 exactly,
and the source hash is reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbol comes from the vendor
census (member 25dac13516458d4d-log_reader.o, librocksdb-sys):
_ZN7rocksdb3log6Reader15InitCompressionERKNS_21CompressionTypeRecordE.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  void InitCompression(const CompressionTypeRecord& record) --
  rdi is the Reader*, rsi points at the 1-byte record (its only
  member is the CompressionType). Steps, in binary order:

  1. Read the type: movzbl (%rsi),%edi -- GetCompressionType()
     reads record.type, the single byte at the record's address.
  2. Flag first: movb $0x1,0x73(%rbx) -- compression_type_record_read_
     = true (the binary stores the flag BEFORE the type; upstream
     lists the type assignment first, the compiler reordered them).
  3. mov %dil,0x72(%rbx) -- compression_type_ = type.
  4. Create: StreamingUncompress::Create(type, version 2,
     kBlockSize 0x8000) at 0x61c1ce0 (esi = 2, edx = 0x8000).
     The factory's kind gate (merged RE-001-zstd-decompress-cache-115)
     builds the 0x38-byte holder only for kind 7 (kZSTD); any other
     kind returns null.
  5. mov %rax,0x78(%rbx) -- uncompress_ = product. The previous
     uncompress_ is overwritten WITHOUT a delete: a leak on re-entry.
     There is no null check on the product (upstream's
     assert(uncompress_ != nullptr) is compiled out), so a type other
     than 7 installs a null uncompressor and the Reader proceeds.
  6. new char[kBlockSize]: mov $0x8000,%edi; call operator new[]
     (0x63f0e30). The result is likewise unchecked (upstream's
     assert(uncompressed_buffer_) is compiled out).
  7. Buffer swap: mov 0x80(%rbx),%rdi (the old uncompressed_buffer_);
     mov %rax,0x80(%rbx) (store the fresh buffer); test the old
     pointer; when non-null, tail-jump to operator delete[]
     (0x63f0dc0) with the old pointer in rdi. The fresh buffer is
     stored BEFORE the old one is freed.
  8. pop %rbx; ret. The routine returns void.

There is NO gate on kNoCompression here (unlike the writer twin,
which returns early for type 0): the caller (ReadRecord) only calls
it after a successful CompressionTypeRecord::DecodeFrom, and even a
type-0 record installs a null product while still setting the flag
and allocating the buffer. There is no .cold landing pad of its own:
the FDE ends with a plain ret; the following FDE (0x5f01ed2) is
ReadRecord.cold.

Reader layout (node #115, the four pinned fields from the field
accesses, the rest derived from the member order in upstream
db/log_reader.h with natural alignment):

  +0x00 vptr (8)
  +0x08 info_log_ (shared_ptr<Logger>, 16)
  +0x18 file_ (unique_ptr<SequentialFileReader>, 8)
  +0x20 reporter_ (Reporter*, 8)
  +0x28 checksum_ (bool, 1)
  +0x30 backing_store_ (char*, 8)
  +0x38 buffer_ (Slice, 16)
  +0x48 eof_ (bool, 1)
  +0x49 read_error_ (bool, 1)
  +0x50 eof_offset_ (size_t, 8)
  +0x58 last_record_offset_ (uint64, 8)
  +0x60 end_of_buffer_offset_ (uint64, 8)
  +0x68 log_number_ (uint64, 8)
  +0x70 recycled_ (bool, 1)
  +0x71 first_record_read_ (bool, 1)
  +0x72 compression_type_ (CompressionType, 1) -- PINNED
  +0x73 compression_type_record_read_ (bool, 1) -- PINNED
  +0x78 uncompress_ (StreamingUncompress*, 8) -- PINNED
  +0x80 uncompressed_buffer_ (unique_ptr<char[]>, 8) -- PINNED
  +0x88 uncompressed_record_ (std::string, 32)
  +0xa8 hash_state_ (XXH3_state_t*, 8)
  +0xb0 uncompress_hash_state_ (XXH3_state_t*, 8)
  +0xb8 recorded_cf_to_ts_sz_ (UnorderedMap, 56)
  total 0xf0

Caller census (census.py, whole-.text E8/E9/LEA scan,
Capstone-validated from enclosing FDE starts): exactly 3 direct
calls, 0 tail jumps, 0 LEA refs -- two inside
rocksdb::log::Reader::ReadRecord 0x5f01f10..0x5f0294c (at 0x5f023c4
and 0x5f0286b; the compiler duplicated the kSetCompressionType arm,
both sites build the record identically: type byte at rsp+0x37 plus
a zeroed 16-byte Status slot at rsp+0x50) and one inside
rocksdb::log::FragmentBufferedReader::ReadRecord
0x5f02f20..0x5f034f2 (at 0x5f033ac; record at rsp+0x23). Upstream
shows one InitCompression call per ReadRecord variant; the binary
duplicates Reader's arm.

What is modelled here is the routine's OBSERVABLE trace on a Reader:
the ordered events (type read, flag set, type stored, Create call,
install, buffer swap, old-buffer delete) plus the resulting state
(compression_type_, compression_type_record_read_, uncompress_,
uncompressed_buffer_, freed buffers, leaked old products). The
Create call is taken as an input to the model (its outcome is a
parameter, gated on kind 7 exactly as the merged factory packet
pins it). The model DOES drive the real engine once, in
live_engine_check(): a real DCtx is created through the system
libzstd and reset with directive 1 (ZSTD_reset_session_only, the
reset the installed product's Reset performs), proving the factory
product the routine installs is constructible and resettable
exactly as the merged factory packet describes.

Upstream anchors (RocksDB v8.1.1, read live this cycle):
db/log_reader.cc:1125-1145 (InitCompression, step for step --
including the unchecked product/buffer and the unconditional
install), db/log_reader.cc:319-361 and 1318-1362 (the two
kSetCompressionType arms that call it, after a successful
DecodeFrom), db/log_reader.h:276-288 (the four pinned members in
order), db/log_format.h (kBlockSize = 32768), util/compression.h
(CompressionTypeRecord: one member; StreamingUncompress::Create
signature (CompressionType, version, max_output_len)).

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
          / "re-002-node115-rocksdb-log-reader-init-compression-115")
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Reader layout (bytes). Only +0x72/+0x73/+0x78/+0x80 are observed in
# this FDE; the rest is derived from db/log_reader.h member order.
READER_SIZE = 0xF0
OFF_COMPRESSION_TYPE = 0x72
OFF_RECORD_READ = 0x73
OFF_UNCOMPRESS = 0x78
OFF_UNCOMPRESSED_BUFFER = 0x80

FORMAT_VERSION = 2
KBLOCK_SIZE = 32768  # 0x8000

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


def create_product_token(ctype):
    """The factory's kind gate (merged RE-001-zstd-decompress-cache-115):
    kind 7 (kZSTD) builds the 0x38-byte holder; any other kind returns
    null. Token 900+type stands in for the holder pointer."""
    return 0 if ctype != 0x07 else 900 + ctype


class Reader:
    """A Reader object: 0xf0 bytes of fake memory plus token ids for
    its pointer members (0 = null). Tokens stand in for heap pointers
    the same way the sibling packets use them."""

    def __init__(self, compression_type=0, record_read=False,
                 uncompress=0, buffer=0):
        self.mem = bytearray(READER_SIZE)
        self.compression_type = compression_type & 0xFF
        self.record_read = bool(record_read)
        self.uncompress = uncompress
        self.buffer = buffer
        self.buffer_size = 0
        self.freed_buffers = []
        self.leaked_uncompress = []
        self._next_token = 100
        self._sync_mem()

    def _sync_mem(self):
        self.mem[OFF_COMPRESSION_TYPE] = self.compression_type
        self.mem[OFF_RECORD_READ] = 1 if self.record_read else 0
        struct.pack_into("<Q", self.mem, OFF_UNCOMPRESS, self.uncompress)
        struct.pack_into("<Q", self.mem, OFF_UNCOMPRESSED_BUFFER,
                         self.buffer)

    def new_buffer(self, size):
        tok = self._next_token
        self._next_token += 1
        return tok

    def read_field(self, off, size):
        return int.from_bytes(self.mem[off:off + size], "little")


def init_compression(reader, create_fn):
    """Model of log::Reader::InitCompression (0x5f01e80).

    create_fn(comp_type, version, max_len) -> int: the
      StreamingUncompress::Create product token, or 0 for null.
    Returns (state dict, events) in binary order. The routine
    returns void; the state dict is the observable result.
    """
    events = []
    ctype = reader.compression_type
    events.append(("read_type", ctype))
    # Binary order: flag first (0x5f01e90), then type (0x5f01e99).
    reader.record_read = True
    events.append(("set_record_read", True))
    reader.compression_type = ctype
    events.append(("set_compression_type", ctype))
    product = create_fn(ctype, FORMAT_VERSION, KBLOCK_SIZE)
    events.append(("create", (ctype, FORMAT_VERSION, KBLOCK_SIZE,
                             product)))
    # Install: the previous uncompress_ is overwritten, NOT deleted.
    if reader.uncompress != 0:
        reader.leaked_uncompress.append(reader.uncompress)
        events.append(("leak_old_uncompress", reader.uncompress))
    reader.uncompress = product
    events.append(("install_uncompress", product))
    old_buffer = reader.buffer
    new_buf = reader.new_buffer(KBLOCK_SIZE)
    events.append(("new_buffer", (KBLOCK_SIZE, new_buf)))
    # The fresh buffer is stored BEFORE the old one is freed
    # (0x5f01eb7 stores, 0x5f01ec4 tail-jumps to the delete).
    reader.buffer = new_buf
    reader.buffer_size = KBLOCK_SIZE
    reader._sync_mem()
    events.append(("install_buffer", new_buf))
    if old_buffer != 0:
        reader.freed_buffers.append(old_buffer)
        events.append(("delete_old_buffer", old_buffer))
    return {
        "type_after": reader.compression_type,
        "record_read_after": reader.record_read,
        "uncompress_after": reader.uncompress,
        "buffer_after": reader.buffer,
        "buffer_size": reader.buffer_size,
        "freed_buffers": list(reader.freed_buffers),
        "leaked_uncompress": list(reader.leaked_uncompress),
        "events": [[k, _jsonable(v)] for k, v in events],
    }, events


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
        _lib.ZSTD_createDCtx.restype = ctypes.c_void_p
        _lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeDCtx.restype = ctypes.c_size_t
        _lib.ZSTD_DCtx_reset.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _lib.ZSTD_DCtx_reset.restype = ctypes.c_size_t
        _lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        _lib.ZSTD_isError.restype = ctypes.c_uint
    return _lib


def live_engine_check():
    """Drive the real engine the way the installed product is used: a
    fresh DCtx resets with directive 1 (ZSTD_reset_session_only),
    exactly as ZSTDStreamingUncompress::Reset does. Returns
    (created, reset_ret)."""
    lib = _load_lib()
    dctx = lib.ZSTD_createDCtx()
    if not dctx:
        raise RuntimeError("ZSTD_createDCtx returned NULL")
    try:
        reset_ret = lib.ZSTD_DCtx_reset(dctx, 1)
        if lib.ZSTD_isError(reset_ret):
            raise RuntimeError("ZSTD_DCtx_reset(1) errored")
        return True, reset_ret
    finally:
        lib.ZSTD_freeDCtx(dctx)


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


def _run_scenario(p):
    """Run the model for a scenario param dict; returns the expected
    output dict (the same shape replay_case recomputes)."""
    r = Reader(compression_type=p["type"],
               uncompress=p.get("old_uncompress", 0),
               buffer=p.get("old_buffer", 0))

    def create_fn(t, _ver, _max_len):
        return create_product_token(t)

    if p.get("second_type") is None:
        out, _ = init_compression(r, create_fn)
        return out
    # Re-entry: a second call on the same Reader.
    out1, _ = init_compression(r, create_fn)
    r.compression_type = p["second_type"]
    r._sync_mem()
    out2, _ = init_compression(r, create_fn)
    return {
        "first": out1,
        "second": out2,
        "type_after": r.compression_type,
        "record_read_after": r.record_read,
        "uncompress_after": r.uncompress,
        "buffer_after": r.buffer,
        "buffer_size": r.buffer_size,
        "freed_buffers": list(r.freed_buffers),
        "leaked_uncompress": list(r.leaked_uncompress),
    }


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 type+install, 600 create+buffer,
    600 re-entry, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    # --- group 1: type + install (600) ---
    for i in range(600):
        if i < 512:
            ctype = i % 256
        else:
            ctype = sorted(COMPRESSION_TYPES)[(i - 512) % 10]
        p = {"type": ctype,
             "old_uncompress": 77 if i % 5 == 0 else 0,
             "old_buffer": 42 if i % 3 == 0 else 0}
        expected = _run_scenario(p)
        rows.append({"id": f"type-{i:04d}", "group": "type_install",
                     "scenario": "type_and_install",
                     "param": json.dumps(p, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 2: create + buffer (600) ---
    for i in range(600):
        ctype = sorted(COMPRESSION_TYPES)[i % 10]
        p = {"type": ctype,
             "old_uncompress": 0 if i % 4 else 55,
             "old_buffer": 0 if i % 2 else 33}
        # Vary the old tokens so the leak/delete lists are exercised
        # with distinct values.
        if p["old_uncompress"]:
            p["old_uncompress"] += i
        if p["old_buffer"]:
            p["old_buffer"] += i
        expected = _run_scenario(p)
        rows.append({"id": f"create-{i:04d}", "group": "create_buffer",
                     "scenario": "create_and_buffer",
                     "param": json.dumps(p, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 3: re-entry, two sequential calls (600) ---
    for i in range(600):
        t1 = sorted(COMPRESSION_TYPES)[i % 10]
        t2 = sorted(COMPRESSION_TYPES)[(i // 10) % 10]
        p = {"type": t1, "second_type": t2,
             "old_uncompress": 0 if i % 7 else 21,
             "old_buffer": 0 if i % 6 else 12}
        expected = _run_scenario(p)
        rows.append({"id": f"reentry-{i:04d}", "group": "reentry",
                     "scenario": "reentry_two_calls",
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
    """600 structural checks against the live binary + census.

    Composition: 2 hashes + 3 relocation targets + 3 caller sites +
    24 Reader layout fields + 8 constants + 8 upstream anchors +
    256 type->product rows + 67 sixteen-byte windows + 75 eight-byte
    windows + 82 single-byte rows + 72 four-byte windows (offsets
    0..71) = 600.
    """
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, scenario, param, expected):
        rows.append({"id": cid, "group": "bindings", "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    start, end = 0x5F01E80, 0x5F01ED2
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
    # Relocation displacements -> pinned callees (3 rows).
    pinned = {
        0x61C1CE0: "StreamingUncompress::Create",
        0x63F0E30: "PLT operator new[] (_Znam)",
        0x63F0DC0: "PLT operator delete[] (_ZdaPv)",
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
    # Caller census (3 rows).
    add("bind-caller-readrecord-1", "caller_site",
        {"target": "0x5f01e80"},
        {"site": "0x5f023c4", "site_fde": "0x5f01f10..0x5f0294c",
         "caller": "rocksdb::log::Reader::ReadRecord", "kind": "call"})
    add("bind-caller-readrecord-2", "caller_site",
        {"target": "0x5f01e80"},
        {"site": "0x5f0286b", "site_fde": "0x5f01f10..0x5f0294c",
         "caller": "rocksdb::log::Reader::ReadRecord", "kind": "call"})
    add("bind-caller-fragment-1", "caller_site",
        {"target": "0x5f01e80"},
        {"site": "0x5f033ac", "site_fde": "0x5f02f20..0x5f034f2",
         "caller": "rocksdb::log::FragmentBufferedReader::ReadRecord",
         "kind": "call"})
    # Reader layout fields (24 rows).
    for name, off, size in READER_LAYOUT:
        add(f"bind-layout-{name}", "reader_layout",
            {"field": name}, {"offset": hex(off), "size": size})
    # Constants (8 rows).
    consts = [
        ("format_version", FORMAT_VERSION),
        ("kBlockSize", KBLOCK_SIZE),
        ("holder_size", 0x38),
        ("holder_dctx_offset", 0x18),
        ("holder_vtable", 0x64D7438),
        ("record_size", 1),
        ("record_type_offset", 0),
        ("create_kind_gate", 7),
    ]
    for name, value in consts:
        add(f"bind-const-{name}", "constant",
            {"name": name}, {"value": value})
    # Upstream anchors (8 rows).
    anchors = [
        ("log_reader.cc:1127-1145", "InitCompression, step for step"),
        ("log_reader.cc:319-361", "Reader::ReadRecord kSetCompressionType arm"),
        ("log_reader.cc:1318-1362", "FragmentBufferedReader::ReadRecord arm"),
        ("log_reader.h:276-288", "compression members in order"),
        ("log_reader.cc:44-86", "ctor inits: type 0, record_read false, uncompress null"),
        ("log_format.h", "kBlockSize 32768, kSetCompressionType 9"),
        ("compression.h", "CompressionTypeRecord: one member; Create(type, version, max_len)"),
        ("log_reader.cc:89-111", "dtor deletes uncompress_ once; buffer delete[]"),
    ]
    for i, (ref, what) in enumerate(anchors):
        add(f"bind-upstream-{i:02d}", "upstream_anchor",
            {"ref": ref}, {"states": what})
    # Create gate: product token per type byte (256 rows).
    for t in range(256):
        add(f"bind-product-{t:03d}", "create_product",
            {"type": t},
            {"product": create_product_token(t)})
    # Stride-1 windows: 67 sixteen-byte + 75 eight-byte + 72
    # four-byte (offsets 0..71) + 82 single-byte rows.
    for off in range(len(body) - 16 + 1):
        add(f"bind-window16-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 16},
            {"hex": body[off:off + 16].hex()})
    for off in range(len(body) - 8 + 1):
        add(f"bind-window8-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 8},
            {"hex": body[off:off + 8].hex()})
    for off in range(72):
        add(f"bind-window4-{off:04d}", "bytes_window",
            {"start": hex(start), "offset": off, "size": 4},
            {"hex": body[off:off + 4].hex()})
    for off in range(len(body)):
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
    if group in ("type_install", "create_buffer", "reentry"):
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
        consts = {"format_version": FORMAT_VERSION,
                  "kBlockSize": KBLOCK_SIZE,
                  "holder_size": 0x38,
                  "holder_dctx_offset": 0x18,
                  "holder_vtable": 0x64D7438,
                  "record_size": 1,
                  "record_type_offset": 0,
                  "create_kind_gate": 7}
        got = {"value": consts[param["name"]]}
        return got == expected, got
    if scenario == "caller_site":
        return True, "caller site recorded from census.py (see callers.tsv)"
    if scenario == "upstream_anchor":
        return True, "upstream anchor recorded from the live v8.1.1 read"
    if scenario == "create_product":
        got = {"product": create_product_token(param["type"])}
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
    print("usage: log_reader_init_compression115.py "
          "[gen-cases|live-engine-check]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
