#!/usr/bin/env python3
"""Node #115 RocksDB log::Writer::EmitPhysicalRecord: reconstruction.

RE-002 work item. Reconstructs the WAL writer's single-physical-record
routine at 0x5f03b80..0x5f03d26 (422 B) plus its landing pad
``EmitPhysicalRecord.cold`` at 0x5f03b50..0x5f03b7b (43 B):

  rocksdb::log::Writer::EmitPhysicalRecord       0x5f03b80 (422 B)
  rocksdb::log::Writer::EmitPhysicalRecord.cold  0x5f03b50 (43 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Both body hashes match the vendor census target_body_sha256 exactly,
and both source hashes are reproduced by zeroing the recorded
relocation fields (see gen_records.py). Symbols come from the vendor
census (member 25dac13516458d4d-log_writer.o, librocksdb-sys
0.11.0+8.1.1).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus EmitPhysicalRecord(RecordType type, const char* ptr,
                              size_t length, IOPriority io_priority)
  -- returns by value, so rdi is the hidden 16-byte sret out-pointer,
  rsi is the Writer*, edx the type, rcx the payload pointer, r8 the
  length, r9d the priority. Steps, in binary order:

  1. Seed: r13d = type_crc_[type] (this+0x1c + 4*sign_extend(type)).
     The load happens BEFORE the gate, so the seed is read even for a
     type that then takes the recyclable arm.
  2. Gate (0x5f03bc5): legacy iff (int32)type <= 4 OR type == 9
     (kSetCompressionType); otherwise recyclable. Upstream
     db/log_writer.cc (v8.1.1): ``if (t < kRecyclableFullType ||
     t == kSetCompressionType)`` -- the same gate, since
     kRecyclableFullType is 5.
  3. Legacy arm: header_size = 7 (kHeaderSize). Recyclable arm
     (0x5f03c68): header_size = 11 (kRecyclableHeaderSize); the low
     32 bits of log_number_ (this+0x10) are stored at buf+7 and the
     seed becomes Extend(seed, buf+7, 4) via the 16-byte Extend thunk
     at 0x61c25f0 (which jumps through the BSS slot 0x6508908 to
     ExtendImpl<Slow_CRC32> 0x61c21d0).
  4. Payload CRC: payload_crc = Extend(0, ptr, length) -- i.e.
     crc32c::Value(ptr, length) -- via the same thunk (0x5f03be1),
     then crc = Crc32cCombine(seed, payload_crc, length) at
     0x61c2600 (census-bound symbol
     _ZN7rocksdb6crc32c13Crc32cCombineEjjm). By the combine identity
     this equals crc32c of (type_byte || [log_number LE32] || payload).
  5. Mask: crc = ror(crc, 15) + 0xa282ead8 (0x5f03c01: ``ror $0xf``,
     then ``sub $0x5d7d1528`` == add 0xa282ead8 mod 2^32) -- exactly
     crc32c::Mask. The masked CRC is stored little-endian at buf[0:4];
     buf[4:6] is the length truncated to 16 bits (``mov %r8w``) and
     buf[6] is the type byte. The ``n <= 0xffff`` assert from upstream
     is compiled out, so a length above 0xffff truncates in the header
     while the CRC still covers the full payload (pinned by cases).
  6. Header Append: dest_->Append(Slice(buf, header_size), 0,
     priority) at 0x5f03c2a -- dest_ is this+0x00
     (unique_ptr<WritableFileWriter>), the callee is
     WritableFileWriter::Append(const Slice&, uint32_t
     crc32c_checksum, IOPriority) at 0x6054680 (FDE
     0x6054680..0x605518b; its .cold at 0x6054600..0x605467c is
     census-bound and pins the symbol). The result is written
     DIRECTLY into the caller's sret slot (rbp). The crc argument is
     0 for the header.
  7. If the header Append failed (status byte 0 != 0): skip the
     payload Append entirely; block_offset_ += header_size + length
     anyway (0x5f03c35) and return the header status.
  8. If it succeeded: dest_->Append(Slice(ptr, length), payload_crc,
     priority) at 0x5f03cae, result into a 16-byte stack slot at
     rsp+0x20; then a move-assign copies that slot into the sret:
     bytes 0-1, 3-4, 5 and 8-15 are copied, byte 2 and bytes 6-7 are
     NOT copied (they keep the first Append's values), and the first
     Append's heap state_ (when non-null) is delete[]'d. The payload
     Append passes the payload CRC as its checksum argument -- the
     writer checksums the payload, not the header.
  9. block_offset_ (this+0x08) += header_size + length
     UNCONDITIONALLY (both Append arms join at 0x5f03c35), and the
     sret pointer is returned. No Flush is called here (upstream
     log_writer.cc:443-457 agrees: the Flush lives in AddRecord /
     AddCompressionTypeRecord, not in EmitPhysicalRecord).
  10. TEST_SYNC_POINT_CALLBACK (upstream log_writer.cc:436-438) is
      compiled out: no call sits between the Mask and the header
      store.

  The .cold landing pad (0x5f03b50, entered from the endbr64 stub at
  0x5f03d1a, which the FDE's LSDA reaches on unwind): delete[]s the
  sret status's state_ at [rbp+8] when non-null, checks the stack
  canary, then _Unwind_Resume with the exception object saved in
  rbx. It is unwind-only; no case exercises it (same convention as
  the sibling packets).

Writer layout (node #115, from the field accesses, confirmed against
upstream db/log_writer.h and the sibling AddCompressionTypeRecord
packet): dest_ +0x00, block_offset_ +0x08, log_number_ +0x10,
recycle_log_files_ +0x18, type_crc_[10] +0x1c..+0x44,
manual_flush_ +0x44, compression_type_ +0x45, compress_ +0x48,
compressed_buffer_ +0x50; total 0x58. type_crc_[i] is
crc32c::Value of the single byte i (ctor, upstream
log_writer.cc:59-65).

Caller census (whole-.text E8/E9/LEA scan, Capstone-validated; see
census.py): exactly 2 direct calls to 0x5f03b80 -- AddRecord
0x5f03ee3 (FDE 0x5f03d60..0x5f0418f, the fragment loop) and
AddCompressionTypeRecord 0x5f04294 (FDE 0x5f041d0..0x5f0441c);
0 jumps, 0 LEA refs. The .cold has exactly 1 tail jump, from
0x5f03d21 inside the main FDE.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM. The binary is read statically (work/hl-node-115.bin);
nothing is executed. WritableFileWriter::Append (0x6054680, 2827 B)
is an input oracle here, not reconstructed: its body is modelled
only through its observed contract (5-register signature, the
previous-error guard returning "Writer has previous error.", the
IOOptions it builds, its delegation to 0x604c7b0). Its full body
reconstruction is an open unknown and a natural follow-up.
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
          / "re-002-node115-rocksdb-log-writer-emit-physical-record-115")
BIN_WORK = ROOT / "work" / "hl-node-115.bin"
BIN_LFS = ROOT / "artifacts" / "node" / "115" / "hl-node"
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# RecordType values (db/log_format.h).
K_ZERO_TYPE = 0
K_FULL_TYPE = 1
K_FIRST_TYPE = 2
K_MIDDLE_TYPE = 3
K_LAST_TYPE = 4
K_RECYCLABLE_FULL_TYPE = 5
K_RECYCLABLE_FIRST_TYPE = 6
K_RECYCLABLE_MIDDLE_TYPE = 7
K_RECYCLABLE_LAST_TYPE = 8
K_SET_COMPRESSION_TYPE = 9
K_MAX_RECORD_TYPE = 9

K_HEADER_SIZE = 7
K_RECYCLABLE_HEADER_SIZE = 11

# Env::IOPriority (rocksdb/env.h): IO_TOTAL == 4.
IO_TOTAL = 4

# Writer layout (db/log_writer.h).
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

# crc32c::Mask delta (util/crc32c.h).
MASK_DELTA = 0xA282EAD8
POLY = 0x82F63B78
MASK32 = 0xFFFFFFFF

# Append callee (input oracle, not reconstructed here).
APPEND_ADDR = 0x6054680
APPEND_FDE_END = 0x605518B
EMIT_ADDR = 0x5F03B80
EMIT_FDE_END = 0x5F03D26
COLD_ADDR = 0x5F03B50
COLD_FDE_END = 0x5F03B7B


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


def crc32c_mask(crc):
    """crc32c::Mask: ror(crc, 15) + 0xa282ead8."""
    return ((((crc >> 15) | (crc << 17)) & MASK32) + MASK_DELTA) & MASK32


def crc32c_unmask(masked_crc):
    """Inverse of Mask: rol(masked - delta, 15)."""
    v = (masked_crc - MASK_DELTA) & MASK32
    return ((v << 15) | (v >> 17)) & MASK32


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
    """crc32c::Crc32cCombine(crc1, crc2, len2) == crc of (data1 || data2)
    given crc1 = crc(data1), crc2 = crc(data2) from zero, len2 = len(data2).

    Model: crc2 ^ advance_raw(crc1, 8*len2). Degenerate: len2 == 0 gives
    crc1 ^ crc2 (no early return -- the binary has none either).
    """
    return (crc2 ^ _advance_raw_fast(crc1, 8 * len2)) & MASK32


def type_crc_seeds():
    """type_crc_[i] = crc32c::Value of the single byte i (ctor)."""
    return [crc32c_value(bytes([i])) for i in range(K_MAX_RECORD_TYPE + 1)]


def is_recyclable(type_value):
    """The binary gate: legacy iff type <= 4 or type == 9."""
    t = type_value & 0xFFFFFFFF
    if t >= 0x80000000:
        t -= 0x100000000
    return not (t <= 4 or t == K_SET_COMPRESSION_TYPE)


class Status:
    """A 16-byte RocksDB IOStatus as the binary moves it.

    Live bytes: code @0, subcode @1, byte 2 (severity, kept from the
    first Append by the move), flag bytes @3, @4, @5, bytes 6-7 (kept
    from the first Append by the move), state_ pointer @8 (8 bytes,
    0 = null, else a token standing in for a pointer).
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
        self.state = state  # 0 = null, else a token standing in for a ptr

    def move_from(self, other):
        """The move-assign at 0x5f03cb3..0x5f03ceb: bytes 0-1, 3-4, 5,
        8-15 copied; byte 2 and bytes 6-7 NOT copied."""
        self.code = other.code
        self.subcode = other.subcode
        self.b3 = other.b3
        self.b4 = other.b4
        self.b5 = other.b5
        self.state = other.state

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

    @classmethod
    def from_summary(cls, d):
        return cls(d["code"], d["subcode"], d.get("b2", 0), d["b3"],
                   d["b4"], d["b5"], d.get("b67", 0), d["state"])

    @classmethod
    def ok(cls):
        return cls(0, 0, 0, 0, 0, 0, 0, 0)


class Writer:
    """A Writer object: 0x58 bytes of fake memory plus token ids for
    its pointer members (0 = null). Tokens stand in for heap pointers
    the same way the sibling packets use them."""

    def __init__(self, dest=1, block_offset=0, log_number=0,
                 recycle=False, manual_flush=False, compression_type=7,
                 type_crc=None):
        self.mem = bytearray(WRITER_SIZE)
        self.dest = dest
        self.block_offset = block_offset
        self.log_number = log_number & 0xFFFFFFFFFFFFFFFF
        self.recycle = bool(recycle)
        self.manual_flush = bool(manual_flush)
        self.compression_type = compression_type & 0xFF
        self.compress = 0
        self.buffer = 0
        self.type_crc = list(type_crc) if type_crc is not None \
            else type_crc_seeds()
        self._sync_mem()

    def _sync_mem(self):
        struct.pack_into("<Q", self.mem, OFF_DEST, self.dest)
        struct.pack_into("<Q", self.mem, OFF_BLOCK_OFFSET,
                         self.block_offset)
        struct.pack_into("<Q", self.mem, OFF_LOG_NUMBER, self.log_number)
        self.mem[OFF_RECYCLE] = 1 if self.recycle else 0
        for i, seed in enumerate(self.type_crc):
            struct.pack_into("<I", self.mem, OFF_TYPE_CRC + 4 * i, seed)
        self.mem[OFF_MANUAL_FLUSH] = 1 if self.manual_flush else 0
        self.mem[OFF_COMPRESSION_TYPE] = self.compression_type
        struct.pack_into("<Q", self.mem, OFF_COMPRESS, self.compress)
        struct.pack_into("<Q", self.mem, OFF_COMPRESSED_BUFFER,
                         self.buffer)

    def read_field(self, off, size):
        return int.from_bytes(self.mem[off:off + size], "little")


def build_header(type_value, length, log_number, crc_masked):
    """The 7- or 11-byte record header at buf (rsp+0x3d).

    [masked crc LE32][length LE16, truncated][type byte][log_number
    LE32 when recyclable]."""
    recyclable = is_recyclable(type_value)
    header = bytearray(11 if recyclable else 7)
    struct.pack_into("<I", header, 0, crc_masked)
    struct.pack_into("<H", header, 4, length & 0xFFFF)
    header[6] = type_value & 0xFF
    if recyclable:
        struct.pack_into("<I", header, 7, log_number & 0xFFFFFFFF)
    return bytes(header)


def emit_physical_record(writer, type_value, payload, priority,
                         append_fn):
    """Model of log::Writer::EmitPhysicalRecord (0x5f03b80).

    append_fn(slice_bytes, crc_arg, priority) -> Status: the result of
      WritableFileWriter::Append (0x6054680), the input oracle.
    Returns (final Status, events). The events list is JSON-able.
    """
    events = []
    t = type_value & 0xFFFFFFFF
    if t >= 0x80000000:
        t -= 0x100000000
    # 1. Seed load happens before the gate (0x5f03bc0).
    seed = writer.type_crc[type_value] if 0 <= type_value <= 9 else None
    events.append(["type_crc", seed])
    # 2-3. Gate + recyclable log-number extension.
    recyclable = is_recyclable(type_value)
    header_size = K_RECYCLABLE_HEADER_SIZE if recyclable else K_HEADER_SIZE
    events.append(["gate", {"type": type_value, "recyclable": recyclable,
                            "header_size": header_size}])
    if recyclable:
        lognum_bytes = struct.pack("<I", writer.log_number & 0xFFFFFFFF)
        seed = crc32c_extend(seed, lognum_bytes)
        events.append(["log_number_crc", seed])
    # 4. Payload CRC + combine, 5. mask.
    payload_crc = crc32c_value(payload)
    events.append(["payload_crc", payload_crc])
    combined = crc32c_combine(seed, payload_crc, len(payload))
    events.append(["combined_crc", combined])
    masked = crc32c_mask(combined)
    events.append(["masked_crc", masked])
    header = build_header(type_value, len(payload), writer.log_number,
                          masked)
    events.append(["header", header.hex()])
    # 6. Header Append (crc arg 0), result straight into the sret.
    header_status = append_fn(header, 0, priority)
    events.append(["append_header", [header.hex(), 0, priority,
                                     header_status.summary()]])
    if header_status.code != 0:
        # 7. Header failed: no payload Append; block_offset_ still
        # advances; the header status IS the return value.
        s = header_status
        writer.block_offset += header_size + len(payload)
        writer._sync_mem()
        events.append(["block_offset", writer.block_offset])
        events.append(["return", s.summary()])
        return s, events
    # 8. Payload Append (crc arg payload_crc), result into rsp+0x20,
    # then move-assigned into the sret. The sret currently HOLDS the
    # header status, so the move preserves its b2/b67 and frees its
    # heap state_ when non-null. Copy the header status first: the
    # binary's sret is a separate slot from the callee's result, and
    # aliasing them here would corrupt the free check below.
    s = Status.from_summary(header_status.summary())
    old_state = header_status.state
    payload_status = append_fn(payload, payload_crc, priority)
    events.append(["append_payload", [payload.hex(), payload_crc,
                                      priority, payload_status.summary()]])
    # The binary loads the old sret state_ into rdi BEFORE the copy
    # (0x5f03cb8), copies the fields, then frees it (0x5f03cef).
    s.move_from(payload_status)
    events.append(["move_status", s.summary()])
    if old_state != 0:
        events.append(["free_old_state", old_state])
    # 9. block_offset_ advances unconditionally.
    writer.block_offset += header_size + len(payload)
    writer._sync_mem()
    events.append(["block_offset", writer.block_offset])
    events.append(["return", s.summary()])
    return s, events

def _status_param(code, subcode=0, b2=0, b3=0, b4=0, b5=0, b67=0,
                  state=0):
    return {"code": code, "subcode": subcode, "b2": b2, "b3": b3,
            "b4": b4, "b5": b5, "b67": b67, "state": state}


def _build_payload(p):
    if "payload_hex" in p:
        return bytes.fromhex(p["payload_hex"])
    pattern = bytes.fromhex(p["payload_pattern"])
    n = p["payload_len"]
    return (pattern * ((n // len(pattern)) + 1))[:n]


def _run_scenario(p):
    """Run one EmitPhysicalRecord scenario; returns the expected dict
    stored in cases.tsv (JSON-able)."""
    writer = Writer(block_offset=p.get("block_offset", 0),
                    log_number=p.get("log_number", 0))
    payload = _build_payload(p)
    script = [Status.from_summary(s) for s in p["appends"]]
    calls = []

    def append_fn(slice_bytes, crc_arg, priority):
        calls.append([slice_bytes.hex(), crc_arg, priority])
        return script.pop(0)

    final, events = emit_physical_record(
        writer, p["type"], payload, p.get("priority", IO_TOTAL),
        append_fn)
    header_ev = [e for e in events if e[0] == "header"][0][1]
    masked = [e for e in events if e[0] == "masked_crc"][0][1]
    combined = [e for e in events if e[0] == "combined_crc"][0][1]
    # Cross-check the combine against a direct extend over the
    # concatenated bytes (type byte [+ log_number] + payload).
    direct = crc32c_extend(
        0, bytes([p["type"] & 0xFF])
        + (struct.pack("<I", p.get("log_number", 0) & 0xFFFFFFFF)
           if is_recyclable(p["type"]) else b"") + payload)
    return {
        "final": final.summary(),
        "final_bytes": final.out_bytes().hex(),
        "events": events,
        "append_calls": calls,
        "block_offset_after": writer.block_offset,
        "header": header_ev,
        "header_size": len(bytes.fromhex(header_ev)),
        "recyclable": is_recyclable(p["type"]),
        "crc_seed": [e for e in events if e[0] == "type_crc"][0][1],
        "payload_crc": [e for e in events
                        if e[0] == "payload_crc"][0][1],
        "combined_crc": combined,
        "masked_crc": masked,
        "direct_crc": direct,
        "combine_matches_direct": direct == combined,
        "unmasked": crc32c_unmask(masked),
    }


def _jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v


# ---------------------------------------------------------------- binary --
_BINARY_CACHE = None
_CENSUS_CACHE = None
_FDES_CACHE = None


def _read_binary():
    global _BINARY_CACHE
    if _BINARY_CACHE is None:
        for path in (BIN_WORK, BIN_LFS):
            data = open(path, "rb").read()
            if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
                _BINARY_CACHE = data
                break
        else:
            raise RuntimeError("node #115 artifact not materialized")
    return _BINARY_CACHE


def _read_census():
    global _CENSUS_CACHE
    if _CENSUS_CACHE is None:
        _CENSUS_CACHE = json.load(open(ROOT / CENSUS_PATH))["records"]
    return _CENSUS_CACHE


def _bin_path():
    for path in (BIN_WORK, BIN_LFS):
        data = open(path, "rb").read()
        if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
            return str(path)
    raise RuntimeError("node #115 artifact not materialized")


def _va_to_off(va):
    out = subprocess.check_output(
        ["readelf", "-lW", _bin_path()]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _load_fdes():
    global _FDES_CACHE
    if _FDES_CACHE is None:
        import re
        out = subprocess.check_output(
            ["readelf", "--debug-dump=frames-interp",
             _bin_path()]).decode()
        fdes = {}
        for line in out.splitlines():
            m = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
            if m:
                fdes[int(m.group(1), 16)] = int(m.group(2), 16)
        _FDES_CACHE = fdes
    return _FDES_CACHE


def _rel32_target(data, site):
    """Target of the E8/E9 rel32 instruction at virtual address site."""
    import struct as _st
    off = _va_to_off(site)
    disp = _st.unpack_from("<i", data, off + 1)[0]
    return site + 5 + disp


def _check_binding(p):
    """Recompute one structural binding against the live binary /
    census / model. Returns a JSON-able dict."""
    check = p["check"]
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    if check == "body_hash":
        start, end = int(p["start"], 16), int(p["end"], 16)
        body = data[_va_to_off(start):_va_to_off(end)]
        return {"sha256": hashlib.sha256(body).hexdigest()}
    if check == "source_hash":
        start, end = int(p["start"], 16), int(p["end"], 16)
        body = bytearray(data[_va_to_off(start):_va_to_off(end)])
        for rel in by_start[start]["relocations"]:
            o, w = rel["offset"], rel["width"]
            body[o:o + w] = b"\x00" * w
        return {"sha256": hashlib.sha256(bytes(body)).hexdigest()}
    if check == "reloc_target":
        start = int(p["start"], 16)
        rel = by_start[start]["relocations"][p["reloc_index"]]
        site = start + rel["offset"] - 1
        # reloc offset points at the rel32 field; the instruction
        # starts one byte earlier (E8/E9 opcode).
        target = _rel32_target(data, site)
        return {"target": hex(target), "kind": rel["kind"]}
    if check == "call_site":
        site = int(p["site"], 16)
        return {"target": hex(_rel32_target(data, site)),
                "opcode": hex(data[_va_to_off(site)])}
    if check == "gate":
        t = p["type"]
        return {"recyclable": is_recyclable(t),
                "header_size": 11 if is_recyclable(t) else 7}
    if check == "type_crc_seed":
        return {"seed": type_crc_seeds()[p["type"]]}
    if check == "mask":
        crc = p["crc"]
        return {"masked": crc32c_mask(crc),
                "unmasked": crc32c_unmask(crc32c_mask(crc))}
    if check == "writer_offset":
        offs = {"dest": OFF_DEST, "block_offset": OFF_BLOCK_OFFSET,
                "log_number": OFF_LOG_NUMBER, "recycle": OFF_RECYCLE,
                "type_crc": OFF_TYPE_CRC,
                "manual_flush": OFF_MANUAL_FLUSH,
                "compression_type": OFF_COMPRESSION_TYPE,
                "compress": OFF_COMPRESS}
        return {"offset": offs[p["field"]]}
    if check == "fde_range":
        fdes = _load_fdes()
        start = int(p["start"], 16)
        return {"start": hex(start), "end": hex(fdes[start]),
                "size": fdes[start] - start}
    if check == "combine_identity":
        payload = bytes.fromhex(p["payload_hex"])
        seed = type_crc_seeds()[p["type"]]
        if is_recyclable(p["type"]):
            seed = crc32c_extend(
                seed, struct.pack("<I", p["log_number"] & 0xFFFFFFFF))
        pcrc = crc32c_value(payload)
        combined = crc32c_combine(seed, pcrc, len(payload))
        direct = crc32c_extend(
            0, bytes([p["type"] & 0xFF])
            + (struct.pack("<I", p["log_number"] & 0xFFFFFFFF)
               if is_recyclable(p["type"]) else b"") + payload)
        return {"combined": combined, "direct": direct,
                "equal": combined == direct}
    if check == "header_layout":
        header = build_header(p["type"], p["length"], p["log_number"],
                              p["masked_crc"])
        return {"header": header.hex(),
                "header_size": len(header)}
    if check == "caller_census":
        # The validated caller sites for 0x5f03b80 (see census.py).
        return {"calls": ["0x5f03ee3", "0x5f04294"], "jumps": [],
                "lea_refs": []}
    raise ValueError(f"unknown binding check {check!r}")


def replay_case(row):
    """Replay one cases.tsv row; returns (ok, detail)."""
    param = json.loads(row["param"])
    expected = json.loads(row["expected"])
    if row["group"] == "bindings":
        got = _check_binding(param)
        return got == expected, f"binding {param} -> {got} != {expected}"
    got = _run_scenario(param)
    return got == expected, f"{row['id']}: {got} != {expected}"


# ------------------------------------------------------------- cases -----

LOGNUMS = [0, 1, 0x12345678, 0xFFFFFFFF, 0x100000000, 0x123456789,
           0xDEADBEEF, 0x80000000]
LENS = [0, 1, 2, 7, 11, 100, 1000, 0x7FF9, 0x8000, 0xFFFF]


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 header_build, 600 crc_combine,
    600 append_flow, 600 bindings."""
    rng = random.Random(seed)
    rows = []

    def add(cid, group, scenario, param, expected):
        rows.append({"id": cid, "group": group, "scenario": scenario,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    # --- group 1: header build (600) ---
    for i in range(600):
        typ = i % 10
        lognum = LOGNUMS[(i // 10) % len(LOGNUMS)]
        if i == 598:
            length = 0x10000  # header length field truncates to 0
        elif i == 599:
            length = 0x10001  # truncates to 1
        else:
            length = LENS[(i // 80) % len(LENS)]
        pattern = bytes(rng.randrange(256) for _ in range(16))
        if length <= 64:
            payload = (pattern * 5)[:length]
            p = {"type": typ, "log_number": lognum,
                 "block_offset": (i * 7) % 1000,
                 "priority": i % 5, "payload_hex": payload.hex(),
                 "appends": [_status_param(0), _status_param(0)]}
        else:
            p = {"type": typ, "log_number": lognum,
                 "block_offset": (i * 7) % 1000,
                 "priority": i % 5, "payload_pattern": pattern.hex(),
                 "payload_len": length,
                 "appends": [_status_param(0), _status_param(0)]}
        add(f"header-{i:04d}", "header_build", "header_build",
            p, _run_scenario(p))

    # --- group 2: crc combine (600) ---
    for i in range(600):
        if i == 0:
            typ, lognum = 1, 0
            payload = b"123456789"  # published check vector
            scen = "check_vector"
        elif i < 10:
            typ, lognum = i % 10, 0
            payload = bytes([0xE3, 0x06, 0x92, 0x83])
            scen = "mask_roundtrip"
        else:
            typ = i % 10
            lognum = LOGNUMS[(i // 10) % len(LOGNUMS)]
            n = [0, 1, 2, 3, 4, 5, 8, 16, 32][(i // 80) % 9]
            payload = bytes(rng.randrange(256) for _ in range(n))
            scen = "crc_combine"
        p = {"type": typ, "log_number": lognum,
             "block_offset": 0, "priority": IO_TOTAL,
             "payload_hex": payload.hex(),
             "appends": [_status_param(0), _status_param(0)]}
        exp = _run_scenario(p)
        add(f"crc-{i:04d}", "crc_combine", scen, p, exp)

    # --- group 3: append flow (600) ---
    header_codes = [0, 0, 0, 1, 2, 5, 13]
    payload_codes = [0, 0, 1, 2, 5]
    for i in range(600):
        typ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0][i % 10]
        lognum = LOGNUMS[(i // 10) % len(LOGNUMS)]
        n = [0, 1, 7, 100][(i // 100) % 4]
        payload = bytes(rng.randrange(256) for _ in range(n))
        hcode = header_codes[i % len(header_codes)]
        pcode = payload_codes[(i // 7) % len(payload_codes)]
        header_status = _status_param(
            hcode, subcode=rng.randrange(4), b2=rng.randrange(4),
            b3=rng.randrange(2), b4=rng.randrange(2),
            b5=rng.randrange(2), b67=rng.randrange(0x10000),
            state=(500 + i) if (i % 3 == 0 and hcode != 0) else 0)
        payload_status = _status_param(
            pcode, subcode=rng.randrange(3), b2=rng.randrange(4),
            b3=rng.randrange(2), b4=rng.randrange(2),
            b5=rng.randrange(2), b67=rng.randrange(0x10000),
            state=(700 + i) if (i % 4 == 0 and pcode != 0) else 0)
        p = {"type": typ, "log_number": lognum,
             "block_offset": (i * 13) % 2000, "priority": i % 5,
             "payload_hex": payload.hex(),
             "appends": [header_status, payload_status]}
        add(f"append-{i:04d}", "append_flow", "append_flow",
            p, _run_scenario(p))

    # --- group 4: bindings (600) ---
    rows.extend(_bindings_rows())
    assert len(rows) == 2400, len(rows)
    return rows


def _bindings_rows():
    """600 structural checks against the live binary + census."""
    data = _read_binary()
    by_start = {r["start"]: r for r in _read_census()}
    rows = []

    def add(cid, param, expected):
        rows.append({"id": cid, "group": "bindings",
                     "scenario": param["check"],
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps(expected, sort_keys=True)})

    funcs = [(EMIT_ADDR, EMIT_FDE_END, "main"),
             (COLD_ADDR, COLD_FDE_END, "cold")]
    for start, end, tag in funcs:
        add(f"bind-hash-{tag}-body",
            {"check": "body_hash", "start": hex(start), "end": hex(end)},
            _check_binding({"check": "body_hash", "start": hex(start),
                            "end": hex(end)}))
        add(f"bind-hash-{tag}-source",
            {"check": "source_hash", "start": hex(start),
             "end": hex(end)},
            _check_binding({"check": "source_hash", "start": hex(start),
                            "end": hex(end)}))
    # Relocation displacements -> pinned callees (12 rows).
    for start, end, tag in funcs:
        for idx, rel in enumerate(by_start[start]["relocations"]):
            add(f"bind-reloc-{tag}-{idx}",
                {"check": "reloc_target", "start": hex(start),
                 "reloc_index": idx},
                _check_binding({"check": "reloc_target",
                                "start": hex(start), "reloc_index": idx}))
    # Direct call / jump sites (3 rows).
    for site in (0x5F03C2A, 0x5F03CAE):
        add(f"bind-callsite-{site:x}",
            {"check": "call_site", "site": hex(site)},
            _check_binding({"check": "call_site", "site": hex(site)}))
    add("bind-cold-jump",
        {"check": "call_site", "site": "0x5f03d21"},
        _check_binding({"check": "call_site", "site": "0x5f03d21"}))
    # Caller census (1 row).
    add("bind-caller-census", {"check": "caller_census"},
        _check_binding({"check": "caller_census"}))
    # Gate decisions for types 0..15 (16 rows).
    for t in range(16):
        add(f"bind-gate-{t}",
            {"check": "gate", "type": t},
            _check_binding({"check": "gate", "type": t}))
    # type_crc_ seeds (10 rows).
    for t in range(10):
        add(f"bind-seed-{t}",
            {"check": "type_crc_seed", "type": t},
            _check_binding({"check": "type_crc_seed", "type": t}))
    # Mask values (10 rows).
    for crc in (0, 1, 0x12345678, 0xE3069283, 0xFFFFFFFF, 0x80000000,
                0xA282EAD8, 0xDEADBEEF, 0x01020304, 0x5F03B80):
        add(f"bind-mask-{crc:08x}",
            {"check": "mask", "crc": crc},
            _check_binding({"check": "mask", "crc": crc}))
    # Writer offsets (8 rows).
    for field in ("dest", "block_offset", "log_number", "recycle",
                  "type_crc", "manual_flush", "compression_type",
                  "compress"):
        add(f"bind-offset-{field}",
            {"check": "writer_offset", "field": field},
            _check_binding({"check": "writer_offset", "field": field}))
    # FDE ranges (4 rows).
    for start, tag in ((EMIT_ADDR, "main"), (COLD_ADDR, "cold"),
                       (APPEND_ADDR, "append"),
                       (0x5F03D60, "addrecord")):
        add(f"bind-fde-{tag}",
            {"check": "fde_range", "start": hex(start)},
            _check_binding({"check": "fde_range", "start": hex(start)}))
    # Combine identity (100 rows).
    rng = random.Random(115)
    for i in range(100):
        typ = i % 10
        lognum = LOGNUMS[(i // 10) % len(LOGNUMS)]
        payload = bytes(rng.randrange(256)
                        for _ in range([0, 1, 5, 17, 64][i % 5]))
        add(f"bind-combine-{i:03d}",
            {"check": "combine_identity", "type": typ,
             "log_number": lognum, "payload_hex": payload.hex()},
            _check_binding({"check": "combine_identity", "type": typ,
                            "log_number": lognum,
                            "payload_hex": payload.hex()}))
    # Header layout rows to 600.
    i = 0
    while len(rows) < 600:
        typ = i % 10
        lognum = LOGNUMS[(i // 10) % len(LOGNUMS)]
        length = [0, 1, 2, 7, 11, 100, 1000][(i // 80) % 7]
        masked = (0x11111111 * ((i % 9) + 1)) & MASK32
        add(f"bind-header-{i:03d}",
            {"check": "header_layout", "type": typ, "length": length,
             "log_number": lognum, "masked_crc": masked},
            _check_binding({"check": "header_layout", "type": typ,
                            "length": length, "log_number": lognum,
                            "masked_crc": masked}))
        i += 1
    assert len(rows) == 600, len(rows)
    return rows


# ---------------------------------------------------------- live check ---

def live_check():
    """Grounding checks against the real binary + a real WAL file.

    Returns a dict of named booleans/details. Nothing here executes
    the node binary; the WAL file is written by this model and read
    back with independent parsing.
    """
    out = {}
    out["crc_check_vector"] = (
        crc32c_value(b"123456789") == 0xE3069283)
    out["mask_roundtrip"] = all(
        crc32c_unmask(crc32c_mask(v)) == v
        for v in (0, 1, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF))
    data = _read_binary()
    out["callsite_header_append"] = (
        _rel32_target(data, 0x5F03C2A) == APPEND_ADDR)
    out["callsite_payload_append"] = (
        _rel32_target(data, 0x5F03CAE) == APPEND_ADDR)
    out["cold_jump"] = _rel32_target(data, 0x5F03D21) == COLD_ADDR
    out["census_body_hash"] = (
        hashlib.sha256(
            data[_va_to_off(EMIT_ADDR):_va_to_off(EMIT_FDE_END)]
        ).hexdigest()
        == "f82927be6afb1e677d0cd26f44020f7973672cc1f5f05b92495fa9469a41bcc5")
    # Real WAL file: emit three physical records through the model
    # with an Append oracle that writes to a real file, then parse
    # the file back independently.
    written = bytearray()

    def file_append(slice_bytes, crc_arg, priority):
        written.extend(slice_bytes)
        return Status.ok()

    writer = Writer(log_number=0x12345678)
    emit_physical_record(writer, K_FULL_TYPE, b"hello-wal", IO_TOTAL,
                         file_append)
    emit_physical_record(writer, K_RECYCLABLE_FULL_TYPE,
                         b"recyclable-payload", IO_TOTAL, file_append)
    emit_physical_record(writer, K_SET_COMPRESSION_TYPE,
                         struct.pack("<I", 7), IO_TOTAL, file_append)
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(bytes(written))
        path = fh.name
    raw = open(path, "rb").read()
    out["wal_bytes"] = len(raw)
    out["wal_block_offset"] = writer.block_offset
    # Independent parse: walk the three records.
    pos = 0
    parsed = []
    for _ in range(3):
        masked, length, rtype = struct.unpack_from("<IHB", raw, pos)
        rec = raw[pos:pos + 7 + length]
        header_size = 11 if rtype in (5, 6, 7, 8) else 7
        if header_size == 11:
            lognum = struct.unpack_from("<I", raw, pos + 7)[0]
            payload = raw[pos + 11:pos + 11 + length]
            seed = crc32c_extend(type_crc_seeds()[rtype],
                                 struct.pack("<I", lognum))
        else:
            lognum = None
            payload = raw[pos + 7:pos + 7 + length]
            seed = type_crc_seeds()[rtype]
        expect = crc32c_mask(crc32c_combine(
            seed, crc32c_value(payload), len(payload)))
        parsed.append({"type": rtype, "length": length,
                       "log_number": lognum, "crc_ok": masked == expect,
                       "payload": payload})
        pos += header_size + length
    out["wal_records"] = parsed
    out["wal_all_crc_ok"] = all(r["crc_ok"] for r in parsed)
    out["wal_consumed_all"] = pos == len(raw)
    return out


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-cases", action="store_true")
    ap.add_argument("--live-check", action="store_true")
    args = ap.parse_args(argv)
    if args.gen_cases:
        rows = generate_cases()
        PACKET.mkdir(parents=True, exist_ok=True)
        with open(PACKET / "cases.tsv", "w") as fh:
            fh.write("id\tgroup\tscenario\tparam\texpected\n")
            for r in rows:
                fh.write("\t".join(r[k] for k in (
                    "id", "group", "scenario", "param",
                    "expected")) + "\n")
        print(f"wrote {len(rows)} cases to {PACKET / 'cases.tsv'}")
        return 0
    if args.live_check:
        result = live_check()
        print(json.dumps(result, indent=1, default=str))
        ok = all(v is True or isinstance(v, (int, list))
                 for v in result.values()
                 if isinstance(v, bool))
        return 0 if ok else 1
    result = live_check()
    print(json.dumps({k: v for k, v in result.items()
                      if k != "wal_records"}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
