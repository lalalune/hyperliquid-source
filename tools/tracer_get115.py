#!/usr/bin/env python3
"""Python model of node #115's rocksdb::Tracer::Get.

Reconstructs one function from the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...):

  * Tracer::Get  0x61b1e40
    (FDE 0x61b1e40..0x61b21ca, 906 bytes; census node115-vendor-61b1e40;
    body SHA-256 cab72ce3...; source SHA-256 23acc0fa... reproduced
    exactly by zeroing its 21 census relocations, kinds 2/4/42 --
    the single kind-42 site, offset 178, is the gotpcrelx-mov-lea
    relaxation of the SystemClockWrapper::NowMicros address load)

Get is the second of the five recording methods (Write, Get,
IteratorSeek, IteratorSeekForPrev, MultiGet) that feed the gate
modelled in tools/tracer_header_footer115.py (open PR #5870, same
author): it stamps a Trace with the tracer clock, sets the
kGetCFID and kGetKey bits in the payload map, serializes the
column-family id (as a fixed u32) and the key (length-prefixed),
and hands the trace to WriteTrace.  The binary is never executed;
this tool is a behavioural model of the one function only.

Order of operations in the binary (0x61b1e40..0x61b21ca):

  1. Trace.type = 4 (kTraceGet, the immediate byte at 0x61b1e76).
     The type byte lives in its own stack slot (rsp+0x13) and is
     passed by address to ShouldSkipTrace (lea 0x13(%rsp) at
     0x61b1e71); it is copied into trace.type (rsp+0x28) only
     after the gate passes (movzbl at 0x61b200c, store at
     0x61b201b).
  2. ShouldSkipTrace(this, type) (0x61b1930, call at 0x61b1e7b):
     a set return skips at once and Get returns Status::OK()
     without consulting the clock or the writer.
  3. ts = clock_->NowMicros(): the same 13-layer
     SystemClockWrapper::NowMicros (0x5d4d490) fast path as
     WriteHeader/WriteFooter/Write -- each layer's vtable slot 19
     (+0x98) is compared against 0x5d4d490 (the expected function
     as an immediate, lea at 0x61b1eef -- the kind-42 site) and
     followed through +0x20; the first layer whose slot differs
     calls that slot's function directly (0x61b2000).  The
     observable result is the innermost clock's NowMicros().
  4. TracerHelper::SetPayloadMap(trace.payload_map, 2) (0x61b18b0,
     call at 0x61b202c) then SetPayloadMap(trace.payload_map, 3)
     (call at 0x61b203b): bts bits 2 (kGetCFID) and 3 (kGetKey) --
     so the in-memory payload_map becomes 12 (it starts at 0).
  5. PutFixed64(&payload, payload_map): the 8 little-endian bytes
     of the map (0c 00 00 00 00 00 00 00) appended to the payload
     string (with the std::string length guard).
  6. PutFixed32(&payload, column_family->GetID()): the CF id is
     read through the ColumnFamilyHandle vtable slot 3 (0x18)
     (call at 0x61b2081) and its 4 little-endian bytes are
     appended (again with the length guard).
  7. PutLengthPrefixedSlice(&payload, key): EncodeVarint32(char*,
     uint32_t) (0x61bd410, its own FDE 0x61bd410..0x61bd4e9)
     writes the LEB128 varint of the LOW 32 BITS of the key size
     (mov 0x8(%r12),%esi -- a 32-bit load) into a 5-byte stack
     buffer, then the varint bytes and the key bytes are appended
     (each with the std::string length guard).  Note the split:
     the varint encodes (uint32_t)size while the append copies
     the full size_t -- a >4 GiB key would prefix the truncated
     length; untestable at that scale, recorded from the
     disassembly.
  8. return WriteTrace(trace) (0x61b1a10, call at 0x61b211e):
     EncodeTrace + TraceWriter::Write (slot 2); the returned
     Status is forwarded unchanged (writer errors propagate).

The key's bytes: the Slice argument is {data at +0x00, size at
+0x08}; the model takes the key bytes directly.  The CF id comes
from ColumnFamilyHandle::GetID() (vtable slot 3, 0x18); the model
takes the resolved u32 id as its input.

Tracer object layout (from the constructor 0x61b3e60, as in the
header/footer packet): +0x00 SystemClock*, +0x08..0x28 the 32-byte
TraceOptions (word 0 max_trace_file_size, word 1 sampling period,
word 2 per-type skip flags, word 3 preserve_write_order),
+0x28 unique_ptr<TraceWriter>, +0x30 sampling counter.

Trace layout: timestamp u64 at +0x00, type u8 at +0x08,
payload_map u64 at +0x10, payload std::string at +0x18.

Status codes follow rocksdb::Status::Code (kOk=0, kCorruption=2,
kIncomplete=7).  Get returns a Status by value (hidden sret
Status* in rdi): this in rsi, the ColumnFamilyHandle* in rdx,
the key Slice* in rcx.

Usage:
  python3 tools/tracer_get115.py --write-cases <path>
      Regenerate cases.tsv (2,400 rows) from the seeded generator.
  python3 tools/tracer_get115.py --demo
      Print a short demo: one traced get and one skipped one.
"""

import argparse
import hashlib
import random
import struct
import sys
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

# TraceType values (include/rocksdb/trace_record.h, confirmed by the
# codec packet's upstream read).  Only kTraceGet is used here.
K_TRACE_GET = 4

# TracePayloadType values (trace_replay/trace_replay.h, confirmed by
# the header/footer packet's upstream read).  Get sets bits 2 and 3.
K_EMPTY_PAYLOAD = 0
K_WRITE_BATCH_DATA = 1
K_GET_CF_ID = 2
K_GET_KEY = 3

# Status codes (rocksdb::Status::Code).
K_OK = 0
K_CORRUPTION = 2
K_INCOMPLETE = 7

# std::string maximum size (libstdc++ _S_max_size).
MAX_STRING_SIZE = 0x3FFFFFFFFFFFFFFF

# ShouldSkipTrace jump table (rodata 0x97c5f4), as modelled in the
# header/footer packet: the mask bit of this+0x18 tested per type.
_SKIP_MASKS = {
    3: 0x02,  # kTraceWrite
    K_TRACE_GET: 0x01,
    5: 0x04,  # kTraceIteratorSeek
    6: 0x08,  # kTraceIteratorSeekForPrev
    13: 0x10,  # kTraceMultiGet
}


class LengthError_(ValueError):
    """Mirror of std::length_error from std::string append."""


class Status:
    """A rocksdb::Status value: code + message (empty when OK)."""

    def __init__(self, code=K_OK, message=b""):
        self.code = code
        self.message = bytes(message)

    def ok(self):
        return self.code == K_OK

    def __eq__(self, other):
        return (
            isinstance(other, Status)
            and self.code == other.code
            and self.message == other.message
        )

    def __repr__(self):
        if self.ok():
            return "Status(OK)"
        return f"Status(code={self.code}, message={self.message!r})"


class Trace:
    """A rocksdb::Trace value: ts u64, type u8, payload_map u64, payload."""

    def __init__(self, timestamp=0, type_=0, payload_map=0, payload=b""):
        self.timestamp = timestamp & 0xFFFFFFFFFFFFFFFF
        self.type = type_ & 0xFF
        self.payload_map = payload_map & 0xFFFFFFFFFFFFFFFF
        self.payload = bytes(payload)

    def __eq__(self, other):
        return (
            isinstance(other, Trace)
            and self.timestamp == other.timestamp
            and self.type == other.type
            and self.payload_map == other.payload_map
            and self.payload == other.payload
        )

    def __repr__(self):
        return (
            f"Trace(ts={self.timestamp}, type={self.type}, "
            f"payload_map={self.payload_map}, "
            f"payload={self.payload!r})"
        )


def _check_append(cur_len, add_len):
    """std::string append capacity guard: throws length_error when the
    remaining capacity (0x3fffffffffffffff - size) is <= the chunk."""
    if MAX_STRING_SIZE - cur_len <= add_len:
        raise LengthError_("basic_string::_M_append: length_error")


def encode_trace(trace, out=b""):
    """Model of TracerHelper::EncodeTrace (0x61b1260).

    Adapted from tools/tracer_helper115.py (open PR #5863, same
    author), as in the header/footer packet.  Appends timestamp
    (8 bytes LE), the type byte, the payload length as a u32 LE
    (low 32 bits of the payload size), then the payload bytes.
    Returns the new bytes object.
    """
    out = bytearray(out)
    _check_append(len(out), 8)
    out += struct.pack("<Q", trace.timestamp & 0xFFFFFFFFFFFFFFFF)
    _check_append(len(out), 1)
    out += bytes([trace.type & 0xFF])
    _check_append(len(out), 4)
    out += struct.pack("<I", len(trace.payload) & 0xFFFFFFFF)
    _check_append(len(out), len(trace.payload))
    out += trace.payload
    return bytes(out)


def set_payload_map(payload_map, payload_type):
    """Model of TracerHelper::SetPayloadMap (0x61b18b0, its own FDE
    0x61b18b0..0x61b18c8, not in the vendor census).

    Copied from the header/footer packet.  The binary is
    `bts %rsi, %rdx` on the payload_map word: it sets bit
    `payload_type` (the index is taken mod 64, as x86-64 bts does)
    and returns whether the bit changed (setne).  Get calls it
    with kGetCFID (2) then kGetKey (3) and discards both return
    values.  Returns (new_payload_map, changed).
    """
    new = (payload_map & 0xFFFFFFFFFFFFFFFF) | (1 << (payload_type & 63))
    return new & 0xFFFFFFFFFFFFFFFF, new != payload_map


def encode_varint32(value):
    """Model of rocksdb::EncodeVarint32 (0x61bd410, its own FDE
    0x61bd410..0x61bd4e9, not in the vendor census).

    LEB128: 7 payload bits per byte, low group first, continuation
    bit set on every byte but the last.  The binary unrolls the
    1/2/3/4/5-byte paths (thresholds 0x7f, 0x3fff, 0x1fffff,
    0xfffffff) and stores the 4-byte path with one 32-bit store;
    the emitted bytes are identical to this loop.  Returns the
    1..5 encoded bytes.
    """
    value &= 0xFFFFFFFF
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def put_fixed64(payload, value):
    """Model of rocksdb::PutFixed64 (coding.h): append the 8
    little-endian bytes of the u64, with the std::string guard."""
    _check_append(len(payload), 8)
    return payload + struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def put_fixed32(payload, value):
    """Model of rocksdb::PutFixed32 (coding.h): append the 4
    little-endian bytes of the u32, with the std::string guard."""
    _check_append(len(payload), 4)
    return payload + struct.pack("<I", value & 0xFFFFFFFF)


def put_length_prefixed_slice(payload, data):
    """Model of rocksdb::PutLengthPrefixedSlice (coding.h).

    Appends EncodeVarint32((uint32_t)len(data)) then the data
    bytes, each with the std::string length guard.  The varint
    encodes the LOW 32 bits of the size (the binary moves the
    size through esi -- a 32-bit load -- before EncodeVarint32)
    while the append copies the full size -- see the module
    docstring.
    """
    varint = encode_varint32(len(data) & 0xFFFFFFFF)
    _check_append(len(payload), len(varint))
    payload += varint
    _check_append(len(payload), len(data))
    return payload + bytes(data)


def build_get_payload(cf_id, key):
    """The payload Tracer::Get builds (0x61b1e40, steps 4..7).

    PutFixed64(payload_map = SetPayloadMap(SetPayloadMap(0,
    kGetCFID), kGetKey) = 12) then PutFixed32(cf_id) then
    PutLengthPrefixedSlice(key).  The payload_map is NOT
    serialized by EncodeTrace, so the map value 12 is visible
    only as these 8 payload bytes.
    """
    payload_map, _c1 = set_payload_map(0, K_GET_CF_ID)
    payload_map, _c2 = set_payload_map(payload_map, K_GET_KEY)
    payload = put_fixed64(b"", payload_map)
    payload = put_fixed32(payload, cf_id)
    return put_length_prefixed_slice(payload, key)


class SystemClock:
    """Minimal SystemClock: NowMicros() returns a u64 microsecond
    timestamp.  The binary calls it through the (possibly wrapped)
    SystemClock at Tracer+0x00: each SystemClockWrapper::NowMicros
    (0x5d4d490) forwards to the wrapped clock's NowMicros (vtable
    slot 19, 0x98), so the observable result is the innermost
    clock's NowMicros()."""

    def now_micros(self):
        raise NotImplementedError


class FakeClock(SystemClock):
    """A clock returning a fixed value (tests / case generation)."""

    def __init__(self, value=0):
        self.value = value & 0xFFFFFFFFFFFFFFFF
        self.calls = 0

    def now_micros(self):
        self.calls += 1
        return self.value


class TraceWriter:
    """Minimal TraceWriter: Write(Slice) -> Status (vtable slot 2,
    0x10) and GetFileSize() -> u64 (vtable slot 4, 0x20)."""

    def write(self, data):
        raise NotImplementedError

    def get_file_size(self):
        raise NotImplementedError


class FakeWriter(TraceWriter):
    """An in-memory writer: records every Write call and reports a
    configurable file size and Write status."""

    def __init__(self, file_size=0, write_status=None):
        self.file_size = file_size
        self.write_status = write_status if write_status is not None \
            else Status()
        self.written = []
        self.write_calls = 0

    def write(self, data):
        self.write_calls += 1
        self.written.append(bytes(data))
        return self.write_status

    def get_file_size(self):
        return self.file_size


class Tracer:
    """Behavioural model of rocksdb::Tracer for Tracer::Get.

    The gate (ShouldSkipTrace) and WriteTrace are copied from the
    header/footer packet (tools/tracer_header_footer115.py, open PR
    #5870, same author), because that PR is not on upstream main
    yet; the Get-specific part is build_get_trace / get.
    Constructed post-construction: the binary constructor (0x61b3e60)
    zeroes the sampling counter and calls WriteHeader once; that
    one-time header write is the caller's business, not this model.
    """

    def __init__(self, clock, max_trace_file_size=64 * 1024 * 1024 * 1024,
                 sampling_period=0, skip_flags=0, options_word3=0,
                 writer=None):
        self.clock = clock
        self.max_trace_file_size = max_trace_file_size & 0xFFFFFFFFFFFFFFFF
        self.sampling_period = sampling_period & 0xFFFFFFFFFFFFFFFF
        self.skip_flags = skip_flags & 0xFFFFFFFFFFFFFFFF
        # TraceOptions word 3 (Tracer+0x20): preserve_write_order
        # (bool, padded to a u64 word) -- copied by the constructor
        # but not read by Get.
        self.options_word3 = options_word3 & 0xFFFFFFFFFFFFFFFF
        self.writer = writer
        self.counter = 0

    def file_size_exceeded(self):
        """The outlined helper at 0x61b1910 (its own FDE, not in the
        vendor census): trace_writer_->GetFileSize() (TraceWriter
        vtable slot 4) > max_trace_file_size (Tracer+0x08).  Strictly
        greater: a file exactly at the limit does not trip the gate.
        """
        return self.writer.get_file_size() > self.max_trace_file_size

    def should_skip_trace(self, trace_type):
        """Model of Tracer::ShouldSkipTrace (0x61b1930).

        trace_type is read as one byte (movzbl).  Returns True when
        the trace must be skipped, False when it is recorded.
        """
        if self.file_size_exceeded():
            return True
        t = trace_type & 0xFF
        # sub $3, cmp $10 (8-bit): types 3..13 go to the jump table.
        d = (t - 3) & 0xFF
        if d <= 10:
            mask = _SKIP_MASKS.get(t)
            if mask is not None:
                # Bit set in this+0x18 -> skip at once, without
                # advancing the sampling counter.
                if self.skip_flags & mask:
                    return True
            # Types 7..12 fall through here with no flag test.
        # Sampling counter (this+0x30 vs period at this+0x10):
        # increment, skip while below the period, record (and reset
        # to 0) once the counter reaches it.  Period 0 or 1 records
        # every trace that reaches this point.
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        if self.counter < self.sampling_period:
            return True
        self.counter = 0
        return False

    def write_trace(self, trace):
        """Model of Tracer::WriteTrace (0x61b1a10).

        Encodes the trace into a stack std::string with EncodeTrace,
        then calls trace_writer_->Write(Slice) (TraceWriter vtable
        slot 2) and returns that Status by value.
        """
        data = encode_trace(trace)
        return self.writer.write(data)

    def build_get_trace(self, cf_id, key):
        """Build the Trace Tracer::Get records (0x61b1e40).

        Returns None when the gate skips this get (the clock is
        never consulted on that path).  Otherwise Trace{ts =
        clock_->NowMicros(), type = kTraceGet (4), payload_map =
        SetPayloadMap(SetPayloadMap(0, kGetCFID), kGetKey) = 12,
        payload = PutFixed64(12) + PutFixed32(cf_id) +
        PutLengthPrefixedSlice(key)}.
        """
        if self.should_skip_trace(K_TRACE_GET):
            return None
        payload_map, _c1 = set_payload_map(0, K_GET_CF_ID)
        payload_map, _c2 = set_payload_map(payload_map, K_GET_KEY)
        trace = Trace(timestamp=self.clock.now_micros(),
                      type_=K_TRACE_GET, payload_map=payload_map,
                      payload=b"")
        trace.payload = put_length_prefixed_slice(
            put_fixed32(put_fixed64(b"", payload_map), cf_id), key)
        return trace

    def get(self, cf_id, key):
        """Model of Tracer::Get (0x61b1e40).

        cf_id is the resolved ColumnFamilyHandle::GetID() (vtable
        slot 3) and key is the Slice bytes.  Returns Status::OK()
        at once when the gate skips; otherwise WriteTrace's Status,
        forwarded unchanged.
        """
        trace = self.build_get_trace(cf_id, key)
        if trace is None:
            return Status()
        return self.write_trace(trace)


# ---------------------------------------------------------------------------
# Deterministic case generation (cases.tsv: kind<TAB>input<TAB>want).
#
# get rows (1,200): input is
#   "clock|flags|period|max|fsize|counter0|cf_id|key_hex[|err=2][|steps=N]"
#   and want is "SKIP|clock_calls" (gate skipped; the clock is never
#   consulted), "R,S,R,...|counter" for a sampling sequence
#   (steps>1), "STATUS|code|message_hex" for a writer error, or the
#   full encoded record as hex.
# get_payload rows (600): input is "cf_id|key_hex" and want is the
#   payload bytes as hex (PutFixed64(12) + PutFixed32(cf_id) +
#   varint + key).
# encode_varint32 rows (600): input is the u32 (decimal) and want
#   is the LEB128 bytes as hex.
# ---------------------------------------------------------------------------

def _gen_get(rng):
    rows = []
    # 200 rows: Get flag set (0x01) -> SKIP at once, clock untouched.
    for i in range(200):
        clock = [0, 1, 1 << 63, (1 << 64) - 1,
                 rng.randrange(1 << 64)][i % 5]
        flags = [0x01, 0x03, 0x1F, 0x11][i % 4]
        cf_id = [0, 1, 2, 0xFFFFFFFF][i % 4]
        key = bytes(rng.randrange(256) for _ in range(i % 13))
        tr = Tracer(FakeClock(clock), skip_flags=flags,
                    writer=FakeWriter())
        status = tr.get(cf_id, key)
        assert status.ok() and not tr.writer.written
        rows.append(("get",
                     f"{clock}|{flags}|0|{1 << 26}|0|0|{cf_id}|{key.hex()}",
                     f"SKIP|{tr.clock.calls}"))
    # 200 rows: file-size gate (fsize above max) -> SKIP at once.
    for i in range(200):
        clock = [0, 1, 1 << 63, (1 << 64) - 1,
                 rng.randrange(1 << 64)][i % 5]
        max_size = 1 << 26
        fsize = [max_size + 1, max_size + 1000, (1 << 64) - 1][i % 3]
        cf_id = [0, 1, 2, 0xFFFFFFFF][i % 4]
        key = bytes(rng.randrange(256) for _ in range(i % 13))
        tr = Tracer(FakeClock(clock), max_trace_file_size=max_size,
                    writer=FakeWriter(file_size=fsize))
        status = tr.get(cf_id, key)
        assert status.ok() and not tr.writer.written
        rows.append(("get",
                     f"{clock}|0|0|{max_size}|{fsize}|0|{cf_id}|{key.hex()}",
                     f"SKIP|{tr.clock.calls}"))
    # 200 rows: sampling sequences (6 consecutive gets, one tracer).
    for i in range(200):
        period = [0, 1, 2, 3, 5, 10][i % 6]
        counter0 = [0, 1, max(period - 1, 0)][i % 3]
        clock = rng.randrange(1 << 64)
        cf_id = [0, 1, 2, 0xFFFFFFFF][i % 4]
        key = bytes(rng.randrange(256) for _ in range(i % 13))
        tr = Tracer(FakeClock(clock), sampling_period=period,
                    writer=FakeWriter())
        tr.counter = counter0
        pattern = []
        for _ in range(6):
            before = len(tr.writer.written)
            tr.get(cf_id, key)
            pattern.append("R" if len(tr.writer.written) > before else "S")
        rows.append(("get",
                     f"{clock}|0|{period}|{1 << 26}|0|{counter0}|"
                     f"{cf_id}|{key.hex()}|steps=6",
                     f"{','.join(pattern)}|{tr.counter}"))
    # 50 rows: writer-error rows: the writer's Status is returned as-is.
    for i in range(50):
        clock = rng.randrange(1 << 64)
        cf_id = [0, 1, 2, 0xFFFFFFFF][i % 4]
        key = bytes(rng.randrange(256) for _ in range(i % 17))
        err = Status(K_CORRUPTION, b"disk full")
        tr = Tracer(FakeClock(clock), writer=FakeWriter(write_status=err))
        status = tr.get(cf_id, key)
        rows.append(("get",
                     f"{clock}|0|0|{1 << 26}|0|0|{cf_id}|{key.hex()}|err=2",
                     f"STATUS|{status.code}|{status.message.hex()}"))
    # 550 rows: full records over boundary clocks, CF ids and key sizes.
    for i in range(550):
        clock = [0, 1, 123456789, 1 << 63, (1 << 64) - 1,
                 rng.randrange(1 << 64)][i % 6]
        cf_id = [0, 1, 2, 3, 0xFFFFFFFF, rng.randrange(1 << 32)][i % 6]
        klen = [0, 1, 3, 127, 128, 256, 1000, 16383, 16384,
                rng.randrange(600)][i % 10]
        if i % 10 == 0:
            # A realistic get: CF 0, the 3-byte key "key".
            cf_id = 0
            key = b"key"
        else:
            key = bytes(rng.randrange(256) for _ in range(klen))
        tr = Tracer(FakeClock(clock), writer=FakeWriter())
        status = tr.get(cf_id, key)
        assert status.ok() and len(tr.writer.written) == 1
        rows.append(("get",
                     f"{clock}|0|0|{1 << 26}|0|0|{cf_id}|{key.hex()}",
                     tr.writer.written[0].hex()))
    return rows


def _gen_get_payload(rng):
    rows = []
    for i in range(600):
        cf_id = [0, 1, 2, 3, 0xFFFFFFFF, rng.randrange(1 << 32)][i % 6]
        klen = [0, 1, 3, 127, 128, 256, 1000, 16383, 16384,
                rng.randrange(600)][i % 10]
        if i % 10 == 0:
            cf_id = 0
            key = b"key"
        else:
            key = bytes(rng.randrange(256) for _ in range(klen))
        rows.append(("get_payload", f"{cf_id}|{key.hex()}",
                     build_get_payload(cf_id, key).hex()))
    return rows


def _gen_encode_varint32(rng):
    rows = []
    bounds = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152,
              268435455, 268435456, 0xFFFFFFFF]
    for i in range(600):
        if i < len(bounds) * 10:
            value = bounds[i % len(bounds)]
        else:
            value = rng.randrange(1 << 32)
        rows.append(("encode_varint32", str(value),
                     encode_varint32(value).hex()))
    return rows


def generate_cases():
    rng = random.Random(115)
    rows = []
    rows += _gen_get(rng)
    rows += _gen_get_payload(rng)
    rows += _gen_encode_varint32(rng)
    assert len(rows) == 2400, len(rows)
    return rows


def write_cases(path):
    rows = generate_cases()
    with open(path, "w") as fh:
        fh.write("kind\tinput\twant\n")
        for kind, inp, want in rows:
            fh.write(f"{kind}\t{inp}\t{want}\n")
    return len(rows)


def demo():
    clock = FakeClock(1700000000000000)
    writer = FakeWriter()
    tracer = Tracer(clock, writer=writer)
    print("get(cf 0, 'key') ->", tracer.get(0, b"key"))
    print("record:", writer.written[0].hex())
    print("payload:", build_get_payload(0, b"key").hex())
    skipped = Tracer(FakeClock(1), skip_flags=0x01, writer=FakeWriter())
    print("get(flagged) ->", skipped.get(0, b"key"),
          "clock calls:", skipped.clock.calls)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-cases", metavar="PATH")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args(argv)
    if args.write_cases:
        n = write_cases(args.write_cases)
        print(f"wrote {n} cases to {args.write_cases}")
        return 0
    if args.demo:
        demo()
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
