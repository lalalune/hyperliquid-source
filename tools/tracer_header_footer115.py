#!/usr/bin/env python3
"""Python model of node #115's rocksdb::Tracer header/footer + write gate.

Reconstructs four functions from the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...):

  * Tracer::ShouldSkipTrace  0x61b1930
    (FDE 0x61b1930..0x61b19e7, 183 bytes; census node115-vendor-61b1930)
  * Tracer::WriteTrace       0x61b1a10
    (FDE 0x61b1a10..0x61b1ac6, 182 bytes; census node115-vendor-61b1a10)
  * Tracer::WriteFooter      0x61b35c0
    (FDE 0x61b35c0..0x61b371d, 349 bytes; census node115-vendor-61b35c0)
  * Tracer::WriteHeader      0x61b3860
    (FDE 0x61b3860..0x61b3e33, 1491 bytes; census node115-vendor-61b3860)

ShouldSkipTrace is the gate the recording methods consult before
tracing an operation: it returns True (skip) when the trace file has
grown past max_trace_file_size, when the operation type's bit is set
in the skip-flags word, or while the sampling counter is below its
period; otherwise it records this trace (and resets the counter).
WriteTrace encodes one Trace with TracerHelper::EncodeTrace
(0x61b1260, modelled here after tools/tracer_helper115.py from open
PR #5863, same author; copied, not imported, because #5863 is not on
upstream main yet) and hands the bytes to TraceWriter::Write.
WriteHeader builds the header trace (magic + "Trace Version: 0.2" +
"RocksDB Version: 8.1" + the format line, type kTraceBegin) and
WriteFooter the footer trace (empty payload, type kTraceEnd,
payload_map = 1 via SetPayloadMap(kEmptyPayload) -- not serialized,
so the footer record stays 13 bytes); both stamp the trace with the
tracer clock's NowMicros() and return WriteTrace's Status.  The binary
is never executed; this tool is a behavioural model of the four
functions only.

Tracer object layout (pinned from the constructor, 0x61b3e60, which
copies the 32-byte TraceOptions into this+0x08..0x28, moves the
writer into this+0x28, zeroes the counter at this+0x30, and calls
WriteHeader once):
  +0x00  SystemClock* clock_ (the timestamp source)
  +0x08  TraceOptions word 0: max_trace_file_size (u64)
  +0x10  TraceOptions word 1: sampling period (u64)
  +0x18  TraceOptions word 2: per-type skip flags (u64 bitmask)
  +0x20  TraceOptions word 3: preserve_write_order (bool, padded to
         a u64 word) -- read only by IsWriteOrderPreserved(), not by
         these four functions
  +0x28  unique_ptr<TraceWriter> trace_writer_
  +0x30  sampling counter (u64, starts at 0)

Trace layout (from the codec packet): timestamp u64 at +0x00, type
u8 at +0x08, payload_map u64 at +0x10, payload std::string at +0x18.

Status codes follow rocksdb::Status::Code (kOk=0, kCorruption=2,
kIncomplete=7).  WriteTrace/WriteHeader/WriteFooter return a Status
by value (hidden sret Status* in rdi): this in rsi, the Trace in rdx
for WriteTrace; ShouldSkipTrace takes (this, const TraceType&) and
returns a bool in al.

Usage:
  python3 tools/tracer_header_footer115.py --write-cases <path>
      Regenerate cases.tsv (2,400 rows) from the seeded generator.
  python3 tools/tracer_header_footer115.py --demo
      Print a short demo: one header record and one footer record.
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

# The header payload the producer writes, built by streaming into an
# std::ostringstream (WriteHeader, 0x61b3860): the magic string at
# .bss 0x6508800 ("feedcafedeadbeef", built from .rodata 0x452c50),
# TAB (.rodata 0x43fc29), "Trace Version: " (.rodata 0x4478de),
# the trace version as two ints joined by "." (.rodata 0x43821e),
# TAB, "RocksDB Version: " (.rodata 0x442aec), the RocksDB version
# as two ints joined by ".", TAB, and the 33-byte format line
# (.rodata 0x969c80).  The four version ints are immediates in the
# binary (operator<<(int) with 0, 2, 8, 1).
MAGIC = b"feedcafedeadbeef"
TAB = b"\t"
DOT = b"."
TRACE_VERSION_LABEL = b"Trace Version: "
ROCKSDB_VERSION_LABEL = b"RocksDB Version: "
FORMAT_LINE = b"Format: Timestamp OpType Payload\n"
TRACE_VERSION_MAJOR = 0
TRACE_VERSION_MINOR = 2
ROCKSDB_VERSION_MAJOR = 8
ROCKSDB_VERSION_MINOR = 1

# TracePayloadType values (trace_replay/trace_replay.h, confirmed by
# the upstream read).  Only kEmptyPayload is used by these four
# functions (WriteFooter, via SetPayloadMap).
K_EMPTY_PAYLOAD = 0
K_WRITE_BATCH_DATA = 1
K_GET_CF_ID = 2
K_GET_KEY = 3

# TraceType values (include/rocksdb/trace_record.h, confirmed by the
# codec packet's upstream read).
K_TRACE_NONE = 0
K_TRACE_BEGIN = 1
K_TRACE_END = 2
K_TRACE_WRITE = 3
K_TRACE_GET = 4
K_TRACE_ITERATOR_SEEK = 5
K_TRACE_ITERATOR_SEEK_FOR_PREV = 6
K_TRACE_MULTI_GET = 13
K_TRACE_MAX = 14

# ShouldSkipTrace jump table (rodata 0x97c5f4, 11 int32 entries for
# types 3..13): the mask bit of this+0x18 tested for each type.
# Types 7..12 (kBlockTrace* and kIOTracer) jump straight to the
# sampling counter with no flag test; types 0, 1, 2 and >= 14 do too.
_SKIP_MASKS = {
    K_TRACE_WRITE: 0x02,
    K_TRACE_GET: 0x01,
    K_TRACE_ITERATOR_SEEK: 0x04,
    K_TRACE_ITERATOR_SEEK_FOR_PREV: 0x08,
    K_TRACE_MULTI_GET: 0x10,
}

# Status codes (rocksdb::Status::Code).
K_OK = 0
K_CORRUPTION = 2
K_INCOMPLETE = 7

# std::string maximum size (libstdc++ _S_max_size).
MAX_STRING_SIZE = 0x3FFFFFFFFFFFFFFF


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
    author).  Appends timestamp (8 bytes LE), the type byte, the
    payload length as a u32 LE (low 32 bits of the payload size),
    then the payload bytes.  Returns the new bytes object.
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

    The binary is `bts %rsi, %rdx` on the payload_map word: it sets
    bit `payload_type` (the index is taken mod 64, as x86-64 bts
    does) and returns whether the bit changed (setne).  WriteFooter
    calls it with kEmptyPayload (0) and discards the return value.
    Returns (new_payload_map, changed).
    """
    new = (payload_map & 0xFFFFFFFFFFFFFFFF) | (1 << (payload_type & 63))
    return new & 0xFFFFFFFFFFFFFFFF, new != payload_map


def header_payload():
    """The exact 90-byte payload WriteHeader builds (see the module
    docstring for the insertion sequence)."""
    return (
        MAGIC
        + TAB
        + TRACE_VERSION_LABEL
        + str(TRACE_VERSION_MAJOR).encode()
        + DOT
        + str(TRACE_VERSION_MINOR).encode()
        + TAB
        + ROCKSDB_VERSION_LABEL
        + str(ROCKSDB_VERSION_MAJOR).encode()
        + DOT
        + str(ROCKSDB_VERSION_MINOR).encode()
        + TAB
        + FORMAT_LINE
    )


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
    """Behavioural model of rocksdb::Tracer for the four functions.

    Constructed post-construction: the binary constructor (0x61b3e60)
    zeroes the sampling counter and calls WriteHeader once; that
    one-time header write is the caller's business, not this model.
    """

    def __init__(self, clock, max_trace_file_size=64 * 1024 * 1024,
                 sampling_period=0, skip_flags=0, options_word3=0,
                 writer=None):
        self.clock = clock
        self.max_trace_file_size = max_trace_file_size & 0xFFFFFFFFFFFFFFFF
        self.sampling_period = sampling_period & 0xFFFFFFFFFFFFFFFF
        self.skip_flags = skip_flags & 0xFFFFFFFFFFFFFFFF
        # TraceOptions word 3 (Tracer+0x20): preserve_write_order
        # (bool, padded to a u64 word) -- copied by the constructor
        # but not read by any of the four functions modelled here.
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

    def write_header(self):
        """Model of Tracer::WriteHeader (0x61b3860).

        Trace{ts = clock_->NowMicros(), type = kTraceBegin (1),
        payload_map = 0, payload = the 90-byte header payload},
        returned via WriteTrace.  The payload is built by streaming
        into an ostringstream (see header_payload()).
        """
        trace = Trace(timestamp=self.clock.now_micros(),
                      type_=K_TRACE_BEGIN, payload_map=0,
                      payload=header_payload())
        return self.write_trace(trace)

    def build_footer_trace(self):
        """Build the footer Trace (0x61b35c0).

        Trace{ts = clock_->NowMicros(), type = kTraceEnd (2),
        payload_map = SetPayloadMap(0, kEmptyPayload) = 1, payload =
        ""}.  The payload_map bit is set by TracerHelper::
        SetPayloadMap (0x61b18b0) before the payload assignment; it
        is NOT serialized by EncodeTrace, so the footer record on
        disk is still 13 bytes (ts 8 + type 1 + length 0).
        """
        payload_map, _changed = set_payload_map(0, K_EMPTY_PAYLOAD)
        return Trace(timestamp=self.clock.now_micros(),
                     type_=K_TRACE_END, payload_map=payload_map,
                     payload=b"")

    def write_footer(self):
        """Model of Tracer::WriteFooter (0x61b35c0).

        The footer Trace (see build_footer_trace), returned via
        WriteTrace.
        """
        return self.write_trace(self.build_footer_trace())


# ---------------------------------------------------------------------------
# Deterministic case generation (cases.tsv: kind<TAB>input<TAB>want).
#
# should_skip rows: input is "type|flags|period|max|fsize|counter0"
#   (decimal) and want is "skip|counter" for one call, or
#   "skip0,skip1,...|counter" for a sampling sequence (steps>1 is
#   encoded by repeating the call; the row input ends with "|steps=N").
# write_trace rows: input is "ts|type|payload_hex" (payload as hex)
#   and want is the encoded record as hex, or "STATUS code|message_hex"
#   when the writer returns an error (input ends with "|err=code").
# write_header / write_footer rows: input is the clock value
#   (decimal) and want is the full encoded record as hex.
# ---------------------------------------------------------------------------

def _gen_should_skip(rng):
    rows = []
    # 200 rows: type sweep (0..15, 255, random) with the file-size
    # gate cycled through below/equal/above the limit.
    for i in range(200):
        t = [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 255,
             rng.randrange(256)][i % 14]
        max_size = 1 << 26
        fsize = [0, max_size - 1, max_size, max_size + 1][i % 4]
        tr = Tracer(FakeClock(), max_trace_file_size=max_size,
                    sampling_period=10, skip_flags=0,
                    writer=FakeWriter(file_size=fsize))
        skip = tr.should_skip_trace(t)
        rows.append(("should_skip",
                     f"{t}|0|10|{max_size}|{fsize}|0",
                     f"{1 if skip else 0}|{tr.counter}"))
    # 200 rows: flag sweep for the five flag-tested types.
    for i in range(200):
        t = [3, 4, 5, 6, 13][i % 5]
        bit = _SKIP_MASKS[t]
        flags = [0, bit, 0x1F, (~bit) & 0x1F, 1 << rng.randrange(5)][i % 5]
        tr = Tracer(FakeClock(), max_trace_file_size=1 << 26,
                    sampling_period=10, skip_flags=flags,
                    writer=FakeWriter(file_size=0))
        skip = tr.should_skip_trace(t)
        rows.append(("should_skip",
                     f"{t}|{flags}|10|{1 << 26}|0|0",
                     f"{1 if skip else 0}|{tr.counter}"))
    # 200 rows: sampling sequences (6 consecutive calls, one type).
    for i in range(200):
        period = [0, 1, 2, 3, 5, 10][i % 6]
        counter0 = [0, 1, max(period - 1, 0)][i % 3]
        t = [3, 7, 13][i % 3]
        tr = Tracer(FakeClock(), max_trace_file_size=1 << 26,
                    sampling_period=period, skip_flags=0,
                    writer=FakeWriter(file_size=0))
        tr.counter = counter0
        pattern = []
        for _ in range(6):
            pattern.append("1" if tr.should_skip_trace(t) else "0")
        rows.append(("should_skip",
                     f"{t}|0|{period}|{1 << 26}|0|{counter0}|steps=6",
                     f"{','.join(pattern)}|{tr.counter}"))
    return rows


def _gen_write_trace(rng):
    rows = []
    for i in range(600):
        if i < 50:
            # Writer-error rows: the writer's Status is returned as-is.
            ts = rng.randrange(1 << 64)
            typ = rng.randrange(256)
            payload = bytes(rng.randrange(256) for _ in range(i % 17))
            err = Status(K_CORRUPTION, b"disk full")
            tr = Tracer(FakeClock(), writer=FakeWriter(write_status=err))
            status = tr.write_trace(Trace(ts, typ, 0, payload))
            rows.append(("write_trace",
                         f"{ts}|{typ}|{payload.hex()}|err=2",
                         f"STATUS|{status.code}|{status.message.hex()}"))
            continue
        ts = [0, 1, 1 << 63, (1 << 64) - 1,
              rng.randrange(1 << 64)][i % 5]
        typ = [0, 1, 2, 3, 13, 255, rng.randrange(256)][i % 7]
        plen = [0, 1, 16, 100, 256][i % 5]
        payload = bytes(rng.randrange(256) for _ in range(plen))
        if i % 11 == 0:
            payload = MAGIC
        tr = Tracer(FakeClock(), writer=FakeWriter())
        tr.write_trace(Trace(ts, typ, 0, payload))
        rows.append(("write_trace",
                     f"{ts}|{typ}|{payload.hex()}",
                     tr.writer.written[0].hex()))
    return rows


def _gen_header_footer(rng, kind):
    rows = []
    for i in range(600):
        clock_value = [0, 1, 123456789, 1 << 63, (1 << 64) - 1,
                       rng.randrange(1 << 64)][i % 6]
        tr = Tracer(FakeClock(clock_value), writer=FakeWriter())
        if kind == "write_header":
            tr.write_header()
        else:
            tr.write_footer()
        rows.append((kind, str(clock_value), tr.writer.written[0].hex()))
    return rows


def generate_cases():
    rng = random.Random(115)
    rows = []
    rows += _gen_should_skip(rng)
    rows += _gen_write_trace(rng)
    rows += _gen_header_footer(rng, "write_header")
    rows += _gen_header_footer(rng, "write_footer")
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
    print("write_header ->", tracer.write_header())
    print("record:", writer.written[0].hex())
    print("payload:", header_payload())
    print("write_footer ->", tracer.write_footer())
    print("record:", writer.written[1].hex())


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
    raise SystemExit(main())
