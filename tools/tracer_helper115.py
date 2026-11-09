#!/usr/bin/env python3
"""Python model of node #115's rocksdb::TracerHelper codec.

Reconstructs four functions from the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...):

  * TracerHelper::ParseVersionStr  0x61b10f0
  * TracerHelper::EncodeTrace      0x61b1260
  * TracerHelper::DecodeTrace      0x61b13b0
  * TracerHelper::DecodeHeader     0x61b1670

The model is derived from the whole-function disassembly of each FDE;
every claim that can be checked against the binary bytes is checked by
tests/test_tracer_helper115.py (2,400 deterministic cases).

Trace layout (from the Encode/Decode bodies):
  +0x00  uint64 timestamp (little-endian)
  +0x08  uint8  type
  +0x18  std::string payload (ptr, size, capacity)

Encoded record layout (EncodeTrace output):
  timestamp u64 LE | type u8 | payload length u32 LE | payload bytes

Status codes follow rocksdb::Status::Code (kOk=0, kCorruption=2,
kIncomplete=7). The binary is never executed; the tool is a behavioural
model of the four functions only.

Usage:
  python3 tools/tracer_helper115.py --write-cases <path>
      Regenerate cases.tsv (2,400 rows) from the seeded generator.
  python3 tools/tracer_helper115.py --demo
      Print a short encode/decode round-trip demo.
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
MAX_STRING_SIZE = 0x3FFFFFFFFFFFFFFF
MAGIC = b"feedcafedeadbeef"

# Status codes (rocksdb::Status::Code).
K_OK = 0
K_CORRUPTION = 2
K_INCOMPLETE = 7

# Error messages, verbatim from .rodata (addresses in records.json).
MSG_VERSION_FORMAT = b"Corrupted trace file. Incorrect version format."
MSG_VERSION_FORMAT_NOPERIOD = b"Corrupted trace file. Incorrect version format"
MSG_DECODE_TRACE_FAILED = b"Decode trace string failed"
MSG_INCORRECT_HEADER = b"Corrupted trace file. Incorrect header."
MSG_INCORRECT_MAGIC = b"Corrupted trace file. Incorrect magic."

# The header trace's type byte. The binary checks `type == 1`; the
# upstream enum name for 1 is recorded in the packet README as an open
# question (the TraceType enumerators are not recoverable from the
# binary alone).
HEADER_TYPE = 1


class LengthError_(ValueError):
    """Mirror of std::length_error from std::string appends."""


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
    """A rocksdb::Trace: timestamp, type byte, payload bytes."""

    def __init__(self, timestamp=0, type_=0, payload=b""):
        self.timestamp = timestamp
        self.type = type_ & 0xFF
        self.payload = bytes(payload)

    def __eq__(self, other):
        return (
            isinstance(other, Trace)
            and self.timestamp == other.timestamp
            and self.type == other.type
            and self.payload == other.payload
        )

    def __repr__(self):
        return (
            f"Trace(timestamp={self.timestamp}, type={self.type}, "
            f"payload={self.payload!r})"
        )


def _to_int32(value):
    """Wrap an accumulated value to a signed 32-bit C++ int."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def parse_version_str(s):
    """Model of TracerHelper::ParseVersionStr.

    Returns (Status, version). The binary requires at least two '.'
    characters, then walks the whole string: '.' bytes are skipped,
    digit bytes accumulate value = value * 10 + digit (32-bit wrap),
    any other byte is an error. The value is the decimal concatenation
    of every digit run in the string, e.g. b"1.0.0" -> 100.
    """
    if not isinstance(s, (bytes, bytearray)):
        raise TypeError("parse_version_str takes bytes")
    s = bytes(s)
    first = s.find(b".")
    if first < 0:
        return Status(K_CORRUPTION, MSG_VERSION_FORMAT), None
    if first == s.rfind(b"."):
        return Status(K_CORRUPTION, MSG_VERSION_FORMAT_NOPERIOD), None
    value = 0
    for ch in s:
        if ch == 0x2E:  # '.'
            continue
        if 0x30 <= ch <= 0x39:
            value = (value * 10 + (ch - 0x30)) & 0xFFFFFFFF
        else:
            return Status(K_CORRUPTION, MSG_VERSION_FORMAT_NOPERIOD), None
    return Status(), _to_int32(value)


def _check_append(cur_len, add_len):
    """std::string append capacity guard: throws length_error when the
    remaining capacity (0x3fffffffffffffff - size) is <= the chunk."""
    if MAX_STRING_SIZE - cur_len <= add_len:
        raise LengthError_("basic_string::_M_append: length_error")


def encode_trace(trace, out=b""):
    """Model of TracerHelper::EncodeTrace.

    Appends timestamp (8 bytes LE), the type byte, the payload length
    as a u32 LE (low 32 bits of the payload size), then the payload
    bytes. Returns the new bytes object.
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


def decode_trace(data, trace):
    """Model of TracerHelper::DecodeTrace.

    Mutates `trace` in place and returns a Status. Rules, in order:
      * len(data) <= 7 -> kIncomplete, trace untouched.
      * timestamp = u64 LE from data[0:8] (written before the next check).
      * len(data) <= 12 -> kIncomplete, timestamp kept, type/payload
        untouched.
      * type = data[8]; payload = data[13:]. The 4-byte length field at
        data[9:13] is skipped and NEVER read or validated: a record
        whose declared length disagrees with the actual trailing bytes
        still decodes, with the whole remainder as the payload.
    """
    if len(data) <= 7:
        return Status(K_INCOMPLETE, MSG_DECODE_TRACE_FAILED)
    trace.timestamp = struct.unpack_from("<Q", data, 0)[0]
    if len(data) <= 12:
        return Status(K_INCOMPLETE, MSG_DECODE_TRACE_FAILED)
    trace.type = data[8]
    trace.payload = bytes(data[13:])
    return Status()


def decode_header(data, trace):
    """Model of TracerHelper::DecodeHeader.

    First decodes the record with DecodeTrace (its status is kept in a
    temporary), then:
      * trace.type != 1 -> kCorruption "Incorrect header."
        (the DecodeTrace status is discarded).
      * len(trace.payload) < 16 or payload[:16] != MAGIC ->
        kCorruption "Incorrect magic." (the DecodeTrace status is
        discarded).
      * otherwise the DecodeTrace status is returned as-is (OK on a
        well-formed header record; the kIncomplete error survives when
        the decode failed but the incoming trace already had type 1
        and a magic payload).
    """
    status = decode_trace(data, trace)
    if trace.type != HEADER_TYPE:
        return Status(K_CORRUPTION, MSG_INCORRECT_HEADER)
    if len(trace.payload) < len(MAGIC) or trace.payload[: len(MAGIC)] != MAGIC:
        return Status(K_CORRUPTION, MSG_INCORRECT_MAGIC)
    return status


# ---------------------------------------------------------------------------
# Case generation (2,400 deterministic cases, seeded).
# ---------------------------------------------------------------------------

def _gen_parse_cases(rng):
    cases = []
    # Hand-picked valid versions (value = digit concatenation).
    for s, want in [
        (b"1.0.0", 100), (b"0.0.0", 0), (b"12.34.56", 123456),
        (b"1.2.3.4", 1234), (b"..", 0), (b".1.2", 12), (b"1.2.", 12),
        (b"1..2.3", 123), (b"9.9.9", 999), (b"10.20.30", 102030),
        (b"0.0.1", 1), (b"255.255.255", 255255255),
        (b"42949672.9.5", None),  # overflow: wraps mod 2**32
        (b"99999.99999.99999", None),  # overflow wrap
        (b"21474836.47.0", None),  # wraps into the negative int32 range
    ]:
        if want is None:
            v = 0
            for ch in s:
                if ch == 0x2E:
                    continue
                v = (v * 10 + (ch - 0x30)) & 0xFFFFFFFF
            want = _to_int32(v)
        cases.append((s, want))
    # Hand-picked errors.
    for s in [
        b"", b".", b"1.2", b"12.34", b"1", b"12", b"1.2.x", b"1.a.2",
        b"v1.2.3", b"1.2.3 ", b"1.2.3\n", b"1.2.3-", b"1.2.3\t",
        b"1.2.3\x00", b"1.2.3\x80", b"a.b.c", b"..a", b"1.2.3.4a",
    ]:
        cases.append((s, None))
    # Random valid: 3-5 dot-separated digit runs (at least two dots).
    while len(cases) < 400:
        runs = [str(rng.randrange(0, 10 ** rng.randrange(1, 4)))
                for _ in range(rng.randrange(3, 6))]
        s = ".".join(runs).encode()
        v = 0
        for ch in s:
            if ch != 0x2E:
                v = (v * 10 + (ch - 0x30)) & 0xFFFFFFFF
        cases.append((s, _to_int32(v)))
    # Random invalid: one dot only, or a bad byte somewhere.
    while len(cases) < 600:
        if rng.random() < 0.5:
            s = (str(rng.randrange(0, 100)) + "." +
                 str(rng.randrange(0, 100))).encode()
        else:
            runs = [str(rng.randrange(0, 100)) for _ in range(3)]
            s = ".".join(runs).encode()
            pos = rng.randrange(len(s))
            bad = rng.choice(b"abxz- _\t\x00\xff")
            s = s[:pos] + bytes([bad]) + s[pos + 1:]
        cases.append((s, None))
    return cases


def _gen_encode_cases(rng):
    cases = []
    specials = [
        (0, 0, b""), (1, 1, b""), (0xFFFFFFFFFFFFFFFF, 255, b"x"),
        (0, 1, MAGIC), (123456789, 7, b"hello"),
        (2**63, 128, bytes(range(256))),
        (0, 0, MAGIC + b"Trace Version: 1.0.0"),
        (9876543210, 3, b"\x00\xff\x00\xff"),
    ]
    for ts, ty, pl in specials:
        cases.append(Trace(ts, ty, pl))
    while len(cases) < 600:
        ts = rng.choice([0, 1, rng.randrange(2**64), rng.randrange(2**63),
                         0xFFFFFFFFFFFFFFFF])
        ty = rng.choice([0, 1, rng.randrange(256)])
        n = rng.choice([0, 1, 2, 13, 16, 17, 100, rng.randrange(0, 300)])
        pl = bytes(rng.randrange(256) for _ in range(n))
        cases.append(Trace(ts, ty, pl))
    return cases


def _gen_decode_cases(rng, encode_cases):
    cases = []
    # Valid records from the encode generator (round-trip inputs).
    for tr in encode_cases[:300]:
        cases.append((encode_trace(tr), tr))
    # Records with a LYING length field: decode must ignore it.
    for tr in encode_cases[300:450]:
        raw = bytearray(encode_trace(tr))
        struct.pack_into("<I", raw, 9, (len(tr.payload) + 7) & 0xFFFFFFFF)
        cases.append((bytes(raw), tr))
    for tr in encode_cases[450:500]:
        raw = bytearray(encode_trace(tr))
        struct.pack_into("<I", raw, 9, 0)
        cases.append((bytes(raw), tr))
    # Truncated records: every length 0..12, from a valid record.
    base = encode_trace(Trace(0x0102030405060708, 5, b"payload-bytes"))
    for n in range(0, 13):
        cases.append((base[:n], None))
    # Random payload bytes with random type, correct length field.
    while len(cases) < 600:
        n = rng.randrange(0, 120)
        pl = bytes(rng.randrange(256) for _ in range(n))
        tr = Trace(rng.randrange(2**64), rng.randrange(256), pl)
        cases.append((encode_trace(tr), tr))
    return cases


def _gen_header_cases(rng):
    cases = []
    # Well-formed headers: type 1, magic payload (plus optional tail).
    for tail in [b"", b"Trace Version: 1.0.0", b"\tTrace Version: 1.0.0",
                 bytes(range(1, 40)), b"X" * 200]:
        cases.append((encode_trace(Trace(0, 1, MAGIC + tail)), True))
    # Wrong type.
    for ty in [0, 2, 3, 7, 255]:
        cases.append((encode_trace(Trace(0, ty, MAGIC)), False))
    # Wrong / short magic.
    for pl in [b"", b"feedcafedeadbee", b"feedcafedeadbeeg",
               b"Feedcafedeadbeef", b"feedcafedeadbeef"[:15] + b"X",
               b"\x00" * 16, b"feedcafedeadbeef" + b"tail"]:
        if pl == b"feedcafedeadbeef" + b"tail":
            cases.append((encode_trace(Trace(0, 1, pl)), True))
        else:
            cases.append((encode_trace(Trace(0, 1, pl)), False))
    # Truncated header records (incoming trace type 0, as the live
    # replayer zeroes it): decode fails, type stays 0 -> header error.
    full = encode_trace(Trace(0, 1, MAGIC))
    for n in range(0, 13):
        cases.append((full[:n], False))
    # Truncated record with an incoming type-1 trace and magic payload:
    # DecodeTrace's kIncomplete status survives (documented edge).
    cases.append((full[:5], "incomplete-survives"))
    # Random: type 1 with random payload (magic match is ~impossible).
    while len(cases) < 600:
        n = rng.randrange(0, 80)
        pl = bytes(rng.randrange(256) for _ in range(n))
        ty = rng.choice([1, 1, rng.randrange(256)])
        cases.append((encode_trace(Trace(rng.randrange(2**64), ty, pl)),
                      pl[:16] == MAGIC and ty == 1))
    return cases


def generate_cases(seed=115):
    rng = random.Random(seed)
    parse = _gen_parse_cases(rng)
    encode = _gen_encode_cases(rng)
    decode = _gen_decode_cases(rng, encode)
    header = _gen_header_cases(rng)
    return parse, encode, decode, header


def write_cases(path):
    parse, encode, decode, header = generate_cases()
    lines = ["kind\tinput_hex\twant"]
    for s, want in parse:
        lines.append("parse_version_str\t" + s.hex() + "\t" +
                     ("ERR" if want is None else str(want)))
    for tr in encode:
        lines.append("encode_trace\t" +
                     f"{tr.timestamp:x}:{tr.type}:{tr.payload.hex()}" + "\t" +
                     encode_trace(tr).hex())
    for data, tr in decode:
        if tr is None:
            lines.append("decode_trace\t" + data.hex() + "\tERR")
        else:
            lines.append("decode_trace\t" + data.hex() + "\t" +
                         f"{tr.timestamp:x}:{tr.type}:{tr.payload.hex()}")
    for data, want in header:
        if want == "incomplete-survives":
            lines.append("decode_header\t" + data.hex() +
                         "\tINCOMPLETE-SURVIVES")
        else:
            lines.append("decode_header\t" + data.hex() + "\t" +
                         ("OK" if want else "ERR"))
    Path(path).write_text("\n".join(lines) + "\n")
    return len(lines) - 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-cases", default=None)
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args(argv)
    if args.write_cases:
        n = write_cases(args.write_cases)
        print(f"wrote {n} cases to {args.write_cases}")
        return 0
    if args.demo:
        tr = Trace(123456789, 1, MAGIC + b"Trace Version: 1.0.0")
        raw = encode_trace(tr)
        print("encoded:", raw.hex())
        back = Trace()
        print("decode:", decode_trace(raw, back), back)
        print("header:", decode_header(raw, Trace()))
        print("version:", parse_version_str(b"1.0.0"))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
