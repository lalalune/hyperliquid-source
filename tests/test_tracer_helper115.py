#!/usr/bin/env python3
"""Tests for tools/tracer_helper115.py (node #115 TracerHelper codec).

Runs the 2,400-case ledger from
research/work-items/re-002-node115-tracer-helper-115/cases.tsv plus
dedicated checks for the partial-mutation semantics that the ledger's
single "want" column cannot express (DecodeTrace writes the timestamp
before its second length check; DecodeHeader returns the DecodeTrace
status when the type and magic already match).

Run: python3 -m unittest tests.test_tracer_helper115 -v
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.tracer_helper115 import (  # noqa: E402
    ARTIFACT_SHA256,
    MAGIC,
    K_CORRUPTION,
    K_INCOMPLETE,
    K_OK,
    LengthError_,
    Status,
    Trace,
    _check_append,
    decode_header,
    decode_trace,
    encode_trace,
    generate_cases,
    parse_version_str,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "re-002-node115-tracer-helper-115"
BIN = ROOT / "work" / "hl-node-115.bin"
CANONICAL = ROOT / "artifacts" / "node" / "115" / "hl-node"


def _load_binary():
    """Canonical artifact path first, work/ fallback (only when the
    canonical file's SHA-256 matches the artifact digest, since in this
    checkout it may be a git-lfs pointer)."""
    for candidate in (CANONICAL, BIN):
        if candidate.exists():
            data = candidate.read_bytes()
            if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
                return data
    raise unittest.SkipTest("node #115 binary unavailable")


class ArtifactTest(unittest.TestCase):
    def test_binary_digest(self):
        data = _load_binary()
        self.assertEqual(hashlib.sha256(data).hexdigest(), ARTIFACT_SHA256)


class ParseVersionStrTest(unittest.TestCase):
    def test_ledger(self):
        parse, _, _, _ = generate_cases()
        self.assertEqual(len(parse), 600)
        for s, want in parse:
            status, version = parse_version_str(s)
            if want is None:
                self.assertFalse(status.ok(), s)
                self.assertEqual(status.code, K_CORRUPTION, s)
                self.assertIsNone(version, s)
            else:
                self.assertTrue(status.ok(), s)
                self.assertEqual(version, want, s)

    def test_boundaries(self):
        self.assertEqual(parse_version_str(b"1.0.0"), (Status(), 100))
        self.assertEqual(parse_version_str(b".."), (Status(), 0))
        self.assertEqual(parse_version_str(b"1.2.3.4.5"),
                         (Status(), 12345))
        # One dot only: the no-trailing-period message.
        st, _ = parse_version_str(b"1.2")
        self.assertEqual(st.code, K_CORRUPTION)
        self.assertEqual(st.message,
                         b"Corrupted trace file. Incorrect version format")
        # No dot at all: the message WITH the trailing period.
        st, _ = parse_version_str(b"123")
        self.assertEqual(st.code, K_CORRUPTION)
        self.assertEqual(st.message,
                         b"Corrupted trace file. Incorrect version format.")
        # 32-bit wrap: digits "42949672960" == 10 * 2**32 -> wraps to 0.
        st, v = parse_version_str(b"429496729.6.0")
        self.assertTrue(st.ok())
        self.assertEqual(v, 0)
        # Digits "4294967295" == 2**32 - 1 -> signed -1.
        st, v = parse_version_str(b"42949672.9.5")
        self.assertTrue(st.ok())
        self.assertEqual(v, -1)

    def test_length_error_guard(self):
        with self.assertRaises(LengthError_):
            _check_append(0x3FFFFFFFFFFFFFFF - 7, 8)
        _check_append(0, 8)  # no raise for ordinary sizes


class EncodeTraceTest(unittest.TestCase):
    def test_ledger(self):
        _, encode, _, _ = generate_cases()
        self.assertEqual(len(encode), 600)
        for tr in encode:
            raw = encode_trace(tr)
            self.assertEqual(raw[:8], struct.pack("<Q", tr.timestamp))
            self.assertEqual(raw[8], tr.type)
            self.assertEqual(raw[9:13],
                             struct.pack("<I", len(tr.payload) & 0xFFFFFFFF))
            self.assertEqual(raw[13:], tr.payload)
            self.assertEqual(len(raw), 13 + len(tr.payload))

    def test_layout_bytes(self):
        raw = encode_trace(Trace(0x0102030405060708, 5, b"ab"))
        self.assertEqual(raw.hex(), "080706050403020105020000006162")

    def test_round_trip(self):
        _, encode, _, _ = generate_cases()
        for tr in encode:
            back = Trace()
            self.assertTrue(decode_trace(encode_trace(tr), back).ok())
            self.assertEqual(back, tr)


class DecodeTraceTest(unittest.TestCase):
    def test_ledger(self):
        _, _, decode, _ = generate_cases()
        self.assertEqual(len(decode), 600)
        for data, tr in decode:
            got = Trace()
            status = decode_trace(data, got)
            if tr is None:
                self.assertFalse(status.ok(), data.hex())
                self.assertEqual(status.code, K_INCOMPLETE)
                self.assertEqual(status.message, b"Decode trace string failed")
            else:
                self.assertTrue(status.ok(), data.hex())
                self.assertEqual(got, tr, data.hex())

    def test_length_field_is_ignored(self):
        # The declared length says 0, the real payload is 5 bytes.
        raw = encode_trace(Trace(42, 3, b"hello"))
        raw = raw[:9] + struct.pack("<I", 0) + raw[13:]
        got = Trace()
        self.assertTrue(decode_trace(raw, got).ok())
        self.assertEqual(got.payload, b"hello")
        # And a declared length far larger than the real payload.
        raw = encode_trace(Trace(42, 3, b"hi"))
        raw = raw[:9] + struct.pack("<I", 0xFFFFFFFF) + raw[13:]
        got = Trace()
        self.assertTrue(decode_trace(raw, got).ok())
        self.assertEqual(got.payload, b"hi")

    def test_partial_mutation(self):
        # 8..12 bytes: timestamp is written, type/payload untouched.
        base = encode_trace(Trace(0x0102030405060708, 5, b"payload"))
        for n in range(8, 13):
            got = Trace(111, 9, b"old")
            st = decode_trace(base[:n], got)
            self.assertEqual(st.code, K_INCOMPLETE)
            self.assertEqual(got.timestamp, 0x0102030405060708)
            self.assertEqual(got.type, 9)
            self.assertEqual(got.payload, b"old")
        # <= 7 bytes: trace fully untouched.
        for n in range(0, 8):
            got = Trace(111, 9, b"old")
            st = decode_trace(base[:n], got)
            self.assertEqual(st.code, K_INCOMPLETE)
            self.assertEqual(got, Trace(111, 9, b"old"))

    def test_empty_payload_ok(self):
        raw = encode_trace(Trace(7, 2, b""))
        self.assertEqual(len(raw), 13)
        got = Trace()
        self.assertTrue(decode_trace(raw, got).ok())
        self.assertEqual(got, Trace(7, 2, b""))


class DecodeHeaderTest(unittest.TestCase):
    def test_ledger(self):
        _, _, _, header = generate_cases()
        self.assertEqual(len(header), 600)
        for data, want in header:
            if want == "incomplete-survives":
                got = Trace(0, 1, MAGIC)
                st = decode_header(data, got)
                self.assertEqual(st.code, K_INCOMPLETE)
                self.assertEqual(got, Trace(0, 1, MAGIC))
                continue
            got = Trace()
            st = decode_header(data, got)
            if want:
                self.assertTrue(st.ok(), data.hex())
            else:
                self.assertFalse(st.ok(), data.hex())
                self.assertEqual(st.code, K_CORRUPTION)

    def test_error_messages(self):
        # Wrong type -> "Incorrect header."
        got = Trace()
        st = decode_header(encode_trace(Trace(0, 2, MAGIC)), got)
        self.assertEqual(st.message, b"Corrupted trace file. Incorrect header.")
        # Right type, wrong magic -> "Incorrect magic."
        got = Trace()
        st = decode_header(encode_trace(Trace(0, 1, b"X" * 16)), got)
        self.assertEqual(st.message, b"Corrupted trace file. Incorrect magic.")
        # Short payload -> "Incorrect magic." too.
        got = Trace()
        st = decode_header(encode_trace(Trace(0, 1, b"feed")), got)
        self.assertEqual(st.message, b"Corrupted trace file. Incorrect magic.")

    def test_truncated_input_uses_incoming_type(self):
        # Live replayer zeroes the type byte first: a truncated record
        # reports the header error, not the decode error.
        full = encode_trace(Trace(0, 1, MAGIC))
        got = Trace(0, 0, b"")
        st = decode_header(full[:5], got)
        self.assertEqual(st.code, K_CORRUPTION)
        self.assertEqual(st.message, b"Corrupted trace file. Incorrect header.")
        # ...while a pre-filled type-1 trace lets the kIncomplete
        # status through.
        got = Trace(0, 1, MAGIC)
        st = decode_header(full[:5], got)
        self.assertEqual(st.code, K_INCOMPLETE)

    def test_header_payload_tail_ignored(self):
        # Anything after the 16 magic bytes is payload, not checked.
        raw = encode_trace(Trace(99, 1, MAGIC + b"Trace Version: 9.9.9"))
        got = Trace()
        self.assertTrue(decode_header(raw, got).ok())
        self.assertEqual(got.payload, MAGIC + b"Trace Version: 9.9.9")


class LedgerTest(unittest.TestCase):
    def test_cases_tsv_matches_generator(self):
        parse, encode, decode, header = generate_cases()
        rows = (PACKET / "cases.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), 2400)
        n_parse = n_encode = n_decode = n_header = 0
        for row in rows:
            kind, inp, want = row.split("\t")
            if kind == "parse_version_str":
                s, w = parse[n_parse]
                n_parse += 1
                self.assertEqual(bytes.fromhex(inp), s)
                self.assertEqual(want, "ERR" if w is None else str(w))
            elif kind == "encode_trace":
                tr = encode[n_encode]
                n_encode += 1
                self.assertEqual(inp, f"{tr.timestamp:x}:{tr.type}:"
                                 f"{tr.payload.hex()}")
                self.assertEqual(bytes.fromhex(want), encode_trace(tr))
            elif kind == "decode_trace":
                data, tr = decode[n_decode]
                n_decode += 1
                self.assertEqual(bytes.fromhex(inp), data)
                if tr is None:
                    self.assertEqual(want, "ERR")
                else:
                    self.assertEqual(want, f"{tr.timestamp:x}:{tr.type}:"
                                     f"{tr.payload.hex()}")
            elif kind == "decode_header":
                data, w = header[n_header]
                n_header += 1
                self.assertEqual(bytes.fromhex(inp), data)
                if w == "incomplete-survives":
                    self.assertEqual(want, "INCOMPLETE-SURVIVES")
                else:
                    self.assertEqual(want, "OK" if w else "ERR")
        self.assertEqual((n_parse, n_encode, n_decode, n_header),
                         (600, 600, 600, 600))


if __name__ == "__main__":
    unittest.main()
