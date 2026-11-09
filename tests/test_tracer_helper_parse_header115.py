#!/usr/bin/env python3
"""Tests for tools/tracer_helper_parse_header115.py (node #115
TracerHelper::ParseTraceHeader).

Runs the 2,400-case ledger from
research/work-items/re-002-node115-tracer-helper-parse-header-115/cases.tsv
plus dedicated checks for the semantics the ledger's single "want"
column cannot express (the npos-wrap in the split loop, the
prefix-agnostic skips, the error precedence between the two version
parses, and which out-parameters are written on each failure).

Run: python3 -m unittest tests.test_tracer_helper_parse_header115 -v
"""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.tracer_helper_parse_header115 import (  # noqa: E402
    ARTIFACT_SHA256,
    MAGIC,
    K_CORRUPTION,
    K_OK,
    OutOfRange_,
    Status,
    generate_cases,
    parse_trace_header,
    parse_version_str,
    split_payload,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / \
    "re-002-node115-tracer-helper-parse-header-115"
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


class SplitPayloadTest(unittest.TestCase):
    def test_ledger(self):
        split, _, _ = generate_cases()
        self.assertEqual(len(split), 600)
        for payload in split:
            fields = split_payload(payload)
            self.assertEqual(len(fields), 3, payload)
            # Reassembling the fields must reproduce the payload up to
            # the wrap quirk: the first two fields are exact prefixes.
            self.assertTrue(payload.startswith(fields[0]), payload)

    def test_no_tabs(self):
        # No TAB at all: every iteration takes the whole remainder and
        # the position wraps to 0, so all three fields are the payload.
        self.assertEqual(split_payload(b"abc"), [b"abc", b"abc", b"abc"])
        self.assertEqual(split_payload(b""), [b"", b"", b""])

    def test_two_tabs(self):
        self.assertEqual(split_payload(b"a\tb\tc"), [b"a", b"b", b"c"])

    def test_extra_tabs_ignored(self):
        self.assertEqual(split_payload(b"a\tb\tc\td\te"),
                         [b"a", b"b", b"c"])

    def test_npos_wrap(self):
        # One TAB only: the third iteration searches from position 0
        # again (32-bit wrap of npos+1), so field 2 is the payload's
        # own first field.
        self.assertEqual(split_payload(b"0123456789abcde\tTrace Version: 1.2.3"),
                         [b"0123456789abcde", b"Trace Version: 1.2.3",
                          b"0123456789abcde"])
        self.assertEqual(split_payload(b"a\tb"), [b"a", b"b", b"a"])
        # Trailing TAB: field 1 is empty, field 2 is the whole payload.
        self.assertEqual(split_payload(b"ab\t"), [b"ab", b"", b"ab"])

    def test_empty_fields(self):
        self.assertEqual(split_payload(b"\t\t"), [b"", b"", b""])
        self.assertEqual(split_payload(b"f0\t\t"), [b"f0", b"", b""])


class ParseVersionStrTest(unittest.TestCase):
    def test_ledger(self):
        _, parse, _ = generate_cases()
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
        # No dot -> the 47-byte message (with period); one dot or a bad
        # byte -> the 46-byte message (no period).
        st, _ = parse_version_str(b"123")
        self.assertEqual(st.message,
                         b"Corrupted trace file. Incorrect version format.")
        st, _ = parse_version_str(b"1.2")
        self.assertEqual(st.message,
                         b"Corrupted trace file. Incorrect version format")
        st, _ = parse_version_str(b"1.2.x")
        self.assertEqual(st.message,
                         b"Corrupted trace file. Incorrect version format")


class ParseTraceHeaderTest(unittest.TestCase):
    def test_ledger(self):
        _, _, header = generate_cases()
        self.assertEqual(len(header), 1200)
        for payload in header:
            try:
                status, tv, rv = parse_trace_header(payload)
            except OutOfRange_:
                self.assertTrue(
                    len(split_payload(payload)[1]) < 15
                    or len(split_payload(payload)[2]) < 17, payload)
                continue
            if status.ok():
                self.assertIsNotNone(tv, payload)
                self.assertIsNotNone(rv, payload)
            elif tv is None:
                # First parse failed: nothing was written.
                self.assertIsNone(rv, payload)
                self.assertEqual(status.code, K_CORRUPTION, payload)
            else:
                # Second parse failed: trace version kept, rocksdb not.
                self.assertIsNone(rv, payload)
                self.assertEqual(status.code, K_CORRUPTION, payload)

    def test_live_header(self):
        payload = (MAGIC + b"\tTrace Version: 1.2.3\t"
                   b"RocksDB Version: 8.1.1")
        status, tv, rv = parse_trace_header(payload)
        self.assertTrue(status.ok())
        self.assertEqual(tv, 123)
        self.assertEqual(rv, 811)

    def test_field_zero_ignored(self):
        # Field 0 is never read: junk, empty, or overlong is fine.
        for f0 in [b"", b"junk", b"x" * 200, MAGIC]:
            status, tv, rv = parse_trace_header(
                f0 + b"\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6")
            self.assertTrue(status.ok(), f0)
            self.assertEqual((tv, rv), (123, 456))

    def test_prefix_bytes_never_checked(self):
        # Only the 15/17-byte skips matter; the label bytes are not
        # compared.  Any 15/17 bytes work.
        payload = (b"f0\t" + b"X" * 15 + b"1.2.3\t" + b"Y" * 17 + b"4.5.6")
        status, tv, rv = parse_trace_header(payload)
        self.assertTrue(status.ok())
        self.assertEqual((tv, rv), (123, 456))

    def test_first_error_skips_second_parse(self):
        # Bad trace version: early return, rocksdb version untouched,
        # returned status is the first error.
        status, tv, rv = parse_trace_header(
            b"f0\tTrace Version: 1.2\tRocksDB Version: 4.5.6")
        self.assertEqual(status.code, K_CORRUPTION)
        self.assertEqual(status.message,
                         b"Corrupted trace file. Incorrect version format")
        self.assertIsNone(tv)
        self.assertIsNone(rv)

    def test_second_error_keeps_trace_version(self):
        # Bad rocksdb version: trace version is written, rocksdb is
        # not, and the returned status is the second error.
        status, tv, rv = parse_trace_header(
            b"f0\tTrace Version: 1.2.3\tRocksDB Version: 4.5")
        self.assertEqual(status.code, K_CORRUPTION)
        self.assertEqual(status.message,
                         b"Corrupted trace file. Incorrect version format")
        self.assertEqual(tv, 123)
        self.assertIsNone(rv)

    def test_throws(self):
        # Field 1 shorter than 15 -> substr(15) throws.
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"f0\tshort\tRocksDB Version: 1.2.3")
        # Field 2 shorter than 17 -> substr(17) throws (checked after
        # field 1, so a short field 1 throws first).
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"f0\tTrace Version: 1.2.3\tshort")
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"f0\tshort\tshort")
        # No tabs at all: fields 1/2 are empty.
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"feedcafedeadbeef")
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"")

    def test_throw_message_offsets(self):
        try:
            parse_trace_header(b"f0\tshort\tRocksDB Version: 1.2.3")
        except OutOfRange_ as exc:
            self.assertIn("15", str(exc))
        try:
            parse_trace_header(b"f0\tTrace Version: 1.2.3\tshort")
        except OutOfRange_ as exc:
            self.assertIn("17", str(exc))

    def test_extra_tabs(self):
        # Anything after the third TAB is not a field; field 2 stops
        # at the third TAB.
        status, tv, rv = parse_trace_header(
            b"f0\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6\textra")
        self.assertTrue(status.ok())
        self.assertEqual((tv, rv), (123, 456))

    def test_wrap_quirk_reaches_version_parse(self):
        # One-TAB payload with a long field 1: field 2 wraps to the
        # payload start, so substr(17) on it throws (it is 15 bytes).
        with self.assertRaises(OutOfRange_):
            parse_trace_header(b"0123456789abcde\tTrace Version: 1.2.3")


class LedgerTest(unittest.TestCase):
    def test_cases_tsv_matches_generator(self):
        split, parse, header = generate_cases()
        rows = (PACKET / "cases.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), 2400)
        n_split = n_parse = n_header = 0
        for row in rows:
            kind, inp, want = row.split("\t")
            if kind == "split_payload":
                payload = split[n_split]
                n_split += 1
                self.assertEqual(bytes.fromhex(inp), payload)
                fields = split_payload(payload)
                self.assertEqual(want,
                                 ":".join(f.hex() for f in fields))
            elif kind == "parse_version_str":
                s, w = parse[n_parse]
                n_parse += 1
                self.assertEqual(bytes.fromhex(inp), s)
                self.assertEqual(want, "ERR" if w is None else str(w))
            elif kind == "parse_trace_header":
                payload = header[n_header]
                n_header += 1
                self.assertEqual(bytes.fromhex(inp), payload)
                try:
                    status, tv, rv = parse_trace_header(payload)
                except OutOfRange_:
                    fields = split_payload(payload)
                    if len(fields[1]) < 15:
                        self.assertEqual(want, "THROW:15")
                    else:
                        self.assertEqual(want, "THROW:17")
                    continue
                if status.ok():
                    self.assertEqual(want, "OK:%d:%d" % (tv, rv))
                elif tv is None:
                    self.assertEqual(
                        want, "ERR1:%d:%s" % (status.code,
                                              status.message.hex()))
                else:
                    self.assertEqual(
                        want, "ERR2:%d:%d:%s" % (tv, status.code,
                                                 status.message.hex()))
            else:  # pragma: no cover
                self.fail("unknown kind %r" % kind)
        self.assertEqual((n_split, n_parse, n_header), (600, 600, 1200))


if __name__ == "__main__":
    unittest.main()
