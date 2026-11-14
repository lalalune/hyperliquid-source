"""Tests for the node #115 rocksdb::LineFileReader::ReadLine model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the line shape (the returned
line never contains its '\\n'; empty lines return b''; '\\r' stays in
the line; a line longer than 8192 bytes is built up across refills and
returned whole; a trailing unterminated line is never returned as a
success), the gates (the sticky-error entry gate leaves out untouched;
a failed Read keeps the partial line in out, does not update
buf_begin_/buf_end_, and makes the error sticky; the IOSTATS counter
still adds a failed Read's partial size; at_eof_ is set only by a
short Read; the append length guard throws), the caller census (one
call, from RocksDBOptionsParser::Parse; no .cold landing pad), the FDE
body hash, and the live engine check (real files read by the model
match the real file bytes split on '\\n').
"""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import line_file_reader_readline115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-line-file-reader-readline-115")
BIN = Path(__file__).resolve().parents[1] / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _reader(data, script=None):
    return m.LineFileReader(m.FakeSequentialFile(data, script=script))


def _va2off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BIN)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"gate": 600, "lines": 600,
                                  "chunking": 600, "bindings": 600})

    def test_replay_all(self):
        for row in _read_cases():
            inputs = json.loads(row["inputs_json"])
            expected = json.loads(row["expected_json"])
            self.assertEqual(m.run_case(inputs), expected, row["case_id"])

    def test_case_ids_unique(self):
        rows = _read_cases()
        self.assertEqual(len({r["case_id"] for r in rows}), 2400)

    def test_every_case_ends_false(self):
        # The Parse loop runs until ReadLine returns False.
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            self.assertFalse(expected["calls"][-1]["ok"], row["case_id"])

    def test_line_numbers_match_returned_lines(self):
        for row in _read_cases():
            expected = json.loads(row["expected_json"])
            returned = sum(1 for c in expected["calls"] if c["ok"])
            self.assertEqual(expected["line_number"], returned,
                             row["case_id"])


class LineShapeTests(unittest.TestCase):
    def _drain(self, data, script=None):
        reader = _reader(data, script=script)
        out = m.OutStr()
        got = []
        while reader.read_line(out):
            got.append(out.value)
        return reader, out, got

    def test_empty_lines(self):
        _, _, got = self._drain(b"\n\n\n")
        self.assertEqual(got, [b"", b"", b""])

    def test_no_trailing_newline_not_returned(self):
        reader, out, got = self._drain(b"first\nsecond-no-newline")
        self.assertEqual(got, [b"first"])
        self.assertEqual(reader.get_line_number(), 1)
        self.assertTrue(reader.get_status().is_ok())
        # The partial line was never appended: it was already in the
        # buffer when at_eof_ was set, so the at_eof_ arm returned
        # before appending.
        self.assertEqual(out.value, b"")

    def test_unterminated_long_tail_keeps_first_chunk(self):
        _, out, got = self._drain(b"x" * 9000 + b"tail-no-newline")
        self.assertEqual(got, [])
        # The refill path appended the first chunk before the short
        # Read set at_eof_; the final chunk was never appended.
        self.assertEqual(out.value, b"x" * 8192)

    def test_crlf_keeps_cr(self):
        _, _, got = self._drain(b"a\r\nb\r\n\r\nc\r\n")
        self.assertEqual(got, [b"a\r", b"b\r", b"\r", b"c\r"])

    def test_long_line_spans_chunks(self):
        _, _, got = self._drain(b"L" * 20000 + b"\nshort\n")
        self.assertEqual(got, [b"L" * 20000, b"short"])

    def test_exact_boundary_line(self):
        _, _, got = self._drain(b"B" * 8192 + b"\nend\n")
        self.assertEqual(got, [b"B" * 8192, b"end"])

    def test_empty_file(self):
        reader, out, got = self._drain(b"")
        self.assertEqual(got, [])
        self.assertTrue(reader.get_status().is_ok())
        self.assertTrue(reader.at_eof)

    def test_binary_bytes_in_line(self):
        _, _, got = self._drain(b"\x00\xff\x80abc\n")
        self.assertEqual(got, [b"\x00\xff\x80abc"])


class GateTests(unittest.TestCase):
    def test_sticky_error_gate_leaves_out_untouched(self):
        reader = _reader(b"a\n")
        reader.io_status = m.IOStatus.io_error("earlier failure")
        out = m.OutStr(b"keep-me")
        self.assertIs(reader.read_line(out), False)
        self.assertEqual(out.value, b"keep-me")

    def test_read_failure_keeps_partial_and_sticky(self):
        reader = _reader(
            b"A" * 9000 + b"\ntwo\n",
            script={"fail_at_read": 1,
                    "fail_status": m.IOStatus.io_error("disk error")})
        out = m.OutStr()
        self.assertIs(reader.read_line(out), False)
        self.assertEqual(out.value, b"A" * 8192)
        self.assertEqual(reader.get_status().code, 5)
        # The error is sticky: the next call fails at the entry gate.
        out.value = b"keep-me"
        self.assertIs(reader.read_line(out), False)
        self.assertEqual(out.value, b"keep-me")

    def test_failed_read_does_not_update_buffer(self):
        reader = _reader(
            b"A" * 9000 + b"\ntwo\n",
            script={"fail_at_read": 1, "fail_size": 100,
                    "fail_status": m.IOStatus.io_error("disk error")})
        out = m.OutStr()
        self.assertIs(reader.read_line(out), False)
        # buf_begin_/buf_end_ still describe the first chunk: the
        # failed Read's bytes were never installed.
        self.assertEqual(reader.buf_begin, 0)
        self.assertEqual(reader.buf_end, 8192)
        self.assertEqual(reader.buf, b"A" * 8192)

    def test_iostats_adds_failed_read_partial_size(self):
        reader = _reader(
            b"A" * 9000 + b"\ntwo\n",
            script={"fail_at_read": 1, "fail_size": 100,
                    "fail_status": m.IOStatus.io_error("disk error")})
        out = m.OutStr()
        self.assertIs(reader.read_line(out), False)
        # The IOSTATS add precedes the status check: 8192 (first
        # Read) + 100 (the failed Read's partial size).
        self.assertEqual(reader.iostats_bytes_read, 8292)

    def test_priority_forwarded(self):
        reader = _reader(b"a\nb\n")
        out = m.OutStr()
        reader.read_line(out, priority=2)
        reader.read_line(out, priority=2)
        reads = [e for e in reader.trace if e["op"] == "read"]
        self.assertTrue(reads)
        self.assertTrue(all(e["priority"] == 2 for e in reads))

    def test_append_overflow_raises(self):
        # The guard is MAX - out->size(); shrink MAX so a short line
        # trips it, exactly as __throw_length_error would.
        old_max = m.MAX_SIZE
        try:
            m.MAX_SIZE = 10
            reader = _reader(b"0123456789ABCDEF\n")
            out = m.OutStr()
            with self.assertRaises(m.LengthError) as ctx:
                reader.read_line(out)
            self.assertEqual(str(ctx.exception),
                             "basic_string::append")
        finally:
            m.MAX_SIZE = old_max

    def test_at_eof_only_on_short_read(self):
        # A file ending exactly on an 8192-byte boundary: the full
        # read does NOT set at_eof_; the next call's zero-byte refill
        # does.
        reader = _reader(b"E" * 8191 + b"\n")
        out = m.OutStr()
        self.assertIs(reader.read_line(out), True)
        self.assertEqual(out.value, b"E" * 8191)
        self.assertIs(reader.at_eof, False)
        self.assertIs(reader.read_line(out), False)
        self.assertIs(reader.at_eof, True)
        self.assertTrue(reader.get_status().is_ok())

    def test_get_status_distinguishes_eof_and_error(self):
        ok_reader = _reader(b"a\n")
        out = m.OutStr()
        while ok_reader.read_line(out):
            pass
        self.assertTrue(ok_reader.get_status().is_ok())
        err_reader = _reader(
            b"A" * 9000 + b"\n",
            script={"fail_at_read": 1,
                    "fail_status": m.IOStatus.io_error("disk error")})
        self.assertIs(err_reader.read_line(out), False)
        self.assertEqual(err_reader.get_status().code, 5)

    def test_second_call_after_eof_returns_false_immediately(self):
        reader = _reader(b"a\n")
        out = m.OutStr()
        self.assertIs(reader.read_line(out), True)
        self.assertIs(reader.read_line(out), False)
        # The at_eof_ arm returns before any Read: no second refill.
        reads = [e for e in reader.trace if e["op"] == "read"]
        self.assertEqual(len(reads), 1)

    def test_out_cleared_on_healthy_call(self):
        reader = _reader(b"a\n")
        out = m.OutStr(b"stale-content")
        self.assertIs(reader.read_line(out), True)
        self.assertEqual(out.value, b"a")


class CensusTests(unittest.TestCase):
    def test_body_hash(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)
        body = data[_va2off(0x60D4CF0):_va2off(0x60D4F62)]
        self.assertEqual(len(body), 626)
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            "4894ad484826ac17944c8af7f6c897240815886e42b70fd44ae700cffa3418b2")

    def test_caller_census(self):
        rows = [line.rstrip("\n").split("\t")
                for line in open(PACKET / "callers.tsv")
                .read().splitlines()[1:]]
        calls = [r for r in rows if r[2] == "call"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][3], "0x60d0343")
        self.assertEqual(calls[0][4], "0x60cfb60")
        self.assertEqual(calls[0][5], "0x60d1354")
        self.assertEqual(len([r for r in rows if r[2] == "jmp"]), 0)
        self.assertEqual(len([r for r in rows if r[2] == "lea"]), 0)

    def test_no_lsda_no_cold_pad(self):
        # The FDE carries no LSDA, so there is no .cold landing pad.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                               / "tools"))
        from fde_extents import eh_frame_records
        data = open(BIN, "rb").read()
        _, fdes = eh_frame_records(data)
        by_start = {f["start"]: f for f in fdes}
        self.assertIsNone(by_start[0x60D4CF0]["lsda"])

    def test_dtor_census_bound(self):
        # The class identity pin: the LineFileReader destructor is
        # census-bound and its body hash matches the census record.
        census = json.load(open(
            Path(__file__).resolve().parents[1] / "research"
            / "work-items" / "RE-002-node115-vendor-census"
            / "census.json"))["records"]
        rec = next(r for r in census if r["start"] == 0x60CBEA0)
        self.assertIn("LineFileReader", rec["symbol"])
        data = open(BIN, "rb").read()
        body = data[_va2off(0x60CBEA0):_va2off(0x60CBEA0 + 680)]
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         rec["target_body_sha256"])


class ManifestTests(unittest.TestCase):
    def test_manifest_verifies(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            want, name = line.split(None, 1)
            got = hashlib.sha256(
                (PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(got, want, name)


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, _ = m.live_engine_check()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
