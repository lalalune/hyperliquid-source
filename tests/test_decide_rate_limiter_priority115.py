#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::DecideRateLimiterPriority
reconstruction (tools/decide_rate_limiter_priority115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import decide_rate_limiter_priority115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-decide-rate-limiter-priority-115"


def test_all_valid_pairs():
    for f in range(5):
        for o in range(5):
            want = o if o != 4 else f
            assert tool.decide(f, o) == want, (f, o)


def test_both_total_is_total():
    assert tool.decide(4, 4) == 4


def test_file_total_falls_through_to_op():
    for o in range(4):
        assert tool.decide(4, o) == o


def test_op_total_falls_back_to_file():
    for f in range(4):
        assert tool.decide(f, 4) == f


def test_neither_total_returns_op():
    for f in range(4):
        for o in range(4):
            assert tool.decide(f, o) == o


def test_out_of_range_passes_through():
    assert tool.decide(5, 4) == 5
    assert tool.decide(4, 255) == 255
    assert tool.decide(0xFFFFFFFF, 4) == 0xFFFFFFFF
    assert tool.decide(0x80000000, 0) == 0
    assert tool.decide(6, 7) == 7


def test_body_hash_matches_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 39
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    assert tool.SOURCE_SHA256 == tool.BODY_SHA256
    assert tool.RELOCATIONS == ""


def test_six_callers():
    assert len(tool.CALLERS) == 6
    assert {c[2] for c in tool.CALLERS} == {
        "rocksdb::WritableFileWriter::WriteBuffered",
        "rocksdb::WritableFileWriter::WriteBufferedWithChecksum",
        "rocksdb::WritableFileWriter::WriteDirect",
        "rocksdb::WritableFileWriter::WriteDirectWithChecksum",
        "rocksdb::WritableFileWriter::Flush",
        "rocksdb::WritableFileWriter::Append",
    }


def test_cases_replay():
    assert tool.verify_cases() == 0


def test_cases_file_shape():
    rows = (PACKET / "cases.tsv").read_text().splitlines()
    assert rows[0] == "group\tcase_id\tinputs_json\texpected_json"
    assert len(rows) == 301
    groups = [r.split("\t")[0] for r in rows[1:]]
    assert groups.count("checks") == 100
    assert groups.count("edge") == 100
    assert groups.count("bindings") == 100


def test_bindings_rows_check_their_invariant():
    rows = (PACKET / "cases.tsv").read_text().splitlines()[1:]
    bindings = [r for r in rows if r.split("\t")[0] == "bindings"]
    assert len(bindings) == 100
    for r in bindings:
        inputs = json.loads(r.split("\t")[2])
        expected = json.loads(r.split("\t")[3])
        inv = inputs["invariant"]
        assert expected["invariant"] == inv
        assert expected["invariant_expected"] == tool.invariant_value(inv)


def test_records_bindings():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["artifact_sha256"] == tool.ARTIFACT_SHA256
    fn = records["functions"]["0x604c800"]
    assert fn["body_sha256"] == tool.BODY_SHA256
    assert fn["source_sha256"] == tool.BODY_SHA256
    assert fn["raw_equal"] is True
    assert fn["relocations"] == ""
    assert len(records["caller_census"]["sites"]) == 6
    assert records["cases"]["count"] == 300


def test_live_check():
    out = subprocess.run(
        [sys.executable,
         str(Path(tool.__file__).resolve()), "--live"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout
