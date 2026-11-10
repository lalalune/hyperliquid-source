#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::UpdateFileChecksum
reconstruction (tools/update_file_checksum115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import update_file_checksum115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-update-file-checksum-115"

NULL_WRITER = {"checksum_generator": None}
GEN_WRITER = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}


def test_null_generator_never_calls():
    for n in (0, 1, 4096, 0xFFFFFFFFFFFFFFFF):
        assert tool.update(NULL_WRITER, {"ptr": "buf", "len": n}) == \
            {"called": False, "update_call": None}


def test_present_generator_always_calls():
    for n in (0, 1, 4096):
        r = tool.update(GEN_WRITER, {"ptr": "buf", "len": n})
        assert r["called"] is True
        assert r["update_call"]["n"] == n
        assert r["update_call"]["data_ptr"] == "buf"


def test_forwards_ptr_and_len_verbatim():
    r = tool.update(GEN_WRITER, {"ptr": "heap", "len": 0x100000000})
    assert r["update_call"]["data_ptr"] == "heap"
    assert r["update_call"]["n"] == 0x100000000
    assert r["update_call"]["target"].startswith(
        "FileChecksumGenerator::Update")
    assert r["update_call"]["this"] == "FileChecksumGenCrc32c"


def test_len_is_64_bit():
    r = tool.update(GEN_WRITER, {"ptr": "buf", "len": 0x1FFFFFFFFFFFFFFFF})
    assert r["update_call"]["n"] == 0xFFFFFFFFFFFFFFFF


def test_body_hash_matches_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 33
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    assert tool.SOURCE_SHA256 == tool.BODY_SHA256
    assert tool.RELOCATIONS == ""


def test_one_caller():
    assert len(tool.CALLERS) == 1
    site, start, name, _member = tool.CALLERS[0]
    assert site == 0x6054764 and start == 0x6054680
    assert name == "rocksdb::WritableFileWriter::Append"


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
    fn = records["functions"]["0x604c7b0"]
    assert fn["body_sha256"] == tool.BODY_SHA256
    assert fn["source_sha256"] == tool.BODY_SHA256
    assert fn["raw_equal"] is True
    assert fn["relocations"] == ""
    assert len(records["caller_census"]["sites"]) == 1
    assert records["cases"]["count"] == 300


def test_live_check():
    out = subprocess.run(
        [sys.executable,
         str(Path(tool.__file__).resolve()), "--live"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout
