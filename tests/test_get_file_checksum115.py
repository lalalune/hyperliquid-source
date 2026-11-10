#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::GetFileChecksum
reconstruction (tools/get_file_checksum115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import get_file_checksum115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-get-file-checksum-115"

NULL_WRITER = {"checksum_generator": None}
GEN_WRITER = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}


def test_null_generator_returns_empty():
    assert tool.get_file_checksum(NULL_WRITER) == {"checksum": ""}
    assert tool.get_file_checksum(NULL_WRITER, gen_checksum="ignored") == \
        {"checksum": ""}


def test_present_generator_returns_its_checksum():
    for value in ("", "a", "deadbeef", "crc32c:1234"):
        assert tool.get_file_checksum(
            GEN_WRITER, gen_checksum=value) == {"checksum": value}


def test_checksum_bytes_verbatim():
    # GetChecksum may return arbitrary bytes, including NUL/0xff.
    value = "\x00\x01\x02\xff\xfehello\x00"
    assert tool.get_file_checksum(
        GEN_WRITER, gen_checksum=value) == {"checksum": value}
    assert len(tool.get_file_checksum(
        GEN_WRITER, gen_checksum=value)["checksum"]) == len(value)


def test_canary_bad_fails_on_both_paths():
    for writer, value in ((NULL_WRITER, None),
                          (GEN_WRITER, "abc")):
        try:
            tool.get_file_checksum(writer, gen_checksum=value,
                                   canary_ok=False)
        except tool.StackCheckFailed:
            pass
        else:
            raise AssertionError("expected StackCheckFailed")


def test_generator_throw_propagates_and_beats_canary():
    try:
        tool.get_file_checksum(GEN_WRITER, gen_checksum="x",
                               gen_throws=True)
    except tool.GeneratorThrew:
        pass
    else:
        raise AssertionError("expected GeneratorThrew")
    # The throw happens inside the virtual call, before the canary
    # check: even with a bad canary the throw wins.
    try:
        tool.get_file_checksum(GEN_WRITER, gen_checksum="x",
                               gen_throws=True, canary_ok=False)
    except tool.GeneratorThrew:
        pass
    else:
        raise AssertionError("expected GeneratorThrew, not "
                             "StackCheckFailed")


def test_body_and_source_hashes_match_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 106
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    src = bytearray(body)
    src[102:106] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(src)).hexdigest() == tool.SOURCE_SHA256
    assert tool.RELOCATIONS == "1 kind-4 relocation at offset 102"


def test_six_callers():
    assert len(tool.CALLERS) == 6
    sites = [c[0] for c in tool.CALLERS]
    assert sites == [0x5E1892E, 0x5E1F4DF, 0x5E2734F,
                     0x60E3F6A, 0x615CEF5, 0x618B378]
    names = [c[3] for c in tool.CALLERS]
    assert names[1] == "rocksdb::BuildTable"
    assert names[3] == \
        "rocksdb::BlockBasedTableBuilder::GetFileChecksum"


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
    fn = records["functions"]["0x604c710"]
    assert fn["body_sha256"] == tool.BODY_SHA256
    assert fn["source_sha256"] == tool.SOURCE_SHA256
    assert fn["raw_equal"] is False
    assert fn["relocations"] == tool.RELOCATIONS
    assert len(records["caller_census"]["sites"]) == 6
    assert records["cases"]["count"] == 300


def test_live_check():
    out = subprocess.run(
        [sys.executable,
         str(Path(tool.__file__).resolve()), "--live"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout
