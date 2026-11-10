#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::GetFileChecksumFuncName
reconstruction (tools/get_file_checksum_func_name115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import get_file_checksum_func_name115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-get-file-checksum-func-name-115"

NULL_WRITER = {"checksum_generator": None}
GEN_WRITER = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}


def test_null_generator_returns_unknown():
    assert tool.get_file_checksum_func_name(NULL_WRITER) == \
        {"func_name": "Unknown"}
    assert tool.get_file_checksum_func_name(
        NULL_WRITER, gen_name="ignored") == {"func_name": "Unknown"}


def test_present_generator_returns_its_name():
    for value in ("", "a", "FileChecksumCrc32c", "Unknown"):
        assert tool.get_file_checksum_func_name(
            GEN_WRITER, gen_name=value) == {"func_name": value}


def test_name_returned_verbatim():
    value = "FileChecksumXXH64WithSeed-0123456789abcdef"
    assert tool.get_file_checksum_func_name(
        GEN_WRITER, gen_name=value) == {"func_name": value}
    assert len(tool.get_file_checksum_func_name(
        GEN_WRITER, gen_name=value)["func_name"]) == len(value)


def test_generator_throw_propagates():
    try:
        tool.get_file_checksum_func_name(GEN_WRITER, gen_name="x",
                                         gen_throws=True)
    except tool.GeneratorThrew:
        pass
    else:
        raise AssertionError("expected GeneratorThrew")


def test_throw_vacuous_with_no_generator():
    # A null generator never calls, so gen_throws has no effect.
    assert tool.get_file_checksum_func_name(
        NULL_WRITER, gen_throws=True) == {"func_name": "Unknown"}


def test_body_and_source_hashes_match_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 40
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    src = bytearray(body)
    src[35:39] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(src)).hexdigest() == tool.SOURCE_SHA256
    assert tool.RELOCATIONS == "1 kind-2 relocation at offset 35"


def test_three_calls_three_jumps():
    assert len(tool.CALLERS) == 6
    kinds = [c[5] for c in tool.CALLERS]
    assert kinds.count("call") == 3
    assert kinds.count("jmp") == 3
    sites = [c[0] for c in tool.CALLERS]
    assert sites == [0x5E189BE, 0x5E1F508, 0x5E27213,
                     0x60E2194, 0x615CB1D, 0x618B340]
    names = [c[3] for c in tool.CALLERS]
    assert names[1] == "rocksdb::BuildTable"
    assert names[3] == \
        "rocksdb::BlockBasedTableBuilder::GetFileChecksumFuncName"


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
    fn = records["functions"]["0x604c780"]
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
