#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::Sync reconstruction
(tools/sync115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import sync115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-sync-115"

OK = tool._ok_status()
ERR = tool._status(5, message="Sync failed: I/O error")


def _writer(seen_error=False, pending_sync=True, tracer=None,
            direct_io=False):
    return {"seen_error": seen_error, "pending_sync": pending_sync,
            "io_tracer": tracer,
            "fs_tracer": {"target": {"use_direct_io": direct_io}}}


def test_seen_error_returns_prev_error():
    out = tool.sync(_writer(True), False, flush_result=OK,
                    sync_result=OK)
    assert out["status"] == tool._fresh_error(
        5, tool.PREV_ERROR_MSG)
    assert out["seen_error"] is True
    assert out["flush_called"] is False
    assert out["sync_internal_called"] is False


def test_flush_failure_sets_seen_error_and_returns_copy():
    s = tool._status(5, subcode=4, message="No space",
                     retryable=True)
    out = tool.sync(_writer(), True, flush_result=s)
    assert out["seen_error"] is True
    assert out["status"]["code"] == 5
    assert out["status"]["sev"] == 0
    assert out["status"]["retryable"] is True
    assert out["status"]["state"] == "No space"
    assert out["sync_internal_called"] is False


def test_direct_io_skips_sync_internal():
    out = tool.sync(_writer(False, True, None, True), False,
                    flush_result=OK, sync_result=ERR)
    assert out["status"] == OK
    assert out["pending_sync"] is False
    assert out["sync_internal_called"] is False


def test_pending_sync_clear_returns_ok_without_sync():
    out = tool.sync(_writer(False, False), False,
                    flush_result=OK, sync_result=ERR)
    assert out["status"] == OK
    assert out["pending_sync"] is False
    assert out["sync_internal_called"] is False


def test_ok_sync_returns_ok_and_clears_pending_sync():
    out = tool.sync(_writer(), False, flush_result=OK,
                    sync_result=OK)
    assert out["status"] == OK
    assert out["seen_error"] is False
    assert out["pending_sync"] is False
    assert out["sync_internal_called"] is True


def test_failed_sync_internal_sets_seen_error_and_resets_severity():
    s = tool._status(5, subcode=4, message="No space",
                     retryable=True, sev=2)
    out = tool.sync(_writer(), True, flush_result=OK,
                    sync_result=s)
    assert out["seen_error"] is True
    assert out["status"]["code"] == 5
    assert out["status"]["sev"] == 0
    assert out["status"]["retryable"] is True
    assert out["status"]["state"] == "No space"
    assert out["pending_sync"] is True


def test_wrapper_vs_target_resolution():
    tracer = {"tracing_enabled": True}
    out = tool.sync(_writer(False, True, tracer), False,
                    flush_result=OK, sync_result=OK)
    assert out["effective"] == "wrapper"
    out = tool.sync(
        _writer(False, True, {"tracing_enabled": False}), False,
        flush_result=OK, sync_result=OK)
    assert out["effective"] == "target"
    out = tool.sync(_writer(False, True, None), False,
                    flush_result=OK, sync_result=OK)
    assert out["effective"] == "target"


def test_throws_propagate():
    try:
        tool.sync(_writer(), False, flush_throws=True)
    except tool.FlushThrew:
        pass
    else:
        raise AssertionError("expected FlushThrew")
    try:
        tool.sync(_writer(), False, flush_result=OK,
                  use_direct_io_throws=True)
    except tool.UseDirectIoThrew:
        pass
    else:
        raise AssertionError("expected UseDirectIoThrew")
    try:
        tool.sync(_writer(), False, flush_result=OK,
                  sync_throws=True)
    except tool.SyncInternalThrew:
        pass
    else:
        raise AssertionError("expected SyncInternalThrew")


def test_new_failure_and_bad_canary():
    try:
        tool.sync(_writer(True), False, new_throws="prev_error")
    except tool.BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
    try:
        tool.sync(_writer(), False, flush_result=OK,
                  sync_result=OK, canary_ok=False)
    except tool.StackCheckFailed:
        pass
    else:
        raise AssertionError("expected StackCheckFailed")
    try:
        tool.sync(_writer(), False, flush_result=OK,
                  sync_throws=True, canary_ok=False)
    except tool.StackCheckFailed:
        pass
    else:
        raise AssertionError(
            "expected StackCheckFailed from the cold cleanup")


def test_body_and_source_hashes_match_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 494
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    src = bytearray(body)
    for off, _kind in tool.RELOCATIONS:
        src[off:off + 4] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(src)).hexdigest() == \
        tool.SOURCE_SHA256
    cold = data[text_off + (tool.COLD_START - text_va):
                text_off + (tool.COLD_END - text_va)]
    assert len(cold) == 87
    assert hashlib.sha256(cold).hexdigest() == \
        tool.COLD_BODY_SHA256
    csrc = bytearray(cold)
    for off, _kind in tool.COLD_RELOCATIONS:
        csrc[off:off + 4] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(csrc)).hexdigest() == \
        tool.COLD_SOURCE_SHA256


def test_eleven_callers():
    assert len(tool.CALLERS) == 11
    names = sorted({c[3] for c in tool.CALLERS})
    assert names == [
        "rocksdb::BlobLogWriter::Sync",
        "rocksdb::BuildTable",
        "rocksdb::CompactionOutputs::WriterSyncClose",
        "rocksdb::CopyFile",
        "rocksdb::CreateFile",
        "rocksdb::DBImpl::Open",
        "rocksdb::DBImpl::SyncClosedLogs",
        "rocksdb::DBImpl::WriteToWAL",
        "rocksdb::PersistRocksDBOptions",
        "rocksdb::SyncManifest",
    ]
    opens = [c for c in tool.CALLERS
             if c[3] == "rocksdb::DBImpl::Open"]
    assert len(opens) == 2
    assert {c[0] for c in opens} == {0x5E63CCE, 0x5E650C7}


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
    fn = records["functions"]["0x6052800"]
    assert fn["body_sha256"] == tool.BODY_SHA256
    assert fn["source_sha256"] == tool.SOURCE_SHA256
    assert fn["raw_equal"] is False
    assert fn["relocations"] == tool.RELOCATIONS_DESC
    assert fn["cold_body_sha256"] == tool.COLD_BODY_SHA256
    assert fn["cold_source_sha256"] == tool.COLD_SOURCE_SHA256
    assert len(records["caller_census"]["sites"]) == 11
    assert records["cases"]["count"] == 300


def test_live_check():
    out = subprocess.run(
        [sys.executable,
         str(Path(tool.__file__).resolve()), "--live"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout
