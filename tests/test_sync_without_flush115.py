#!/usr/bin/env python3
"""Tests for the node #115 WritableFileWriter::SyncWithoutFlush
reconstruction (tools/sync_without_flush115.py)."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import sync_without_flush115 as tool  # noqa: E402

PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-sync-without-flush-115"

OK = tool._ok_status()
ERR = tool._status(5, message="Sync failed: I/O error")


def _writer(seen_error=False, tracer=None, safe=True):
    return {"seen_error": seen_error, "io_tracer": tracer,
            "fs_tracer": {"target": {"sync_thread_safe": safe}}}


def test_seen_error_returns_prev_error():
    out = tool.sync_without_flush(_writer(True), False,
                                  sync_result=OK)
    assert out["status"] == tool._fresh_error(
        5, tool.PREV_ERROR_MSG)
    assert out["seen_error"] is True
    assert out["sync_internal_called"] is False


def test_not_thread_safe_returns_not_supported():
    out = tool.sync_without_flush(_writer(False, None, False), True)
    assert out["status"] == tool._fresh_error(
        3, tool.NOT_SUPPORTED_MSG)
    assert out["seen_error"] is False
    assert out["sync_internal_called"] is False


def test_ok_sync_returns_ok_and_leaves_seen_error_clear():
    out = tool.sync_without_flush(_writer(), False, sync_result=OK)
    assert out["status"] == OK
    assert out["seen_error"] is False
    assert out["sync_internal_called"] is True


def test_failed_sync_sets_seen_error_and_resets_severity():
    s = tool._status(5, subcode=4, message="No space",
                     retryable=True)
    out = tool.sync_without_flush(_writer(), True, sync_result=s)
    assert out["seen_error"] is True
    assert out["status"]["code"] == 5
    assert out["status"]["sev"] == 0
    assert out["status"]["retryable"] is True
    assert out["status"]["state"] == "No space"


def test_wrapper_vs_target_resolution():
    tracer = {"tracing_enabled": True}
    out = tool.sync_without_flush(_writer(False, tracer), False,
                                  sync_result=OK)
    assert out["effective"] == "wrapper"
    out = tool.sync_without_flush(
        _writer(False, {"tracing_enabled": False}), False,
        sync_result=OK)
    assert out["effective"] == "target"
    out = tool.sync_without_flush(_writer(False, None), False,
                                  sync_result=OK)
    assert out["effective"] == "target"


def test_throws_propagate_without_landing_pad():
    try:
        tool.sync_without_flush(_writer(), False,
                                is_sync_throws=True)
    except tool.IsSyncThreadSafeThrew:
        pass
    else:
        raise AssertionError("expected IsSyncThreadSafeThrew")
    try:
        tool.sync_without_flush(_writer(), False, sync_throws=True)
    except tool.SyncInternalThrew:
        pass
    else:
        raise AssertionError("expected SyncInternalThrew")


def test_new_failure_and_bad_canary():
    try:
        tool.sync_without_flush(_writer(False, None, False), False,
                                new_throws="not_supported")
    except tool.BadAlloc:
        pass
    else:
        raise AssertionError("expected BadAlloc")
    try:
        tool.sync_without_flush(_writer(), False, sync_result=OK,
                                canary_ok=False)
    except tool.StackCheckFailed:
        pass
    else:
        raise AssertionError("expected StackCheckFailed")


def test_body_and_source_hashes_match_census():
    data = open(tool._bin_path(), "rb").read()
    assert hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256
    text_va, text_off, text = tool._load_text()
    body = data[text_off + (tool.START - text_va):
                text_off + (tool.END - text_va)]
    assert len(body) == 445
    assert hashlib.sha256(body).hexdigest() == tool.BODY_SHA256
    src = bytearray(body)
    for off, _kind in tool.RELOCATIONS:
        src[off:off + 4] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(src)).hexdigest() == \
        tool.SOURCE_SHA256
    cold = data[text_off + (tool.COLD_START - text_va):
                text_off + (tool.COLD_END - text_va)]
    assert len(cold) == 86
    assert hashlib.sha256(cold).hexdigest() == \
        tool.COLD_BODY_SHA256
    csrc = bytearray(cold)
    for off, _kind in tool.COLD_RELOCATIONS:
        csrc[off:off + 4] = b"\x00\x00\x00\x00"
    assert hashlib.sha256(bytes(csrc)).hexdigest() == \
        tool.COLD_SOURCE_SHA256


def test_one_caller_dbimpl_syncwal():
    assert len(tool.CALLERS) == 1
    site, start, end, name, member, kind = tool.CALLERS[0]
    assert (site, kind) == (0x5D7F657, "call")
    assert name == "rocksdb::DBImpl::SyncWAL"
    assert (start, end) == (0x5D7F3B0, 0x5D7FB40)
    assert member == "4d429ab1cb2d8f8b-db_impl.o"


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
    fn = records["functions"]["0x604d500"]
    assert fn["body_sha256"] == tool.BODY_SHA256
    assert fn["source_sha256"] == tool.SOURCE_SHA256
    assert fn["raw_equal"] is False
    assert fn["relocations"] == tool.RELOCATIONS_DESC
    assert fn["cold_body_sha256"] == tool.COLD_BODY_SHA256
    assert fn["cold_source_sha256"] == tool.COLD_SOURCE_SHA256
    assert len(records["caller_census"]["sites"]) == 1
    assert records["cases"]["count"] == 300


def test_live_check():
    out = subprocess.run(
        [sys.executable,
         str(Path(tool.__file__).resolve()), "--live"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout
