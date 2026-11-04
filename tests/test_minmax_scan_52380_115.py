"""Tests for tools/minmax_scan_52380_115.py (node #115, RE-001).

pytest is not installed on this VM, so verify.py invokes each test_*
function directly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from minmax_scan_52380_115 import OutOfRange, quotient, run, scan_list, walk_chain


def _scan(nodes, root="root"):
    return scan_list(nodes, root)


def test_empty_list_emits_zero_and_skips_walk():
    nodes = {"root": {"next": "root", "a": 0, "b": 0, "flag": 0}}
    result = run(nodes, "root", {}, None, "sentinel")
    assert result["emit"] == (0, 0)
    assert result["quotient"] is None
    assert result["walk"] == "skipped"
    assert result["temp_builder"] == "default"
    assert result["out"] == {"dword0": 0, "word4": 0, "qword8": 0}


def test_flagged_and_zero_nodes_skipped():
    nodes = {
        "root": {"next": "n1", "a": 0, "b": 0, "flag": 0},
        "n1": {"next": "n2", "a": 5, "b": 9, "flag": 1},
        "n2": {"next": "n3", "a": 0, "b": 7, "flag": 0},
        "n3": {"next": "root", "a": 4, "b": 4, "flag": 0},
    }
    assert _scan(nodes) == (4, 4)


def test_scan_min_max():
    nodes = {
        "root": {"next": "n1", "a": 0, "b": 0, "flag": 0},
        "n1": {"next": "n2", "a": 10, "b": 3, "flag": 0},
        "n2": {"next": "n3", "a": 8, "b": 8, "flag": 0},
        "n3": {"next": "root", "a": 20, "b": 6, "flag": 0},
    }
    assert _scan(nodes) == (3, 8)


def test_quotient_arithmetic():
    assert quotient(1) == 1
    assert quotient(100) == 1
    assert quotient(101) == 2
    assert quotient(12345) == 124
    assert quotient(10 ** 12) == 10 ** 10
    assert quotient(2 ** 64 - 1) == 0


def test_walk_finds_kind3_via_next():
    nodes = {
        "h": {"kind": 4, "nxt": "k", "down": None},
        "k": {"kind": 3, "nxt": None, "down": None},
    }
    assert walk_chain(nodes, "h", "sentinel") == ("found", "k")


def test_walk_throws_on_null_head():
    try:
        walk_chain({}, None, "sentinel")
    except OutOfRange:
        return
    raise AssertionError("null head did not throw")


def test_walk_throws_on_kind4():
    nodes = {"h": {"kind": 4, "nxt": None, "down": None}}
    try:
        walk_chain(nodes, "h", "sentinel")
    except OutOfRange:
        return
    raise AssertionError("kind-4 end node did not throw")


def test_walk_throws_at_sentinel():
    nodes = {"h": {"kind": 1, "nxt": None, "down": None}}
    try:
        walk_chain(nodes, "h", "sentinel")
    except OutOfRange:
        return
    raise AssertionError("backup to sentinel did not throw")


def test_walk_descends_then_finds():
    nodes = {
        "h": {"kind": 1, "nxt": None, "down": "d"},
        "d": {"kind": 2, "nxt": "s", "down": None},
        "s": {"kind": 0, "nxt": None, "down": None},
    }
    # h descends to d (kind 2, down null) -> backs up to sentinel? No:
    # d's down is null, so the walk checks rdx, which is still the
    # sentinel -> throws. Use a next-step instead:
    nodes2 = {
        "h": {"kind": 1, "nxt": None, "down": "d"},
        "d": {"kind": 3, "nxt": "s", "down": None},
        "s": {"kind": 0, "nxt": None, "down": None},
    }
    assert walk_chain(nodes2, "h", "sentinel") == ("found", "d")
    try:
        walk_chain(nodes, "h", "sentinel")
    except OutOfRange:
        return
    raise AssertionError("descent to null down did not throw")


def test_full_run_found_path():
    scan = {
        "root": {"next": "n1", "a": 0, "b": 0, "flag": 0},
        "n1": {"next": "root", "a": 50, "b": 40, "flag": 0},
    }
    walk = {"w": {"kind": 2, "nxt": None, "down": None}}
    # w has kind 2 and null down, so the walk backs up to the sentinel
    # and throws; give it a kind-3 node with a next link instead.
    walk = {"w": {"kind": 3, "nxt": "v", "down": None},
            "v": {"kind": 0, "nxt": None, "down": None}}
    result = run(scan, "root", walk, "w", "sentinel")
    assert result["emit"] == (40, 40)
    assert result["quotient"] == 1
    assert result["walk"] == ("found", "w")
    assert result["temp_builder"] == "found"


def test_full_run_wrap_corner_skips_walk():
    scan = {
        "root": {"next": "n1", "a": 0, "b": 0, "flag": 0},
        "n1": {"next": "root", "a": 2 ** 64 - 1, "b": 2 ** 64 - 1, "flag": 0},
    }
    result = run(scan, "root", {}, None, "sentinel")
    assert result["emit"] == (2 ** 64 - 1, 2 ** 64 - 1)
    assert result["quotient"] == 0
    assert result["walk"] == "skipped-wrap"
    assert result["temp_builder"] == "default"
