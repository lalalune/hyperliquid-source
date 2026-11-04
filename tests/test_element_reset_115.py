"""Tests for tools/element_reset_115.py (node #115 element reset).

Runs under pytest when available, and under plain python3 via the
``__main__`` runner below (this VM has no pytest installed).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from element_reset_115 import (  # noqa: E402
    EMBEDDED,
    element_reset,
    string_field,
)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-element-reset-115"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def make_object():
    return {
        "dword_0x00": 7,
        "buf_0x08": bytearray(b"hello\x00"),
        "qword_0x10": 9,
        "field_0x20": 12345,
        "buf_0x28": bytearray(b"world\x00"),
        "qword_0x30": 11,
        "block_0x48": bytearray(range(0x38)),
        "array_0x80": {"elements": [], "live": 0},
        "list_0xa8": {"head": None, "field_0xb0": "old", "field_0xb8": "old",
                      "field_0xc0": 5},
        "array_0xc8": {"elements": [], "live": 0},
        "array_0xe0": {"elements": [], "live": 0},
        "field_0xf8": 0xAAAA,
        "field_0x100": 0xBBBB,
        "field_0x110": 0xCCCC,
        "field_0x118": 0xDDDD,
        "field_0x128": 3,
        "field_0x130": 4,
        "field_0x134": 5,
        "buf_0x138": bytearray(b"tail1\x00"),
        "field_0x140": 6,
        "field_0x158": 7,
        "field_0x15c": 8,
        "buf_0x160": bytearray(b"tail2\x00"),
        "field_0x168": 9,
    }


def run(obj):
    seen = []

    def node_callback(arg):
        seen.append(arg)

    log = element_reset(obj, node_callback)
    return log, seen


def test_head_scalars_cleared_and_untouched_field_preserved():
    obj = make_object()
    run(obj)
    assert obj["dword_0x00"] == 0
    assert obj["qword_0x10"] == 0
    assert obj["buf_0x08"][0] == 0
    assert obj["qword_0x30"] == 0
    assert obj["buf_0x28"][0] == 0
    assert obj["field_0x20"] == 12345


def test_block_zeroed_except_the_0x64_gap():
    obj = make_object()
    run(obj)
    block = obj["block_0x48"]
    for index in range(0x38):
        if 0x1C <= index <= 0x1F:
            assert block[index] == index, "gap byte must survive"
        else:
            assert block[index] == 0


def test_first_array_dispose_order_and_live_reset():
    obj = make_object()
    obj["array_0x80"] = {
        "elements": [
            {"field": string_field("heap-a", 41)},
            {"field": string_field(EMBEDDED, 99)},
            {"field": string_field(None, 7)},
            {"field": string_field("heap-b", 0)},
        ],
        "live": 4,
    }
    log, _ = run(obj)
    assert log["deletes"][:2] == [("heap-a", 42), ("heap-b", 1)]
    assert obj["array_0x80"]["live"] == 0
    assert len(obj["array_0x80"]["elements"]) == 4


def test_first_array_empty_is_a_no_op():
    obj = make_object()
    log, _ = run(obj)
    assert log["deletes"] == []
    assert obj["array_0x80"]["live"] == 0


def test_list_walk_order_node_calls_and_header_reset():
    n3 = {"id": "n3", "next": None, "callee_arg": "arg3"}
    n2 = {"id": "n2", "next": n3, "callee_arg": "arg2"}
    n1 = {"id": "n1", "next": n2, "callee_arg": "arg1"}
    obj = make_object()
    obj["list_0xa8"]["head"] = n1
    log, seen = run(obj)
    assert seen == ["arg1", "arg2", "arg3"]
    assert log["node_calls"] == ["arg1", "arg2", "arg3"]
    assert log["deletes"] == [("n1", 0x30), ("n2", 0x30), ("n3", 0x30)]
    header = obj["list_0xa8"]
    assert header["head"] is None
    assert header["field_0xb0"] == "embedded_0xa0"
    assert header["field_0xb8"] == "embedded_0xa0"
    assert header["field_0xc0"] == 0


def test_second_array_four_disposes_in_order():
    obj = make_object()
    obj["array_0xc8"] = {
        "elements": [{
            "f_0x100": string_field("h100", 10),
            "f_0xe0": string_field(EMBEDDED, 0),
            "f_0x50": string_field("h50", 20),
            "f_0x30": string_field("h30", 30),
        }],
        "live": 1,
    }
    log, _ = run(obj)
    assert log["deletes"] == [("h100", 11), ("h50", 21), ("h30", 31)]
    assert obj["array_0xc8"]["live"] == 0


def test_third_array_two_disposes_in_order():
    obj = make_object()
    obj["array_0xe0"] = {
        "elements": [{
            "f_0x38": string_field("h38", 5),
            "f_0x18": string_field("h18", 6),
        }],
        "live": 1,
    }
    log, _ = run(obj)
    assert log["deletes"] == [("h38", 6), ("h18", 7)]
    assert obj["array_0xe0"]["live"] == 0


def test_tail_scalars_and_buffers():
    obj = make_object()
    run(obj)
    assert obj["field_0x100"] == 0xAAAA
    assert obj["field_0x118"] == 0xCCCC
    assert obj["field_0x128"] == 0
    assert obj["field_0x130"] == 0
    assert obj["field_0x134"] == 0
    assert obj["field_0x140"] == 0
    assert obj["buf_0x138"][0] == 0
    assert obj["field_0x158"] == 0
    assert obj["field_0x15c"] == 0
    assert obj["field_0x168"] == 0
    assert obj["buf_0x160"][0] == 0


def test_end_to_end_delete_order_across_sections():
    obj = make_object()
    obj["array_0x80"] = {
        "elements": [{"field": string_field("first", 1)}], "live": 1}
    node = {"id": "node", "next": None, "callee_arg": "arg"}
    obj["list_0xa8"]["head"] = node
    obj["array_0xc8"] = {
        "elements": [{
            "f_0x100": string_field("c100", 2),
            "f_0xe0": string_field("ce0", 3),
            "f_0x50": string_field("c50", 4),
            "f_0x30": string_field("c30", 5),
        }],
        "live": 1,
    }
    obj["array_0xe0"] = {
        "elements": [{
            "f_0x38": string_field("e38", 6),
            "f_0x18": string_field("e18", 7),
        }],
        "live": 1,
    }
    log, seen = run(obj)
    assert log["deletes"] == [
        ("first", 2), ("node", 0x30),
        ("c100", 3), ("ce0", 4), ("c50", 5), ("c30", 6),
        ("e38", 7), ("e18", 8),
    ]
    assert seen == ["arg"]


def test_null_head_buffer_raises():
    obj = make_object()
    obj["buf_0x08"] = None
    try:
        run(obj)
    except ValueError:
        return
    raise AssertionError("expected a null-buffer fault")


def test_packet_records_bind_the_digest():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["artifact"]["sha256"] == SHA256
    assert records["artifact"]["sha256_match"] is True
    assert records["window"]["start"] == "0x5f54ee0"
    assert records["window"]["end"] == "0x5f551c2"


def test_packet_excerpt_is_whole_function():
    excerpt = (PACKET / "function_0x5f54ee0.txt").read_text()
    assert "5f54ee0:" in excerpt
    assert "5f55179:" in excerpt  # the ret
    assert "5f551c2:" not in excerpt  # next function, excluded
    assert "endbr64" in excerpt


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print("PASS %s" % name)
    print("%d tests passed" % len(tests))
