"""Tests for tools/object_teardown_56f50_115.py (node #115, RE-001).

Run without pytest (not installed on this VM) by importing the module
and calling every test_* function; research/work-items/
RE-001-object-teardown-56f50-115/verify.py does exactly that.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from object_teardown_56f50_115 import teardown


def _empty():
    return {
        "ptr_1f0": None, "flag_148": False,
        "buf_198": {"begin": False, "end_differs": False, "size": 0},
        "records": [],
        "record_array": {"begin": False, "size": 0},
        "flag_c8": False,
        "buf_118": {"begin": False, "end_differs": False, "size": 0},
        "buf_98": {"begin": False, "size": 0},
        "buf_80": {"begin": False, "size": 0},
        "strvec_68": [],
        "buf_68": {"begin": False, "size": 0},
        "buf_50": {"begin": False, "size": 0},
        "elems_38": [],
        "buf_38": {"begin": False, "size": 0},
        "elems_08": [],
        "buf_08": {"begin": False, "size": 0},
    }


def _record():
    return {
        "elem_210": None, "count_strings": [], "strvec": [],
        "strvec_buf": {"begin": False, "size": 0}, "flag_00": False,
        "buf_50": {"begin": False, "end_differs": False, "size": 0},
    }


def test_null_object_only_calls_member_and_returns_plainly():
    ops = teardown(_empty())
    assert ops == [("member_call", "obj+0xb0", 0x5D35C30),
                   ("plain_return",)], ops


def test_entry_pointer_calls_then_frees_0x10_first():
    obj = _empty()
    obj["ptr_1f0"] = "p"
    ops = teardown(obj)
    assert ops[0] == ("member_call", "obj+0x1f0", 0x5F3C850)
    assert ops[1] == ("free", "obj+0x1f0", 0x10)


def test_flags_cleared_only_when_nonzero():
    obj = _empty()
    obj["flag_148"] = True
    obj["flag_c8"] = True
    ops = teardown(obj)
    assert ("clear_flag", "obj+0x148") in ops
    assert ("clear_flag", "obj+0xc8") in ops
    assert ops.count(("clear_flag", "obj+0x148")) == 1


def test_reset_buffer_resets_before_freeing():
    obj = _empty()
    obj["buf_198"] = {"begin": True, "end_differs": True, "size": 0x40}
    ops = teardown(obj)
    assert ops[0] == ("reset_end", "obj+0x198")
    assert ops[1] == ("free_buffer", "obj+0x198", 0x40)


def test_reset_buffer_without_end_difference_skips_reset():
    obj = _empty()
    obj["buf_118"] = {"begin": True, "end_differs": False, "size": 0x10}
    ops = teardown(obj)
    assert ("reset_end", "obj+0x118") not in ops
    assert ("free_buffer", "obj+0x118", 0x10) in ops


def test_record_order_is_elem_then_reverse_count_then_strvec():
    obj = _empty()
    rec = _record()
    rec["elem_210"] = "e"
    rec["count_strings"] = [("a", None), ("b", 0x10)]
    rec["strvec"] = [("s", None)]
    rec["strvec_buf"] = {"begin": True, "size": 0x30}
    rec["flag_00"] = True
    rec["buf_50"] = {"begin": True, "end_differs": False, "size": 0x20}
    obj["records"] = [rec]
    obj["record_array"] = {"begin": True, "size": 0x218}
    ops = teardown(obj)
    assert ops[0] == ("member_call", "record0+0x210", 0x5D8D820)
    assert ops[1] == ("free", "record0+0x210", 0x290)
    # Count strings dispose in reverse: "b" (heap) before "a" (short).
    assert ops[2] == ("dispose_string", "record0+0x1f0[0]", "sized", 0x11)
    assert ops[3] == ("dispose_string", "record0+0x1f0[1]", "short")
    assert ops[4] == ("clear_count", "record0+0x68")
    assert ops[5] == ("dispose_string", "record0+0x1f8[0]", "short")
    assert ops[6] == ("reset_end", "record0+0x200")
    assert ops[7] == ("free_buffer", "record0+0x1f8", 0x30)
    assert ops[8] == ("clear_flag", "record0+0x00")
    assert ops[9] == ("free_buffer", "record0+0x50", 0x20)
    assert ops[10] == ("free_buffer", "obj+0x130", 0x218)


def test_empty_record_strvec_skips_end_reset():
    obj = _empty()
    rec = _record()
    rec["strvec_buf"] = {"begin": True, "size": 0x30}
    obj["records"] = [rec]
    ops = teardown(obj)
    assert ("reset_end", "record0+0x200") not in ops
    assert ("free_buffer", "record0+0x1f8", 0x30) in ops


def test_strvec_68_short_and_heap_and_buffer_free():
    obj = _empty()
    obj["strvec_68"] = [("a", None), ("b", 0x08)]
    obj["buf_68"] = {"begin": True, "size": 0x50}
    ops = teardown(obj)
    assert ("dispose_string", "obj+0x68[0]", "short") in ops
    assert ("dispose_string", "obj+0x68[1]", "sized", 0x09) in ops
    assert ("free_buffer", "obj+0x68", 0x50) in ops


def test_elems_38_member_call_then_string_then_buffer():
    obj = _empty()
    obj["elems_38"] = [(None, ("t", None)), ("m", ("u", 0x04))]
    obj["buf_38"] = {"begin": True, "size": 0x80}
    ops = teardown(obj)
    assert ("member_call", "obj+0x38[1]+0x38", 0x5D350C0) in ops
    assert ops.count(("member_call", "obj+0x38[0]+0x38", 0x5D350C0)) == 0
    assert ("dispose_string", "obj+0x38[1]", "sized", 0x05) in ops
    assert ("free_buffer", "obj+0x38", 0x80) in ops


def test_elems_08_two_strings_in_order_and_tail_exit():
    obj = _empty()
    obj["elems_08"] = [(("u", None), ("v", 0x04))]
    obj["buf_08"] = {"begin": True, "size": 0x40}
    ops = teardown(obj)
    tail = ops.index(("tail_free_buffer", "obj+0x08", 0x40))
    assert ops[tail - 2] == ("dispose_string", "obj+0x08[0]+0x20", "short")
    assert ops[tail - 1] == ("dispose_string", "obj+0x08[0]+0x00", "sized", 0x05)
    assert ops[-1] == ("tail_free_buffer", "obj+0x08", 0x40)
