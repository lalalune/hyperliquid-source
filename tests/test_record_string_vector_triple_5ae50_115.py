"""Model tests for node #115 routine 0x5d5ae50 (record string-vector
triple destructor)."""
from tools.record_string_vector_triple_5ae50_115 import destroy


def _vec(elems, begin, cap):
    return {"elems": elems, "begin": begin, "cap": cap}


def _rec(v50, v38, v08):
    return {"v50": v50, "v38": v38, "v08": v08}


def _empty_vec():
    return _vec([], None, None)


def test_null_empty_holder_returns_nothing():
    holder = {"records": [], "begin": None, "cap": None}
    assert destroy(holder) == []


def test_empty_holder_with_buffer_frees_span():
    holder = {"records": [], "begin": 100, "cap": 900}
    assert destroy(holder) == [("free_span", 800)]


def test_single_record_sso_only_frees_spans_only():
    rec = _rec(_vec([(True, 0), (True, 0)], 1000, 2000),
               _vec([(True, 0)], 3000, 4000),
               _vec([], 5000, 5000))
    holder = {"records": [rec], "begin": 100, "cap": 900}
    assert destroy(holder) == [("free_span", 1000), ("free_span", 1000),
                               ("free_span", 0), ("free_span", 800)]


def test_heap_strings_freed_capacity_plus_one_in_order():
    rec = _rec(_vec([(False, 10)], 1000, 2000),
               _vec([(True, 0), (False, 4)], 3000, 4000),
               _vec([(False, 0)], 5000, 6000))
    holder = {"records": [rec], "begin": 100, "cap": 900}
    assert destroy(holder) == [("free", 11), ("free_span", 1000),
                               ("free", 5), ("free_span", 1000),
                               ("free", 1), ("free_span", 1000),
                               ("free_span", 800)]


def test_null_vector_buffers_free_nothing_for_that_vector():
    rec = _rec(_empty_vec(),
               _vec([(False, 7)], 3000, 4000),
               _empty_vec())
    holder = {"records": [rec], "begin": 100, "cap": 100}
    assert destroy(holder) == [("free", 8), ("free_span", 1000),
                               ("free_span", 0)]


def test_multiple_records_in_order():
    rec1 = _rec(_vec([(False, 1)], 1000, 1100),
                _empty_vec(), _empty_vec())
    rec2 = _rec(_empty_vec(),
                _vec([(False, 2)], 2000, 2100),
                _empty_vec())
    holder = {"records": [rec1, rec2], "begin": 100, "cap": 300}
    assert destroy(holder) == [("free", 2), ("free_span", 100),
                               ("free", 3), ("free_span", 100),
                               ("free_span", 200)]


def test_inconsistent_holder_raises():
    holder = {"records": [_rec(_empty_vec(), _empty_vec(), _empty_vec())],
              "begin": None, "cap": None}
    try:
        destroy(holder)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_inconsistent_vector_raises():
    rec = _rec(_vec([(False, 1)], None, None),
               _empty_vec(), _empty_vec())
    holder = {"records": [rec], "begin": 100, "cap": 300}
    try:
        destroy(holder)
    except ValueError:
        return
    raise AssertionError("expected ValueError")
