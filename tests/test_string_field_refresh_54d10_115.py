"""Tests for the node #115 string-field refresh model
(tools/string_field_refresh_54d10_115.py).

Runnable with pytest, or by invoking each test_* function directly.
"""


from tools.string_field_refresh_54d10_115 import refresh_string_field


def sso(data):
    return {"data": data, "heap": False, "capacity": None}


def heap(data, capacity):
    return {"data": data, "heap": True, "capacity": capacity}


def test_heap_produced_into_sso_dest_moves():
    dest, frees = refresh_string_field(sso(b"old"), heap(b"new-value", 32))
    assert dest == heap(b"new-value", 32)
    assert frees == []


def test_heap_produced_into_heap_dest_moves_and_frees_old():
    dest, frees = refresh_string_field(
        heap(b"old-value", 16), heap(b"new-value", 64))
    assert dest == heap(b"new-value", 64)
    assert frees == [("old", 17)]


def test_heap_produced_into_null_ptr_dest_moves_without_free():
    dest, frees = refresh_string_field(
        {"data": None, "heap": True, "capacity": 16},
        heap(b"new-value", 32))
    assert dest == heap(b"new-value", 32)
    assert frees == []


def test_sso_produced_into_sso_dest_copies():
    dest, frees = refresh_string_field(sso(b"old"), sso(b"new"))
    assert dest == sso(b"new")
    assert frees == []


def test_sso_produced_into_heap_dest_copies_and_keeps_capacity():
    dest, frees = refresh_string_field(heap(b"old-value", 48), sso(b"new"))
    assert dest == heap(b"new", 48)
    assert frees == []


def test_empty_sso_produced_copies_zero_bytes():
    dest, frees = refresh_string_field(sso(b"old"), sso(b""))
    assert dest == sso(b"")
    assert frees == []


def test_sso_produced_sizes_cover_copy_paths():
    # 1, 2, 4, 8 and 15 bytes exercise the copy loop's path shapes.
    for size in (1, 2, 4, 8, 15):
        data = bytes(range(size))
        dest, frees = refresh_string_field(sso(b"x" * size), sso(data))
        assert dest == sso(data)
        assert frees == []


def test_heap_produced_capacity_preserved():
    dest, frees = refresh_string_field(sso(b""), heap(b"v", 16))
    assert dest["capacity"] == 16
    assert frees == []


def test_copy_into_null_ptr_dest_is_rejected():
    try:
        refresh_string_field(
            {"data": None, "heap": True, "capacity": 16}, sso(b"new"))
    except AssertionError:
        pass
    else:
        raise AssertionError("expected a precondition failure")


def test_oversize_sso_produced_is_rejected():
    try:
        refresh_string_field(sso(b"old"), sso(b"x" * 16))
    except AssertionError:
        pass
    else:
        raise AssertionError("expected a precondition failure")
