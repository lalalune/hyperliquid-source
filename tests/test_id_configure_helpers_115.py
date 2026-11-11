"""Tests for the node #115 id-configure helpers model (RE-001).

Every expectation is grounded in the evidence packet
research/work-items/RE-001-id-configure-helpers-115/.
"""
import unittest

from tools.id_configure_helpers_115 import (
    BSS_STRING_ADDR,
    DELIMITER,
    FIND_HASH_SEED,
    FIND_LINEAR_MAX_ELEMENTS,
    MAP_BUCKETS,
    MAP_BUCKET_COUNT,
    MAP_ELEMENT_COUNT,
    MAP_NODE_SIZE,
    MAP_SIZE,
    NODE_HASH,
    NODE_KEY_PTR,
    NODE_KEY_SIZE,
    NODE_VALUE_PTR,
    NODE_VALUE_SIZE,
    NULL_OBJECT_CODE,
    NULL_OBJECT_MESSAGE,
    SLOT9_ADDR,
    SLOT9_VTABLE_OFFSET,
    map_clear,
    map_erase,
    map_find,
    find_uses_linear_scan,
    nullchecked_entry,
    resolve_id_name,
    slot9_entry_arg5,
    slot9_path,
)

# The .bss string content is not pinned; tests use a stand-in value and
# exercise the comparison logic, not the runtime content.
BSS = "<bss-string>"


class TestResolveIdName(unittest.TestCase):
    def test_empty_input_yields_id(self):
        name, surviving, status = resolve_id_name("", "myid", BSS, False, None)
        self.assertEqual(name, "myid")
        self.assertTrue(status.is_ok())

    def test_bss_input_yields_id(self):
        name, surviving, status = resolve_id_name(BSS, "myid", BSS, False, None)
        self.assertEqual(name, "myid")
        self.assertTrue(status.is_ok())

    def test_no_equals_yields_input(self):
        name, surviving, status = resolve_id_name("plain", "myid", BSS, False, None)
        self.assertEqual(name, "plain")
        self.assertTrue(status.is_ok())

    def test_parse_failure_discards_error_and_clears_map(self):
        name, surviving, status = resolve_id_name(
            "k=v;k", "myid", BSS, False, {"k": "v"})
        self.assertEqual(name, "k=v;k")
        self.assertIsNone(surviving)  # map cleared
        self.assertTrue(status.is_ok())  # parse error discarded, kOk

    def test_id_key_extracted_and_erased(self):
        name, surviving, status = resolve_id_name(
            "id=foo;x=1", "myid", BSS, True, {"id": "foo", "x": "1"})
        self.assertEqual(name, "foo")
        self.assertEqual(surviving, {"x": "1"})  # only 'id' erased
        self.assertTrue(status.is_ok())

    def test_id_value_equal_to_bss_truncates_to_empty(self):
        name, surviving, status = resolve_id_name(
            "id=<bss>;x=1", "myid", BSS, True, {"id": BSS, "x": "1"})
        self.assertEqual(name, "")
        self.assertEqual(surviving, {"x": "1"})

    def test_no_id_key_nonempty_id_yields_id_and_map_survives(self):
        name, surviving, status = resolve_id_name(
            "x=1;y=2", "myid", BSS, True, {"x": "1", "y": "2"})
        self.assertEqual(name, "myid")
        self.assertEqual(surviving, {"x": "1", "y": "2"})

    def test_no_id_key_empty_id_yields_input_and_map_cleared(self):
        name, surviving, status = resolve_id_name(
            "x=1", "", BSS, True, {"x": "1"})
        self.assertEqual(name, "x=1")
        self.assertIsNone(surviving)
        self.assertTrue(status.is_ok())

    def test_always_kok(self):
        for args in [
            ("", "i", BSS, False, None),
            (BSS, "i", BSS, False, None),
            ("a=b", "i", BSS, False, {"a": "b"}),
            ("a=b", "i", BSS, True, {"a": "b"}),
        ]:
            _, _, status = resolve_id_name(*args)
            self.assertTrue(status.is_ok(), args)


class TestSlot9Path(unittest.TestCase):
    def test_empty_map_byte3_clear_returns_kok(self):
        self.assertEqual(slot9_path(True, 1, 0, True, False), ["return_kok"])

    def test_empty_map_byte3_set_calls_slot5_then_returns(self):
        self.assertEqual(slot9_path(True, 1, 1, True, False),
                         ["call_slot5", "return_kok"])

    def test_empty_map_slot5_failure_with_nonempty_s0_calls_setter(self):
        self.assertEqual(slot9_path(True, 1, 1, False, True),
                         ["call_slot5", "call_setter_6099e70"])

    def test_nonempty_map_byte0_clear_forces_delimiter_then_applies(self):
        self.assertEqual(
            slot9_path(False, 0, 0, True, False),
            ["delimiter_prestep", "call_prestep_6098510",
             "call_apply_609c8c0", "return_kok"])
        self.assertEqual(DELIMITER, "; ")

    def test_nonempty_map_byte3_set_calls_setter(self):
        self.assertEqual(
            slot9_path(False, 1, 1, True, False),
            ["call_apply_609c8c0", "call_setter_6099e70"])

    def test_nonempty_map_apply_failure_with_nonempty_s0_calls_setter(self):
        self.assertEqual(
            slot9_path(False, 1, 0, False, True),
            ["call_apply_609c8c0", "call_setter_6099e70"])

    def test_nonempty_map_apply_failure_empty_s0_returns(self):
        self.assertEqual(
            slot9_path(False, 1, 0, False, False),
            ["call_apply_609c8c0", "return_kok"])


class TestNullCheckedEntry(unittest.TestCase):
    def test_null_object_nonempty_map_is_invalid_argument(self):
        status, forwarded = nullchecked_entry(True, False)
        self.assertEqual(status.code, NULL_OBJECT_CODE)
        self.assertEqual(status.message, NULL_OBJECT_MESSAGE)
        self.assertEqual(len(status.message), 29)
        self.assertFalse(forwarded)

    def test_null_object_empty_map_is_ok(self):
        status, forwarded = nullchecked_entry(True, True)
        self.assertTrue(status.is_ok())
        self.assertFalse(forwarded)

    def test_nonnull_object_forwards_to_slot9(self):
        status, forwarded = nullchecked_entry(False, False)
        self.assertTrue(status.is_ok())
        self.assertTrue(forwarded)


class TestMapHelpers(unittest.TestCase):
    def test_find_and_erase(self):
        entries = {"id": "foo", "x": "1"}
        self.assertEqual(map_find(entries, "id"), "foo")
        self.assertIsNone(map_find(entries, "missing"))
        self.assertTrue(map_erase(entries, "id"))
        self.assertFalse(map_erase(entries, "id"))
        self.assertEqual(entries, {"x": "1"})

    def test_clear(self):
        entries = {"a": "1", "b": "2"}
        map_clear(entries)
        self.assertEqual(entries, {})

    def test_find_linear_scan_threshold(self):
        self.assertTrue(find_uses_linear_scan(20))
        self.assertTrue(find_uses_linear_scan(0))
        self.assertFalse(find_uses_linear_scan(21))
        self.assertEqual(FIND_LINEAR_MAX_ELEMENTS, 20)
        self.assertEqual(FIND_HASH_SEED, 0xC70F6907)


class TestLayoutConstants(unittest.TestCase):
    def test_node_layout(self):
        self.assertEqual(MAP_NODE_SIZE, 0x50)
        self.assertEqual(NODE_KEY_PTR, 0x08)
        self.assertEqual(NODE_KEY_SIZE, 0x10)
        self.assertEqual(NODE_VALUE_PTR, 0x28)
        self.assertEqual(NODE_VALUE_SIZE, 0x30)
        self.assertEqual(NODE_HASH, 0x48)

    def test_map_layout(self):
        self.assertEqual(MAP_SIZE, 0x38)
        self.assertEqual(MAP_BUCKETS, 0x00)
        self.assertEqual(MAP_BUCKET_COUNT, 0x08)
        self.assertEqual(MAP_ELEMENT_COUNT, 0x18)

    def test_slot9_identity(self):
        self.assertEqual(SLOT9_ADDR, 0x609D0E0)
        self.assertEqual(SLOT9_VTABLE_OFFSET, 0x48)
        self.assertEqual(BSS_STRING_ADDR, 0x6508980)
        self.assertEqual(slot9_entry_arg5(), 0)


if __name__ == "__main__":
    unittest.main()
