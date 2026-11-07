"""End-to-end tests for the dump slot-method-names model (RE-001, node #115).

Each test drives an input through the model to an observable output:
helper routing by level, GetPrintableOptions dispatch by concrete
class, ToString guard outcomes, the host gate, Logger Close
idempotence, and the GetOption "id" special case.
"""

import unittest

from tools.dump_slot_method_names_115 import (
    BASE_GET_PRINTABLE_OPTIONS,
    BASE_TOSTRING,
    GET_OPTION,
    HEADER_LEVEL,
    INFO_LEVEL,
    blob_cache_options,
    cache_name,
    collector_to_string,
    collector_to_string_for_class,
    get_option_route,
    get_printable_options,
    helper_levelled,
    helper_nolevel,
    host_dump_gate,
    logger_close,
    logger_gate,
    vtable_slot,
)


class TestLoggerGate(unittest.TestCase):
    def test_gate_boundary(self):
        # Slot 5: skip iff level < log_level_; emit iff level >= log_level_.
        self.assertTrue(logger_gate(3, 3))
        self.assertTrue(logger_gate(5, 0))
        self.assertFalse(logger_gate(0, 1))
        self.assertFalse(logger_gate(2, 3))
        self.assertTrue(logger_gate(1, 1))


class TestHelperLevelled(unittest.TestCase):
    def test_header_at_info_level_emits_via_log_header(self):
        path, emitted = helper_levelled(HEADER_LEVEL, INFO_LEVEL)
        self.assertEqual(path, "log_header")
        self.assertTrue(emitted)

    def test_header_at_warn_level_dropped_by_regate(self):
        # LogHeader forwards to Logv(INFO_LEVEL=1); 1 < 2 drops it.
        path, emitted = helper_levelled(HEADER_LEVEL, 2)
        self.assertEqual(path, "log_header")
        self.assertFalse(emitted)

    def test_header_at_debug_level_emits(self):
        self.assertEqual(helper_levelled(HEADER_LEVEL, 0), ("log_header", True))

    def test_plain_level_passes_gate(self):
        self.assertEqual(helper_levelled(3, 3), ("logv_levelled", True))
        self.assertEqual(helper_levelled(3, 2), ("logv_levelled", True))

    def test_plain_level_below_gate_skips(self):
        self.assertEqual(helper_levelled(3, 4), ("skip", False))
        self.assertEqual(helper_levelled(0, 1), ("skip", False))

    def test_level_zero_at_debug_emits(self):
        self.assertEqual(helper_levelled(0, 0), ("logv_levelled", True))


class TestHelperNolevel(unittest.TestCase):
    def test_nolevel_at_info_emits(self):
        self.assertEqual(helper_nolevel(1), ("log_header", True))

    def test_nolevel_at_warn_drops(self):
        self.assertEqual(helper_nolevel(2), ("log_header", False))

    def test_nolevel_at_debug_emits(self):
        self.assertEqual(helper_nolevel(0), ("log_header", True))


class TestLoggerClose(unittest.TestCase):
    def test_first_close_calls_close_impl(self):
        action, closed = logger_close(False)
        self.assertEqual(action, "close_impl")
        self.assertTrue(closed)

    def test_second_close_is_noop_ok(self):
        action, closed = logger_close(True)
        self.assertEqual(action, "ok_noop")
        self.assertTrue(closed)


class TestGetPrintableOptions(unittest.TestCase):
    def test_factories_format(self):
        fn, result = get_printable_options("BlockBasedTableFactory")
        self.assertEqual(fn, 0x60DA1F0)
        self.assertEqual(result, "formatted")
        fn, result = get_printable_options("CuckooTableFactory")
        self.assertEqual(fn, 0x615ACA0)
        self.assertEqual(result, "formatted")
        fn, result = get_printable_options("PlainTableFactory")
        self.assertEqual(fn, 0x6192D70)
        self.assertEqual(result, "formatted")

    def test_base_cache_is_empty(self):
        fn, result = get_printable_options("Cache")
        self.assertEqual(fn, BASE_GET_PRINTABLE_OPTIONS)
        self.assertEqual(result, "")

    def test_lru_formats(self):
        fn, result = get_printable_options("LRUCache")
        self.assertEqual(fn, 0x5D3F210)
        self.assertEqual(result, "formatted")

    def test_charged_and_wrapper_inherit_empty_default(self):
        for cls in ("ChargedCache", "CacheWrapper"):
            fn, result = get_printable_options(cls)
            self.assertEqual(fn, BASE_GET_PRINTABLE_OPTIONS)
            self.assertEqual(result, "")

    def test_secondary_adapter_delegates(self):
        fn, result = get_printable_options("CacheWithSecondaryAdapter")
        self.assertEqual(fn, 0x5D42460)
        self.assertEqual(result, "delegated")

    def test_sharded_shares_lru_formatter(self):
        fn, result = get_printable_options("ShardedCache<LRUCacheShard>")
        self.assertEqual(fn, 0x5D3F210)
        self.assertEqual(result, "formatted")


class TestCacheName(unittest.TestCase):
    def test_lru_and_charged_names(self):
        self.assertEqual(cache_name("LRUCache"), "LRUCache")
        self.assertEqual(cache_name("ChargedCache"), "ChargedCache")

    def test_secondary_adapter_delegates(self):
        self.assertEqual(cache_name("CacheWithSecondaryAdapter"), "delegate")

    def test_base_cache_name_is_pure_virtual(self):
        with self.assertRaises(ValueError):
            cache_name("Cache")


class TestBlobCacheOptionsGuard(unittest.TestCase):
    def test_base_default_gives_empty_string(self):
        self.assertEqual(blob_cache_options(BASE_GET_PRINTABLE_OPTIONS), "")

    def test_override_calls_slot_25(self):
        self.assertEqual(blob_cache_options(0x5D3F210), "formatted")
        self.assertEqual(blob_cache_options(0x5D42460), "formatted")


class TestCollectorToString(unittest.TestCase):
    def test_base_tostring_takes_name_fast_path(self):
        path, target = collector_to_string(BASE_TOSTRING)
        self.assertEqual(path, "name_fast_path")
        self.assertEqual(target, "slot_14_name")

    def test_compact_on_deletion_calls_its_override(self):
        path, target = collector_to_string_for_class(
            "CompactOnDeletionCollectorFactory")
        self.assertEqual(path, "call_slot20")
        self.assertEqual(target, 0x61FB370)

    def test_other_override_calls_slot_20(self):
        self.assertEqual(collector_to_string(0x61FB370),
                         ("call_slot20", 0x61FB370))


class TestHostGate(unittest.TestCase):
    def test_below_ten_dumps(self):
        self.assertEqual(host_dump_gate(0), "dump")
        self.assertEqual(host_dump_gate(9), "dump")

    def test_ten_or_more_skips(self):
        self.assertEqual(host_dump_gate(10), "skip")
        self.assertEqual(host_dump_gate(42), "skip")


class TestVtableSlots(unittest.TestCase):
    def test_logger_slots(self):
        self.assertEqual(vtable_slot("EnvLogger", 3), 0x5FCC200)
        self.assertEqual(vtable_slot("EnvLogger", 5), 0x5FCD400)
        self.assertEqual(vtable_slot("EnvLogger", 8), 0x5FCC220)
        self.assertEqual(vtable_slot("EnvLogger", 2), 0x5FCC410)
        self.assertEqual(vtable_slot("AutoRollLogger", 3), 0x6057000)
        self.assertEqual(vtable_slot("AutoRollLogger", 8), 0x60552E0)
        # Close and the leveled Logv are shared by both loggers.
        self.assertEqual(vtable_slot("AutoRollLogger", 2),
                         vtable_slot("EnvLogger", 2))
        self.assertEqual(vtable_slot("AutoRollLogger", 5),
                         vtable_slot("EnvLogger", 5))

    def test_factory_and_collector_slots(self):
        self.assertEqual(vtable_slot("BlockBasedTableFactory", 4), 0x60DA1F0)
        self.assertEqual(vtable_slot("BlockBasedTableFactory", 14), 0x60B1D90)
        self.assertEqual(vtable_slot("BlockBasedTableFactory", 2), GET_OPTION)
        self.assertEqual(
            vtable_slot("CompactOnDeletionCollectorFactory", 20), 0x61FB370)
        self.assertEqual(
            vtable_slot("CompactOnDeletionCollectorFactory", 14), 0x61F9880)
        self.assertEqual(
            vtable_slot("CompactOnDeletionCollectorFactory", 19), 0x61FB010)


class TestGetOptionId(unittest.TestCase):
    def test_id_routes_to_get_id(self):
        self.assertEqual(get_option_route("id"), "get_id")

    def test_other_names_go_generic(self):
        self.assertEqual(get_option_route("block_size"), "generic")
        self.assertEqual(get_option_route("i"), "generic")
        self.assertEqual(get_option_route("idx"), "generic")


if __name__ == "__main__":
    unittest.main()
