"""Tests for the SystemClock registry factory dispatch model (node #115).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The fixture library uses an exact-match "TimeEmulatedSystemClock" creator
to exercise the dispatch; the registered SystemClock creators are not
pinned (see the model docstring), so the fixture is a model exercise, not
a binary claim.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from system_clock_dispatch_115 import (
    CTRL_TYPEINFO,
    CTRL_VTABLE,
    CTRL_VTABLE_SLOTS,
    DEFAULT_INVOKERS,
    DISPATCH,
    DISPATCHER,
    FIXTURE_INVOKER,
    K_INVALID_ARGUMENT,
    K_NOT_SUPPORTED,
    K_OK,
    LOOKUP,
    STATUS_CTOR,
    STATUS_MOVE_ASSIGN,
    STR_CTOR,
    TYPE_SYSTEM_CLOCK,
    WRAPPER,
    ControlBlock,
    FactoryEntry,
    FactoryRecord,
    ObjectLibrary,
    ObjectRegistry,
    SharedSlot,
    Status,
    clock_library,
    dispatch,
    lookup,
    null_creator,
    null_creator_with_message,
    pattern_matches,
    status_message,
    unguarded_creator,
)


def registry_with_clock(parent=None):
    reg = ObjectRegistry(parent=parent)
    reg.add_library(clock_library())
    return reg


class TestStatusMessage(unittest.TestCase):
    def test_join_with_name(self):
        self.assertEqual(
            status_message("Could not load SystemClock",
                           "TimeEmulatedSystemClock"),
            "Could not load SystemClock: TimeEmulatedSystemClock")

    def test_join_unguarded_keeps_trailing_space(self):
        self.assertEqual(
            status_message(
                "Cannot make a shared SystemClock from unguarded one ",
                "TimeEmulatedSystemClock"),
            "Cannot make a shared SystemClock from unguarded one "
            ": TimeEmulatedSystemClock")

    def test_join_factory_message(self):
        self.assertEqual(
            status_message("factory refused the name",
                           "TimeEmulatedSystemClock"),
            "factory refused the name: TimeEmulatedSystemClock")

    def test_empty_second_message(self):
        self.assertEqual(status_message("Could not load SystemClock", ""),
                         "Could not load SystemClock")

    def test_codes(self):
        self.assertEqual((K_OK, K_NOT_SUPPORTED, K_INVALID_ARGUMENT),
                         (0, 3, 4))


class TestPatternMatches(unittest.TestCase):
    def test_exact_only_entry(self):
        self.assertTrue(pattern_matches(
            "TimeEmulatedSystemClock", [], "TimeEmulatedSystemClock"))
        self.assertFalse(pattern_matches(
            "TimeEmulatedSystemClock", [], "TimeEmulatedSystemClockX"))
        self.assertFalse(pattern_matches(
            "TimeEmulatedSystemClock", [], "TimeEmulatedSystemCloc"))

    def test_ctr_style_modes(self):
        self.assertTrue(pattern_matches("CTR", [("://test", 2)], "CTR"))
        self.assertTrue(
            pattern_matches("CTR", [("://test", 2)], "CTR://test"))
        self.assertFalse(
            pattern_matches("CTR", [("://test", 2)], "CTR://other"))
        self.assertTrue(pattern_matches("ROT13", [(":", 3)], "ROT13:32"))
        self.assertFalse(pattern_matches("ROT13", [(":", 3)], "ROT13:abc"))


class TestLookup(unittest.TestCase):
    def test_hit(self):
        rec = lookup(registry_with_clock(), "TimeEmulatedSystemClock")
        self.assertEqual(rec, FactoryRecord(FIXTURE_INVOKER,
                                            FIXTURE_INVOKER))

    def test_miss(self):
        self.assertIsNone(lookup(registry_with_clock(), "AES"))
        self.assertIsNone(lookup(registry_with_clock(), "SystemClock"))

    def test_parent_recursion(self):
        parent = registry_with_clock()
        child = ObjectRegistry(parent=parent)
        self.assertEqual(lookup(child, "TimeEmulatedSystemClock").invoker,
                         FIXTURE_INVOKER)

    def test_no_parent_miss_is_none(self):
        self.assertIsNone(lookup(ObjectRegistry(),
                                 "TimeEmulatedSystemClock"))

    def test_clone_is_a_copy(self):
        reg = registry_with_clock()
        rec = lookup(reg, "TimeEmulatedSystemClock")
        lib = reg.libraries[0]
        entry = lib.entries[TYPE_SYSTEM_CLOCK][0]
        self.assertIsNot(rec, entry.record)
        self.assertEqual(rec, entry.record)


class TestDispatch(unittest.TestCase):
    def test_success(self):
        slot = SharedSlot()
        status, _ = dispatch(registry_with_clock(),
                             "TimeEmulatedSystemClock", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(status, Status(K_OK))
        self.assertEqual(slot.object,
                         ("TimeEmulatedSystemClock",
                          "TimeEmulatedSystemClock"))
        self.assertIsInstance(slot.control, ControlBlock)
        self.assertEqual(slot.control.vtable, CTRL_VTABLE)
        self.assertEqual((slot.control.use_count, slot.control.weak_count),
                         (1, 1))
        self.assertEqual(slot.control.object, slot.object)

    def test_miss_is_not_supported(self):
        slot = SharedSlot()
        status, _ = dispatch(registry_with_clock(), "AES", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(
            status,
            Status(K_NOT_SUPPORTED, "Could not load SystemClock: AES"))
        self.assertIsNone(slot.object)

    def test_factory_null_is_invalid_argument(self):
        reg = registry_with_clock()
        invokers = dict(DEFAULT_INVOKERS)
        invokers[FIXTURE_INVOKER] = null_creator
        slot = SharedSlot()
        status, _ = dispatch(reg, "TimeEmulatedSystemClock", slot, invokers)
        self.assertEqual(
            status,
            Status(K_INVALID_ARGUMENT,
                   "Could not load SystemClock: TimeEmulatedSystemClock"))
        self.assertIsNone(slot.object)

    def test_factory_null_with_message(self):
        reg = registry_with_clock()
        invokers = dict(DEFAULT_INVOKERS)
        invokers[FIXTURE_INVOKER] = null_creator_with_message
        slot = SharedSlot()
        status, _ = dispatch(reg, "TimeEmulatedSystemClock", slot, invokers)
        self.assertEqual(
            status,
            Status(K_INVALID_ARGUMENT,
                   "factory refused the name: TimeEmulatedSystemClock"))
        self.assertIsNone(slot.object)

    def test_unguarded_return_is_invalid_argument(self):
        reg = registry_with_clock()
        invokers = dict(DEFAULT_INVOKERS)
        invokers[FIXTURE_INVOKER] = unguarded_creator
        slot = SharedSlot()
        status, _ = dispatch(reg, "TimeEmulatedSystemClock", slot, invokers)
        self.assertEqual(
            status,
            Status(K_INVALID_ARGUMENT,
                   "Cannot make a shared SystemClock from unguarded one "
                   ": TimeEmulatedSystemClock"))
        self.assertIsNone(slot.object)

    def test_success_replaces_old_clock(self):
        slot = SharedSlot()
        dispatch(registry_with_clock(), "TimeEmulatedSystemClock", slot,
                 DEFAULT_INVOKERS)
        old_control = slot.control
        status, _ = dispatch(registry_with_clock(),
                             "TimeEmulatedSystemClock", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(status, Status(K_OK))
        self.assertIsNot(slot.control, old_control)


class TestControlBlock(unittest.TestCase):
    def test_vtable_and_typeinfo(self):
        self.assertEqual(CTRL_VTABLE, 0x64CDF38)
        self.assertEqual(
            CTRL_TYPEINFO,
            "St15_Sp_counted_ptrIPN7rocksdb11SystemClockE"
            "LN9__gnu_cxx12_Lock_policyE2EE")

    def test_five_slots(self):
        self.assertEqual(
            CTRL_VTABLE_SLOTS,
            [0x5FCC690, 0x5FCC800, 0x5FCC750, 0x5FCC810, 0x5FCC770])


class TestIdentities(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual((DISPATCH, LOOKUP), (0x5FD4080, 0x5FD3D00))
        self.assertEqual(DISPATCHER, 0x5FD46C0)
        self.assertEqual(WRAPPER, 0x5FD4C30)
        self.assertEqual(STATUS_CTOR, 0x61CF670)
        self.assertEqual(STATUS_MOVE_ASSIGN, 0x5FCDF70)
        self.assertEqual(STR_CTOR, 0x5FCD890)

    def test_type_name(self):
        self.assertEqual(TYPE_SYSTEM_CLOCK, "SystemClock")
        self.assertEqual(len(TYPE_SYSTEM_CLOCK), 11)


if __name__ == "__main__":
    unittest.main()
