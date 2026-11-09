"""Tests for the registry factory dispatch model (node #115).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from registry_factory_dispatch_115 import (
    CTRL_TYPEINFO,
    CTRL_VTABLE,
    CTRL_VTABLE_SLOTS,
    DEFAULT_INVOKERS,
    DISPATCH,
    DISPATCHER,
    K_INVALID_ARGUMENT,
    K_NOT_SUPPORTED,
    K_OK,
    LOOKUP,
    MANAGER_TYPEINFO,
    STATUS_CTOR,
    TWIN_DISPATCH,
    TWIN_DISPATCHER,
    TWIN_LOOKUP,
    TYPE_BLOCK_CIPHER,
    TYPE_ENCRYPTION_PROVIDER,
    ControlBlock,
    FactoryEntry,
    FactoryRecord,
    ObjectLibrary,
    ObjectRegistry,
    SharedSlot,
    Status,
    dispatch,
    encryption_library,
    lookup,
    manager_op,
    null_creator,
    pattern_matches,
    status_message,
    unguarded_creator,
)


def registry_with_encryption(parent=None):
    reg = ObjectRegistry(parent=parent)
    reg.add_library(encryption_library())
    return reg


class TestStatusMessage(unittest.TestCase):
    def test_join_with_name(self):
        self.assertEqual(
            status_message("Could not load BlockCipher", "ROT13"),
            "Could not load BlockCipher: ROT13")

    def test_join_unguarded_keeps_trailing_space(self):
        self.assertEqual(
            status_message(
                "Cannot make a shared BlockCipher from unguarded one ",
                "ROT13"),
            "Cannot make a shared BlockCipher from unguarded one : ROT13")

    def test_empty_second_message(self):
        self.assertEqual(status_message("Could not load BlockCipher", ""),
                         "Could not load BlockCipher")

    def test_codes(self):
        self.assertEqual((K_OK, K_NOT_SUPPORTED, K_INVALID_ARGUMENT),
                         (0, 3, 4))


class TestPatternMatches(unittest.TestCase):
    def test_ctr_plain_and_test_suffix(self):
        self.assertTrue(pattern_matches("CTR", [("://test", 2)], "CTR"))
        self.assertTrue(
            pattern_matches("CTR", [("://test", 2)], "CTR://test"))

    def test_ctr_rejects_other_tails(self):
        self.assertFalse(
            pattern_matches("CTR", [("://test", 2)], "CTR://other"))
        self.assertFalse(pattern_matches("CTR", [("://test", 2)], "CTRX"))
        self.assertFalse(pattern_matches("CTR", [("://test", 2)], "CT"))

    def test_exact_only_entry(self):
        self.assertTrue(pattern_matches("1://test", [], "1://test"))
        self.assertFalse(pattern_matches("1://test", [], "1://testX"))
        self.assertFalse(pattern_matches("1://test", [], "1://tes"))

    def test_rot13_digits_only(self):
        self.assertTrue(pattern_matches("ROT13", [(":", 3)], "ROT13"))
        self.assertTrue(pattern_matches("ROT13", [(":", 3)], "ROT13:32"))
        self.assertFalse(pattern_matches("ROT13", [(":", 3)], "ROT13:abc"))
        self.assertFalse(pattern_matches("ROT13", [(":", 3)], "ROT13:"))
        self.assertFalse(pattern_matches("ROT13", [(":", 3)], "ROT13X"))


class TestLookup(unittest.TestCase):
    def test_hit_rot13(self):
        rec = lookup(registry_with_encryption(), "ROT13")
        self.assertEqual(rec, FactoryRecord(0x5FEFAB0, 0x5FF7120))

    def test_hit_ctr_variants(self):
        reg = registry_with_encryption()
        self.assertEqual(lookup(reg, "CTR").invoker, 0x5FF6D60)
        self.assertEqual(lookup(reg, "CTR://test").invoker, 0x5FF6D60)
        self.assertEqual(lookup(reg, "1://test").invoker, 0x5FF6A00)

    def test_miss(self):
        self.assertIsNone(lookup(registry_with_encryption(), "AES"))
        self.assertIsNone(lookup(registry_with_encryption(), "CTR://x"))

    def test_parent_recursion(self):
        parent = registry_with_encryption()
        child = ObjectRegistry(parent=parent)
        self.assertEqual(lookup(child, "ROT13").invoker, 0x5FF7120)

    def test_no_parent_miss_is_none(self):
        self.assertIsNone(lookup(ObjectRegistry(), "ROT13"))

    def test_clone_is_a_copy(self):
        reg = registry_with_encryption()
        rec = lookup(reg, "ROT13")
        lib = reg.libraries[0]
        entry = lib.entries[TYPE_BLOCK_CIPHER][2]
        self.assertIsNot(rec, entry.record)
        self.assertEqual(rec, entry.record)

    def test_first_match_wins_in_registration_order(self):
        # "CTR://test" matches the CTR entry first; the 1://test entry
        # is only reached for its exact name.
        reg = registry_with_encryption()
        self.assertEqual(lookup(reg, "CTR://test").invoker, 0x5FF6D60)


class TestManagerOps(unittest.TestCase):
    def test_op0_stores_typeinfo(self):
        for manager, typeinfo in MANAGER_TYPEINFO.items():
            dest = [None]
            self.assertEqual(manager_op(manager, dest, [None], 0), 0)
            self.assertEqual(dest[0], typeinfo)

    def test_op1_clones_functor(self):
        dest = [None]
        self.assertEqual(
            manager_op(0x5FEFA50, dest, [0x5FF6D60], 1), 0)
        self.assertEqual(dest[0], 0x5FF6D60)

    def test_op2_and_op3_are_noops(self):
        dest = ["untouched"]
        self.assertEqual(manager_op(0x5FEFA50, dest, [1], 2), 0)
        self.assertEqual(manager_op(0x5FEFA50, dest, [1], 3), 0)
        self.assertEqual(dest, ["untouched"])


class TestDispatch(unittest.TestCase):
    def test_success_rot13(self):
        slot = SharedSlot()
        status, _ = dispatch(registry_with_encryption(), "ROT13", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(status, Status(K_OK))
        self.assertEqual(slot.object, ("ROT13BlockCipher", 32))
        self.assertIsInstance(slot.control, ControlBlock)
        self.assertEqual(slot.control.vtable, CTRL_VTABLE)
        self.assertEqual((slot.control.use_count, slot.control.weak_count),
                         (1, 1))
        self.assertEqual(slot.control.object, ("ROT13BlockCipher", 32))

    def test_success_ctr(self):
        slot = SharedSlot()
        status, _ = dispatch(registry_with_encryption(), "CTR", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(status, Status(K_OK))
        self.assertEqual(slot.object, ("CTREncryptionProvider", "CTR"))

    def test_miss_is_not_supported(self):
        slot = SharedSlot()
        status, _ = dispatch(registry_with_encryption(), "AES", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(
            status,
            Status(K_NOT_SUPPORTED, "Could not load BlockCipher: AES"))
        self.assertIsNone(slot.object)

    def test_factory_null_is_invalid_argument(self):
        reg = registry_with_encryption()
        invokers = dict(DEFAULT_INVOKERS)
        invokers[0x5FF7120] = null_creator
        slot = SharedSlot()
        status, _ = dispatch(reg, "ROT13", slot, invokers)
        self.assertEqual(
            status,
            Status(K_INVALID_ARGUMENT, "Could not load BlockCipher: ROT13"))
        self.assertIsNone(slot.object)

    def test_unguarded_return_is_invalid_argument(self):
        reg = registry_with_encryption()
        invokers = dict(DEFAULT_INVOKERS)
        invokers[0x5FF7120] = unguarded_creator
        slot = SharedSlot()
        status, _ = dispatch(reg, "ROT13", slot, invokers)
        self.assertEqual(
            status,
            Status(K_INVALID_ARGUMENT,
                   "Cannot make a shared BlockCipher from unguarded one "
                   ": ROT13"))
        self.assertIsNone(slot.object)

    def test_success_replaces_old_cipher(self):
        slot = SharedSlot()
        dispatch(registry_with_encryption(), "ROT13", slot,
                 DEFAULT_INVOKERS)
        old_control = slot.control
        status, _ = dispatch(registry_with_encryption(), "CTR", slot,
                             DEFAULT_INVOKERS)
        self.assertEqual(status, Status(K_OK))
        self.assertEqual(slot.object, ("CTREncryptionProvider", "CTR"))
        self.assertIsNot(slot.control, old_control)


class TestControlBlock(unittest.TestCase):
    def test_vtable_and_typeinfo(self):
        self.assertEqual(CTRL_VTABLE, 0x64D0198)
        self.assertEqual(
            CTRL_TYPEINFO,
            "St15_Sp_counted_ptrIPN7rocksdb11BlockCipherE"
            "LN9__gnu_cxx12_Lock_policyE2EE")

    def test_five_slots(self):
        self.assertEqual(
            CTRL_VTABLE_SLOTS,
            [0x5FEFB50, 0x5FEFCE0, 0x5FEFC20, 0x5FEFCF0, 0x5FEFC40])


class TestIdentities(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual((DISPATCH, LOOKUP), (0x5FF9FE0, 0x5FF9C60))
        self.assertEqual((TWIN_DISPATCH, TWIN_LOOKUP),
                         (0x5FFB250, 0x5FFAEB0))
        self.assertEqual((DISPATCHER, TWIN_DISPATCHER),
                         (0x5FFA710, 0x5FFBA10))
        self.assertEqual(STATUS_CTOR, 0x61CF670)

    def test_type_names(self):
        self.assertEqual(TYPE_BLOCK_CIPHER, "BlockCipher")
        self.assertEqual(len(TYPE_BLOCK_CIPHER), 11)
        self.assertEqual(TYPE_ENCRYPTION_PROVIDER, "EncryptionProvider")
        self.assertEqual(len(TYPE_ENCRYPTION_PROVIDER), 18)


if __name__ == "__main__":
    unittest.main()
