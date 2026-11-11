"""Tests for the provider dispatch factory model (node #115).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from provider_dispatch_factory_115 import (
    CIPHER_SIZE,
    CONTROL_SIZE,
    CTR_VTABLE_SLOTS,
    CTRL_VTABLE_SLOTS,
    FACTORY,
    GATE_MESSAGE,
    GROUP_NAME,
    K_NOT_SUPPORTED,
    K_OK,
    MAP_BLOCK,
    MAP_BLOCK_ENTRIES,
    MAP_REGISTRY,
    RESET_MESSAGE,
    TYPEINFO_CTRL,
    TYPEINFO_CTR,
    TYPEINFO_ROT13,
    VT_CTRL,
    VT_CTR,
    VT_ROT13,
    ConfigOptions,
    ControlBlock,
    Holder,
    ROT13BlockCipher,
    SharedPtr,
    Status,
    dispatch,
    dispatcher_factory_tail,
    registry_dispatcher,
    string_from_cstr,
    wrapper_id_guard,
)


class TestFactoryGate(unittest.TestCase):
    def test_occupied_holder_is_refused(self):
        holder = Holder(SharedPtr("old-cipher", ControlBlock()))
        status, outcome = dispatch("ROT13", 32, holder)
        self.assertEqual(status.code, K_NOT_SUPPORTED)
        self.assertEqual(status.message, GATE_MESSAGE)
        self.assertEqual(outcome, "gate-error")
        self.assertEqual(holder.cipher.ptr, "old-cipher")

    def test_gate_message_is_40_bytes(self):
        self.assertEqual(len(GATE_MESSAGE), 40)


class TestRot13Path(unittest.TestCase):
    def test_builds_cipher_with_block_size(self):
        holder = Holder()
        status, outcome = dispatch("ROT13", 32, holder)
        self.assertEqual(status.code, K_OK)
        kind, cipher, control = outcome
        self.assertEqual(kind, "rot13")
        self.assertEqual(cipher.SIZE, CIPHER_SIZE)
        self.assertEqual(cipher.vtable, VT_ROT13)
        self.assertEqual(cipher.block_size, 32)
        self.assertIs(holder.cipher.ptr, cipher)

    def test_registers_block_size_group(self):
        holder = Holder()
        _, (_, cipher, _) = dispatch("ROT13", 16, holder)
        self.assertEqual(cipher.groups_registered,
                         [(GROUP_NAME, MAP_BLOCK)])
        self.assertEqual(MAP_BLOCK_ENTRIES["block_size"]["type"], 22)
        self.assertEqual(MAP_BLOCK_ENTRIES["block_size"]["flags"], 0x400)

    def test_control_block_is_non_inplace(self):
        holder = Holder()
        _, (_, _, control) = dispatch("ROT13", 32, holder)
        self.assertEqual(control.vtable, VT_CTRL)
        self.assertEqual(control.use_count, 1)
        self.assertEqual(control.weak_count, 1)
        self.assertEqual(CONTROL_SIZE, 0x18)

    def test_old_cipher_is_released(self):
        old_control = ControlBlock(use_count=1)
        holder = Holder(SharedPtr("old", old_control))
        # Gate blocks the build while occupied; clear first, then build.
        holder.cipher = SharedPtr()
        _, _ = dispatch("ROT13", 32, holder)
        self.assertIsNot(holder.cipher.ptr, "old")

    def test_old_control_released_on_replace(self):
        old_control = ControlBlock(use_count=1)
        holder = Holder()
        holder.store_cipher(SharedPtr("old", old_control))
        holder.store_cipher(SharedPtr("new", ControlBlock()))
        self.assertTrue(old_control.destroyed)


class TestDelegatePath(unittest.TestCase):
    def test_non_rot13_delegates(self):
        holder = Holder()
        status, outcome = dispatch("CTR", 32, holder)
        self.assertEqual(status.code, K_OK)
        self.assertEqual(outcome, ("delegate", "CTR", 32))

    def test_other_names_delegate_too(self):
        holder = Holder()
        _, outcome = dispatch("AES", 0, holder)
        self.assertEqual(outcome[0], "delegate")


class TestDispatcher(unittest.TestCase):
    def _configure(self, code=K_OK, message="", out_name="",
                   map_nonempty=False):
        return {"status": Status(code, message), "out_name": out_name,
                "map_nonempty": map_nonempty}

    def test_configure_error_propagates(self):
        holder = Holder()
        status, outcome = registry_dispatcher(
            "CTR", ConfigOptions(), holder,
            self._configure(code=K_NOT_SUPPORTED, message="x"))
        self.assertEqual(status.code, K_NOT_SUPPORTED)
        self.assertEqual(outcome, "configure-error")

    def test_out_name_dispatches_to_factory(self):
        holder = Holder()
        status, outcome = registry_dispatcher(
            "CTR", ConfigOptions(), holder,
            self._configure(out_name="CTR"))
        self.assertEqual(status.code, K_OK)
        self.assertEqual(outcome, ("factory-dispatch", "CTR"))

    def test_nonempty_map_is_reset_error(self):
        holder = Holder()
        status, outcome = registry_dispatcher(
            "CTR", ConfigOptions(), holder,
            self._configure(map_nonempty=True))
        self.assertEqual(status.code, K_NOT_SUPPORTED)
        self.assertEqual(status.message, RESET_MESSAGE)
        self.assertEqual(outcome, "reset-error")

    def test_empty_map_resets_cipher_slot(self):
        control = ControlBlock(use_count=1)
        holder = Holder(SharedPtr("cipher", control))
        status, outcome = registry_dispatcher(
            "CTR", ConfigOptions(), holder, self._configure())
        self.assertEqual(status.code, K_OK)
        self.assertEqual(outcome, "reset-ok")
        self.assertTrue(holder.cipher.is_null())


class TestDispatcherTail(unittest.TestCase):
    def test_code3_swallowed_when_byte01_set(self):
        self.assertEqual(dispatcher_factory_tail(3, 1), "swallow-to-ok")

    def test_code0_null_configure_when_byte01_clear(self):
        self.assertEqual(dispatcher_factory_tail(0, 0), "null-configure")

    def test_other_codes_propagate(self):
        self.assertEqual(dispatcher_factory_tail(1, 1), "propagate")
        self.assertEqual(dispatcher_factory_tail(3, 0), "propagate")
        self.assertEqual(dispatcher_factory_tail(0, 1), "propagate")

    def test_default_config_options_has_byte01_set(self):
        self.assertEqual(ConfigOptions().byte_01(), 1)


class TestWrapperGuard(unittest.TestCase):
    def test_id_case_clears(self):
        self.assertEqual(wrapper_id_guard(2, True, 0), "clear")

    def test_other_cases_forward(self):
        self.assertEqual(wrapper_id_guard(1, True, 0), "forward")
        self.assertEqual(wrapper_id_guard(2, False, 0), "forward")
        self.assertEqual(wrapper_id_guard(2, True, 1), "forward")


class TestHelpers(unittest.TestCase):
    def test_config_init_defaults(self):
        opts = ConfigOptions()
        self.assertEqual(opts.flags_word, 0x01010100)
        self.assertEqual(opts.delimiter, ";")
        self.assertEqual(opts.plus_0x30, 0x80000)
        self.assertEqual(opts.plus_0x2c, 0xFF)

    def test_string_ctor_sso_boundary(self):
        self.assertFalse(string_from_cstr("ROT13")["heap"])
        self.assertFalse(string_from_cstr("x" * 15)["heap"])
        self.assertTrue(string_from_cstr("x" * 16)["heap"])
        self.assertTrue(
            string_from_cstr("ROT13BlockCipherOptions")["heap"])

    def test_vtable_slot_21_is_the_factory(self):
        self.assertEqual(CTR_VTABLE_SLOTS[21], FACTORY)
        self.assertEqual(CTR_VTABLE_SLOTS[1], 0x5FF30B0)
        self.assertEqual(CTR_VTABLE_SLOTS[16], 0x5FF1030)
        self.assertEqual(VT_CTR, 0x64CFFB0)

    def test_control_block_vtable_slots(self):
        self.assertEqual(CTRL_VTABLE_SLOTS,
                         [0x5FEFB60, 0x5FEFD10, 0x5FF0580, 0x5FEFD20,
                          0x5FEFC60])

    def test_typeinfo_names(self):
        self.assertEqual(TYPEINFO_CTR,
                         "N7rocksdb21CTREncryptionProviderE")
        self.assertEqual(TYPEINFO_ROT13,
                         "*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE")
        self.assertIn("Sp_counted_ptr", TYPEINFO_CTRL)
        self.assertIn("ROT13BlockCipher", TYPEINFO_CTRL)

    def test_registry_map(self):
        self.assertEqual(MAP_REGISTRY, 0x6505278)


if __name__ == "__main__":
    unittest.main()
