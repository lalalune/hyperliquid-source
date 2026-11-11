"""Tests for the node #115 CTR/ROT13 provider model
(tools/ctr_rot13_provider_115.py).

Expectations are grounded in the binary (work/hl-node-115.bin):
  * Factory 0x5ff6a00 (registry name "1://test") and factory 0x5ff6d60
    (registry name "CTR") both build a 0x38-byte
    _Sp_counted_ptr_inplace<ROT13BlockCipher> (vtable 0x64d0160,
    use/weak counts (1, 1), ROT13 cipher in place at +0x10 with
    block_size 32 at +0x30) and a 0x30-byte CTREncryptionProvider
    (vtable 0x64cffb0) holding an aliasing shared_ptr to that cipher.
  * The factory registers "ROT13BlockCipherOptions" with map 0x65052c0
    (one entry, "block_size"); the holder init 0x5ff6880 registers
    "Cipher" with map 0x6505280 (one entry, "cipher"); both entries are
    type 22, verification 1, flags 0x400, offset 0.
  * 0x5ff6d60 builds the ROT13 provider only when the spec ends with
    "://test"; otherwise the provider's cipher is null.
  * Replacing the out-slot provider destroys the old one: vtable slot 1
    is compared against the CTR deleting destructor 0x5ff30b0; a derived
    destructor is called instead of the inline steps.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ctr_rot13_provider_115 import (  # noqa: E402
    CIPHER_GROUP_MAP,
    CIPHER_GROUP_NAME,
    DEFAULT_BLOCK_SIZE,
    DTOR_CTR,
    MAP_ENTRIES,
    PROVIDER_SIZE,
    REGISTRY,
    ROT13_GROUP_MAP,
    ROT13_GROUP_NAME,
    TEST_SUFFIX,
    VTABLE_CONFIG,
    VTABLE_CTR,
    VTABLE_INPLACE,
    VTABLE_ROT13,
    WRAPPER_SIZE,
    create_provider_1_test,
    create_provider_ctr,
    destroy_provider,
    ends_with_test,
)


class TestRegistry(unittest.TestCase):
    def test_names(self):
        self.assertEqual(REGISTRY["1://test"]["factory"], 0x5FF6A00)
        self.assertEqual(REGISTRY["CTR"]["factory"], 0x5FF6D60)
        self.assertEqual(REGISTRY["ROT13"]["factory"], 0x5FF7120)


class TestOneTestFactory(unittest.TestCase):
    def test_builds_rot13_provider(self):
        out = [None]
        provider = create_provider_1_test(out)
        self.assertIs(out[0], provider)
        self.assertEqual(provider.vtable, VTABLE_CTR)
        self.assertEqual(provider.size, PROVIDER_SIZE)
        self.assertFalse(provider.cipher.is_null())
        # Aliasing: the provider's cipher IS the in-place cipher.
        self.assertIs(provider.cipher.ptr, provider.wrapper.cipher)
        self.assertIs(provider.cipher.control, provider.wrapper)
        self.assertEqual(provider.wrapper.vtable, VTABLE_INPLACE)
        self.assertEqual(provider.wrapper.size, WRAPPER_SIZE)
        self.assertEqual(provider.wrapper.use_count, 1)
        self.assertEqual(provider.wrapper.weak_count, 1)
        self.assertEqual(provider.wrapper.cipher["vtable"], VTABLE_ROT13)
        self.assertEqual(provider.wrapper.cipher["block_size"],
                         DEFAULT_BLOCK_SIZE)

    def test_groups_registered(self):
        out = [None]
        provider = create_provider_1_test(out)
        self.assertEqual(provider.rot13_group["name"], ROT13_GROUP_NAME)
        self.assertEqual(provider.rot13_group["map"], ROT13_GROUP_MAP)
        self.assertEqual(provider.rot13_group["base_offset"], 0x30)
        cipher_groups = [g for g in provider.groups
                         if g["name"] == CIPHER_GROUP_NAME]
        self.assertEqual(len(cipher_groups), 1)
        self.assertEqual(cipher_groups[0]["map"], CIPHER_GROUP_MAP)
        self.assertEqual(cipher_groups[0]["base_offset"], 0x20)

    def test_map_entries(self):
        self.assertEqual(MAP_ENTRIES[ROT13_GROUP_MAP]["block_size"],
                         {"type": 22, "verification": 1, "flags": 0x400,
                          "offset": 0})
        self.assertEqual(MAP_ENTRIES[CIPHER_GROUP_MAP]["cipher"],
                         {"type": 22, "verification": 1, "flags": 0x400,
                          "offset": 0})


class TestCtrFactoryGate(unittest.TestCase):
    def test_suffix_gate(self):
        self.assertTrue(ends_with_test("CTR://test"))
        self.assertTrue(ends_with_test("://test"))
        self.assertFalse(ends_with_test("CTR"))
        self.assertFalse(ends_with_test("CTR://testx"))
        self.assertFalse(ends_with_test("CTR://tes"))
        self.assertFalse(ends_with_test(""))

    def test_test_spec_builds_rot13_provider(self):
        out = [None]
        provider = create_provider_ctr("CTR://test", out)
        self.assertFalse(provider.cipher.is_null())
        self.assertEqual(provider.wrapper.cipher["block_size"], 32)

    def test_other_spec_builds_empty_holder(self):
        for spec in ("CTR", "CTR://prod", "CTR://testx", ""):
            out = [None]
            provider = create_provider_ctr(spec, out)
            self.assertTrue(provider.cipher.is_null(), spec)
            self.assertEqual(provider.vtable, VTABLE_CTR)
            self.assertEqual(provider.size, PROVIDER_SIZE)
            # The empty holder still carries the Cipher group.
            self.assertEqual(
                [g["name"] for g in provider.groups], [CIPHER_GROUP_NAME])


class TestDestroyProvider(unittest.TestCase):
    def test_replace_destroys_old_inline(self):
        out = [None]
        first = create_provider_1_test(out)
        second = create_provider_ctr("CTR://test", out)
        self.assertIs(out[0], second)
        self.assertTrue(first.destroyed)
        self.assertEqual(first.destroy_trace, [
            ("vtable_reset", VTABLE_CTR),
            ("release_cipher_shared_ptr", True),
            ("vtable_reset", VTABLE_CONFIG),
            ("destroy_group", CIPHER_GROUP_NAME),
            ("free_object", PROVIDER_SIZE),
        ])
        # The old wrapper's control died with its last reference.
        self.assertTrue(first.wrapper.destroyed)

    def test_replace_with_null_old_is_a_noop(self):
        out = [None]
        provider = create_provider_1_test(out)
        self.assertFalse(provider.destroyed)

    def test_derived_dtor_called_instead(self):
        out = [None]
        provider = create_provider_1_test(out)
        provider.deleting_dtor = 0x5FF1234
        trace = destroy_provider(provider)
        self.assertEqual(trace, [("call_derived_dtor", 0x5FF1234)])
        self.assertTrue(provider.destroyed)
        # The inline steps did not run: groups still present.
        self.assertEqual(len(provider.groups), 1)

    def test_destroy_none_is_empty(self):
        self.assertEqual(destroy_provider(None), [])

    def test_base_dtor_constant(self):
        self.assertEqual(DTOR_CTR, 0x5FF30B0)
        self.assertEqual(TEST_SUFFIX, "://test")


if __name__ == "__main__":
    unittest.main()
