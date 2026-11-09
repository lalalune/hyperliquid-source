"""Tests for the EncryptedFileSystemImpl factory model (node #115).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
"""
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from encrypted_fs_factory_115 import (
    CALLBACKS,
    GROUP_MAP,
    GROUP_NAME,
    MANAGER_TYPEINFO,
    MAP_ENTRIES,
    OBJECT_SIZE,
    REGISTRY,
    TARGET_MAP,
    VTABLE_CONFIG,
    VTABLE_FS,
    VTABLE_IMPL,
    VTABLE_WRAPPER,
    ControlBlock,
    EncryptedFileSystemImpl,
    OutSlot,
    SharedPtr,
    build_provider_record,
    build_target_record,
    create_encrypted_fs,
    create_registered_encrypted_fs,
    manager_op,
)


class TestFactory(unittest.TestCase):
    def test_object_layout(self):
        wrapped = SharedPtr("fs", ControlBlock())
        cipher = SharedPtr("cipher", ControlBlock())
        slot = OutSlot()
        status, obj = create_encrypted_fs(wrapped, cipher, slot)
        self.assertEqual(status, 0)
        self.assertIs(slot.current, obj)
        self.assertEqual(obj.size, OBJECT_SIZE)
        self.assertEqual(obj.vtable, VTABLE_IMPL)
        self.assertEqual(obj.fs_vtable, VTABLE_FS)
        self.assertEqual(obj.name(), "EncryptedFileSystem")

    def test_wrapped_fs_stored_at_plus_0x20(self):
        control = ControlBlock(use_count=1)
        wrapped = SharedPtr("fs", control)
        _, obj = create_encrypted_fs(wrapped, SharedPtr(), OutSlot())
        self.assertEqual(obj.wrapped_fs.ptr, "fs")
        self.assertIs(obj.wrapped_fs.control, control)
        self.assertEqual(control.use_count, 2)  # copied once

    def test_cipher_stored_at_plus_0x30(self):
        control = ControlBlock(use_count=1)
        cipher = SharedPtr("cipher", control)
        _, obj = create_encrypted_fs(SharedPtr(), cipher, OutSlot())
        self.assertEqual(obj.cipher.ptr, "cipher")
        self.assertIs(obj.cipher.control, control)
        self.assertEqual(control.use_count, 2)  # copied once

    def test_null_cipher(self):
        _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), OutSlot())
        self.assertTrue(obj.cipher.is_null())
        self.assertTrue(obj.wrapped_fs.is_null())
        self.assertEqual(obj.name(), "EncryptedFileSystem")

    def test_groups_registered_in_order(self):
        _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), OutSlot())
        self.assertEqual(obj.groups, [("", TARGET_MAP),
                                     (GROUP_NAME, GROUP_MAP)])
        self.assertEqual(GROUP_NAME, "EncryptionProvider")

    def test_out_slot_replacement_destroys_old(self):
        slot = OutSlot()
        _, old = create_encrypted_fs(SharedPtr(), SharedPtr(), slot)
        _, new = create_encrypted_fs(SharedPtr(), SharedPtr(), slot)
        self.assertIs(slot.current, new)
        self.assertTrue(old.destroyed)
        self.assertIn("sized delete 0x40", old.destroy_log)

    def test_out_slot_empty_no_destroy(self):
        slot = OutSlot()
        _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), slot)
        self.assertIs(slot.current, obj)
        self.assertFalse(obj.destroyed)


class TestDestroyOrder(unittest.TestCase):
    def test_complete_dtor_releases_cipher_first(self):
        cipher = SharedPtr("c", ControlBlock())
        wrapped = SharedPtr("w", ControlBlock())
        _, obj = create_encrypted_fs(wrapped, cipher, OutSlot())
        obj.destroy()
        self.assertEqual(obj.destroy_log, [
            "reset vtable to impl",
            "release cipher",
            "reset vtable to wrapper",
            "release wrapped fs",
            "group dtor",
        ])
        self.assertEqual(obj.groups, [])
        self.assertTrue(obj.destroyed)

    def test_deleting_dtor_adds_sized_delete(self):
        _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), OutSlot())
        size = obj.deleting_destroy()
        self.assertEqual(size, 0x40)
        self.assertEqual(obj.destroy_log[-1], "sized delete 0x40")

    def test_null_members_skip_release(self):
        _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), OutSlot())
        obj.destroy()
        self.assertNotIn("release cipher", obj.destroy_log)
        self.assertNotIn("release wrapped fs", obj.destroy_log)


class TestMaps(unittest.TestCase):
    def test_provider_record(self):
        rec = build_provider_record()
        self.assertEqual(rec.type, 22)
        self.assertEqual(rec.verification, 1)
        self.assertEqual(rec.flags, 0x400)
        self.assertEqual(rec.offset, 0)
        self.assertEqual(rec.pack(), 0x100000016)
        self.assertEqual(rec.callbacks, CALLBACKS)

    def test_target_record(self):
        rec = build_target_record()
        self.assertEqual(rec.type, 22)
        self.assertEqual(rec.verification, 1)
        self.assertEqual(rec.flags, 0x2400)
        self.assertEqual(rec.offset, 0)
        self.assertEqual(rec.pack(), 0x100000016)

    def test_map_entries(self):
        self.assertEqual(MAP_ENTRIES[0x6505300]["provider"]["flags"], 0x400)
        self.assertEqual(MAP_ENTRIES[0x65051E0]["target"]["flags"], 0x2400)
        self.assertEqual(MAP_ENTRIES[0x65051E0]["target"]["type"], 22)


class TestRegisteredFactory(unittest.TestCase):
    def test_creates_blank_impl(self):
        slot = OutSlot()
        err = [""]
        obj = create_registered_encrypted_fs(slot, err)
        self.assertIsNotNone(obj)
        self.assertIs(slot.current, obj)
        self.assertTrue(obj.wrapped_fs.is_null())
        self.assertTrue(obj.cipher.is_null())
        self.assertEqual(err[0], "")  # no error on success

    def test_error_path_fills_error_string(self):
        slot = OutSlot()
        err = [""]
        obj = create_registered_encrypted_fs(slot, err, fail=True)
        self.assertIsNone(obj)
        self.assertEqual(err[0], "Status(error)")


class TestRegistryAndManager(unittest.TestCase):
    def test_registry_entries(self):
        self.assertEqual(REGISTRY["EncryptedFileSystem"]["factory"], 0x5FE7A20)
        self.assertEqual(REGISTRY["EncryptedFileSystem"]["manager"], 0x5FE5700)
        self.assertEqual(len(REGISTRY), 5)
        self.assertIn("ReadOnlyFilesystem", REGISTRY)
        self.assertIn("MemoryFileSystem", REGISTRY)

    def test_manager_op_get_typeinfo(self):
        holder = [None]
        self.assertEqual(manager_op(0, holder), 0)
        self.assertEqual(holder[0], MANAGER_TYPEINFO)

    def test_manager_op_store_functor(self):
        holder = [None]
        self.assertEqual(manager_op(1, holder, rsi="fn"), 0)
        self.assertEqual(holder[0], "fn")

    def test_manager_op_other_returns_zero(self):
        holder = [None]
        self.assertEqual(manager_op(2, holder), 0)
        self.assertIsNone(holder[0])

    def test_vtable_constants(self):
        self.assertEqual(VTABLE_IMPL, 0x64CFCA0)
        self.assertEqual(VTABLE_WRAPPER, 0x64CF200)
        self.assertEqual(VTABLE_FS, 0x64CF008)
        self.assertEqual(VTABLE_CONFIG, 0x64D3430)


if __name__ == "__main__":
    unittest.main()
