import importlib.util
import pathlib
import struct
import tempfile
import unittest

PACKET = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("byte_bool_native", PACKET / "collect.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (NATIVE.ROOT / "artifacts/node/94/hl-node").read_bytes()

    def test_complete_identity_and_metadata(self):
        records = NATIVE.validate(self.data)
        self.assertEqual([len(code) for _, code in records], [89, 108])

    def changed(self, offset):
        data = bytearray(self.data)
        data[offset] ^= 1
        with self.assertRaises(NATIVE.EvidenceError):
            NATIVE.validate(data, require_identity=False)

    def test_mode_byte_change_rejected_below_identity(self):
        self.changed(0x466ABB5)

    def test_counter_gate_change_rejected_below_identity(self):
        self.changed(0x466ABBF)

    def test_u8_cursor_store_change_rejected_below_identity(self):
        self.changed(0x466ABE9)

    def test_boolean_classification_change_rejected_below_identity(self):
        self.changed(0x466AE49)

    def test_boolean_budget_word_change_rejected_below_identity(self):
        self.changed(0x466AE5A)

    def test_fde_extent_change_rejected_below_identity(self):
        view = NATIVE.view_for(self.data)
        _, offset = view(0xEF1E60 + 12, 1)
        self.changed(offset)

    def test_cie_change_rejected_below_identity(self):
        view = NATIVE.view_for(self.data)
        _, offset = view(0xCE1518 + 16, 1)
        self.changed(offset)

    def test_nonexecutable_code_mapping_rejected_below_identity(self):
        data = bytearray(self.data)
        headers = struct.unpack_from("<Q", data, 32)[0]
        count = struct.unpack_from("<H", data, 56)[0]
        for index in range(count):
            entry = struct.unpack_from("<IIQQQQQQ", data, headers + 56 * index)
            if entry[0] == 1 and entry[3] <= 0x466BBB0 < entry[3] + entry[5]:
                data[headers + 56 * index + 4] ^= 1
                break
        with self.assertRaisesRegex(NATIVE.EvidenceError, "not executable"):
            NATIVE.validate(data, require_identity=False)

    def test_real_rela_redirected_into_code_is_rejected_below_identity(self):
        data = bytearray(self.data)
        headers = struct.unpack_from("<Q", data, 40)[0]
        count = struct.unpack_from("<H", data, 60)[0]
        for index in range(count):
            entry = struct.unpack_from("<IIQQQQIIQQ", data, headers + 64 * index)
            if entry[1] == 4 and entry[5] >= 24:
                struct.pack_into("<Q", data, entry[4], 0x466BBB0)
                break
        with self.assertRaisesRegex(NATIVE.EvidenceError, "relocation targets"):
            NATIVE.validate(data, require_identity=False)

    def test_type18_write_starting_before_code_is_rejected_below_identity(self):
        data = bytearray(self.data)
        headers = struct.unpack_from("<Q", data, 40)[0]
        count = struct.unpack_from("<H", data, 60)[0]
        for index in range(count):
            entry = struct.unpack_from("<IIQQQQIIQQ", data, headers + 64 * index)
            if entry[1] == 4 and entry[5] >= 24:
                struct.pack_into("<QQ", data, entry[4], 0x466BBB0 - 4, 18)
                break
        with self.assertRaisesRegex(NATIVE.EvidenceError, "relocation targets"):
            NATIVE.validate(data, require_identity=False)

    def test_wrong_identity_preserves_absent_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "invalid"
            target.write_bytes(b"not an ELF")
            destination = root / "new"
            with self.assertRaisesRegex(NATIVE.EvidenceError, "identity"):
                NATIVE.collect(target, destination)
            self.assertFalse(destination.exists())

    def test_existing_output_is_preserved_before_target_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"keep")
            with self.assertRaisesRegex(NATIVE.EvidenceError, "must be new"):
                NATIVE.collect(root / "absent-target", root)
            self.assertEqual(sentinel.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
