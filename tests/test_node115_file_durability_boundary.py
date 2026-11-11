"""Target-grounded static replay and independently corrupted coordinates/bytes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-file-durability-boundary'
spec = importlib.util.spec_from_file_location('durability_boundary', PACKET / 'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / v.TARGET).read_bytes()
        cls.record = json.loads((PACKET / 'boundary.json').read_text())
        cls.offset = int(cls.record['file_offset'], 16)
        cls.body = cls.data[cls.offset:cls.offset + cls.record['bytes']]

    def test_authenticated_native_replay(self):
        self.assertEqual(v.verify(self.data, self.record), self.record)

    def test_wrong_target_rejected(self):
        with self.assertRaisesRegex(ValueError, 'target SHA-256'):
            v.verify(self.data[:-1], self.record)

    def test_coordinate_and_record_corruption(self):
        changes = {'start_va': '0x6019691', 'end_va_exclusive': '0x601976b',
                   'file_offset': '0x6019690', 'bytes': 219, 'fsync_dynsym': 400,
                   'fsync_got': '0x64ee768', 'body_sha256': '0' * 64,
                   'negative_branch': '0x60196c0', 'fd_source': '[entry_rsi+0x48]',
                   'gate_requested': True}
        for key, value in changes.items():
            with self.subTest(key=key):
                record = copy.deepcopy(self.record); record[key] = value
                with self.assertRaisesRegex(ValueError, 'record differs'):
                    v.verify(self.data, record)

    def corrupt_body(self, va):
        body = bytearray(self.body); body[va - v.START] ^= 1
        with self.assertRaises(ValueError):
            v.code_checks(body)

    def test_descriptor_layout_control(self):
        self.corrupt_body(0x60196a6)

    def test_fsync_call_control(self):
        self.corrupt_body(0x60196b8)

    def test_negative_branch_control(self):
        self.corrupt_body(0x60196bf)

    def test_success_store_control(self):
        self.corrupt_body(0x60196c4)

    def test_errno_call_control(self):
        self.corrupt_body(0x60196f9)

    def test_error_context_control(self):
        self.corrupt_body(0x601970d)

    def test_literal_control(self):
        self.corrupt_body(0x6019717)

    def test_helper_call_control(self):
        self.corrupt_body(0x601973b)

    def test_fde_extent_control(self):
        data = bytearray(self.data)
        sec = v.sections(data)['.eh_frame']
        data[sec[4] + 0x7550ec + 12] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            v.observe(data)

    def test_plt_target_control(self):
        data = bytearray(self.data)
        sec = v.sections(data)['.plt']
        data[sec[4] + 0x63f1640 - sec[3] + 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'PLT to GOT'):
            v.observe(data)

    def test_relocation_control(self):
        data = bytearray(self.data)
        sec = v.sections(data)['.rela.plt']
        import struct
        for off in range(sec[4], sec[4] + sec[5], 24):
            if struct.unpack_from('<Q', data, off)[0] == 0x64ee770:
                data[off] ^= 1
                break
        else:
            self.fail('native relocation absent')
        with self.assertRaisesRegex(ValueError, 'fsync JUMP_SLOT'):
            v.observe(data)


if __name__ == '__main__':
    unittest.main()
