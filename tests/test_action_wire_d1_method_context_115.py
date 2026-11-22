import json
import unittest
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import action_wire_d1_method_context_115 as subject
from elf_index import sections


class D1MethodContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subject.TARGET.read_bytes()

    def test_records_reproduce(self):
        expected = json.loads((ROOT / 'research/work-items/RE-005-node115-d1-method-context/records.json')
                              .read_text(encoding='utf-8'))
        self.assertEqual(subject.extract(self.original), expected)

    def test_wrong_target_identity_rejects_before_analysis(self):
        changed = bytearray(self.original)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target size/SHA-256 mismatch'):
            subject.extract(bytes(changed))

    def test_relocation_target_corruption_rejects(self):
        changed = bytearray(self.original)
        rela = next(s for s in sections(changed) if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            slot = struct.unpack_from('<Q', changed, pos)[0]
            if slot == 0x64e8e48:
                struct.pack_into('<q', changed, pos + 16, 0x442d008)
                break
        else:
            self.fail('fixture lacks the expected relocation slot')
        with self.assertRaisesRegex(ValueError, 'relocation target mismatch'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_nested_callback_instruction_corruption_rejects(self):
        changed = bytearray(self.original)
        offset = 0x442d192 - 0x1000
        self.assertEqual(changed[offset:offset + 2], b'\xff\x10')
        changed[offset + 1] = 0x11
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x442d179'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_direct_handoff_corruption_rejects(self):
        changed = bytearray(self.original)
        offset = 0x442d31f - 0x1000
        self.assertEqual(changed[offset:offset + 5].hex(), 'e80c9a2b00')
        changed[offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x442d30a'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_fde_boundary_corruption_rejects(self):
        changed = bytearray(self.original)
        # FDEs are parsed from .eh_frame; corrupt the FDE's initial-location encoding.
        frame = next(s for s in sections(changed) if s['name'] == '.eh_frame')
        changed[frame['offset'] + 8] ^= 1
        with self.assertRaises(ValueError):
            subject.extract(bytes(changed), expected_digest=None)


if __name__ == '__main__':
    unittest.main()
