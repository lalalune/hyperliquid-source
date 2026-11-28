import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re010_e114a_error_layout_18bf680 as subject
from elf_index import sections


class E114AHelperLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subject.TARGET.read_bytes()

    def test_records_reproduce(self):
        expected = json.loads((ROOT / 'research/work-items/RE-005-node115-e114a-error-layout-18bf680/records.json')
                              .read_text(encoding='utf-8'))
        self.assertEqual(subject.extract(self.original), expected)

    def test_dispatch_crosswalk_maps_seventeen_variants(self):
        result = subject.extract(self.original)
        self.assertEqual(result['dispatch_crosswalk']['count'], 17)
        self.assertEqual(result['dispatch_crosswalk']['variants'],
                         [2, 7, 8, 12, 14, 16, 17, 19, 20, 21, 70, 71, 75, 92, 100, 102, 109])

    def test_wrong_target_identity_rejects(self):
        changed = bytearray(self.original)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target size/SHA-256 mismatch'):
            subject.extract(bytes(changed))

    def test_first_fde_corruption_rejects(self):
        changed = bytearray(self.original)
        text = next(s for s in sections(changed) if s['name'] == '.text')
        offset = text['offset'] + 0x18bf680 - text['address']
        changed[offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'body digest mismatch at 0x18bf680'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_constructor_fde_corruption_rejects(self):
        changed = bytearray(self.original)
        text = next(s for s in sections(changed) if s['name'] == '.text')
        offset = text['offset'] + 0x18be120 - text['address']
        changed[offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'body digest mismatch at 0x18be120'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_relocated_formatter_fde_corruption_rejects(self):
        changed = bytearray(self.original)
        text = next(s for s in sections(changed) if s['name'] == '.text')
        offset = text['offset'] + 0x141e3a0 - text['address']
        changed[offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'body digest mismatch at 0x141e3a0'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_got_relocation_corruption_rejects(self):
        changed = bytearray(self.original)
        relas = next(s for s in sections(changed) if s['name'] == '.rela.dyn')
        for offset in range(relas['offset'], relas['offset'] + relas['size'], 24):
            slot = int.from_bytes(changed[offset:offset + 8], 'little')
            if slot == 0x64df6e8:
                changed[offset + 16] ^= 1
                break
        else:
            self.fail('expected GOT relocation slot was not found')
        with self.assertRaisesRegex(ValueError, 'relocation mismatch at 0x64df6e8'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_format_literal_corruption_rejects(self):
        changed = bytearray(self.original)
        rodata = next(s for s in sections(changed) if s['name'] == '.rodata')
        offset = rodata['offset'] + 0x44f07a - rodata['address']
        changed[offset + 1] ^= 1
        with self.assertRaisesRegex(ValueError, 'rodata witness mismatch at 0x44f07a'):
            subject.extract(bytes(changed), expected_digest=None)


if __name__ == '__main__':
    unittest.main()
