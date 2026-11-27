import sys
import unittest
from pathlib import Path
import struct
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
import evm_json_bytes_writer_115 as subject


class EvmJsonBytesWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subject.TARGET.read_bytes()

    def test_records_reproduce(self):
        expected = (ROOT / 'research/work-items/evm-json-bytes-writer-115/records.json')
        self.assertEqual(subject.extract(self.original), json.loads(expected.read_text()))

    def test_wrong_target_identity_rejects(self):
        changed = bytearray(self.original)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'target size/SHA-256 mismatch'):
            subject.extract(bytes(changed))

    def test_writer_quote_path_corruption_rejects(self):
        changed = bytearray(self.original)
        changed[0x25ce838 - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction witness mismatch at 0x25ce838'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_hex_digit_table_corruption_rejects(self):
        changed = bytearray(self.original)
        rodata = next(s for s in sections(changed) if s['name'] == '.rodata')
        offset = rodata['offset'] + 0x455d40 - rodata['address']
        changed[offset + 10] ^= 1
        with self.assertRaisesRegex(ValueError, 'rodata witness mismatch at 0x455d40'):
            subject.extract(bytes(changed), expected_digest=None)

    def test_configuration_relocation_corruption_rejects(self):
        changed = bytearray(self.original)
        rela = next(s for s in sections(changed) if s['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            slot = struct.unpack_from('<Q', changed, pos)[0]
            if slot == 0x64dfa60:
                changed[pos + 16] ^= 1
                break
        else:
            self.fail('configuration relocation not found')
        with self.assertRaisesRegex(ValueError, 'relocation target mismatch'):
            subject.extract(bytes(changed), expected_digest=None)


if __name__ == '__main__':
    unittest.main()
