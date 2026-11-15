"""Real node115 static binding and below-identity corruption controls."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'research/work-items/RE-012-tcp-transform-error-cleanup-115'
spec = importlib.util.spec_from_file_location('tcp_cleanup115', HERE / 'verify.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CleanupEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.TARGET.read_bytes()
        cls.evidence = json.loads((HERE / 'evidence.json').read_text())

    def test_authentic_capture(self):
        m.verify(self.data, self.evidence)

    def test_every_clause_rejects_below_identity_corruption(self):
        data = bytearray(self.data)
        for pin in self.evidence['clauses']:
            with self.subTest(clause=pin['name']):
                off = pin['file_offset']
                data[off] ^= 1
                try:
                    with self.assertRaisesRegex(ValueError, 'clause:'):
                        m.structure(data, self.evidence)
                finally:
                    data[off] ^= 1

    def test_each_fde_corruption_rejected(self):
        for frame in self.evidence['frames']:
            with self.subTest(frame=frame['start']):
                data = bytearray(self.data)
                data[frame['file_offset'] + 12] ^= 1
                with self.assertRaisesRegex(ValueError, 'FDE'):
                    m.structure(data, self.evidence)

    def test_each_cie_corruption_rejected(self):
        for frame in self.evidence['frames']:
            with self.subTest(frame=frame['start']):
                data = bytearray(self.data)
                data[frame['cie_file_offset'] + 8] ^= 1
                with self.assertRaisesRegex(ValueError, 'CIE'):
                    m.structure(data, self.evidence)

    def test_each_relocation_target_corruption_rejected(self):
        img = m.Image(self.data)
        section = img.sections['.rela.dyn']
        for row in self.evidence['relocations']:
            with self.subTest(slot=row['slot']):
                data = bytearray(self.data)
                for off in range(section[4], section[4] + section[5], 24):
                    if m.struct.unpack_from('<Q', data, off)[0] == int(row['slot'], 16):
                        data[off + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                    m.structure(data, self.evidence)

    def test_wrong_capture_and_truncation(self):
        for data in (self.data[:-1], b'not an ELF'):
            with self.assertRaisesRegex(ValueError, 'capture identity'):
                m.verify(data, self.evidence)

if __name__ == '__main__':
    unittest.main()
