import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_u128_binary64 as subject


class MigrationTests(unittest.TestCase):
    def test_target_and_complete_extent(self):
        record = subject.verify()
        self.assertEqual((record['start'], record['end']), (0x63f00d0, 0x63f0154))
        self.assertIsNone(record['fde']['lsda'])
        self.assertEqual(record['normalization_masks'], [])

    def test_wrong_capture_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'wrong'
            target.write_bytes(b'not the pinned node')
            with patch.object(subject, 'TARGET', target), self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.verify()

    def test_changed_bounds_and_reference_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            record = json.loads((packet / 'records.json').read_text())
            record['end'] -= 1
            (packet / 'records.json').write_text(json.dumps(record))
            with patch.object(subject, 'PACKET', packet), self.assertRaisesRegex(ValueError, 'bounds changed'):
                subject.verify()
            record['end'] += 1
            (packet / 'records.json').write_text(json.dumps(record))
            body = bytearray((packet / 'official-body.bin').read_bytes())
            body[-1] ^= 1
            (packet / 'official-body.bin').write_bytes(body)
            with patch.object(subject, 'PACKET', packet), self.assertRaisesRegex(ValueError, 'body correspondence'):
                subject.verify()


if __name__ == '__main__':
    unittest.main()
