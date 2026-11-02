import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_tagged_count as subject


class TaggedCountTests(unittest.TestCase):
    def test_three_complete_target_functions(self):
        record = subject.verify()
        self.assertEqual([r['start'] for r in record['windows']], [0x1531940, 0x1768140, 0x2b77ea0])
        self.assertTrue(all(r['end'] - r['start'] == 69 and r['fde']['lsda'] is None
                            for r in record['windows']))
        self.assertEqual(record['cases'], 2058)

    def test_other_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.verify(b'unrelated executable')

    def test_corrupt_bounds_body_and_fixture_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            with patch.object(subject, 'PACKET', packet):
                records = packet / 'records.json'
                original = records.read_text()
                record = json.loads(original)
                record['windows'][0]['end'] -= 1
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Exact FDE changed'):
                    subject.verify()
                records.write_text(original)
                body = packet / 'body.hex'
                original_body = body.read_text()
                body.write_text('00' + original_body[2:])
                with self.assertRaisesRegex(ValueError, 'Body reference changed'):
                    subject.verify()
                body.write_text(original_body)
                with (packet / 'vectors.tsv').open('a') as stream:
                    stream.write('0\t0\t0\t0\t1\n')
                with self.assertRaisesRegex(ValueError, 'Frozen fixture changed'):
                    subject.verify()


if __name__ == '__main__':
    unittest.main()
