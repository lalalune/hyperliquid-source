import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_lu_f64_scaling as subject


class LuF64ScalingTests(unittest.TestCase):
    def test_conversion_instance_exact(self):
        record = subject.verify()
        conv = [o for o in record['owners'] if o['role'] == 'conversion'][0]
        self.assertEqual((conv['start'], conv['end']), ('0x15d5cb0', '0x15d606b'))
        self.assertEqual(conv['bytes'], 955)
        self.assertEqual(conv['sha256'], '1f95e20d63dd2cf0a6633a332a819d502b16a81c7d98f782c202f9f3c7129013')
        self.assertEqual(conv['frames']['fde']['va'], '0x105b070')
        self.assertEqual(conv['frames']['lsda'], '0x1823b0')
        tables = {t['tag_offset']: t for t in record['dispatch_tables']}
        self.assertEqual([e['target'] for e in tables['0x90']['entries']],
                         ['0x15d5cde', '0x15d5fb4', '0x15d5fa7', '0x15d5cfd'])
        self.assertEqual([e['target'] for e in tables['0x88']['entries']],
                         ['0x15d5d1f', '0x15d5fd0', '0x15d5fc1', '0x15d5f37'])
        self.assertEqual([(r['line'], r['col']) for r in record['location_records'][:3]],
                         [(63, 46), (74, 57), (75, 5)])
        self.assertEqual(record['location_records'][3]['line'], 962)

    def test_skeleton_family_and_calls(self):
        record = subject.verify()
        family = record['skeleton_family']
        self.assertEqual([m['start'] for m in family],
                         ['0x15d5cb0', '0x15ebbe0', '0x2a90a50', '0x2c7f360'])
        self.assertEqual([m['e8_calls'] for m in family], [2, 3, 10, 7])
        self.assertEqual(sum(m['e8_calls'] for m in family), 22)
        self.assertEqual(record['direct_callers_of_conversion_instance'],
                         ['0x15d6e4c', '0x15d5bc7'])

    def test_context_functions(self):
        record = subject.verify()
        by_role = {o['role']: o for o in record['owners']}
        self.assertEqual((by_role['caller_context']['start'], by_role['caller_context']['bytes']),
                         ('0x15d6e00', 225))
        self.assertEqual((by_role['guard_context']['start'], by_role['guard_context']['bytes']),
                         ('0x15d6ef0', 212))

    def test_other_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.verify(b'unrelated executable')

    def test_corrupt_body_table_record_and_calls_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet)
            with patch.object(subject, 'PACKET', packet):
                records = packet / 'records.json'
                original = records.read_text()
                record = json.loads(original)
                record['owners'][0]['bytes'] -= 1
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Body reference changed'):
                    subject.verify()
                records.write_text(original)
                record = json.loads(original)
                record['dispatch_tables'][0]['entries'][0]['offset'] += 4
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Dispatch table entry changed'):
                    subject.verify()
                records.write_text(original)
                record = json.loads(original)
                record['location_records'][0]['line'] += 1
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Location fields changed'):
                    subject.verify()
                records.write_text(original)
                record = json.loads(original)
                record['skeleton_family'][0]['e8_calls'] += 1
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'Family call count changed'):
                    subject.verify()
                records.write_text(original)
                body = packet / 'conversion.hex'
                original_body = body.read_text()
                body.write_text('00' + original_body[2:])
                with self.assertRaisesRegex(ValueError, 'Body reference changed'):
                    subject.verify()
                body.write_text(original_body)


if __name__ == '__main__':
    unittest.main()
