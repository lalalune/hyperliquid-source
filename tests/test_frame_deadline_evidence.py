"""Digest, branch, relocation and native-boundary controls for frame deadlines."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-frame-deadlines-94'
spec = importlib.util.spec_from_file_location('frame_deadline_evidence', PACKET / 'verify.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class DeadlineEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.image = subject.Image(cls.data)

    def test_fresh_record_matches_full_target_and_prior_contracts(self):
        record = subject.analyze(self.data)
        self.assertEqual(record, json.loads((PACKET / 'records.json').read_text()))
        self.assertEqual(len(record['facts']), 41)
        self.assertEqual(record['reused_contracts']['reader_timeouts']['header']['seconds'], 40)
        self.assertTrue(all(w['default_seconds'] == 20 for w in record['reused_contracts']['writer_timeouts']))

    def test_each_selected_instruction_is_a_native_start(self):
        prior = ROOT / 'research/work-items/RE-012-tcp-stream-94'
        for provider in ('gnu', 'llvm'):
            sources = [PACKET / f'{name}.{provider}.txt' for name in ('reader', 'header-timeout', 'sleep-poll')]
            sources += [prior / f'{name}.{provider}.txt' for name in ('read-exact', 'write-all')]
            starts = set()
            for path in sources:
                starts |= {int(m.group(1), 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', path.read_text(), re.M)}
            for name, address, *_ in subject.FACTS:
                self.assertIn(address, starts, (provider, name))

    def test_each_selected_instruction_is_sensitive_below_digest(self):
        for name, address, *_ in subject.FACTS:
            with self.subTest(name=name):
                changed = bytearray(self.data)
                changed[self.image.offset(address)] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    subject.inspect(changed)

    def test_sleep_location_and_timer_binding_are_not_guessed(self):
        for address in (0x1f359c, 0x5755108):
            changed = bytearray(self.data)
            changed[self.image.offset(address)] ^= 1
            with self.assertRaisesRegex(ValueError, 'Sleep'):
                subject.inspect(changed)
        changed = bytearray(self.data)
        rela = next(s for s in self.image.secs if s['name'] == '.rela.dyn')
        for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
            if struct.unpack_from('<Q', changed, off)[0] == 0x576f088:
                struct.pack_into('<q', changed, off + 16, 0x4f68f01)
                break
        with self.assertRaisesRegex(ValueError, 'relocation changed'):
            subject.inspect(changed)

    def test_counterfactuals_do_not_receive_authentic_origin(self):
        self.assertEqual(subject.inspect(self.data)['origin'], 'unqualified structural inspection')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            subject.analyze(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
