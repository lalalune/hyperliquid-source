"""Binary-grounded transport-prefix observations; no target execution/emulation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-tcp-prefix'
spec = importlib.util.spec_from_file_location('node115_tcp_prefix', PACKET / 'collect.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class PrefixEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('materialized authenticated node115 required')

    def mutate(self, address, value):
        changed = bytearray(self.data)
        offset = subject.read(changed, address, 1)[0]
        changed[offset] = value
        return changed

    def test_native_exports_reproduce_retained_record(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            actual = subject.collect(self.data, output)
            self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
            self.assertEqual((actual['total_bytes'], actual['total_instructions']), (10726, 2054))
            for name in ['frames.txt', 'relocations.txt', *[f'{start:x}.objdump.txt' for start, _ in subject.RANGES]]:
                self.assertEqual((output / name).read_bytes(), (PACKET / name).read_bytes())

    def test_real_header_span_shift_and_marker_counterfactuals(self):
        for address, value, field, observed in [
            (0x2b78116, 4, 'prefix_bytes', 4),
            (0x2b7a6bb, 31, 'sender_length_bits', 31),
            (0x2b791c9, 2, 'marker_equal_to', 2),
        ]:
            changed = subject.projection(self.mutate(address, value))
            self.assertEqual(changed[field], observed)
            with self.assertRaisesRegex(ValueError, 'relation changed'):
                subject.validate_projection(changed)
        # The changed marker comparison accepts raw 2 instead of raw 1.
        self.assertFalse(2 == subject.projection(self.data)['marker_equal_to'])
        self.assertTrue(2 == subject.projection(self.mutate(0x2b791c9, 2))['marker_equal_to'])
        # SHR 31 would refuse an otherwise representable unsigned32 length.
        self.assertEqual(0xffffffff >> 32, 0)
        self.assertNotEqual(0xffffffff >> 31, 0)

    def test_real_endian_offsets_limit_branch_and_header_append_controls(self):
        for address in [0x2b780ff, 0x2b78227, 0x2b78229, 0x2b7822d,
                        0x2b78232, 0x2b78236, 0x2b7823a,
                        0x2b7903d, 0x2b79044, 0x2b791cd,
                        0x2b7a705, 0x2b7a72f, 0x2b7a732,
                        0x2b7a75b, 0x2b7a763, 0x2b7a76e, 0x2b7a779,
                        0x2b7a77e, 0x2b7a788, 0x2b7a79d]:
            old = subject.read(self.data, address, 1)[1][0]
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    subject.projection(self.mutate(address, old ^ 1))

    def test_wrong_or_truncated_target_refuses_before_output(self):
        for value in [self.data[:-1], self.mutate(0x2b78228, 0x90)]:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'not-created'
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    subject.collect(value, output)
                self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
