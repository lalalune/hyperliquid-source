"""Static unsigned-reduction and actual startup caller controls."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import startup_end_height_static as subject


class StartupEndHeightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong capture')
        cls.report = subject.analyze(cls.data)

    def mutate(self, address, raw, data=None):
        changed = bytearray(self.data if data is None else data)
        offset = subject.reader(changed)[1](address, len(raw))[0]
        changed[offset:offset + len(raw)] = raw
        return changed

    def test_two_complete_native_exports_and_retained_record(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']), 6789)
        self.assertEqual(sum(x['instructions'] for x in self.report['owners']), 1418)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            subject.generate(subject.TARGET, output)
            for path in output.iterdir():
                self.assertEqual(path.read_bytes(), (subject.PACKET / path.name).read_bytes())

    def test_unsigned_maximum_boundary_permutations(self):
        p = self.report['parameters']
        self.assertEqual(p['cmov_conditions'], [0x46] * 3)
        self.assertIsNone(subject.reduce_values(p, []))
        boundaries = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        for length in range(1, 5):
            for values in itertools.product(boundaries, repeat=length):
                self.assertEqual(subject.reduce_values(p, values), max(values))

    def test_real_cmov_counterfactual_selects_minimum(self):
        changed = self.data
        for address in [0x595b3a9, 0x595b3ba, 0x595b3d8]:
            changed = self.mutate(address, b'\x47', changed)
        p = subject.parameters(changed)
        self.assertEqual(subject.reduce_values(p, [1, 1 << 63, 3]), 1)
        self.assertEqual(subject.reduce_values(self.report['parameters'], [1, 1 << 63, 3]), 1 << 63)

    def test_caller_gate_assignment_and_bound_branch_operands(self):
        p = self.report['parameters']
        self.assertEqual((p['caller_error_tag'], p['caller_store_offset'], p['caller_unsigned_condition'],
                          p['caller_unsigned_destination']), (1, 0x30, 0x82, 0x2b42d07))
        for address, raw in [(0x2b41d45, b'\x02'), (0x2b41eb7, b'\x38'),
                             (0x2b41ebc, b'\x83'), (0x2b41ebd, struct.pack('<i', 0))]:
            self.assertNotEqual(subject.parameters(self.mutate(address, raw)), p)

    def test_actual_call_binding_and_location_control(self):
        changed = self.mutate(0x2b41d3e, b'\xdf')
        self.assertNotEqual(subject.analyze(changed)['rip_bindings'], self.report['rip_bindings'])
        changed = self.mutate(0x64b6838 + 16, struct.pack('<I', 365))
        self.assertNotEqual(subject.analyze(changed)['locations'], self.report['locations'])
        changed = self.mutate(0x64e7720, struct.pack('<Q', 0x595b1a1))
        # A RELA addend is authoritative; changing the file's placeholder alone
        # must not pretend to redirect the runtime target.
        self.assertEqual(subject.analyze(changed)['rip_bindings'], self.report['rip_bindings'])
        secs, _ = subject.reader(self.data)
        section = next(s for s in secs if s['name'] == '.rela.dyn')
        changed = bytearray(self.data)
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            if struct.unpack_from('<Q', changed, offset)[0] == 0x64e7720:
                struct.pack_into('<q', changed, offset + 16, 0x595b1a1)
                break
        else:
            self.fail('measured RELA slot missing')
        with self.assertRaisesRegex(ValueError, 'selector relocation changed'):
            subject.analyze(changed)

    def test_wrong_target_fails_before_output(self):
        for data in [b'wrong', self.data[:-1], self.mutate(0x595b3a9, b'\x47')]:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'input'
                output = Path(directory) / 'absent'
                target.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    subject.generate(target, output)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
