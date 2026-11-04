"""Native full-body evidence plus operand and identity counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import checkpoint_lifecycle_static as subject


class CheckpointLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong capture')
        cls.report = subject.analyze(cls.data)

    def mutate(self, address, raw):
        data = bytearray(self.data)
        offset = subject.mapping(data)[1](address, len(raw))[0]
        data[offset:offset + len(raw)] = raw
        return data

    def test_retained_evidence_and_independent_native_decode(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(sum(o['bytes'] for o in self.report['owners']), 3664)
        self.assertEqual(sum(o['instructions'] for o in self.report['owners']), 792)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            subject.generate(subject.TARGET, output)
            for path in output.iterdir():
                if path.name == 'native-tools.txt':
                    self.assertRegex(path.read_text(), r'^GNU objdump .+ [0-9]')
                else:
                    self.assertEqual(path.read_bytes(), (subject.PACKET / path.name).read_bytes(), path.name)

    def test_cp_arguments_are_real_read_operands(self):
        self.assertEqual(subject.command_projection(self.data, 0), {'command': 'cp', 'flag': b'-R'.hex()})
        self.assertEqual(subject.command_projection(self.data, 1), {'command': 'cp', 'flag': b'-al'.hex()})
        changed = self.mutate(0x1502a04, b'\x03')
        self.assertNotEqual(subject.command_projection(changed, 1), subject.command_projection(self.data, 1))
        # Actual LEA displacement counterfactual selects the other flag, not a synthetic fixture.
        changed = self.mutate(0x15029f0, struct.pack('<i', 0x465a05 - 0x15029f4))
        self.assertEqual(subject.command_projection(changed, 1)['flag'], b'-R-'.hex())

    def test_mode_branch_and_file_type_operands_are_observed(self):
        p = subject.predicates(self.data)
        self.assertEqual(p['zero_mode_target'], 0x4468692)
        changed = self.mutate(0x44682eb, struct.pack('<i', 0x4468724 - 0x44682ef))
        self.assertEqual(subject.predicates(changed)['zero_mode_target'], 0x4468724)
        for key, expected in [('directory_value', 0x4000), ('file_value', 0x8000)]:
            self.assertEqual(p[key], expected)
            for permission in [0, 0o600, 0o755, 0xfff]:
                self.assertEqual(((expected | permission) & 0xf000), expected)
        changed = self.mutate(0x1500de4, struct.pack('<I', 0x4000))
        q = subject.predicates(changed)
        self.assertNotEqual((0x8000 & q['file_mask']) == q['file_value'],
                            (0x8000 & p['file_mask']) == p['file_value'])

    def test_actual_call_and_source_binding_changes_are_visible(self):
        # Mutate the actual call-to-adapter slot displacement in the primary body.
        changed = self.mutate(0x446837b, b'\x98')
        report = subject.analyze(changed)
        self.assertNotEqual(report['rip_bindings'], self.report['rip_bindings'])
        address = 0x648b8a8
        changed = self.mutate(address + 16, struct.pack('<I', 292))
        self.assertNotEqual(subject.analyze(changed)['locations'], self.report['locations'])

    def test_identity_failure_precedes_output_or_native_tools(self):
        for raw in [b'not an ELF', self.data[:-1], self.mutate(0x44682e9, b'\x90')]:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'input'
                output = Path(directory) / 'absent'
                target.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    subject.generate(target, output)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
