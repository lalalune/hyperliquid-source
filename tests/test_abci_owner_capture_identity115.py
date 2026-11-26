import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_owner_capture_identity115 as subject
from elf_index import sections


class OwnerCaptureIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = sections(cls.data)

    def mutate_va(self, va, replacement):
        offset, _ = subject.file_bytes(self.secs, self.data, va, len(replacement))
        changed = bytearray(self.data)
        changed[offset:offset + len(replacement)] = replacement
        return bytes(changed)

    def test_distinct_allocation_origins_and_task_capture_slots(self):
        report = subject.analyze(self.data)
        self.assertEqual(report['owner_origins']['root_apply_owner']['parent_slot'], '0x840')
        self.assertEqual(report['owner_origins']['result_write_owner']['parent_slot'], '0xae8')
        self.assertIn('separate origins', report['conclusion'])
        self.assertEqual(report['allocator']['relative_relocation_addend'], '0x6355830')
        self.assertEqual(report['constructor_call']['relative_relocation_addend'], '0x5a6cbc0')
        self.assertEqual(len(report['anchors']), 35)

    def test_rejects_wrong_target_digest(self):
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.analyze(bytes(changed))

    def test_instruction_mutations_fail_after_repinning_digest(self):
        for va, replacement in (
            (0x2CB865D, bytes.fromhex('bff1060000')),
            (0x2CB868D, bytes.fromhex('4c89bbe90a0000')),
            (0x5A6CE1C, bytes.fromhex('4889842429010000')),
        ):
            with self.subTest(va=hex(va)):
                changed = self.mutate_va(va, replacement)
                digest = hashlib.sha256(changed).hexdigest()
                with mock.patch.object(subject, 'SHA', digest):
                    with self.assertRaisesRegex(ValueError, 'anchor bytes changed'):
                        subject.analyze(changed)

    def test_rejects_changed_reused_projection_context(self):
        path = ROOT / 'research/work-items/RE-017-abci-compact-root-115/parent_projection.tsv'
        original = path.read_text(encoding='utf-8')
        with mock.patch.object(Path, 'read_text', return_value=original.replace('0x840', '0x848')):
            with self.assertRaisesRegex(ValueError, 'projection changed'):
                subject.analyze(self.data)


if __name__ == '__main__':
    unittest.main()
