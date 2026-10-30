"""Architectural corruption controls for the node #94 tracker update packet."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import file_tracker_update_static as tracker
from artifacts import ROOT, check
from elf_index import sections


class FileTrackerUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == 'artifacts/node/94/hl-node')
        check(cls.target, identity)
        cls.data = cls.target.read_bytes()

    def changed_byte(self, va, value=None):
        data = bytearray(self.data)
        offset = tracker.read_va(data, va, 1)[0]
        data[offset] = data[offset] ^ 1 if value is None else value
        return data

    def test_actual_original_obligations(self):
        tracker.controls(self.data)
        self.assertEqual(len(tracker.relocations(self.data)), 7)
        self.assertEqual(len(tracker.calls(self.data)), 8)
        self.assertEqual(tracker.frames(self.data)['updater']['end'] - 0x13CC5D0, 931)

    def test_every_instruction_obligation_rejects_real_byte_corruption(self):
        for name, (va, _) in tracker.CONTROLS.items():
            with self.subTest(control=name):
                with self.assertRaisesRegex(ValueError, 'Updater instruction changed: ' + name):
                    tracker.controls(self.changed_byte(va))

    def test_branch_conditions_and_store_offsets_are_not_interchangeable(self):
        # JBE -> JA loses unordered suppression; SETG -> SETA changes signed
        # order; the third JA -> JG changes unsigned third-word ordering.
        # Store displacement changes move the poll/value/mtime/error fields.
        for va, value in [(0x13CC65E, 0x87), (0x13CC6BD, 0x97),
                          (0x13CC6CC, 0x7F), (0x13CC666, 0x48),
                          (0x13CC6A8, 0x85), (0x13CC704, 0x80),
                          (0x13CC86D, 0x18), (0x13CC886, 0x54),
                          (0x13CC8A6, 0x50)]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'Updater instruction changed'):
                    tracker.controls(self.changed_byte(va, value))

    def test_actual_diagnostic_mutations_rejected(self):
        for va in tracker.LITERALS:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'Updater diagnostic changed'):
                    tracker.controls(self.changed_byte(va))

    def test_actual_call_retargets_rejected(self):
        for va, (kind, _) in tracker.CALLS.items():
            with self.subTest(va=hex(va)):
                data = self.changed_byte(va + (2 if kind == 'slot' else 1))
                with self.assertRaisesRegex(ValueError, 'Updater call target changed'):
                    tracker.calls(data)

    def relocation_offset(self, slot):
        matches = []
        for section in sections(self.data):
            if section['type'] == 4:
                matches.extend(offset for offset in range(section['offset'], section['offset'] + section['size'], 24)
                               if struct.unpack_from('<Q', self.data, offset)[0] == slot)
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_all_seven_relocation_retargets_rejected(self):
        for slot in tracker.RELATIVE:
            with self.subTest(slot=hex(slot)):
                data = bytearray(self.data)
                data[self.relocation_offset(slot) + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'Updater relocation changed'):
                    tracker.relocations(data)

    def test_missing_and_duplicate_relocations_rejected(self):
        slot = next(iter(tracker.RELATIVE))
        offset = self.relocation_offset(slot)
        missing = bytearray(self.data)
        struct.pack_into('<Q', missing, offset, 0)
        with self.assertRaisesRegex(ValueError, 'Missing updater relocation'):
            tracker.relocations(missing)
        duplicate = bytearray(self.data)
        # A different RELA entry becomes a second identical wanted binding.
        section = next(s for s in sections(self.data) if s['type'] == 4 and s['offset'] <= offset < s['offset'] + s['size'])
        other = section['offset'] if section['offset'] != offset else offset + 24
        duplicate[other:other + 24] = duplicate[offset:offset + 24]
        with self.assertRaisesRegex(ValueError, 'duplicated'):
            tracker.relocations(duplicate)

    def test_fde_range_mutation_rejected_independently_of_digest(self):
        data = bytearray(self.data)
        fde = tracker.frames(data)['updater']['fde']
        offset = tracker.read_va(data, fde, 16)[0]
        data[offset + 12] ^= 1  # DW_EH_PE_sdata4 pc_range, not next-index bound.
        with self.assertRaisesRegex(ValueError, 'exact updater/caller FDE extent'):
            tracker.frames(data)

    def test_decoded_coverage_rejects_missing_or_false_instruction_bytes(self):
        data = self.data
        start = 0x13CC5D0
        text = ' 13cc5d0: 55 push %rbp\n 13cc5d1: 41 57 push %r15\n'
        self.assertEqual(len(tracker.decoded_body(text, data, start, start + 3)), 2)
        for broken in [text.replace('41 57', '41 56'), text.splitlines()[1] + '\n']:
            with self.assertRaisesRegex(ValueError, 'coverage/bytes'):
                tracker.decoded_body(broken, data, start, start + 3)
        with self.assertRaisesRegex(ValueError, 'complete body'):
            tracker.decoded_body(text, data, start, start + 4)

    def test_wrong_release_and_corrupted_original_fail_before_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            corrupted = Path(directory) / 'corrupted-node94'
            changed = bytearray(self.data)
            changed[-1] ^= 1
            corrupted.write_bytes(changed)
            with mock.patch.object(tracker.subprocess, 'check_output', side_effect=AssertionError('tool ran before digest gate')):
                for binary in [ROOT / 'artifacts/node/115/hl-node', corrupted]:
                    with self.subTest(binary=binary.name):
                        with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                            tracker.generate(binary, output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
