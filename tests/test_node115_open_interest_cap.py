"""Static evidence integrity controls; no captured instruction evaluation."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-007-node115-open-interest-cap'
spec = importlib.util.spec_from_file_location('open_interest_cap_collect', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.image = collector.Image(cls.data)

    def offset(self, address):
        matches = [p[2] + address - p[3] for p in self.image.ph
                   if p[0] == 1 and p[3] <= address < p[3] + p[5]]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_wrong_target_precedes_output_and_any_native_tool(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'must-not-exist'
            with patch.object(collector.subprocess, 'run') as native:
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    collector.collect(changed, destination)
                native.assert_not_called()
            self.assertFalse(destination.exists())

    def test_inner_evidence_accepts_the_authentic_target(self):
        self.assertEqual(collector.validate_inner(self.data), {
            'instruction_anchors': 155, 'data_anchors': 15,
            'relocations': 18, 'full_fdes': 5,
        })

    def test_instruction_and_operand_corruption_below_outer_digest(self):
        changed = bytearray(self.data)
        for address, raw in collector.ANCHORS.items():
            for delta in sorted({0, len(raw) // 2 - 1}):
                offset = self.offset(address + delta)
                with self.subTest(address=hex(address), delta=delta):
                    changed[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, 'native operand/instruction anchor'):
                        collector.validate_inner(changed)
                    changed[offset] ^= 1

    def test_literals_and_descriptor_tails_are_required(self):
        changed = bytearray(self.data)
        for address, raw in collector.DATA_PINS.items():
            offset = self.offset(address + len(raw) // 2 - 1)
            with self.subTest(address=hex(address)):
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'data anchor'):
                    collector.validate_inner(changed)
                changed[offset] ^= 1

    def test_relocation_symbol_type_and_addend_below_outer_digest(self):
        changed = bytearray(self.data)
        section = self.image.sections['.rela.dyn']
        offsets = {struct.unpack_from('<Q', self.data, offset)[0]: offset
                   for offset in range(section[4], section[4] + section[5], 24)}
        for slot in collector.RELA_PINS:
            # Type, symbol index and signed addend are separate obligations.
            for field in [8, 12, 16]:
                offset = offsets[slot] + field
                with self.subTest(slot=hex(slot), field=field):
                    changed[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, 'RELATIVE symbol/type/addend'):
                        collector.validate_inner(changed)
                    changed[offset] ^= 1

    def test_full_unwind_bytes_are_bound(self):
        changed = bytearray(self.data)
        controls = set()
        for body in collector.BODIES.values():
            for kind in ['fde', 'cie']:
                address = body[kind + '_va']
                controls.add((address + len(body[kind + '_raw']) // 2 - 1, kind))
        for address, kind in sorted(controls):
            offset = self.offset(address)
            with self.subTest(address=hex(address)):
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'full ' + kind.upper() + ' raw bytes'):
                    collector.validate_inner(changed)
                changed[offset] ^= 1

    def test_ambiguous_or_disagreeing_file_mapping_is_rejected(self):
        changed = bytearray(self.data)
        start = collector.BODY_START
        section_index = next(i for i, s in enumerate(self.image.sh)
                             if s[1] != 8 and s[3] <= start < s[3] + s[5])
        table = struct.unpack_from('<Q', changed, 40)[0]
        # Keep the VA span, but move its file offset by one byte.
        field = table + section_index * 64 + 24
        struct.pack_into('<Q', changed, field, self.image.sh[section_index][4] + 1)
        with self.assertRaisesRegex(ValueError, 'offset disagreement'):
            collector.validate_inner(changed)
        with self.assertRaisesRegex(ValueError, 'mapping'):
            self.image.read(0, 1)

    def test_complete_native_exports_regenerate_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'fresh'
            result = collector.collect(self.data, output)
            comparison = collector.compare_packet(output)
            self.assertTrue(comparison['semantic_records_equal'])
            self.assertEqual(comparison['exact_native_files'], 10)
            selected = next(row for row in result['bodies']
                            if row['role'] == 'selected-helper')
            self.assertEqual(selected['instructions'], 101)
            self.assertEqual(selected['end'] - int(selected['start'], 16), 420)

    def test_provenance_exception_cannot_hide_a_changed_native_record(self):
        names = ['records.json', 'commands.json', 'objdump-version.txt',
                 'objdump-version.stderr']
        names += [f'native/{start:x}.{suffix}' for start in collector.BODIES
                  for suffix in ['objdump.txt', 'stderr']]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in names:
                (output / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(PACKET / name, output / name)
            record = json.loads((output / 'records.json').read_text())
            record['tool_sha256'] = '0' * 64
            (output / 'records.json').write_text(json.dumps(record))
            self.assertTrue(collector.compare_packet(output)['semantic_records_equal'])
            record['bodies'][0]['rows'][0]['raw'] = '90'
            (output / 'records.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'record mismatch'):
                collector.compare_packet(output)


if __name__ == '__main__':
    unittest.main()
