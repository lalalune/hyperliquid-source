"""Real node94 diagnostic-field/table controls, without target execution."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_integer_error_static as diagnostic

PACKET = ROOT / 'research/work-items/RE-005-integer-error-kinds-94'
_DATA = None
_RECORD = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = diagnostic.TARGET.read_bytes()
    return _DATA


def record():
    global _RECORD
    if _RECORD is None:
        _RECORD = diagnostic.analyze(data())
    return _RECORD


def offset(va):
    return diagnostic.bv.va_to_off(diagnostic.bv.sections(data()), va)


class DiagnosticBindings(unittest.TestCase):
    def reject(self, pos, value, message):
        changed = bytearray(data())
        changed[pos:pos + len(value)] = value
        with self.assertRaisesRegex(diagnostic.EvidenceError, message):
            diagnostic.derive(changed)

    def test_real_record_matches_retained_packet(self):
        expected = json.loads((PACKET / 'observed/records.json').read_text())
        self.assertEqual(record(), expected)

    def test_builder_fields_and_selected_formatter_associations(self):
        result = record()
        self.assertEqual(result['builder'], {'tag_offset': 0, 'tag': 3, 'sil_offset': 1, 'dl_offset': 2})
        arm = result['diagnostic_arm']
        self.assertEqual((arm['tag3_target'], arm['label']), ('0x14f6bfa', 'InvalidIntegerType'))
        self.assertEqual((arm['expected_field']['record_offset'], arm['found_field']['record_offset']), (1, 2))
        self.assertEqual([v['format_slot']['addend_va'] for v in result['descriptors']], ['0x14f7910', '0x14f7310'])
        self.assertEqual(arm['opaque_field_helper']['addend_va'], '0x1571f50')

    def test_observed_name_slices_and_unclaimed_byte_domain(self):
        rows = record()['observed_name_rows']
        self.assertEqual([(i, rows[i]['literal']) for i in [2, 3, 4, 5, 12]],
                         [(2, 'U32'), (3, 'U64'), (4, 'U128'), (5, 'Usize'), (12, 'Reserved')])
        self.assertEqual(record()['pointer_window'], ['0x566fb80', '0x566fbe8'])
        self.assertEqual(record()['length_window'], ['0x21d4a0', '0x21d508'])
        self.assertFalse(record()['local_index_guard'])
        self.assertEqual(record()['uninspected_indices'], '13..255; no behavior claimed')
        self.assertFalse(record()['nominal_type_or_runtime_rendering_claimed'])
        self.assertFalse(record()['component_gates_requested'])

    def test_wrong_identity_and_truncation_fail_production_admission(self):
        for value in [data()[:128], b'not a captured ELF']:
            with self.subTest(size=len(value)), self.assertRaisesRegex(diagnostic.EvidenceError, 'authenticated node94'):
                diagnostic.analyze(value)
        changed = bytearray(data())
        changed[-1] ^= 1
        with self.assertRaisesRegex(diagnostic.EvidenceError, 'authenticated node94'):
            diagnostic.analyze(changed)

    def test_real_constructor_field_and_indirection_mutations(self):
        for va, value, anchor in [(0x466DAC5, b'\x04', '0x466dac0'),
                                  (0x14F6BFE, b'\x02', '0x14f6bfa'),
                                  (0x14F6C02, b'\x01', '0x14f6bfa'),
                                  (0x14F7912, b'\x06', '0x14f7910'),
                                  (0x14F7312, b'\x06', '0x14f7310')]:
            with self.subTest(va=hex(va)):
                self.reject(offset(va), value, 'Instruction obligation at ' + anchor)

    def test_real_tag3_dispatch_retarget_is_rejected(self):
        pos = offset(0x21D2D8 + 12)
        self.reject(pos, struct.pack('<i', 0x14F6C77 - 0x21D2D8), 'dispatch entry3')

    def test_real_descriptor_relocation_kind_and_target_controls(self):
        for descriptor in record()['descriptors']:
            link = descriptor['format_slot']
            pos = int(link['record_file_offset'], 16)
            with self.subTest(slot=link['slot_va'], mutation='kind'):
                self.reject(pos + 8, struct.pack('<Q', 9), 'RELA binding')
            with self.subTest(slot=link['slot_va'], mutation='target'):
                self.reject(pos + 16, struct.pack('<q', 0x14F68E0), 'RELA binding')
        self.reject(offset(0x566FA20) + 8, struct.pack('<Q', 2), 'Descriptor words')
        helper = record()['diagnostic_arm']['opaque_field_helper']
        self.reject(int(helper['record_file_offset'], 16) + 16, struct.pack('<q', 0x14F7910), 'RELA binding')

    def test_real_name_pointer_length_utf8_and_reserved_controls(self):
        for i in [2, 3, 4, 5, 12]:
            row = record()['observed_name_rows'][i]
            with self.subTest(index=i, mutation='length'):
                self.reject(offset(int(row['length_slot_va'], 16)), struct.pack('<Q', row['length'] + 1), 'Name length')
            with self.subTest(index=i, mutation='literal'):
                self.reject(int(row['literal_file_offset'], 16), b'X', 'Name literal')
        row = record()['observed_name_rows'][2]
        self.reject(int(row['literal_file_offset'], 16), b'\xff', 'Name UTF-8')
        self.reject(int(row['relocation']['record_file_offset'], 16) + 16,
                    struct.pack('<q', 0x21D452), 'RELA binding')

    def test_real_fde_and_cie_controls(self):
        for name in ['name-value', 'diagnostic-parent']:
            row = record()['selected_fdes'][name]
            pos = int(row['fde_file_offset'], 16)
            with self.subTest(name=name, mutation='extent'):
                self.reject(pos + 12, struct.pack('<I', row['bytes'] + 1), 'FDE extent')
            with self.subTest(name=name, mutation='cie'):
                pointer = struct.unpack_from('<I', data(), pos + 4)[0]
                self.reject(pos + 4, struct.pack('<I', pointer + 4), 'CIE reference')
            with self.subTest(name=name, mutation='record length'):
                length = struct.unpack_from('<I', data(), pos)[0]
                self.reject(pos, struct.pack('<I', length + 1), 'FDE record length')

    def test_retained_native_listing_bytes_and_completeness_controls(self):
        row = record()['selected_fdes']['name-value']
        start = int(row['start_va'], 16)
        pos = int(row['file_offset'], 16)
        body = data()[pos:pos + row['bytes']]
        text = (PACKET / 'observed/name-value.objdump.txt').read_text()
        self.assertEqual(diagnostic.verify_listing(text, body, start), 11)
        with self.assertRaisesRegex(diagnostic.EvidenceError, 'Native instruction bytes'):
            diagnostic.verify_listing(text.replace('0f b6 07', '0f b6 06', 1), body, start)
        with self.assertRaisesRegex(diagnostic.EvidenceError, 'cover complete'):
            diagnostic.verify_listing('\n'.join(text.splitlines()[:-1]), body, start)

    def test_output_refusal_precedes_input_read_and_preserves_sentinel(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'retained'
            output.mkdir()
            sentinel = output / 'sentinel'
            sentinel.write_bytes(b'keep evidence')
            with self.assertRaisesRegex(diagnostic.EvidenceError, 'already exists'):
                diagnostic.generate(Path(folder) / 'missing input', output)
            self.assertEqual(sentinel.read_bytes(), b'keep evidence')

    def test_wrong_input_cli_creates_no_output(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'wrong input'
            bad.write_bytes(b'not authenticated')
            output = Path(folder) / 'output'
            run = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/bincode_integer_error_static.py'),
                                  '--input', str(bad), '--output', str(output)],
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn(b'authenticated node94', run.stderr)


def gnu_available():
    if not shutil.which('objdump'):
        return False
    result = subprocess.run(['objdump', '--version'], capture_output=True, text=True)
    return result.returncode == 0 and 'GNU objdump' in result.stdout


@unittest.skipUnless(gnu_available(), 'SKIPPED (not a PASS): GNU objdump is required')
class NativeRegeneration(unittest.TestCase):
    def test_real_cli_regenerates_records_and_validated_raw_spans(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'fresh'
            run = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/bincode_integer_error_static.py'),
                                  '--output', str(output)],
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertEqual(json.loads((output / 'records.json').read_text()), record())
            metadata = json.loads((output / 'native.json').read_text())
            self.assertEqual(metadata['instruction_rows'], {'diagnostic-parent': 533, 'name-reference': 12,
                                                            'name-value': 11, 'raw-builder': 5})
            self.assertFalse(metadata['whole_elf_path_reopened'])
            for name, (start, end) in diagnostic.RANGES.items():
                pos = int(record()['selected_fdes'][name]['file_offset'], 16)
                text = (output / (name + '.objdump.txt')).read_text()
                self.assertEqual(diagnostic.verify_listing(text, data()[pos:pos + end - start], start),
                                 metadata['instruction_rows'][name])


if __name__ == '__main__':
    unittest.main()
