"""Corruption controls for the actual captured Node115 registration contract."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from node115_cli_option_registration import Image, derive, TARGET_SHA256
SPEC = ROOT / 'research/work-items/RE-012-node115-cli-option-registration/spec.json'
TARGET = ROOT / 'artifacts/node/115/hl-node'

class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != TARGET_SHA256:
            raise RuntimeError('Materialize the pinned Node115 input; no skip or substitute')
        cls.spec = json.loads(SPEC.read_text())
        cls.image = Image(cls.data)

    def changed(self, va, xor=1):
        data = bytearray(self.data)
        data[self.image.offset(va, 1)] ^= xor
        return Image(data, verify_identity=False)

    def operand(self, name):
        row = next(r for r in self.spec['facts'] if r['name'] == name)
        return int(row['site'], 16) + len(bytes.fromhex(row['prefix']))

    def check_fact(self, name):
        with self.assertRaisesRegex(ValueError, 'fact operand: ' + name):
            derive(self.changed(self.operand(name)), self.spec)

    def test_real_target_contract(self):
        out = derive(self.image, self.spec)
        self.assertEqual((len(out['functions']), len(out['facts']), len(out['calls'])), (12, 21, 23))
        self.assertEqual(out['versionLiteral'], 'version')
        self.assertEqual(sum(f['bytes'] for f in out['functions']), 6165)
        self.assertFalse(out['capturedExecution'])
        self.assertFalse(out['componentGate'])

    def test_public_identity_refuses_changed_capture(self):
        data = bytearray(self.data)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'sole Node115 identity'):
            Image(data)

    def test_refuses_other_declared_target(self):
        spec = copy.deepcopy(self.spec)
        spec['targetSHA256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'spec target'):
            derive(self.image, spec)

    def test_actual_global_operand(self):
        self.check_fact('global')

    def test_actual_required_operand(self):
        self.check_fact('required')

    def test_actual_last_operand(self):
        self.check_fact('last')

    def test_actual_takes_value_operand(self):
        self.check_fact('takes-value')

    def test_actual_help_literal(self):
        self.check_fact('help-literal')

    def test_actual_overlapping_version_operand(self):
        self.check_fact('version-overlap')

    def test_actual_special_name_masks(self):
        for name in ['help-clear', 'version-clear', 'app-settings-field']:
            with self.subTest(name=name):
                self.check_fact(name)

    def test_actual_record_copy_and_stride_operands(self):
        for name in ['arg-copy-bytes', 'flag-record-stride', 'option-record-stride',
                     'flag-record-prefix-copy', 'option-record-copy']:
            with self.subTest(name=name):
                self.check_fact(name)

    def test_actual_short_none_sentinel(self):
        self.check_fact('short-none-tag')

    def test_actual_call_displacement(self):
        row = next(r for r in self.spec['calls'] if r['form'] == 'direct')
        with self.assertRaisesRegex(ValueError, 'call binding'):
            derive(self.changed(int(row['site'], 16) + 1), self.spec)

    def test_actual_relative_writer(self):
        section = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        data = bytearray(self.data)
        entries = [p for p in range(section['offset'], section['offset'] + section['size'], 24)
                   if struct.unpack_from('<Q', data, p)[0] == 0x64e1cf0]
        self.assertEqual(len(entries), 1)
        data[entries[0] + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'unique RELATIVE writer'):
            derive(Image(data, verify_identity=False), self.spec)

    def test_actual_fde_extent(self):
        fde = next(f for f in self.image.fdes if f['start'] == 0x1638840)
        data = bytearray(self.data)
        p = self.image.offset(fde['fde'], 16)
        self.assertEqual(struct.unpack_from('<I', data, p + 12)[0], 1923)
        data[p + 12] ^= 1
        with self.assertRaisesRegex(ValueError, 'function FDE range'):
            derive(Image(data, verify_identity=False), self.spec)

    def test_actual_opcode_control(self):
        site = int(self.spec['facts'][0]['site'], 16)
        with self.assertRaisesRegex(ValueError, 'fact opcode: global'):
            derive(self.changed(site), self.spec)

    def test_actual_lsda_encoding(self):
        out = derive(self.image, self.spec)
        table = out['functions'][0]['exceptionTable']
        self.assertEqual(len(table['sites']), 15)
        self.assertEqual(table['sites'][0]['landing'], '0x1638fa8')
        with self.assertRaisesRegex(ValueError, 'LSDA call-site encoding'):
            derive(self.changed(int(table['callSiteEncodingVA'], 16)), self.spec)

    def test_actual_lsda_table_size(self):
        out = derive(self.image, self.spec)
        va = int(out['functions'][0]['exceptionTable']['callSiteEncodingVA'], 16) + 1
        with self.assertRaises(ValueError):
            derive(self.changed(va), self.spec)


    @classmethod
    def packet_comparator(cls):
        import importlib.util
        path = SPEC.parent / 'verify.py'
        module_spec = importlib.util.spec_from_file_location('registration_packet_verifier', path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        return module

    def test_corrupted_original_native_byte_is_rejected(self):
        import re
        expected = json.loads((SPEC.parent / 'independent-instructions.json').read_text())['0x1638840']
        lines = (SPEC.parent / '0x1638840.gnu.objdump').read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if re.match(r'^\s*1638840:', line))
        self.assertIn('55', lines[index])
        lines[index] = lines[index].replace('55', '54', 1)
        with self.assertRaisesRegex(ValueError, 'native address/bytes'):
            self.packet_comparator().compare_native('\n'.join(lines), expected)

    def test_missing_original_native_row_is_rejected(self):
        import re
        expected = json.loads((SPEC.parent / 'independent-instructions.json').read_text())['0x1638840']
        lines = (SPEC.parent / '0x1638840.gnu.objdump').read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if re.match(r'^\s*1638840:', line))
        del lines[index]
        with self.assertRaisesRegex(ValueError, 'native instruction count'):
            self.packet_comparator().compare_native('\n'.join(lines), expected)


if __name__ == '__main__':
    unittest.main()
