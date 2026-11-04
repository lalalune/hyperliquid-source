import copy
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cli_common_settings as common


class CommonSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.spec = json.loads((common.PACKET / 'spec.json').read_text())
        cls.image = common.Image(cls.data)
        cls.records = common.collect(cls.data, cls.spec)

    def changed(self, va):
        data = bytearray(self.data)
        data[self.image.offset(va, 1)] ^= 1
        return bytes(data)

    def test_complete_producer_names_and_flags(self):
        expected = ['write-trades', 'write-fills', 'write-raw-book-diffs',
                    'write-order-statuses', 'write-misc-events',
                    'write-hip3-oracle-updates', 'write-user-clearinghouse-states',
                    'write-system-and-core-writer-actions',
                    'disable-output-file-buffering', 'batch-by-block',
                    'stream-with-block-info', 'serve-evm-rpc', 'serve-info',
                    'replica-cmds-style']
        self.assertEqual([r['longName'] for r in self.records['options']], expected)
        self.assertEqual([r['initialFlags'] for r in self.records['options']],
                         ['0x424' if i in (6, 13) else '0x404' for i in range(14)])
        self.assertEqual(sum(r['bytes'] for r in self.records['functions']), 11696)
        self.assertEqual(self.records['masks'], [])

    def test_real_alias_internal_name_and_predicate_bytes(self):
        self.assertEqual(self.records['alias']['name'], 'serve-eth-rpc')
        self.assertEqual(self.records['alias']['entryByte'], 0)
        self.assertEqual(self.records['style']['internalName'], 'actions')
        self.assertEqual(self.records['style']['acceptedComparisons'],
                         ['actions', 'recent-actions', 'actions-and-responses'])
        self.assertEqual(self.records['style']['errorText'], 'Matching variant not found')

    def test_identity_rejects_a_real_mutation(self):
        with self.assertRaisesRegex(ValueError, 'size/SHA256'):
            common.collect(self.changed(0x92ab5a), self.spec)

    def test_mutated_name_pool_is_not_accepted_after_hash_control_is_removed(self):
        # Internal derivation deliberately bypasses only the outer digest gate:
        # this is an actual input-byte corruption control, not a fabricated record.
        with self.assertRaisesRegex(ValueError, 'exact long option name'):
            common.derive(common.Image(self.changed(0x92ab5a)), self.spec)

    def test_mutated_flag_store_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'anchor: flagWriter'):
            common.derive(common.Image(self.changed(0x5656e9b + 7)), self.spec)

    def test_mutated_registration_displacement_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'anchor: registration'):
            common.derive(common.Image(self.changed(0x5656ec5 + 2)), self.spec)

    def test_mutated_alias_visibility_entry_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'anchor: alias-empty-entry'):
            common.derive(common.Image(self.changed(0x5658d79 + 3)), self.spec)

    def test_mutated_style_comparison_changes_the_real_operand_contract(self):
        mutant = common.Image(self.changed(0x565985e))
        self.assertNotEqual(common.style_names(mutant)[0], 'actions')
        with self.assertRaisesRegex(ValueError, 'anchor: style'):
            common.derive(mutant, self.spec)

    def test_mutated_callback_relocation_is_not_accepted(self):
        data = bytearray(self.data)
        section = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            if struct.unpack_from('<Q', data, pos)[0] == 0x64aa928:
                data[pos + 16] ^= 1
                break
        else:
            self.fail('actual callback relocation absent')
        with self.assertRaisesRegex(ValueError, 'RELATIVE writer'):
            common.derive(common.Image(bytes(data)), self.spec)

    def test_mutated_fde_range_is_not_a_full_function(self):
        fde = self.records['functions'][0]['fde']
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            common.derive(common.Image(self.changed(fde['fde'] + 12)), self.spec)

    def test_mutated_actual_lsda_encoding_is_not_accepted(self):
        table = self.records['functions'][0]['exceptionTable']
        with self.assertRaisesRegex(ValueError, 'LSDA call-site encoding'):
            common.derive(common.Image(self.changed(int(table['callSiteEncodingVA'], 16))),
                          self.spec)


    def packet_verifier(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('common_settings_packet_verifier',
                                                     common.PACKET / 'verify.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_actual_native_byte_corruption_is_rejected(self):
        import re
        verifier = self.packet_verifier()
        text = (common.PACKET / 'common-constructor.gnu.objdump').read_text(encoding='utf-8-sig')
        rows = json.loads((common.PACKET / 'independent-instructions.json').read_text())[
            'common-output-option-constructor']
        self.assertEqual(verifier.compare_native(text, rows), 1486)
        mutant = re.sub(r'(?m)^(\s*5656bf0:\s+)55', r'\g<1>54', text, count=1)
        self.assertNotEqual(mutant, text)
        with self.assertRaisesRegex(ValueError, 'native address/bytes'):
            verifier.compare_native(mutant, rows)

    def test_missing_native_instruction_row_is_rejected(self):
        import re
        verifier = self.packet_verifier()
        text = (common.PACKET / 'common-constructor.gnu.objdump').read_text(encoding='utf-8-sig')
        rows = json.loads((common.PACKET / 'independent-instructions.json').read_text())[
            'common-output-option-constructor']
        mutant = re.sub(r'(?m)^\s*5656bf0:.*\n', '', text, count=1)
        self.assertNotEqual(mutant, text)
        with self.assertRaisesRegex(ValueError, 'native instruction count'):
            verifier.compare_native(mutant, rows)



if __name__ == '__main__':
    unittest.main()
