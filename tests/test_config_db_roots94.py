"""Offline controls for the selected node 94 configuration-rooted path."""
import csv
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import config_db_roots94 as collector


class ConfigDbRoots94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (collector.ROOT / collector.ARTIFACT).read_bytes()
        cls.outputs = collector.collect(cls.data)
        cls.evidence = json.loads(cls.outputs['evidence.json'])
        cls.image = collector.Image(cls.data)

    def test_target_identity_and_selected_scope(self):
        summary = self.evidence['summary']
        self.assertEqual(summary['artifact_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
        self.assertEqual((summary['function_count'], summary['exception_table_count'],
                          summary['exception_site_count']), (8, 5, 29))
        entries = {r['start_va']: r for r in self.evidence['functions']}
        self.assertEqual(entries['0x15861d0']['end_va'], '0x1586308')
        self.assertEqual(entries['0x4adda00']['start_file_offset'], '0x4adca00')
        self.assertEqual(entries['0x428f680']['lsda_va'], '0xb25a7c')
        for entry in entries.values():
            body = bytes.fromhex(entry['body_hex'])
            self.assertEqual(len(body), entry['size'])
            self.assertEqual(hashlib.sha256(body).hexdigest(), entry['body_sha256'])
            offset = int(entry['start_file_offset'], 16)
            self.assertEqual(body, self.data[offset:offset + len(body)])

    def test_independent_relative_operand_coordinates(self):
        # Decode only four fixed, independently selected sites in the original
        # file. The executable section's VA and file offset are not identical.
        text = next(s for s in collector.sections(self.data) if s['name'] == '.text')
        for site, length, displacement_offset, expected in (
                (0x158621e, 7, 3, 0x1ea808),
                (0x1586254, 7, 3, 0x1f3db9),
                (0x4adda4f, 6, 2, 0x57707e8),
                (0x4adda9b, 5, 1, 0x489d9c0)):
            offset = text['offset'] + site - text['address']
            operand = self.data[offset + displacement_offset:offset + displacement_offset + 4]
            displacement = int.from_bytes(operand, byteorder='little', signed=True)
            self.assertEqual(site + length + displacement, expected)

    def test_entire_format_entries_and_relocation_chain(self):
        templates = {r['entry_va']: r for r in self.evidence['templates']}
        self.assertEqual(bytes.fromhex(templates['0x1f3db9']['raw_hex']),
                         b'\xc0\x18/hyperliquid_data/db_hub\x00')
        self.assertEqual(bytes.fromhex(templates['0x1ea808']['raw_hex']),
                         b'\xc0\x1b/hyperliquid_data/no_db_hub\x00')
        self.assertEqual(templates['0x1ea44d']['raw_hex'], 'c000')
        records = {r['slot_va']: r['addend_va'] for r in self.evidence['relocations']}
        self.assertEqual(records['0x576e928'], '0x577b288')
        self.assertEqual(records['0x577b288'], '0x164ff00')
        self.assertEqual(records['0x57707e8'], '0x15861d0')

    def test_selector_boundaries_and_cleanup_are_distinct(self):
        marker = 0x8000000000000001
        floor = -0x7ffffffffffffffe
        self.assertEqual(collector.selector_case(0x8000000000000000, marker), 'global_db_hub')
        self.assertEqual(collector.selector_case(marker, marker), 'global_no_db_hub')
        for word in (0, 1, 0x7fffffffffffffff, 0x8000000000000002, 0xffffffffffffffff):
            self.assertEqual(collector.selector_case(word, marker), 'input_string')
        self.assertFalse(collector.signed_cleanup_eligible(0, floor))
        self.assertFalse(collector.signed_cleanup_eligible(0x8000000000000000, floor))
        self.assertFalse(collector.signed_cleanup_eligible(marker, floor))
        self.assertTrue(collector.signed_cleanup_eligible(0x8000000000000002, floor))
        self.assertTrue(collector.signed_cleanup_eligible(0xffffffffffffffff, floor))
        with self.assertRaises(ValueError):
            collector.selector_case(1 << 64, marker)
        with self.assertRaises(ValueError):
            collector.signed_cleanup_eligible(-1, floor)

    def test_two_record_normal_flow_model(self):
        self.assertEqual(collector.model_pair_insert([0, 1]), [(0, 0), (1, 1)])
        self.assertEqual(collector.model_pair_insert([1, 0]), [(0, 1), (1, 0)])
        self.assertEqual(collector.model_pair_insert([0, 0]), [(0, 1)])
        self.assertEqual(collector.model_pair_insert([255, 0]), [(0, 1), (255, 0)])
        leaf = self.evidence['two_record_leaf_model_is_inference']
        self.assertEqual((leaf['root_allocation_size'], leaf['count_word_offset'],
                          leaf['initial_count'], leaf['pointer_stride']), (112, '0x62', 0, 8))
        self.assertEqual([(r['key'], r['leaf_count_after'], r['key_byte_offset'],
                           r['pointer_word_offset']) for r in leaf['writes']],
                         [(0, 1, '0x64', '0x8'), (1, 2, '0x65', '0x10')])
        for invalid in ([], [0], [0, 1, 2], [0, 256], [-1, 0]):
            with self.assertRaises(ValueError):
                collector.model_pair_insert(invalid)

    def test_selected_exception_landing_pads(self):
        rows = list(csv.DictReader(io.StringIO(self.outputs['exceptions.tsv'].decode()), delimiter='\t'))
        def owner(site):
            return [row for row in rows if row['function_va'] == '0x4adda00'
                    and int(row['start_va'], 16) <= site < int(row['end_va'], 16)]
        self.assertEqual([r['landing_va'] for r in owner(0x4adda4f)], ['0x4addb1b'])
        self.assertEqual([r['landing_va'] for r in owner(0x4adda9b)], ['0x4addb08'])
        self.assertEqual(owner(0x4adda4f)[0]['action_index'], '0')

    def test_wrong_targets_opcodes_and_nobits_are_rejected(self):
        with self.assertRaises(ValueError):
            collector.checked_transfer(self.image, 0x4adda9b, 'e8', 0x489d9c1)
        with self.assertRaises(ValueError):
            collector.checked_transfer(self.image, 0x4adda9b, 'e9', 0x489d9c0)
        with self.assertRaises(ValueError):
            collector.checked_rel32(self.image, 0x158621e, '488d15', 0x1ea809)
        bss = next(section for section in self.image.sections if section['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        for address, size in ((-1, 1), (0, 0), ((1 << 64) - 1, 2)):
            with self.assertRaises(ValueError):
                self.image.read(address, size)
        duplicate = collector.Image(self.data)
        duplicate.sections.append(dict(next(s for s in duplicate.sections if s['name'] == '.rodata')))
        with self.assertRaises(ValueError):
            duplicate.read(0x1ea808, 1)

    def test_corruption_controls_digest_instruction_template_and_lsda(self):
        data = bytearray(self.data)
        va = 0x15861e2
        offset = self.image.offset(va, 10)
        data[offset + 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            collector.collect(data)
        changed = collector.Image(data)
        with self.assertRaises(ValueError):
            changed.expect(va, bytes.fromhex('48b90100000000000080'))
        data[offset + 2] ^= 1
        # Change an instruction outside the small semantic windows: full-FDE
        # validation must catch it even when the selected windows are intact.
        start, end = 0x15861d0, 0x1586308
        expected = '0708e4510d25b8d4b5fde39b85aefb822df85b4431644bb13c6e4b40a1b39dc3'
        collector.checked_body(changed, start, end, expected)
        offset = self.image.offset(start, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE byte hash'):
            collector.checked_body(changed, start, end, expected)
        data[offset] ^= 1
        offset = self.image.offset(0x1f3db9, 27)
        data[offset + 26] ^= 1
        with self.assertRaises(ValueError):
            collector.parse_template(changed, 0x1f3db9, b'/hyperliquid_data/db_hub')
        data[offset + 26] ^= 1
        fde = {'start': 0x4adda00, 'end': 0x4addb60, 'lsda': 0xb93490}
        offset = self.image.offset(fde['lsda'], 2)
        data[offset] = 0
        with self.assertRaises(ValueError):
            collector.exception_table(changed, fde)

    def test_relocation_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            collector.parse_relocations(self.image, {0x57707e8: 0x15861d1})
        with self.assertRaises(ValueError):
            collector.parse_relocations(self.image, {0x57707e9: 0x15861d0})

    def test_generated_files_and_identity_template(self):
        self.assertEqual(set(self.outputs), {'evidence.json', 'windows.tsv', 'transfers.tsv',
                                             'rip-references.tsv', 'exceptions.tsv'})
        # The parser must not read beyond the selected identity template into
        # the adjacent unrelated bytes.
        self.assertEqual(self.evidence['templates'][2]['raw_hex'], 'c000')
        self.assertEqual(len(list(csv.DictReader(io.StringIO(self.outputs['transfers.tsv'].decode()),
                                                  delimiter='\t'))), 43)


if __name__ == '__main__':
    unittest.main()
