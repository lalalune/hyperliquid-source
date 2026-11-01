import json
import struct
import unittest
from pathlib import Path

from tools import abci_json_exchange94 as subject


class AbciJsonExchangeEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.authenticated(cls.data)
        cls.sections = subject.sections(cls.data)
        cls.record = subject.evidence(cls.data)
        cls.lo = int(cls.record['functions'][2]['start'], 16)
        cls.hi = int(cls.record['functions'][2]['end'], 16)

    def test_field_paths_and_unknown(self):
        rows = self.record['rows']
        self.assertEqual(len(rows), 61)
        self.assertEqual(rows[31]['label'], 'hyper_evm')
        self.assertEqual(rows[42]['label'], 'action_delayer')
        self.assertEqual(rows[60]['role'], 'unknown field arm')
        self.assertEqual(len(self.record['classifier_checked']), 14)
        self.assertEqual(len(self.record['classifier_length_routes']), 50)
        self.assertEqual((self.record['classifier_name_length_min'],
                          self.record['classifier_name_length_max']), (2, 51))
        self.assertEqual(self.record['root_field'], 'exchange')
        self.assertEqual(len(self.record['classifier_simd_checked']), 30)
        alias = self.record['alias']
        self.assertEqual((alias['tag'], alias['canonical_name'], alias['alternate_name']),
                         (43, 'default_hip3_limits', 'default_perp_dex_limits'))
        self.assertEqual(alias['equality_symbol'], 'bcmp')
        self.assertEqual(len(self.record['classifier_names']), 63)
        self.assertEqual(len(self.record['missing_field_sites']), 35)
        self.assertIn(43, {r['tag'] for r in self.record['missing_field_sites']})
        self.assertEqual({r['tag'] for r in self.record['classifier_names']}, set(range(60)))
        self.assertEqual([(r['tag'],r['name']) for r in self.record['aliases']], [
            (43, 'default_perp_dex_limits'), (47, 'hip3_isolated_only'),
            (50, 'last_aligned_quote_token_sample_time')])

    def test_alias_pairs_share_duplicate_guard(self):
        known = {r['name']:r['tag'] for r in self.record['classifier_names']}
        for a in self.record['aliases']:
            self.assertEqual(known[a['name']], known[a['duplicate_label']])
            for pair in ((a['name'], a['duplicate_label']),
                         (a['duplicate_label'], a['name'])):
                seen = set()
                for key in pair:
                    tag = known[key]
                    duplicate = tag in seen
                    seen.add(tag)
                self.assertTrue(duplicate)
        self.assertNotEqual(known['hyper_evm'], known['evm_enabled'])

    def test_hash_mismatch(self):
        with self.assertRaises(subject.EvidenceError):
            subject.authenticated(b'not the target')

    def test_bad_relative_instruction(self):
        with self.assertRaises(subject.EvidenceError):
            subject.rel32(b'\x90\0\0\0\0', 0, b'\xe8')
        with self.assertRaises(subject.EvidenceError):
            subject.rel32(b'\xe8\0', 0, b'\xe8')

    def test_file_mapping_rejects_invalid_and_nobits(self):
        with self.assertRaises(subject.EvidenceError):
            subject.mapping(self.sections, -1, 1)
        with self.assertRaises(subject.EvidenceError):
            subject.mapping(self.sections, 0, 0)
        bss = next(s for s in self.sections if s['name'] == '.bss')
        with self.assertRaises(subject.EvidenceError):
            subject.mapping(self.sections, bss['address'], 1)

    def test_table_target_corruption(self):
        changed = bytearray(self.data)
        pos = subject.mapping(self.sections, subject.TABLE, 4)
        struct.pack_into('<i', changed, pos, 0)
        with self.assertRaises(subject.EvidenceError):
            subject.extract_rows(changed, self.sections, self.lo, self.hi)

    def test_duplicate_label_instruction_corruption(self):
        changed = bytearray(self.data)
        address = int(self.record['rows'][0]['duplicate_va'], 16)
        changed[subject.mapping(self.sections, address, 1)] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.extract_rows(changed, self.sections, self.lo, self.hi)

    def test_duplicate_diagnostic_corruption(self):
        changed = bytearray(self.data)
        address = int(self.record['rows'][7]['diagnostic_site'], 16)
        changed[subject.mapping(self.sections, address + 3, 1)] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.extract_rows(changed, self.sections, self.lo, self.hi)

    def test_missing_field_diagnostic_corruption(self):
        changed = bytearray(self.data)
        address = int(self.record['missing_field_sites'][0]['diagnostic_site'], 16)
        changed[subject.mapping(self.sections, address+3, 1)] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.missing_field_sites(changed, self.sections, self.lo, self.hi, self.record['rows'])

    def test_simd_constant_corruption(self):
        row = next(x for x in self.record['classifier_simd_checked'] if x['tag'] == 43)
        changed = bytearray(self.data)
        address = int(row['first_constant_va'], 16) + 10
        changed[subject.mapping(self.sections, address, 1)] ^= 1
        f = self.record['functions'][3]
        with self.assertRaises(subject.EvidenceError):
            subject.simd_classifier_names(changed, self.sections, int(f['start'],16),
                                          int(f['end'],16), self.record['rows'])

    def test_guard_branch_corruption(self):
        changed = bytearray(self.data)
        va = int(self.record['rows'][1]['conditional_va'], 16)
        changed[subject.mapping(self.sections, va, 1)] = 0x90
        with self.assertRaises(subject.EvidenceError):
            subject.extract_rows(changed, self.sections, self.lo, self.hi)

    def test_pin_rejects_corruption(self):
        sample = bytearray(self.data)
        va = 0x315bd13
        offset = subject.mapping(self.sections, va, 1)
        sample[offset] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.pin(sample, self.sections, va, '83bc24c03f0000020f858d050000')

    def test_committed_evidence_matches_fresh_extraction(self):
        p = Path('research/work-items/RE-009-abci-json-exchange-94/evidence.json')
        self.assertEqual(json.loads(p.read_text()), self.record)


if __name__ == '__main__':
    unittest.main()
