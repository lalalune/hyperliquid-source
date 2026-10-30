"""Tests for tools/perp_spot_scale_gate.py: census, site reads and damaged copies of node #94."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research/work-items/RE-004-perp-spot-scale-gate-94'
spec = importlib.util.spec_from_file_location('perp_spot_scale_gate', ROOT / 'tools/perp_spot_scale_gate.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def set_up_class(cls):
    cls.image = tool.Image(tool.load_target(ROOT / tool.BINARY))
    cls.evidence, cls.analysed, cls.excluded, cls.controls, cls.messages = tool.analyse(cls.image)
    cls.by_site = {row['site']: row for row in cls.analysed}


class Packet(unittest.TestCase):
    setUpClass = classmethod(set_up_class)

    def read(self, va, value):
        return tool.analyse_site(self.image, va, value)

    def assert_damage_fails(self, va, value, edits):
        damaged = self.image.patched(edits)
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_site(damaged, va, value)

    def test_census(self):
        self.assertEqual(self.evidence['text_sites'], 31)
        self.assertEqual(self.evidence['text_sites_by_value'], {'0x68db8bac710cb': 22, '0x68db8bac710cc': 9})
        self.assertEqual(self.evidence['data_copies'], [{'section': '.rodata', 'va': '0x7c6208'}])
        self.assertEqual(self.evidence['analysed_sites'] + self.evidence['excluded_sites'] + self.evidence['not_read_sites'], 31)

    def test_classes(self):
        self.assertEqual(self.evidence['sites_by_class'], {'branch': 4, 'cmov-zero': 3, 'divisible-by-10000': 8})
        self.assertEqual(self.evidence['analysed_sites'], 15)
        self.assertEqual(self.evidence['excluded_sites'], 13)
        self.assertEqual(self.evidence['not_read_sites'], 3)

    def test_constants_are_bare(self):
        self.assertEqual(tool.CAP, ((1 << 64) - 1) // 10000)
        self.assertEqual(tool.ROUND_BOUND, tool.CAP + 1)
        self.assertEqual((tool.INVERSE_625 * 625) & tool.U64, 1)

    def test_scale_lemma(self):
        lemma = tool.scale_lemma()
        self.assertTrue(all(lemma[key] for key in lemma if key != 'cap'))

    def test_scale_lemma_rejects_the_next_value(self):
        lemma = tool.scale_lemma(tool.CAP + 1)
        self.assertFalse(lemma['cap_is_floor_max_over_10000'])
        self.assertFalse(lemma['times_10000_fits'])
        self.assertFalse(lemma['times_100_at_most_max_over_100'])

    def test_scale_lemma_rejects_the_previous_value(self):
        lemma = tool.scale_lemma(tool.CAP - 1)
        self.assertFalse(lemma['cap_is_floor_max_over_10000'])
        self.assertFalse(lemma['next_times_10000_overflows'])

    def test_divisibility_lemma(self):
        self.assertTrue(tool.divisibility_lemma()['proved'])

    def test_divisibility_lemma_rejects_a_wrong_inverse(self):
        self.assertFalse(tool.divisibility_lemma(inverse=tool.INVERSE_625 + 2)['proved'])

    def test_divisibility_lemma_rejects_a_wrong_bound(self):
        self.assertFalse(tool.divisibility_lemma(bound=tool.ROUND_BOUND + 1)['proved'])

    def test_divisibility_lemma_rejects_a_wrong_rotate(self):
        self.assertFalse(tool.divisibility_lemma(rotate=3)['proved'])

    def test_divisibility_matches_a_direct_remainder(self):
        def image_of(x):
            y = (x * tool.INVERSE_625) & tool.U64
            return ((y >> 4) | (y << 60)) & tool.U64
        step = 0x10001
        for x in list(range(0, 200000, 7)) + [tool.U64 - k * step for k in range(5000)] + [tool.U64 - tool.U64 % 10000]:
            self.assertEqual(image_of(x) <= tool.CAP, x % 10000 == 0, x)

    def test_gate_conditions(self):
        self.assertIs(tool.gate_within(tool.CAP, 6), True)
        self.assertIs(tool.gate_within(tool.CAP, 7), False)
        self.assertIs(tool.gate_within(tool.ROUND_BOUND, 2), True)
        self.assertIs(tool.gate_within(tool.ROUND_BOUND, 3), False)

    def test_gate_condition_rejects_the_wrong_pair(self):
        for pair in ((tool.CAP, 2), (tool.CAP, 3), (tool.ROUND_BOUND, 6), (tool.ROUND_BOUND, 7), (tool.CAP, 4)):
            with self.assertRaises(tool.EvidenceError):
                tool.gate_within(*pair)

    def test_every_control_was_caught(self):
        self.assertTrue(all(row['caught'] for row in self.controls))
        self.assertEqual(self.evidence['controls_survived'], 0)
        self.assertEqual(self.evidence['controls'],
                         {'cmov-source': 3, 'constant-low-byte': 15, 'factor': 10, 'flip-gate': 15, 'rotate-count': 8})

    def test_tag_of_the_three_invalid_order_gates(self):
        rows = [row for row in self.analysed if row['class'] == 'branch' and row['value'] == tool.ROUND_BOUND]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual([tag for _, tag in row['tags']], [0x69])
        self.assertEqual(tool.tag_text(self.image, 0x69), 'Invalid order')

    def test_tags_of_the_loop_gate(self):
        row = self.by_site[0x4d04814]
        self.assertEqual({tag for _, tag in row['tags']}, {0xea, 0xfb, 0x13f, 0x160})
        self.assertEqual(tool.tag_text(self.image, 0x13f), 'Invalid input number')

    def test_zero_gate_reads(self):
        for va in (0x271e0ee, 0x4d1ff2e, 0x4d2067e):
            self.assertEqual(self.read(va, tool.CAP)['class'], 'cmov-zero')

    def test_labels(self):
        self.assertEqual(self.by_site[0x220bf11]['labels'], ['freeze', 'periodic'])
        self.assertEqual(self.by_site[0x220bf3c]['labels'], ['periodic'])

    def test_message_rows(self):
        self.assertEqual(self.evidence['message_copies'], ['0x3eff7e', '0x71537f'])
        self.assertEqual(len(self.messages), 3)
        self.assertEqual({row['site'] for row in self.messages}, {0x274ff1f, 0x4d72ca5, 0x4d73775})

    def test_power_records(self):
        self.assertEqual(self.evidence['power_tables'],
                         [{'copy': '0x7c6208', 'first_power': 2, 'first_record': '0x7c61f0', 'last_power': 8,
                           'power': 4, 'stride': 24}])

    def test_periodic_prefixes_have_no_zero_test(self):
        self.assertEqual([row['zero_tests'] for row in self.evidence['periodic_prefixes']], [0, 0, 0])
        self.assertEqual(len(self.evidence['periodic_prefixes']), 3)

    def test_prefix_check_sees_an_inserted_zero_test(self):
        damaged = self.image.patched([(0x220bef6, bytes.fromhex('4d85f6'))])
        self.assertEqual(tool.periodic_prefix(damaged, 0x220bf11)['zero_tests'], 1)

    def test_flipped_zero_gate_fails(self):
        row = self.by_site[0x271e0ee]
        self.assert_damage_fails(row['site'], tool.CAP, [(row['gate'] + 3, bytes([0x46]))])

    def test_changed_zero_factor_fails(self):
        self.assert_damage_fails(0x271e0ee, tool.CAP, [(0x271e0ed, bytes([101]))])

    def test_changed_constant_fails(self):
        self.assert_damage_fails(0x24f8a4e, tool.ROUND_BOUND, [(0x24f8a50, bytes([0xcd]))])

    def test_changed_inverse_is_not_a_divisibility_read(self):
        damaged = self.image.patched([(0x220beff + 2, bytes([0x93]))])
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_site(damaged, 0x220bf11, tool.ROUND_BOUND)

    def test_changed_branch_factor_fails(self):
        self.assert_damage_fails(0x4d04814, tool.CAP, [(0x4d048a8, bytes([101]))])

    def test_other_constant_at_a_site_fails(self):
        with self.assertRaises(tool.EvidenceError):
            self.read(0x271e0ee, tool.ROUND_BOUND)

    def test_address_outside_every_fde_fails(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde_of(0x10)

    def test_nobits_section_has_no_file_bytes(self):
        bss = next(s for s in tool.elf_index.sections(self.image.data) if s['name'] == '.bss')
        with self.assertRaises(tool.EvidenceError):
            self.image.file_offset(bss['address'] + 8)

    def test_wrong_binary_hash_fails(self):
        blob = bytearray(self.image.data)
        blob[-1] ^= 1
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'copy'
            path.write_bytes(blob)
            with self.assertRaises(tool.EvidenceError):
                tool.load_target(path)

    def test_rows_of_the_excluded_table(self):
        names = {row['function'] for row in self.excluded}
        self.assertEqual(names, set(tool.EXCLUDED_FUNCTIONS) | set(tool.NOT_READ_FUNCTIONS))
        self.assertFalse(names & {row['function'] for row in self.analysed})

    def test_outputs_match_the_stored_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            tool.write_outputs(name, self.evidence, self.analysed, self.excluded, self.controls, self.messages)
            for path in sorted(Path(name).iterdir()):
                self.assertEqual(path.read_bytes(), (FOLDER / path.name).read_bytes(), path.name)

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        self.assertEqual(len(lines), len([p for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256']))
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_is_valid_json(self):
        data = json.loads((FOLDER / 'evidence.json').read_text())
        self.assertEqual(data['target_sha256'], tool.SHA256)
        self.assertEqual(struct.pack('<Q', int(data['cap'], 16))[:2], bytes.fromhex('cb10'))


if __name__ == '__main__':
    unittest.main()
