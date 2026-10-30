"""Tests for the node #94 spot wire to raw price and size converter evidence."""

import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import spot_wire_scale as tool  # noqa: E402

FOLDER = ROOT / 'research/work-items/RE-004-spot-wire-scale-94'
SHARED = {}


def setUpModule():
    data = tool.load_binary()
    SHARED['data'] = data
    SHARED['image'] = tool.Image(data)
    SHARED['files'] = tool.analyse(data)


def rows(name):
    return list(csv.DictReader(io.StringIO(SHARED['files'][name]), delimiter='\t'))


class GeneratedEvidence(unittest.TestCase):
    def test_packet_files_are_the_tool_output(self):
        for name, text in SHARED['files'].items():
            self.assertEqual((FOLDER / name).read_bytes(), text.encode('utf-8'), name)

    def test_manifest_covers_the_folder(self):
        listed = {}
        for line in (FOLDER / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
            digest, name = line.split('  ', 1)
            listed[name] = digest
        present = {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_every_byte_case_is_counted(self):
        totals = {}
        for row in rows('scale-table.tsv'):
            totals[row['helper']] = totals.get(row['helper'], 0) + int(row['byte_cases'])
        self.assertEqual(totals, {'0x4ca6940': 65536, '0x230af90': 65536, '0x4ca6a90': 256})

    def test_price_divisors_follow_the_decimals_difference(self):
        table = {r['case']: r for r in rows('scale-table.tsv') if r['helper'] == '0x4ca6940'}
        for k in range(9):
            row = table[f'k={k}']
            self.assertEqual(int(row['divisor']), 10 ** (8 - k))
            self.assertEqual(int(row['byte_cases']), 256 - k)
            self.assertEqual((row['ok_leaves'], row['error_leaves']), ('2', '4'))
        self.assertEqual(int(table['k>8']['byte_cases']), 30628)
        self.assertEqual(int(table['underflow']['byte_cases']), 32640)
        self.assertEqual(table['underflow']['error'], 'l1/src/spot_meta.rs:984:9')

    def test_size_divisors_follow_the_size_decimals(self):
        table = {r['case']: r for r in rows('scale-table.tsv') if r['helper'] == '0x4ca6a90'}
        for b in range(9):
            self.assertEqual(int(table[f'b={b}']['divisor']), 10 ** (8 - b))
            self.assertEqual((table[f'b={b}']['ok_leaves'], table[f'b={b}']['error_leaves']), ('2', '2'))
        self.assertEqual(int(table['b>8']['byte_cases']), 247)

    def test_two_price_copies_have_one_table(self):
        columns = ('case', 'byte_cases', 'rule', 'divisor', 'error', 'ok_leaves', 'error_leaves')
        table = rows('scale-table.tsv')
        first = [[r[c] for c in columns] for r in table if r['helper'] == '0x4ca6940']
        second = [[r[c] for c in columns] for r in table if r['helper'] == '0x230af90']
        self.assertEqual(first, second)

    def test_every_instruction_was_walked(self):
        evidence = json.loads(SHARED['files']['evidence.json'])
        for name, helper in evidence['helpers'].items():
            self.assertEqual(helper['instructions_not_reached'], [], name)
            self.assertEqual(helper['instructions'], helper['instructions_reached'])

    def test_tag_text_comes_from_the_display_table(self):
        evidence = json.loads(SHARED['files']['evidence.json'])
        self.assertEqual(evidence['tag_text'], {'0x65': 'Order has invalid price.', '0x66': 'Order has invalid size.'})

    def test_every_control_was_detected(self):
        table = rows('mutation-controls.tsv')
        self.assertEqual(len(table), len(tool.CONTROLS))
        self.assertEqual({r['outcome'] for r in table}, {'detected'})

    def test_census_classes(self):
        table = rows('census.tsv')
        status = {r['fde_start']: r['status'] for r in table}
        self.assertEqual(status['0x4ca6940'], 'analysed')
        self.assertTrue(status['0x230b0e0'].startswith('left out'))
        self.assertEqual(status['0x4ff4080'], 'bytes are not an instruction start')

    def test_no_absolute_paths_in_evidence(self):
        for name, text in SHARED['files'].items():
            for word in ('home', 'tmp', 'srv', 'mnt'):
                self.assertNotIn(chr(47) + word, text, name)
            self.assertNotIn(chr(64), text, name)


class NegativeControls(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        spoiled = bytearray(SHARED['data'])
        spoiled[-1] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.Image(bytes(spoiled))

    def test_addresses_without_file_bytes_are_refused(self):
        image = SHARED['image']
        with self.assertRaises(tool.EvidenceError):
            image.file_offset(0x10)
        with self.assertRaises(tool.EvidenceError):
            image.file_offset(1 << 40)
        bss = next(s for s in tool.elf_index.sections(SHARED['data']) if s['name'] == '.bss')
        with self.assertRaises(tool.EvidenceError):
            image.file_offset(bss['address'])

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            SHARED['image'].fde_of(0x10)

    def test_a_patched_size_helper_fails_and_a_restored_one_passes(self):
        image = SHARED['image']
        start = tool.SIZE_ONLY
        va = start + image.read(start, 252).index(b'\x83\xe8\x08') + 2
        old = image.patch(va, b'\x07')
        try:
            proof, error = tool.prove_size(image, start)
        finally:
            image.patch(va, old)
        self.assertIsNone(proof)
        self.assertIn('fact outside the closed form', error)
        proof, error = tool.prove_size(image, start)
        self.assertIsNone(error)
        self.assertEqual(proof['cases'], 256)

    def test_unmodelled_instruction_stops_the_walk(self):
        image = SHARED['image']
        start = tool.SIZE_ONLY
        old = image.patch(start, b'\xf4')
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.run(image, start, tool.World(8, 2), 100, {})
        finally:
            image.patch(start, old)

    def test_read_outside_the_table_stops_the_walk(self):
        world = tool.World(8, 2)
        del world.memory[(tool.TOKENS + tool.QUOTE * tool.TOKEN_STRIDE + 0x49, 1)]
        with self.assertRaises(tool.EvidenceError):
            tool.run(SHARED['image'], tool.PRICE_FIRST, world, 100, {})

    def test_closed_form_refuses_wrong_leaves(self):
        s = 100
        decided = {('small', s): True, ('gt', s): False, ('exact', s): True}
        self.assertIsNone(tool.check_leaf(decided, ('ok', ('quot', s)), s, 0x65, True))
        self.assertIsNotNone(tool.check_leaf(decided, ('err', 0x65), s, 0x65, True))
        self.assertIsNotNone(tool.check_leaf({**decided, ('exact', s): False}, ('ok', ('quot', s)), s, 0x65, True))
        self.assertIsNotNone(tool.check_leaf({**decided, ('gt', s): True}, ('ok', ('quot', s)), s, 0x65, True))
        self.assertIsNotNone(tool.check_leaf({('small', s): True, ('exact', s): True}, ('ok', ('quot', s)), s, 0x65, True))
        self.assertIsNotNone(tool.check_leaf({**decided, ('ge', s): True}, ('ok', ('quot', s)), s, 0x65, True))

    def test_concrete_runs_match_the_rule_at_the_edges(self):
        image = SHARED['image']
        world = tool.World(8, 2)
        for x, wanted in ((0, ('err', 0x65)), (99, ('err', 0x65)), (100, ('ok', 1)), (101, ('err', 0x65)),
                          (2 ** 64 - 1, ('err', 0x65)), (2 ** 64 - 16, ('ok', 184467440737095516))):
            self.assertEqual(tool.run(image, tool.PRICE_FIRST, world, x, {})[0], wanted, x)
        world = tool.World(0, 2)
        for x, wanted in ((0, ('ok', 0)), (999999, ('err', 0x66)), (1000000, ('ok', 1))):
            self.assertEqual(tool.run(image, tool.SIZE_ONLY, world, x, {})[0], wanted, x)

    def test_vectors_stay_in_range(self):
        for k in range(9):
            points = tool.vectors_for(10 ** k)
            self.assertIn(tool.U64, points)
            self.assertTrue(all(0 <= p <= tool.U64 for p in points))

    def test_tool_uses_no_external_program(self):
        source = (ROOT / 'tools/spot_wire_scale.py').read_text(encoding='utf-8')
        for word in ('subprocess', 'os.system', 'popen', 'objdump -', 'readelf -'):
            self.assertNotIn(word, source)


if __name__ == '__main__':
    unittest.main()
