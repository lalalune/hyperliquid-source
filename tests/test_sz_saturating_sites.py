#!/usr/bin/env python3
import csv
import filecmp
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import sz_saturating_sites as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-004-sz-saturating-sites-94'
EVIDENCE = ('evidence.json', 'sz-sites.tsv', 'mutation-controls.tsv', 'excluded-functions.tsv')
TARGET = ROOT / tool.BINARY
IMAGE = {}


def image():
    if 'image' not in IMAGE:
        IMAGE['image'] = tool.Image(tool.load_target(TARGET))
    return IMAGE['image']


def site(va):
    target = image()
    records = tool.location_records(target)
    fn = target.fde_of(va)
    rows = tool.sweep(target, *fn)
    index = {insn.va: insn for insn in rows}
    record = va + 7 + struct.unpack_from('<i', target.data, target.file_offset(va + 3))[0]
    kind = tool.LINE_KIND[records[record][0]]
    return target, fn, rows, index, record, kind


def rows_of(name):
    with open(FOLDER / name, newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


def set_up(cls):
    cls.temp = tempfile.TemporaryDirectory()
    tool.write_outputs(cls.temp.name, *tool.analyse(image()))
    cls.summary = json.loads((FOLDER / 'evidence.json').read_text())


def tear_down(cls):
    cls.temp.cleanup()


class Evidence(unittest.TestCase):
    setUpClass = classmethod(set_up)
    tearDownClass = classmethod(tear_down)

    def test_tool_reproduces_every_file(self):
        for name in EVIDENCE:
            self.assertTrue(filecmp.cmp(FOLDER / name, os.path.join(self.temp.name, name), shallow=False), name)

    def test_manifest(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().split('\n')
        listed = {}
        for line in filter(None, lines):
            digest, name = line.split('  ', 1)
            listed[name] = digest
        present = {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_census(self):
        s = self.summary
        self.assertEqual(s['target_sha256'], tool.SHA256)
        self.assertEqual(len(s['location_records']), 11)
        self.assertEqual(s['lea_sites'], 74)
        self.assertEqual(s['lea_sites_by_line'], {'9': 49, '35': 25})
        self.assertEqual(s['location_data_references'], 0)
        self.assertEqual(s['functions_holding_sites'], 40)
        self.assertEqual(s['excluded_functions'], 16)
        self.assertEqual(s['excluded_sites'] + s['analysed_sites'], s['lea_sites'])
        self.assertEqual(s['analysed_sites'], 35)
        self.assertEqual(s['guards'], 41)

    def test_every_site_has_a_guard_row_and_a_location(self):
        rows = rows_of('sz-sites.tsv')
        self.assertEqual(len(rows), self.summary['guards'])
        self.assertEqual(len({row['lea'] for row in rows}), self.summary['analysed_sites'])
        for row in rows:
            self.assertTrue(row['joins'], row)
            self.assertTrue(row['locations'], row)

    def test_signed_results_saturate_and_unsigned_are_constants(self):
        for row in rows_of('sz-sites.tsv'):
            signed = row['operation'].endswith('signed') and not row['operation'].endswith('unsigned')
            self.assertEqual(row['line'], '35' if signed else '9', row)
            forms = set(row['compiled_form'].split(';'))
            self.assertTrue(forms <= ({'sar-xor', 'setns-add'} if signed else {'constant'}), row)

    def test_recorder_and_guard_controls_are_all_caught(self):
        rows = rows_of('mutation-controls.tsv')
        for name in ('drop-recorder', 'flip-guard'):
            chosen = [row for row in rows if row['control'] == name]
            self.assertTrue(chosen)
            self.assertTrue(all(row['caught'] == 'true' for row in chosen), name)

    def test_survivors_write_no_result_location(self):
        places = {}
        for row in rows_of('sz-sites.tsv'):
            places.setdefault(row['lea'], set()).update(row['locations'].split(';'))
        survivors = [row for row in rows_of('mutation-controls.tsv') if row['caught'] == 'false']
        self.assertEqual(len(survivors), 9)
        for row in survivors:
            self.assertTrue(row['writes'], row)
            self.assertNotIn(row['writes'], places[row['lea']], row)


class Controls(unittest.TestCase):
    def analyse(self, target, fn, lea, record, kind):
        return tool.analyse_site(target, tool.sweep(target, *fn), lea, record, kind)

    def test_real_sites_pass_before_damage(self):
        for lea in (0x232c8cc, 0x23971ae, 0x370e51e):
            target, fn, rows, _, record, kind = site(lea)
            self.assertTrue(tool.analyse_site(target, rows, lea, record, kind))

    def test_digest_is_checked(self):
        data = bytearray(TARGET.read_bytes())
        data[-1] ^= 1
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'copy'
            path.write_bytes(data)
            with self.assertRaises(tool.EvidenceError):
                tool.load_target(path)

    def test_address_controls(self):
        target = image()
        with self.assertRaises(tool.EvidenceError):
            target.fde_of(0)
        bss = next(s for s in elf_index.sections(target.data) if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(tool.EvidenceError):
            target.file_offset(bss['address'])

    def test_sweep_must_end_on_the_fde(self):
        target = image()
        start, end = target.fde_of(0x232c8cc)
        wide = next(insn for insn in tool.sweep(target, start, end) if insn.size > 1)
        with self.assertRaises(tool.EvidenceError):
            tool.sweep(target, start, wide.va + 1)

    def test_wrong_kind_fails(self):
        for lea, wrong in ((0x232c8cc, 'signed'), (0x23971ae, 'unsigned'), (0x370e51e, 'signed')):
            target, fn, rows, _, record, _ = site(lea)
            with self.assertRaises(tool.EvidenceError):
                tool.analyse_site(target, rows, lea, record, wrong)

    def test_other_location_fails(self):
        target, fn, rows, _, record, kind = site(0x232c8cc)
        with self.assertRaises(tool.EvidenceError):
            tool.analyse_site(target, rows, 0x232c8cc, record + 0x18, kind)

    def test_dropped_recorder_fails(self):
        target, fn, rows, index, record, kind = site(0x232c8cc)
        call = next(insn for insn in rows if insn.va > 0x232c8cc and insn.key == 0xff)
        self.assertTrue(tool.fails(target, fn, 0x232c8cc, record, kind, [(call.va, bytes.fromhex('660f1f440000'))]))

    def test_zero_turned_into_kept_value_fails(self):
        # xor r13d,r13d at 0x232c8c9 becomes or r13d,r13d, so the wrapped value stays.
        target, fn, rows, index, record, kind = site(0x232c8cc)
        self.assertEqual(target.data[target.file_offset(0x232c8c9):target.file_offset(0x232c8c9) + 3], bytes.fromhex('4531ed'))
        self.assertTrue(tool.fails(target, fn, 0x232c8cc, record, kind, [(0x232c8c9, bytes.fromhex('4509ed'))]))

    def test_inverted_cmov_fails(self):
        # cmovo rbp,rcx at 0x23971b5 becomes cmovno rbp,rcx.
        target, fn, rows, index, record, kind = site(0x23971ae)
        self.assertEqual(target.data[target.file_offset(0x23971b5):target.file_offset(0x23971b5) + 4], bytes.fromhex('480f40e9'))
        self.assertTrue(tool.fails(target, fn, 0x23971ae, record, kind, [(0x23971b5, bytes.fromhex('480f41e9'))]))

    def test_saturated_value_of_doubling_fails_when_changed(self):
        # The doubling site must end on u64::MAX, so its -1 immediate has to matter.
        target, fn, rows, index, record, kind = site(0x370e51e)
        loads = [insn for insn in rows if insn.key == 0xc7 and insn.va > 0x370e51e
                 and target.data[insn.off + insn.size - 4:insn.off + insn.size] == b'\xff\xff\xff\xff']
        self.assertTrue(any(tool.fails(target, fn, 0x370e51e, record, kind, [(insn.va + insn.size - 1, b'\xfe')]) for insn in loads[:2]))

    def test_saturated_form_matcher(self):
        wrapped = tool.atom('r', 3)
        sar = tool.pure('sar', wrapped, 63)
        good = tool.xor(sar, tool.konst(tool.I64_MIN))
        self.assertEqual(tool.saturated_signed(good), wrapped)
        ns = tool.add(tool.atom('ns', wrapped), tool.konst(tool.I64_MAX))
        self.assertEqual(tool.saturated_signed(ns), wrapped)
        self.assertIsNone(tool.saturated_signed(tool.xor(sar, tool.konst(tool.I64_MAX))))
        self.assertIsNone(tool.saturated_signed(tool.xor(tool.pure('sar', wrapped, 62), tool.konst(tool.I64_MIN))))
        self.assertIsNone(tool.saturated_signed(tool.add(tool.atom('ns', wrapped), tool.konst(tool.I64_MIN))))
        self.assertIsNone(tool.saturated_signed(wrapped))

    def test_saturation_lemma(self):
        self.assertTrue(tool.saturation_lemma(4)['proved'])
        self.assertEqual(tool.saturation_lemma(8)['pairs'], 65536)

    def test_carry_rewrite_is_an_identity(self):
        for left in range(256):
            for right in range(256):
                wrapped = (left - right) & 255
                self.assertEqual(left < right, wrapped + right > 255)

    def test_sign_bit_is_the_carry_of_a_doubling(self):
        for value in range(256):
            self.assertEqual(bool(value & 128), value + value > 255)

    def test_predicates(self):
        a, b = tool.atom('r', 1), tool.atom('r', 2)
        flags = ('a', 'sub', a, b)
        self.assertEqual(tool.predicate(flags, 2), (('CF', 'sub', a, b), True))
        self.assertEqual(tool.predicate(flags, 3), (('CF', 'sub', a, b), False))
        self.assertEqual(tool.predicate(flags, 7), (('CF', 'sub', b, a), True))
        self.assertEqual(tool.predicate(flags, 6), (('CF', 'sub', b, a), False))
        self.assertEqual(tool.predicate(flags, 0), (('OF', 'sub', a, b), True))
        total = tool.add(a, b)
        self.assertEqual(tool.predicate(('a', 'sub', total, b), 2)[0], tool.carry_key('add', a, b))
        with self.assertRaises(tool.Unsupported):
            tool.predicate(None, 2)

    def test_linear_arithmetic(self):
        a = tool.atom('r', 1)
        self.assertEqual(tool.sub(a, a), tool.konst(0))
        self.assertEqual(tool.add(a, a), tool.scaled(a, 2))
        self.assertEqual(tool.add(tool.konst(tool.U64), tool.konst(1)), tool.konst(0))

    def test_tool_runs_no_external_program(self):
        source = (ROOT / 'tools' / 'sz_saturating_sites.py').read_text()
        self.assertNotIn('import subprocess', source)
        self.assertNotIn('os.system', source)


if __name__ == '__main__':
    unittest.main()
