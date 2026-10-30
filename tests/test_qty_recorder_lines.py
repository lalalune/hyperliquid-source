#!/usr/bin/env python3
import csv
import filecmp
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import qty_recorder_lines as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-004-qty-recorder-lines-94'
EVIDENCE = ('evidence.json', 'line-table.tsv', 'sites.tsv', 'cooccurrence.tsv', 'record-neighbours.tsv',
            'excluded-functions.tsv', 'unresolved.tsv', 'mutation-controls.tsv')
TARGET = ROOT / tool.BINARY
SHARED = {}

# A hoisted site: the lea sits before the loop and is rebuilt after the recorder call.
HOIST_LEA, HOIST_AGAIN, HOIST_CALL, HOIST_GUARD = 0x4d8dc82, 0x4d8dcd0, 0x4d8dcc3, 0x4d8dcbf
HOIST_LOAD, HOIST_CONSTANT_ROW = 0x4d8dc89, 0x4d8dc90
# A plain site of line 831: lea and recorder call in the cold block of one add.
PLAIN_CALL = 0x26d868e
# A signed add of line 830 that stores the result in rbp after a shadow copy in rbx.
SHADOW_CALL, SHADOW_ADD = 0x370410b, 0x370411e


def image():
    if 'image' not in SHARED:
        SHARED['image'] = tool.Image(tool.load_target(TARGET))
    return SHARED['image']


def packet():
    if 'packet' not in SHARED:
        SHARED['packet'] = tool.analyse(image())
    return SHARED['packet']


def references():
    target = image()
    if 'references' not in SHARED:
        records = tool.location_records(target)
        chosen = {va for va, row in records.items() if (row[0], row[1]) in tool.LINES}
        SHARED['references'] = {lea: rec for lea, rec in tool.lea_references(target, records).items() if rec in chosen}
    return SHARED['references']


def site(call):
    """Everything check_guard needs for the recorder call at this address."""
    target = image()
    fn = target.fde_of(call)
    table = references()
    leas = sorted(lea for lea in table if fn[0] <= lea < fn[1])
    rows = tool.sweep(target, *fn)
    calls = tool.bind_function(target, rows, leas, table)[0]
    return target, fn, leas, table, next(iter(calls[call]))


def facts_of(call):
    return [item for item in packet()[1] if item['call'] == call]


def outcome(call, edits, branch=None):
    target, fn, leas, table, record = site(call)
    return tool.fails(target, fn, leas, table, call, record, branch, edits, facts_of(call))


def rows_of(name):
    with open(FOLDER / name, newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


def set_up(cls):
    cls.temp = tempfile.TemporaryDirectory()
    tool.write_outputs(cls.temp.name, *packet())
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
        listed = {}
        for line in filter(None, (FOLDER / 'MANIFEST.sha256').read_text().split('\n')):
            digest, name = line.split('  ', 1)
            listed[name] = digest
        present = {p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_census(self):
        self.assertEqual(self.summary['lea_sites'], 687)
        self.assertEqual(self.summary['functions_holding_sites'], 264)
        self.assertEqual(self.summary['excluded_functions'] + self.summary['read_functions'], 264)
        self.assertEqual(self.summary['excluded_leas'] + self.summary['read_leas'], 687)
        self.assertEqual({row['column'] for row in self.summary['location_records'].values()}, {1})
        self.assertEqual(len(self.summary['location_records']), 72)

    def test_every_line_has_one_signedness(self):
        table = self.summary['line_table']
        signed = {'impl_ntl.rs:16', 'impl_ntl.rs:62', 'mod.rs:830'}
        for name, row in table.items():
            for operation in row['operations']:
                self.assertEqual(operation.endswith('-signed'), name in signed, name)

    def test_mod_lines_are_add_only(self):
        table = self.summary['line_table']
        for name in ('mod.rs:827', 'mod.rs:829', 'mod.rs:830', 'mod.rs:831'):
            self.assertEqual({op.split('-')[0] for op in table[name]['operations']}, {'add'}, name)
            self.assertGreater(table[name]['guards'], 15, name)

    def test_lines_without_a_read_guard_are_named(self):
        table = self.summary['line_table']
        self.assertEqual([name for name, row in table.items() if not row['leas_read']], ['impl_ntl.rs:6', 'mod.rs:828'])

    def test_saturated_value_matches_the_operation(self):
        for row in rows_of('sites.tsv'):
            forms = set(row['compiled_form'].split(';'))
            if row['operation'].endswith('-unsigned'):
                self.assertEqual(forms, {'constant'}, row['guard'])
            else:
                self.assertFalse(forms & {'constant'}, row['guard'])

    def test_sites_keep_out_of_excluded_functions(self):
        named = {int(row['function'], 16) for row in rows_of('excluded-functions.tsv')}
        self.assertEqual(named, set(tool.EXCLUDED_FUNCTIONS))
        for name in ('sites.tsv', 'unresolved.tsv'):
            self.assertFalse({int(row['function'], 16) for row in rows_of(name)} & named, name)

    def test_unresolved_rows_are_counted_per_line(self):
        rows = rows_of('unresolved.tsv')
        self.assertEqual(len(rows), self.summary['unresolved_guards'])
        self.assertEqual(sum(row['unresolved'] for row in self.summary['line_table'].values()), len(rows))

    def test_survivors_never_write_a_result_location(self):
        places = {}
        for row in rows_of('sites.tsv'):
            places.setdefault(row['call'], set()).update(row['locations'].split(';'))
        survivors = [row for row in rows_of('mutation-controls.tsv') if row['outcome'] == 'same']
        self.assertTrue(survivors)
        for row in survivors:
            self.assertNotIn(row['writes'], places[row['call']])

    def test_recorder_and_guard_flips_never_survive(self):
        controls = self.summary['controls']
        for name in ('drop-recorder', 'flip-guard', 'condition', 'shift-count'):
            self.assertEqual(controls[name]['same'], 0, name)

    def test_cooccurrence_partners(self):
        rows = {row['line']: row for row in rows_of('cooccurrence.tsv')}
        self.assertEqual(rows['mod.rs:827']['impl_sz.rs:9'], '10')
        self.assertEqual(rows['mod.rs:828']['impl_sz.rs:35'], '5')
        self.assertEqual(rows['mod.rs:831']['impl_wei.rs:6'], '25')
        self.assertEqual(rows['mod.rs:830']['impl_ntl.rs:62'], '22')
        for name, row in rows.items():
            for other in rows:
                self.assertEqual(row[other], rows[other][name], (name, other))

    def test_no_absolute_path_or_binary_location_string(self):
        for name in EVIDENCE:
            text = (FOLDER / name).read_text()
            for word in ('home', 'tmp', 'srv', 'mnt', 'ubuntu'):
                self.assertNotIn(chr(47) + word, text, name)
            self.assertNotIn(chr(64), text, name)


class Binding(unittest.TestCase):
    def rows(self, va):
        target = image()
        rows = tool.sweep(target, *target.fde_of(va))
        return target, rows, {insn.va: k for k, insn in enumerate(rows)}

    def test_hoisted_lea_reaches_its_call(self):
        target, rows, index = self.rows(HOIST_LEA)
        self.assertEqual(tool.bind_lea(target, rows, index, HOIST_LEA, references()[HOIST_LEA]), {HOIST_CALL})

    def test_rebuilt_lea_reaches_the_same_call(self):
        target, rows, index = self.rows(HOIST_LEA)
        self.assertEqual(tool.bind_lea(target, rows, index, HOIST_AGAIN, references()[HOIST_AGAIN]), {HOIST_CALL})

    def test_other_record_binds_nothing(self):
        target, rows, index = self.rows(HOIST_LEA)
        self.assertEqual(tool.bind_lea(target, rows, index, HOIST_LEA, references()[HOIST_LEA] + 0x18), set())

    def test_reaching_constant_holds_at_the_guard(self):
        target, rows, index = self.rows(HOIST_LEA)
        held = tool.reaching_constants(target, rows, index)
        self.assertEqual(held[HOIST_GUARD].get(13), tool.U64)

    def test_function_with_indirect_jump_gets_no_constants(self):
        target, rows, index = self.rows(HOIST_LEA)
        off = target.file_offset(HOIST_CONSTANT_ROW)
        keep = rows[index[HOIST_CONSTANT_ROW]]
        forged = tool.Insn(keep.va, keep.off, keep.size, 0xff, 0, keep.modrm, None, keep.body)
        saved = bytes(target.data[keep.modrm:keep.modrm + 1])
        self.assertEqual(off, keep.off)
        target.data[keep.modrm] = 0xe0
        try:
            self.assertEqual(tool.reaching_constants(target, [forged], {forged.va: 0}), {})
        finally:
            target.data[keep.modrm:keep.modrm + 1] = saved


class Controls(unittest.TestCase):
    def test_every_guard_of_the_sites_is_proved(self):
        for call in (HOIST_CALL, PLAIN_CALL, SHADOW_CALL):
            self.assertTrue(facts_of(call), hex(call))

    def test_hoisted_site_operation(self):
        item = facts_of(HOIST_CALL)[0]
        self.assertEqual((item['line'], item['operation'], item['guard']), ('mod.rs:831', 'add-unsigned', HOIST_GUARD))

    def test_dropped_recorder_stops_the_proof(self):
        target = image()
        rows = tool.sweep(target, *target.fde_of(PLAIN_CALL))
        size = next(row.size for row in rows if row.va == PLAIN_CALL)
        self.assertEqual(outcome(PLAIN_CALL, [(PLAIN_CALL, bytes.fromhex('660f1f440000')[:size])]), 'stopped')

    def test_flipped_guard_stops_the_proof(self):
        target, fn, _, _, _ = site(HOIST_CALL)
        rows = tool.sweep(target, *fn)
        insn = next(row for row in rows if row.va == HOIST_GUARD)
        edit = [(insn.va, tool.flipped_condition(target, insn))]
        self.assertEqual(outcome(HOIST_CALL, edit, HOIST_GUARD), 'stopped')

    def test_register_call_needs_a_load_of_the_recorder_slot(self):
        target = image()
        rows = tool.sweep(target, *target.fde_of(HOIST_LEA))
        insn = next(row for row in rows if row.va == HOIST_LOAD)
        raw = bytearray(target.data[insn.off:insn.off + insn.size])
        raw[-4] ^= 8
        self.assertEqual(outcome(HOIST_CALL, [(insn.va, bytes(raw))]), 'stopped')

    def test_changed_hoisted_constant_stops_the_proof(self):
        target = image()
        rows = tool.sweep(target, *target.fde_of(HOIST_CONSTANT_ROW))
        insn = next(row for row in rows if row.va == HOIST_CONSTANT_ROW)
        raw = bytearray(target.data[insn.off:insn.off + insn.size])
        raw[-1] ^= 1
        self.assertEqual(outcome(HOIST_CALL, [(insn.va, bytes(raw))]), 'stopped')

    def test_shadow_copy_does_not_hide_a_changed_result(self):
        self.assertIn('rbp', facts_of(SHADOW_CALL)[0]['locations'])
        target = image()
        rows = tool.sweep(target, *target.fde_of(SHADOW_CALL))
        insn = next(row for row in rows if row.va == SHADOW_ADD)
        raw = bytearray(target.data[insn.off:insn.off + insn.size])
        raw[insn.body - insn.off] ^= 0x28
        self.assertEqual(outcome(SHADOW_CALL, [(insn.va, bytes(raw))]), 'changed')

    def test_damage_is_undone(self):
        target = image()
        off = target.file_offset(PLAIN_CALL)
        before = bytes(target.data[off:off + 6])
        outcome(PLAIN_CALL, [(PLAIN_CALL, bytes(6))])
        self.assertEqual(bytes(target.data[off:off + 6]), before)


class Rejections(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'not the node')
            handle.flush()
            with self.assertRaises(tool.EvidenceError):
                tool.load_target(handle.name)

    def test_nobits_section_is_not_resolved(self):
        target = image()
        table = elf_index.sections(bytes(target.data))
        bss = next(s for s in table if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(tool.EvidenceError):
            target.file_offset(bss['address'] + 8)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            image().fde_of(0x10)

    def test_wrong_recorder_slot_stops_the_packet(self):
        target = image()
        saved = target.relocs[tool.RECORDER_SLOT]
        target.relocs[tool.RECORDER_SLOT] = saved + 16
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.analyse(target, False)
        finally:
            target.relocs[tool.RECORDER_SLOT] = saved

    def test_missing_line_stops_the_packet(self):
        saved = tool.LINES
        tool.LINES = saved + (('mod.rs', 9999),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.analyse(image(), False)
        finally:
            tool.LINES = saved

    def test_sweep_must_end_on_the_fde_end(self):
        target = image()
        start, end = target.fde_of(PLAIN_CALL)
        with self.assertRaises(tool.EvidenceError):
            tool.sweep(target, start, PLAIN_CALL + 1)

    def test_lemma_and_form_reader(self):
        self.assertTrue(tool.saturation_lemma(6)['proved'])
        wrapped = tool.atom('r', 1)
        good = tool.xor(tool.pure('sar', wrapped, 63), tool.konst(tool.I64_MIN))
        wrong = tool.xor(tool.pure('sar', wrapped, 62), tool.konst(tool.I64_MIN))
        self.assertEqual(tool.saturated_signed(good), wrapped)
        self.assertIsNone(tool.saturated_signed(wrong))
        self.assertEqual(tool.compiled_form(tool.konst(tool.I64_MAX)), 'one-sided-max')

    def test_tool_runs_no_external_program(self):
        text = (ROOT / 'tools' / 'qty_recorder_lines.py').read_text()
        for word in ('subprocess', 'os.system', 'objdump', 'readelf'):
            self.assertEqual(text.count(word), 1 if word == 'objdump' else 0, word)


if __name__ == '__main__':
    unittest.main()
