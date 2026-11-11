import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from neighbor_statics import (BODIES, MESSAGE_KINDS, PACKET,
                              PR3000_PANIC_MSG_THUNK_SHA256, SHA, SIZE,
                              TARGET, analyze, cell_records, generate,
                              message_census, raw_section_headers,
                              relocations, run_pins, slot_records)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class NeighborStaticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)
        cls.regenerated = generate(TARGET, tempfile.mkdtemp())

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        offset = self.offset_of(va)
        data[offset + delta] = value
        return bytes(data)

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def reloc_entry_offset(self, want_off):
        headers = raw_section_headers(self.data)
        for s in headers:
            if s['type'] != 4 or not s['entsize']:
                continue
            for off in range(s['offset'], s['offset'] + s['size'],
                             s['entsize']):
                r_offset, _, _ = struct.unpack_from('<QQq', self.data,
                                                    off)
                if r_offset == want_off:
                    return off
        raise AssertionError('relocation not found')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.regenerated, self.retained)
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, regen_dir)
        names = ['frames.txt'] + [f'{role}.objdump.txt'
                                  for role in BODIES]
        for name in names:
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_five_bodies_and_pr3000_cross_check(self):
        self.assertEqual(len(self.payload['bodies']), 5)
        roles = {b['role'] for b in self.payload['bodies']}
        self.assertEqual(roles, set(BODIES))
        thunk = next(b for b in self.payload['bodies']
                     if b['role'] == 'panic_msg_thunk')
        self.assertEqual(thunk['sha256'],
                         PR3000_PANIC_MSG_THUNK_SHA256)
        self.assertTrue(self.payload['cross_checks']
                        ['window_census_matches_pr3000'])

    def test_cell_decodes(self):
        cells = {c['cell']: c for c in self.payload['cells']}
        c1 = cells['0x6400488']
        self.assertEqual(c1['kind'], 'io_error_message')
        self.assertEqual(c1['text'], 'failed to write whole buffer')
        self.assertEqual(c1['str_length'], 28)
        self.assertEqual(c1['dword_at_0x10'], 23)
        self.assertEqual(c1['dword_at_0x14'], 0)
        c2 = cells['0x64004a0']
        self.assertEqual(c2['kind'], 'panic_location')
        self.assertTrue(c2['file'].endswith(
            '/library/std/src/io/mod.rs'))
        self.assertEqual((c2['line'], c2['column']), (1881, 36))
        c3 = cells['0x64004b8']
        self.assertEqual(c3['kind'], 'panic_location')
        self.assertTrue(c3['file'].endswith(
            '/library/std/src/thread/functions.rs'))
        self.assertEqual((c3['line'], c3['column']), (131, 29))

    def test_message_kind_calibration(self):
        census = {r['message']: r['kind_dword']
                  for r in self.payload['message_census']}
        self.assertEqual(census, MESSAGE_KINDS)
        self.assertEqual(census['failed to write whole buffer'], 23)
        self.assertEqual(census['failed to fill whole buffer'], 37)
        self.assertEqual(census['failed to allocate read buffer'], 38)

    def test_no_other_reference_to_the_cells(self):
        census = self.payload['census']
        refs = census['rip_refs_to_cells']
        self.assertEqual(
            [(r['site'], r['target'], r['kind']) for r in refs],
            [('0x1533e56', '0x6400488', 'lea'),
             ('0x1533e5f', '0x64004a0', 'lea'),
             ('0x15d5c49', '0x64004b8', 'lea')])
        self.assertEqual(census['stores_into_cells'], [])
        self.assertEqual(census['movabs_immediates_to_cells'], [])
        self.assertEqual(census['direct_rel32_callers'],
                         {'write_body': [], 'spawn_supervisor': []})
        self.assertEqual(len(census['rip_refs_in_window']), 9)
        data_census = self.payload['data_census']
        self.assertEqual(data_census['relocation_addends_into_cells'],
                         [])
        self.assertEqual(data_census['raw_qwords_naming_cells'], [])
        self.assertEqual(data_census['relocations_landing_in_cells'],
                         ['0x6400488', '0x64004a0', '0x64004b8'])
        self.assertEqual(
            data_census['relocation_counts']['total'], 61001)
        self.assertTrue(self.payload['relro']
                        ['covers_cells_and_table'])

    def test_slots(self):
        slots = {s['slot']: s for s in self.payload['slots']}
        self.assertEqual(slots['0x64dffc0']['symbol'], 'write')
        self.assertEqual(slots['0x64dffc8']['symbol'],
                         '__errno_location')
        self.assertEqual(slots['0x64df508']['symbol'], 'memcpy')
        self.assertEqual(slots['0x64df570']['target'], '0x16817e0')
        self.assertEqual(slots['0x64df6a0']['target'], '0x1680c30')
        self.assertEqual(slots['0x64e0010']['target'], '0x1533d60')
        self.assertEqual(slots['0x6401300']['target'], '0x15d5b00')

    def test_error_value_vtable(self):
        vt = self.payload['error_value_vtable']
        self.assertEqual(vt['base'], '0x64005f0')
        self.assertEqual(vt['drop_in_place'], '0x15be1a0')
        self.assertEqual(vt['size'], 8)
        self.assertEqual(vt['align'], 8)
        self.assertEqual(vt['method'], '0x5ca5610')

    def test_answers(self):
        answers = self.payload['answers']
        self.assertIn('WriteZero', answers['cell_0x6400488'])
        self.assertIn('io/mod.rs:1881:36', answers['cell_0x64004a0'])
        self.assertIn('functions.rs:131:29',
                      answers['cell_0x64004b8'])
        self.assertIn('not spawn siblings', answers['family'])

    def test_mutation_write_body_lea_cell1(self):
        data = self.mutated(0x1533e56, 3, 0x00)
        with self.assertRaises(ValueError):
            run_pins(data, 'write_body')

    def test_mutation_spawn_supervisor_lea_cell3(self):
        data = self.mutated(0x15d5c49, 3, 0x00)
        with self.assertRaises(ValueError):
            run_pins(data, 'spawn_supervisor')

    def test_mutation_range_check_call(self):
        data = self.mutated(0x1681822, 0, 0x90)
        with self.assertRaises(ValueError):
            run_pins(data, 'range_check')

    def test_mutation_cell1_message(self):
        data = self.mutated(0x469219, 0, ord('X'))
        with self.assertRaises(ValueError):
            cell_records(data, relocations(data))

    def test_mutation_cell2_line(self):
        # Location 0x64004a0 line dword at +0x10.
        data = self.mutated(0x64004a0, 0x10, 0x58)
        with self.assertRaises(ValueError):
            cell_records(data, relocations(data))

    def test_mutation_cell3_column(self):
        # Location 0x64004b8 column dword at +0x14.
        data = self.mutated(0x64004b8, 0x14, 0x1e)
        with self.assertRaises(ValueError):
            cell_records(data, relocations(data))

    def test_mutation_slot_relocation(self):
        data = bytearray(self.data)
        hit = self.reloc_entry_offset(0x64df570)
        data[hit + 16] ^= 0x01  # addend low byte
        mutated = bytes(data)
        with self.assertRaises(ValueError):
            slot_records(mutated, relocations(mutated))

    def test_mutation_message_kind_dword(self):
        # One retained 'failed to fill whole buffer' static.
        data = self.mutated(0x64b0270, 0x10, 36)
        with self.assertRaises(ValueError):
            message_census(data, relocations(data))


if __name__ == '__main__':
    unittest.main()
