import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from dispatcher_table_static import (BODIES, PACKET, SHA, SIZE,
                                     TARGET, analyze, generate,
                                     location_records, relocations,
                                     run_pins, slot_records,
                                     string_records, table_records,
                                     body_map)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class DispatcherTableStaticTest(unittest.TestCase):
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

    def test_twentyone_bodies(self):
        self.assertEqual(len(self.payload['bodies']), 21)
        roles = {b['role'] for b in self.payload['bodies']}
        self.assertEqual(roles, set(BODIES))

    def test_table_entries(self):
        entries = self.payload['table']['entries']
        self.assertEqual([e['size'] for e in entries],
                         [0x30, 0x38, 0x28, 0x58])
        self.assertEqual([e['align'] for e in entries], [8, 8, 8, 8])
        e4 = entries[3]
        self.assertEqual(e4['method_cell'], '0x6400548')
        self.assertEqual(e4['method'], '0x15b8fd0')
        self.assertEqual(e4['drop_in_place'], '0x15bb300')
        self.assertTrue(self.payload['table']['relro']['covers_table'])

    def test_no_runtime_registration(self):
        census = self.payload['census']
        self.assertEqual(
            census['direct_rel32_branches_to_dispatcher'], [])
        self.assertEqual(census['stores_into_table'], [])
        refs = census['rip_refs_in_window']
        self.assertEqual(len(refs), 9)
        self.assertTrue(all(r['kind'] == 'lea' for r in refs))
        self.assertNotIn('0x6400548', {r['target'] for r in refs})
        self.assertEqual(self.payload['init_array']['entries'], 168)
        self.assertEqual(
            self.payload['init_array']
            ['targets_that_are_pinned_bodies'], [])

    def test_dispatcher_drains_one_cell(self):
        census = self.payload['census']
        self.assertEqual(census['drain_block_branch_sources'],
                         ['0x15b91b7'])
        sites = census['slot_call_sites']
        self.assertEqual(sites['0x64e1190'], ['0x15b907d'])
        self.assertEqual(sites['0x64e1318'], ['0x15b9054'])
        self.assertEqual(len(sites['0x64e1188']), 6)
        self.assertIn('0x155f9f7', sites['0x64e1188'])

    def test_caller_chain_slots(self):
        sites = self.payload['census']['slot_call_sites']
        create = sites['0x64e1580']
        self.assertEqual(len(create), 14)
        for sibling in ('0x15b7068', '0x15b7710', '0x15b7d91',
                        '0x15b8476'):
            self.assertIn(sibling, create)
        join = sites['0x64e1590']
        self.assertEqual(len(join), 3)
        self.assertIn('0x15b8824', join)
        slots = {s['slot']: s for s in self.payload['slots']}
        self.assertEqual(slots['0x64e1580']['target'], '0x5c87b50')
        self.assertEqual(slots['0x64ec838']['symbol'], 'pthread_create')
        self.assertEqual(slots['0x64e1590']['symbol'], 'pthread_join')

    def test_join_locations(self):
        locs = {(l['line'], l['col'])
                for l in self.payload['locations']}
        self.assertEqual(locs, {(247, 14), (251, 14)})
        for loc in self.payload['locations']:
            self.assertTrue(
                loc['file'].endswith('/std/src/thread/lifecycle.rs'))

    def test_answers(self):
        answers = self.payload['answers']
        self.assertIn('0x6400548', answers['registrar'])
        self.assertIn('one shared packet cell', answers['walked'])
        self.assertIn('0x5ca44a0', answers['caller'])

    def test_mutation_dispatcher_adapter_call(self):
        data = self.mutated(0x15b9054, 0, 0x90)
        with self.assertRaises(ValueError):
            run_pins(data, 'dispatcher')

    def test_mutation_spawn_vtable_lea(self):
        data = self.mutated(0x15b8436, 3, 0x00)
        with self.assertRaises(ValueError):
            run_pins(data, 'spawn_e4')

    def test_mutation_thread_start_method_call(self):
        data = self.mutated(0x5ca45d7, 3, 0x10)
        with self.assertRaises(ValueError):
            run_pins(data, 'thread_start')

    def test_mutation_table_method_cell(self):
        data = bytearray(self.data)
        from dispatcher_table_static import raw_section_headers
        headers = raw_section_headers(self.data)
        hit = None
        for s in headers:
            if s['type'] != 4 or not s['entsize']:
                continue
            for off in range(s['offset'], s['offset'] + s['size'],
                             s['entsize']):
                r_offset, _, _ = struct.unpack_from('<QQq', self.data,
                                                    off)
                if r_offset == 0x6400548:
                    hit = off
                    break
            if hit is not None:
                break
        self.assertIsNotNone(hit)
        data[hit + 16] ^= 0x01  # addend low byte
        mutated = bytes(data)
        with self.assertRaises(ValueError):
            table_records(mutated, relocations(mutated),
                          body_map(mutated))

    def test_mutation_join_panic_message(self):
        data = self.mutated(0x469273, 0, ord('X'))
        with self.assertRaises(ValueError):
            string_records(data)

    def test_mutation_location_line(self):
        # Location struct 0x6400550 line field at +0x10.
        data = self.mutated(0x6400550, 0x10, 0xf8)
        with self.assertRaises(ValueError):
            location_records(data, relocations(data))

    def test_mutation_slot_relocation(self):
        data = bytearray(self.data)
        from dispatcher_table_static import raw_section_headers
        headers = raw_section_headers(self.data)
        hit = None
        for s in headers:
            if s['type'] != 4 or not s['entsize']:
                continue
            for off in range(s['offset'], s['offset'] + s['size'],
                             s['entsize']):
                r_offset, _, _ = struct.unpack_from('<QQq', self.data,
                                                    off)
                if r_offset == 0x64e1190:
                    hit = off
                    break
            if hit is not None:
                break
        self.assertIsNotNone(hit)
        data[hit + 16] ^= 0x01
        mutated = bytes(data)
        with self.assertRaises(ValueError):
            slot_records(mutated, relocations(mutated))


if __name__ == '__main__':
    unittest.main()
