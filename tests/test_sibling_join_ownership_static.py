import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

from artifacts import ROOT
from sibling_join_ownership_static import (
    FATES, OWNERS, PINS, analyze, check_pins, detach_census,
    exports, fates, frame_lines, join_census, lea_census, owners,
    prev_packet_check, pthread_census, slots, spawn_call_census,
    tables, take_idiom_census)

TARGET = ROOT / 'artifacts/node/115/hl-node'
MATERIALISED = (
    TARGET.exists() and TARGET.stat().st_size == 105896032)


@unittest.skipUnless(
    MATERIALISED, 'node artifact is an LFS pointer')
class SiblingJoinOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.records = analyze(cls.data)

    def test_records_file_matches_regeneration(self):
        packet = (ROOT / 'research/work-items'
                        / 'RE-005-node115-sibling-join-ownership'
                        / 'records.json')
        stored = json.loads(packet.read_text())
        self.assertEqual(self.records, stored)

    def test_exported_disassembly_matches_regeneration(self):
        packet = (ROOT / 'research/work-items'
                        / 'RE-005-node115-sibling-join-ownership')
        for role in ('spawn_v4', 'join_a', 'join_x5',
                     'handle_drop_a', 'handle_drop_x5',
                     'caller_v2', 'caller_x5', 'join_consumer_a',
                     'other_join', 'insert_x5'):
            stored = (packet / f'{role}.objdump.txt').read_text()
            self.assertEqual(stored, exports(self.data, role))

    def test_frames_file_matches_regeneration(self):
        packet = (ROOT / 'research/work-items'
                        / 'RE-005-node115-sibling-join-ownership'
                        / 'frames.txt')
        self.assertEqual(packet.read_text(),
                         ''.join(frame_lines(self.data)))

    def test_owner_extents_and_hashes(self):
        records = owners(self.data)
        self.assertEqual(len(records), 32)
        self.assertEqual(records, self.records['owners'])

    def test_prev_packet_hashes_agree(self):
        records = prev_packet_check(self.data)
        self.assertTrue(all(r['matches_3050']
                            for r in records.values()))

    def test_tables_methods_and_families(self):
        records = tables(self.data)
        self.assertEqual(len(records), 11)
        families = [r['family'] for r in records]
        self.assertEqual(families.count('L'), 4)
        self.assertEqual(families.count('X2'), 3)

    def test_slots(self):
        records = slots(self.data)
        self.assertEqual(records['pthread_detach']['symbol'],
                         'pthread_detach')
        self.assertEqual(records['pthread_detach']['slot'],
                         '0x64dfe50')
        join = records['pthread_join_slots']
        self.assertEqual(set(join), {'0x64e1590', '0x64ee1f0'})
        self.assertEqual(records['cell_drop_a']['target'],
                         '0x5bc2a80')
        self.assertEqual(records['cell_drop_x4']['target'],
                         '0x5cd86e0')
        self.assertEqual(records['cell_drop_x5']['target'],
                         '0x5ce8390')

    def test_caller_byte_pins(self):
        records = check_pins(self.data)
        self.assertEqual(records, self.records['pins'])
        self.assertIn('caller_v2', records)

    def test_lea_census_one_spawn_per_entry(self):
        records = lea_census(self.data)
        self.assertEqual(len(records), 11)
        for sites in records.values():
            self.assertEqual(len(sites), 1)

    def test_spawn_call_census_one_caller_per_spawn(self):
        records = spawn_call_census(self.data)
        self.assertEqual(len(records), 11)
        for sites in records.values():
            self.assertEqual(len(sites), 1)

    def test_take_idiom_census_exactly_two_joins(self):
        records = take_idiom_census(self.data)
        self.assertEqual(records['bodies'],
                         ['0x15b8810', '0x5cf7550'])

    def test_pthread_join_census_three_bodies(self):
        records = pthread_census(self.data)
        self.assertEqual(records['pthread_join_bodies'],
                         ['0x15b8810', '0x56467d0', '0x5cf7550'])
        self.assertEqual(records['pthread_detach_count'], 40)
        self.assertEqual(records['pthread_join_unused_slot_sites'],
                         [])

    def test_detach_census_v2_keeps_handle(self):
        records = detach_census(self.data)
        self.assertEqual(records['caller_v2'], [])
        self.assertEqual(len(records['caller_v4']), 1)
        self.assertEqual(len(records['caller_x5']), 1)

    def test_join_census_chains(self):
        records = join_census(self.data)
        self.assertEqual(len(records['join_a']), 1)
        self.assertEqual(len(records['join_x5']), 3)
        self.assertEqual(len(records['join_consumer_a']), 1)
        self.assertEqual(len(records['join_consumer_top']), 2)
        self.assertEqual(records['relative_slots_to']['join_a'],
                         [])
        self.assertEqual(records['relative_slots_to']
                         ['other_join'], ['0x64e7388'])
        self.assertEqual(records['relative_slots_to']
                         ['caller_v2'], ['0x64e1750'])

    def test_fates_table(self):
        records = fates(self.data)
        self.assertEqual(len(records), 11)
        dropped = [r for r in records.values()
                   if r['fate'] == 'dropped_detached_in_place']
        self.assertEqual(len(dropped), 9)
        self.assertEqual(records['dispatcher_v2']['fate'],
                         FATES['dispatcher_v2'])
        self.assertEqual(records['dispatcher_x5']['fate'],
                         'stored_in_owner_map')

    def test_boundary_statements_present(self):
        self.assertFalse(self.records['captured_code_executed'])
        self.assertTrue(any('3074' in b
                            for b in self.records['boundaries']))

    def test_owner_mutation_is_rejected(self):
        start, end, digest = OWNERS['join_x5']
        raw = bytearray(self.data)
        offset = None
        from elf_index import sections
        for section in sections(bytes(raw)):
            if section['type'] == 8:
                continue
            if (section['address'] <= start
                    < section['address'] + section['size']):
                offset = (section['offset'] + start
                          - section['address'])
                break
        self.assertIsNotNone(offset)
        raw[offset] ^= 0xFF
        self.assertNotEqual(
            hashlib.sha256(bytes(raw[offset:offset + end - start])
                           ).hexdigest(), digest)
        with self.assertRaises(ValueError):
            owners(bytes(raw))


if __name__ == '__main__':
    unittest.main()
