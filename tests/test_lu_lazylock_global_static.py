import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from lu_lazylock_global_static import (ACCESSOR, BUILDER, CELL,
                                       CFG_CTOR, ONCE, OWNERS,
                                       PACKET, SHA, SIZE, TARGET,
                                       analyze, generate,
                                       text_census)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class LuLazyLockGlobalStaticTest(unittest.TestCase):
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
        cls.regen_dir = Path(tempfile.mkdtemp())
        cls.regenerated = generate(TARGET, cls.regen_dir)

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
        names = ['frames.txt'] + [f'{role}.objdump.txt'
                                  for role in OWNERS]
        for name in names:
            self.assertEqual((self.regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_nine_owners(self):
        self.assertEqual(len(self.payload['owners']), 9)
        roles = {o['role'] for o in self.payload['owners']}
        self.assertEqual(roles, set(OWNERS))

    def test_answer(self):
        ans = self.payload['answer']
        self.assertIs(ans['caches_the_wrapper_a_runtime'], False)

    def test_statics_shape(self):
        st = self.payload['statics']
        self.assertEqual(st['deposit_relocation'],
                         {'offset': hex(CELL), 'kind': 'RELATIVE',
                          'addend': '0x1568de0'})
        self.assertEqual(st['once_state_file_value'], 3)
        self.assertEqual(st['once_state'], hex(ONCE))

    def test_locations(self):
        locs = self.payload['locations']
        self.assertTrue(
         locs['call']['file'].endswith('std/src/sync/once.rs'))
        self.assertEqual((locs['call']['line'],
                          locs['call']['column']), (219, 20))
        self.assertEqual((locs['null_fn_pointer']['line'],
                          locs['null_fn_pointer']['column']),
                         (219, 49))
        self.assertTrue(
         locs['poisoned']['file'].endswith(
          'std/src/sync/lazy_lock.rs'))
        self.assertEqual((locs['poisoned']['line'],
                          locs['poisoned']['column']), (410, 5))

    def test_census_totals(self):
        c = self.payload['census']
        rng = c['range']
        self.assertEqual(rng['validated_references'], 1713)
        self.assertEqual(rng['store_opcodes'], 0)
        self.assertEqual(rng['distinct_bodies'], 421)
        self.assertEqual(rng['by_target_opcode'], {
         '0x64f01c0/0x8d': 569, '0x64f01c8/0x8b': 2,
         '0x64f01d0/0x8b': 2, '0x64f01d8/0x8b': 572,
         '0x64f01d8/0x8d': 568})
        self.assertEqual(rng['value_load_bodies'], [hex(ACCESSOR)])
        self.assertEqual(c['ensure_sites']['bodies_with_lea_cell'],
                         421)
        self.assertEqual(
         c['ensure_sites']['bodies_missing_a_feature'], 0)
        self.assertEqual(c['sys_once_slot_call_sites'], 1553)
        acc = c['accessor_slot_call_sites']
        self.assertEqual(acc['count'], 100)
        self.assertEqual(len(acc['bodies']), 65)
        self.assertNotIn('0x15d6fd0', acc['bodies'])
        self.assertEqual(c['rel32_direct_references'],
                         {'accessor': [], 'init_fn': [],
                          'sys_once': []})
        self.assertEqual(
         c['body_feature_histogram'][
          'call_sys_slot,lea_cell,lea_loc,lea_once,lea_vtable,'
          'load_state'], 421)

    def test_wrapper_a_references(self):
        refs = self.payload['census']['wrapper_a_range_references']
        self.assertEqual(len(refs), 3)
        self.assertEqual({(r['target'], r['opcode']) for r in refs},
                         {(hex(ONCE), '0x8b'), (hex(CELL), '0x8d'),
                          (hex(ONCE), '0x8d')})

    def test_initializer_never_reaches_builder(self):
        calls = self.payload['init_fn_calls']
        targets = {r['target'] for r in calls['rel32_calls']}
        self.assertNotIn(hex(BUILDER), targets)
        self.assertNotIn(hex(CFG_CTOR), targets)
        slots = {s['slot'] for s in calls['slot_calls']}
        self.assertNotIn('0x64e1760', slots)

    def test_mutation_cell_byte_fails(self):
        with self.assertRaises(Exception):
            analyze(self.mutated(CELL, 0, 1))

    def test_mutation_state_dword_fails(self):
        with self.assertRaises(Exception):
            analyze(self.mutated(ONCE, 0, 0))

    def test_mutation_wrapper_a_pin_fails(self):
        with self.assertRaises(Exception):
            analyze(self.mutated(0x15d6fec, 0, 0x8c))

    def test_mutation_census_modrm_fails(self):
        # rep_site lea cell: clear the RIP-relative ModRM so the
        # census loses one validated reference.
        with self.assertRaises(Exception):
            text_census(self.mutated(0x150bd74, 2, 0x06))


if __name__ == '__main__':
    unittest.main()
