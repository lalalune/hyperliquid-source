import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import predicate_chain_static as pc  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))


def load():
    return TARGET.read_bytes()


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class PredicateChainPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()
        cls.records = pc.analyze(cls.data)

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'], 105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278'
            'fa39f249e98c3867b5301')
        self.assertEqual(self.records['work_item'],
                         'RE-005-node115-predicate-chain')

    def test_owners(self):
        r = self.records['owners']
        sizes = {'checker_a': 955, 'builder': 409, 'predicate': 703,
                 'normalise': 136, 'accessor': 228, 'basevalue': 201,
                 'desccall': 198, 'conversion': 309, 'setter': 599,
                 'postcall': 769, 'insert': 319, 'bucket': 214}
        for role, size in sizes.items():
            self.assertEqual(r[role]['bytes'], size, role)
        self.assertEqual(
            r['setter']['sha256'],
            '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b3355c96a'
            '8da582d905f4d8e2')
        self.assertEqual(
            r['conversion']['sha256'],
            'a6069a107a631c0f5efdb0f22e5b4a623ad077389b6b'
            '09225b8a5ca31de923dd')
        self.assertEqual(
            r['predicate']['sha256'],
            'fb3fb193f0b14f251e01da509c670d299323482419d1e'
            'def4170d948604cbbb2')

    def test_slots(self):
        s = self.records['slots']
        self.assertEqual(s['0x64e0518'], '0x5ce91b0')
        self.assertEqual(s['0x64e0848'], '0x5cf2b50')
        self.assertEqual(s['0x64e13a0'], '0x5cf2150')
        self.assertEqual(s['0x64e1248'], 'clock_gettime@GLOB_DAT')
        self.assertEqual(s['0x644dc28'], '0x4326c1')
        self.assertEqual(s['0x64c6a48'], '0x446310')

    def test_strings(self):
        st = self.records['strings']
        self.assertTrue(st['timers_disabled']['text']
                        .startswith('A Tokio 1.x context was found'))
        self.assertEqual(st['duration_overflow']['text'],
                         'overflow in Duration::new')
        self.assertEqual(st['add_duration_overflow']['text'],
                         'overflow when adding duration to instant')
        self.assertEqual(st['lu_rs']['text'], 'base/src/lu.rs')
        self.assertTrue(st['wheel_path']['text']
                        .endswith('runtime/time/wheel/mod.rs'))

    def test_statics(self):
        d = self.records['statics']['descriptor_0x644dc28']['qwords']
        self.assertEqual(d, ['0x0', '0xe', '0x50000004b',
                             '0x0', '0xe', '0x390000004a'])
        w = self.records['statics']['wheel_location_0x64c6a48']
        self.assertEqual(w['qwords'], ['0x0', '0x49', '0x1100000082'])

    def test_conversion_never_stores_through_argument(self):
        c = self.records['store_censuses']
        self.assertEqual(c['conversion_through_argument'], [])
        self.assertEqual(len(c['conversion_all_stores']), 4)
        self.assertTrue(all(e['base'] == 'rsp'
                            for e in c['conversion_all_stores']))

    def test_postcall_cannot_reach_sentinel(self):
        c = self.records['store_censuses']
        offsets = {e['disp'] for e in c['postcall_argument_stores']}
        self.assertEqual(offsets, {0, 8, 16})
        all_arg = (c['postcall_argument_stores']
                   + c['postcall_eh_rbx_stores'])
        self.assertTrue(all(e['disp'] >= 0 for e in all_arg))
        self.assertEqual(c['postcall_eh_rdi_stores'], [])
        globals_ = c['postcall_eh_global_stores']
        self.assertEqual([e['site'] for e in globals_],
                         ['0x5ce9296', '0x5ce9350', '0x5ce946b'])

    def test_setter_value_store(self):
        q = self.records['store_censuses']['setter_q_stores_pre_rebind']
        by_site = {e['site']: e for e in q}
        self.assertEqual(by_site['0x5cea8c1']['disp'], 24)
        self.assertEqual(by_site['0x5cea8c5']['disp'], 16)
        self.assertEqual(by_site['0x5cea897']['disp'], 56)
        self.assertEqual(by_site['0x5cea89c']['disp'], 24)
        self.assertEqual(by_site['0x5cea8b7']['disp'], 48)

    def test_builder_and_predicate_stores(self):
        c = self.records['store_censuses']
        b = {e['site']: e['disp'] for e in c['builder_s_stores']}
        self.assertEqual(b, {'0x5cf2261': 96, '0x5cf2265': 104,
                             '0x5cf2268': 0, '0x5cf226b': 8,
                             '0x5cf226f': 16})
        sentinel = [e['site'] for e in c['predicate_s_stores']
                    if e['disp'] == 56]
        self.assertEqual(sentinel, ['0x5cf2e1e', '0x5cf2fb1'])
        self.assertEqual(c['normalise_through_argument'], [])

    def test_decision_table(self):
        t = self.records['decision_table']
        self.assertEqual(len(t['rows']), 3)
        self.assertIn('byte [wheel+0x30] == 0',
                      t['testable_statement'])
        self.assertIn('0x5cea8c1', t['rows'][0]['setter_outcome'])
        self.assertIn('timer-error', t['rows'][2]['predicate_result'])

    def test_constants(self):
        k = self.records['constants']
        self.assertEqual(k['nsec_per_sec'], 1000000000)
        self.assertEqual(k['conversion_threshold'], 999000001)
        self.assertEqual(k['conversion_adjust_up'], 999999)
        self.assertEqual(k['millis_magic_multiplier'], 1125899907)

    def test_records_and_exports_regenerate(self):
        import json
        committed = json.loads(
            (pc.OUT / 'records.json').read_text())
        self.assertEqual(self.records, committed)
        for role in ('conversion', 'setter', 'postcall'):
            self.assertEqual(
                (pc.OUT / f'{role}.objdump.txt').read_text(),
                pc.exports(self.data, role))

    def test_wrong_artifact_rejected(self):
        with self.assertRaises(ValueError):
            pc.analyze(b'\x7fELF' + b'\x00' * 1024)
        with self.assertRaises(ValueError):
            pc.analyze(self.data[:1000])

    def test_mutated_body_rejected(self):
        mutated = bytearray(self.data)
        off = 0x5CEA8C1 - 0x1000  # setter value-store site, .text
        mutated[off] ^= 0xFF
        with self.assertRaises(ValueError):
            pc.pins_census(bytes(mutated))
        mutated2 = bytearray(self.data)
        off2 = 0x5CEAD40 - 0x1000  # conversion body start
        mutated2[off2] ^= 0xFF
        with self.assertRaises(ValueError):
            pc.owners(bytes(mutated2))


if __name__ == '__main__':
    unittest.main()
