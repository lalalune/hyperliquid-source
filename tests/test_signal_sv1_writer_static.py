import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import signal_sv1_writer_static as sw  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))
RECORDS = (ROOT / 'research' / 'work-items' /
           'RE-005-node115-signal-sv1-writer' / 'records.json')


def load():
    return TARGET.read_bytes()


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class SignalSv1WriterPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()
        cls.records = sw.analyze(cls.data)

    def test_artifact_and_records_match(self):
        self.assertEqual(self.records['artifact']['size'], 105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        want = json.loads(RECORDS.read_text())
        self.assertEqual(self.records, want)

    def test_body_pins(self):
        b = self.records['bodies']
        self.assertEqual(
            b['wake_call']['sha256'],
            'bcb6335b6c1dd826cd4f0a015c1c666eec2b950355b93d452ac871cc2eaf4bb2')
        self.assertEqual(
            b['wake_call_once']['sha256'],
            '4b20d2c88ea478a8b58a2e88649ff497e332e3416232fef73d3ba5aba39803c3')
        self.assertEqual(b['wake_call']['bytes'], 135)
        self.assertEqual(b['wake_call_once']['bytes'], 135)
        self.assertEqual(b['entry_init']['bytes'], 3700)
        self.assertEqual(b['os_handler']['bytes'], 1343)
        # Cross-checks against the #2952 packet's independently made pins.
        self.assertEqual(
            b['entry_lookup']['sha256'],
            '4d3182ad772f96cf6dd9042ed0737b5109ff2df95b6987a03a8fa0b5184f0b8b')
        self.assertEqual(
            b['signal_attach']['sha256'],
            '53d22092e6cf21707c22a3c004e2ef4ea4089a642db1c457f340b535b17853a9')
        self.assertEqual(
            b['table_drain']['sha256'],
            'b0d541b3058ae4035211645b3440e15a0e391b25347f1729f06787bdf6aff06f')
        self.assertEqual(
            b['init_closure']['sha256'],
            '139d017d4d4bce261c422682a27f8b0e1c17db94cf78fa87e192f66e6e1b4fb8')

    def test_global_born_state(self):
        g = self.records['global_state']
        self.assertTrue(g['value_words_zero'])
        self.assertEqual(g['once_word'], '0x3')

    def test_absolute_census_no_sv1_access(self):
        c = self.records['absolute_census']
        # +0x00 (sv[1]): six lea sites only, no load/store anywhere.
        self.assertEqual(len(c['0x0']), 6)
        self.assertEqual({s['body'] for s in c['0x0']},
                         {'0x5cde710', '0x5ce71f0', '0x5ce7380'})
        # +0x04 (sv[0]): exactly one load, in signal_attach.
        self.assertEqual(c['0x4'], [{'site': '0x5ce7211',
                                     'body': '0x5ce71f0'}])
        self.assertEqual(len(c['0x8']), 2)
        self.assertEqual(len(c['0x10']), 3)
        self.assertEqual(len(c['0x18']), 4)
        self.assertEqual(sum(self.records['imm64_census'].values()), 0)
        # The neighbouring word is a different static (lock xadd sites).
        self.assertEqual(len(self.records['neighbor_xadd_sites']), 8)

    def test_wake_vtable(self):
        vt = self.records['wake_vtable']
        self.assertEqual(vt['base'], '0x64c54b8')
        self.assertEqual(vt['slots']['0x8']['value'], '0x10')
        self.assertEqual(vt['slots']['0x10']['value'], '0x8')
        self.assertEqual(vt['slots']['0x18']['target'], '0x5cdd040')
        self.assertEqual(vt['slots']['0x20']['target'], '0x5cdcda0')
        self.assertEqual(vt['slots']['0x28']['target'], '0x5cdcda0')
        refs = self.records['wake_vtable_refs']
        self.assertEqual(len(refs), 5)
        self.assertEqual({r['body'] for r in refs}, {'0x5cdd480'})

    def test_send_call_sites(self):
        sites = {(s['site'], s['body'])
                 for s in self.records['send_call_sites']}
        self.assertEqual(sites, {('0x5cdcddc', '0x5cdcda0'),
                                 ('0x5cdd07c', '0x5cdd040'),
                                 ('0x5cdfd3e', '0x5cdfc90')})

    def test_call_graph_edges(self):
        e = self.records['e8_callers']
        self.assertEqual(e['entry_init'], ['0x5cdf48c', '0x5cdf65c'])
        self.assertEqual(e['signal_attach'], ['0x5ce02bd'])
        self.assertEqual(e['wake_call'], [])
        self.assertEqual(e['wake_call_once'], [])

    def test_byte_pins(self):
        p = self.records['byte_pins']
        self.assertEqual(p['wake_call_fd_load'], '8b39')
        self.assertEqual(p['wake_call_once_fd_load'], '8b39')
        self.assertEqual(p['handler_action_call'], 'ff5028')
        self.assertEqual(self.records['wake_byte']['value'], '01')
        self.assertEqual(self.records['got']['send']['symbol'], 'send')
        self.assertEqual(self.records['got']['sigaction']['symbol'],
                         'sigaction')


if __name__ == '__main__':
    unittest.main()
