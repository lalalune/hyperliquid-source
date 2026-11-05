"""Tests for the RE-005 park contention fallback packet.

The tool re-derives, from the authenticated hl-node 115
artifact only: the identity of the contention fallback
body 0x5ce30d0 (the vendored tokio multi-thread park
core, from its own panic Locations in
multi_thread/park.rs), its sole route in (one call in
registration_b, no jump, no stored pointer, no rela
reference), the two entry arms and their byte-claim
conditions, the supply above registration_b that
restricts the fallback to (secs = 0, nanos = sentinel),
the guard-byte / state-word protocol it runs on the
per-thread cell, and its four encoded panics.  Any
drift in a body hash, census, Location, message, rela
census, jump table or instruction pin must fail the
suite rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'park_contention_fallback_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-park-contention-fallback')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'park_contention_fallback_static', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL_MOD = load_tool()


def materialised():
    target = TOOL_MOD.TARGET
    if not target.is_file():
        return False
    with target.open('rb') as handle:
        return not handle.read(64).startswith(b'version https://')


@unittest.skipUnless(materialised(),
                     'hl-node artifact not materialised')
class ParkContentionFallbackPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278'
            'fa39f249e98c3867b5301')
        self.assertEqual(
            self.records['work_item'],
            'RE-005-node115-park-contention-fallback')

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(
            owners['contention_fallback']['bytes'], 854)
        self.assertEqual(
            owners['contention_fallback']['start'],
            '0x5ce30d0')
        self.assertEqual(
            owners['contention_fallback']['end'],
            '0x5ce3426')
        self.assertEqual(owners['registration_b']['bytes'],
                         936)
        self.assertEqual(
            owners['contention_fallback']['sha256'],
            '1727765a7756690cfec9d1c24f087b05362624a8'
            '154f7e40b5bc94ffe491f16f')

    def test_pinned_bodies(self):
        pinned = self.records['pinned_bodies']
        self.assertEqual(pinned['wrapper_state']['bytes'],
                         247)
        self.assertEqual(pinned['top_reg_b']['bytes'], 4274)
        self.assertEqual(pinned['wait_helper']['bytes'],
                         1677)
        self.assertEqual(pinned['byte_wait']['bytes'], 1693)
        self.assertEqual(pinned['byte_notify']['bytes'],
                         885)
        self.assertEqual(pinned['clock']['bytes'], 201)
        self.assertEqual(pinned['instant_sub']['bytes'],
                         198)
        # Same digests the provenance packet pinned for
        # wrapper_state, top_reg_b and instant_sub.
        self.assertEqual(
            pinned['wrapper_state']['sha256'],
            '17d62a55fe9d639eee5e5d26f3694a090f7f07e6'
            '29ca729d11bc66c31d3e0e37')
        self.assertEqual(
            pinned['top_reg_b']['sha256'],
            '6daa4de9236c851758d6f62ee795cdd95d9450cb'
            '932fe723046dd5218d53604d')
        self.assertEqual(
            pinned['instant_sub']['sha256'],
            'f9d8d8a41505bf8c9552d4a34ac4e190a6d0665c'
            '245595be11f2848e1a333a4a')

    def test_fallback_census(self):
        census = self.records['call_census']
        self.assertEqual(
            census['contention_fallback'],
            {'calls': ['0x5cec9ec'], 'jmps': []})

    def test_chain_census(self):
        census = self.records['call_census']
        self.assertEqual(
            census['registration_b'],
            {'calls': ['0x5cece59', '0x5ced567',
                       '0x5ced78d'],
             'jmps': []})
        self.assertEqual(census['wrapper_state'],
                         {'calls': ['0x5cec9d9'], 'jmps': []})

    def test_pointer_references(self):
        rela = self.records['rela_refs']
        # The only RELATIVE references to any chain body
        # are the three GOT slots resolving to the
        # wait/notify helpers; the fallback itself and
        # its caller have no pointer reference at all.
        self.assertEqual(
            rela['relative_addend_hits'],
            [{'offset': '0x64e01f8', 'addend': '0x5bb59d0'},
             {'offset': '0x64e0f38', 'addend': '0x5bb5650'},
             {'offset': '0x64e73b8', 'addend': '0x5bb4670'}])
        self.assertEqual(
            rela['fallback_raw_pointer_hits'], [])
        self.assertEqual(len(rela['chain_bodies']), 9)

    def test_exit_switch(self):
        table = self.records['exit_switch']
        self.assertEqual(table['base'], '0x94cb10')
        self.assertEqual(
            table['targets'],
            ['0x5ce32ca', '0x5ce3316', '0x5ce32ca',
             '0x5ce3316'])

    def test_locations_and_messages(self):
        locs = self.records['locations']
        park_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                   'tokio/src/runtime/scheduler/'
                   'multi_thread/park.rs')
        self.assertEqual(locs['park_inconsistent']['file'],
                         park_rs)
        self.assertEqual(
            (locs['park_inconsistent']['line'],
             locs['park_inconsistent']['col']), (179, 28))
        self.assertEqual(
            (locs['park_timeout_inconsistent']['line'],
             locs['park_timeout_inconsistent']['col']),
            (211, 25))
        self.assertEqual(
            (locs['park_timeout_invalid']['line'],
             locs['park_timeout_invalid']['col']),
            (213, 32))
        self.assertEqual(
            (locs['duration_overflow']['line'],
             locs['duration_overflow']['col']), (429, 33))
        self.assertIn('std/src/time.rs',
                      locs['duration_overflow']['file'])
        msgs = self.records['messages']
        self.assertEqual(
            msgs['park_inconsistent']['text'],
            'inconsistent park state; actual = ')
        self.assertEqual(
            msgs['park_timeout_inconsistent']['text'],
            'inconsistent park_timeout state, actual = ')
        self.assertEqual(
            msgs['park_timeout_invalid']['text'],
            'invalid park_timeout state, actual = ')
        self.assertEqual(
            msgs['duration_overflow']['text'],
            'overflow when adding duration to instant')

    def test_pins(self):
        self.assertGreaterEqual(len(self.records['pins']),
                                40)

    def test_findings_and_open_edges(self):
        findings = self.records['findings']
        self.assertIn('SETTLED', findings['identity'])
        self.assertIn('multi_thread/park.rs',
                      findings['identity'])
        self.assertIn('SETTLED', findings['supply'])
        self.assertIn('0x3b9aca00',
                      findings['entry_conditions'])
        self.assertIn('SETTLED', findings['inside'])
        self.assertIn('SETTLED', findings['panic_surface'])
        self.assertEqual(len(self.records['open_edges']),
                         4)

    def test_packet_records_match(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(on_disk, self.records)


if __name__ == '__main__':
    unittest.main()
