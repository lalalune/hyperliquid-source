"""Tests for the RE-005 time-context writers packet.

The tool re-derives, from the authenticated hl-node
115 artifact only: the identity of the forwarder's
time context (ctx = driver value + 0x40, the value
being what driver_ctor 0x5ce01f0 builds), the single
constructor writer of the base timestamp pair with
its sentinel-nanos disabled encoding, the wheel
state's sole construction by wheel_ctor 0x5cf6480,
the shutdown byte's sole runtime writer
(shutdown_setter 0x5ce08e0, two callers), the three
writers and zero readers of the ctx+0x78 deadline
cache, and the unlock/process body 0x5ceaa20 on the
forwarder's exit path.  Any drift in a body hash,
census, byte-lock census, Location, message, rela
census or instruction pin must fail the suite
rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'time_context_writers_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-time-context-writers')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'time_context_writers_static', TOOL)
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
class TimeContextWritersPacketTests(unittest.TestCase):

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
        self.assertEqual(self.records['work_item'],
                         'RE-005-node115-time-context-writers')

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(owners['driver_ctor']['bytes'], 1627)
        self.assertEqual(owners['wheel_ctor']['bytes'], 139)
        self.assertEqual(owners['wheel_resolve']['bytes'], 237)
        self.assertEqual(owners['wheel_process']['bytes'], 870)
        self.assertEqual(owners['unlock']['bytes'], 791)
        self.assertEqual(owners['shutdown_setter']['bytes'], 184)
        self.assertEqual(owners['forwarder']['bytes'], 1001)
        self.assertEqual(owners['driver_ctor']['start'],
                         '0x5ce01f0')
        self.assertEqual(owners['shutdown_setter']['start'],
                         '0x5ce08e0')
        # Same digests the earlier RE-005 packets pinned
        # for the shared bodies.
        self.assertEqual(
            owners['wheel_resolve']['sha256'],
            '7f576d12868e201a625c9ff780d4816c77d80f50d55c'
            '1666485a8f5c957bd1ac')
        self.assertEqual(
            owners['forwarder']['sha256'],
            '2d8ea94341d17a31bd755de9d3226f6911a337d3a6c9'
            '7134ed1721c6a097c647')

    def test_pinned_bodies(self):
        pinned = self.records['pinned_bodies']
        self.assertEqual(pinned['builder']['bytes'], 4785)
        self.assertEqual(pinned['registration_a']['bytes'], 409)
        self.assertEqual(pinned['registration_b']['bytes'], 936)
        self.assertEqual(pinned['signal_body']['bytes'], 718)
        self.assertEqual(pinned['drop_body']['bytes'], 506)
        self.assertEqual(pinned['cancel_body']['bytes'], 468)
        self.assertEqual(pinned['insert_body']['bytes'], 599)
        self.assertEqual(pinned['wheel_insert']['bytes'], 319)
        self.assertEqual(pinned['levels_alloc']['bytes'], 592)
        self.assertEqual(pinned['io_wake']['bytes'], 390)
        self.assertEqual(pinned['clock']['bytes'], 201)
        self.assertEqual(pinned['instant_sub']['bytes'], 198)

    def test_call_census(self):
        census = self.records['call_census']
        self.assertEqual(
            census['driver_ctor'],
            {'calls': ['0x5cf9669', '0x5cf96eb'], 'jmps': []})
        self.assertEqual(census['wheel_ctor'],
                         {'calls': ['0x5ce0412'], 'jmps': []})
        self.assertEqual(
            census['wheel_resolve'],
            {'calls': ['0x5ceaba7', '0x5cf657f', '0x5cfdd56'],
             'jmps': []})
        self.assertEqual(census['wheel_process'],
                         {'calls': ['0x5ceaa76'], 'jmps': []})
        self.assertEqual(
            census['unlock'],
            {'calls': ['0x5ce0950'], 'jmps': ['0x5cfe088']})
        self.assertEqual(
            census['shutdown_setter'],
            {'calls': ['0x5ceb47e', '0x5cfc20d'], 'jmps': []})
        self.assertEqual(
            census['forwarder'],
            {'calls': [], 'jmps': ['0x5ce019f', '0x5ce088d']})

    def test_byte_lock_census(self):
        locks = self.records['byte_lock_census']
        self.assertEqual(
            locks['cmpxchg'],
            ['0x5ceb00a', '0x5ceb468', '0x5cec95e', '0x5cec9c8',
             '0x5cfdd2e', '0x5cfdd80'])
        self.assertEqual(
            locks['xchg'],
            ['0x5ceb485', '0x5ceb4fe', '0x5ceca09', '0x5cecbca'])

    def test_pointer_references(self):
        rela = self.records['rela_refs']
        # The cancel body has no direct caller: it is
        # reached through the function-pointer slot at
        # 0x64dfe40.  The builder is referenced from the
        # slot at 0x64e1760.  No other chain body has a
        # pointer reference.
        self.assertEqual(
            rela['relative_addend_hits'],
            [{'offset': '0x64dfe40', 'addend': '0x5ceafd0'},
             {'offset': '0x64e1760', 'addend': '0x5cf9600'}])
        self.assertEqual(len(rela['chain_bodies']), 19)

    def test_locations_and_messages(self):
        locs = self.records['locations']
        time_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                   'tokio/src/runtime/time/mod.rs')
        entry_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                    'tokio/src/runtime/time/entry.rs')
        wheel_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                    'tokio/src/runtime/time/wheel/mod.rs')
        wake_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                   'tokio/src/util/wake_list.rs')
        self.assertEqual(locs['forwarder_time']['file'], time_rs)
        self.assertEqual((locs['forwarder_time']['line'],
                          locs['forwarder_time']['col']),
                         (214, 32))
        self.assertEqual((locs['forwarder_shutdown']['line'],
                          locs['forwarder_shutdown']['col']),
                         (217, 9))
        self.assertEqual(
            (locs['setter_timers_disabled']['line'],
             locs['setter_timers_disabled']['col']), (190, 32))
        self.assertEqual(locs['cancel_timers_disabled']['file'],
                         entry_rs)
        self.assertEqual(
            (locs['cancel_timers_disabled']['line'],
             locs['cancel_timers_disabled']['col']), (549, 30))
        self.assertEqual((locs['entry_state_panic']['line'],
                          locs['entry_state_panic']['col']),
                         (181, 13))
        self.assertEqual(locs['wheel_level_panic']['file'],
                         wheel_rs)
        self.assertEqual((locs['wheel_ctor_panic']['line'],
                          locs['wheel_ctor_panic']['col']),
                         (56, 39))
        self.assertEqual(locs['wake_list_first']['file'], wake_rs)
        self.assertEqual((locs['wake_list_second']['line'],
                          locs['wake_list_second']['col']),
                         (36, 9))
        msgs = self.records['messages']
        self.assertTrue(msgs['timers_disabled']['text']
                        .startswith('A Tokio 1.x context'))
        self.assertEqual(msgs['is_shutdown']['text'],
                         'assertion failed: !handle.is_shutdown()')
        self.assertTrue(msgs['mark_pending']['text']
                        .startswith('mark_pending called when'))

    def test_pins(self):
        self.assertGreaterEqual(len(self.records['pins']), 45)

    def test_findings_and_open_edges(self):
        findings = self.records['findings']
        self.assertIn('SETTLED', findings['identity'])
        self.assertIn('value + 0x40', findings['identity'])
        self.assertIn('SETTLED', findings['base_pair'])
        self.assertIn('0x3b9aca00', findings['base_pair'])
        self.assertIn('SETTLED', findings['wheel_state'])
        self.assertIn('SETTLED', findings['shutdown_byte'])
        self.assertIn('SETTLED', findings['budget_cache'])
        self.assertIn('SETTLED', findings['exit_recompute'])
        self.assertEqual(len(self.records['open_edges']), 5)

    def test_packet_records_match(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(on_disk, self.records)


if __name__ == '__main__':
    unittest.main()
