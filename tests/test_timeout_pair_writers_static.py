"""Tests for the RE-005 timeout-pair writers packet tool.

The tool re-derives, from the authenticated hl-node 115
artifact only: the predicate the two io-driver selectors
apply to the park / park_timeout pair, the complete
writer census for the pair head (full .text rel32,
stored pointers, .rela.dyn addends), the single
constructor's two variants and tag-3 error exits, the
installing builder's tag-3 rejection, the current_thread
and multi_thread passages, and the semantics of the
three slow-path bodies (io poll, signal drain, global
refresh). Any drift in a body hash, slot resolution,
Location, call census, byte pin, message or sentinel
site must fail the suite rather than silently rewrite
the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'timeout_pair_writers_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-timeout-pair-writers')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'timeout_pair_writers_static', TOOL)
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
class TimeoutPairWritersPacketTests(unittest.TestCase):

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
                         'RE-005-node115-timeout-pair-writers')

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(owners['sel_timeout']['bytes'], 137)
        self.assertEqual(owners['sel_park']['bytes'], 140)
        self.assertEqual(owners['ctor']['bytes'], 1627)
        self.assertEqual(owners['forwarder']['bytes'], 1001)
        self.assertEqual(owners['builder']['bytes'], 4785)
        self.assertEqual(owners['poll_new']['bytes'], 576)
        self.assertEqual(owners['waker_reg']['bytes'], 388)
        self.assertEqual(owners['slow_a_poll']['bytes'], 729)
        self.assertEqual(owners['slow_b_signal']['bytes'], 550)
        self.assertEqual(owners['slow_c_refresh']['bytes'], 679)
        pinned = self.records['pinned_bodies']
        self.assertEqual(pinned['park_body']['bytes'], 321)
        self.assertEqual(pinned['park_timeout_body']['bytes'],
                         493)

    def test_selector_census(self):
        census = self.records['call_census']
        sel_t = census['sel_timeout']
        self.assertEqual(
            [(c['site'], c['kind']) for c in sel_t],
            [('0x5ce2ff3', 'call'), ('0x5ce3045', 'call'),
             ('0x5cfb801', 'call')])
        sel_p = census['sel_park']
        self.assertEqual(
            [(c['site'], c['kind']) for c in sel_p],
            [('0x5ce3022', 'call'), ('0x5cec986', 'call'),
             ('0x5cfb7f6', 'call')])
        fwd = census['forwarder']
        self.assertEqual(
            [(c['site'], c['kind']) for c in fwd],
            [('0x5ce019f', 'jmp'), ('0x5ce088d', 'jmp')])
        for role in ('slow_a_poll', 'slow_b_signal',
                     'slow_c_refresh'):
            sites = [(c['site'], c['in_body'])
                     for c in census[role]]
            self.assertEqual(
                sites,
                [('0x5ce01b0' if role == 'slow_a_poll' else
                  '0x5ce01b8' if role == 'slow_b_signal' else
                  '0x5ce01cb', '0x5ce0160'),
                 ('0x5ce08a3' if role == 'slow_a_poll' else
                  '0x5ce08ab' if role == 'slow_b_signal' else
                  '0x5ce08be', '0x5ce0850'),
                 ('0x5cfdfdb' if role == 'slow_a_poll' else
                  '0x5cfdfe3' if role == 'slow_b_signal' else
                  '0x5cfdfef', '0x5cfdd00')], role)

    def test_writer_census(self):
        census = self.records['call_census']
        self.assertEqual(
            [c['site'] for c in census['ctor']],
            ['0x5cf9669', '0x5cf96eb'])
        self.assertEqual(
            [c['site'] for c in census['poll_new']],
            ['0x5ce0218'])
        self.assertEqual(
            [c['site'] for c in census['waker_reg']],
            ['0x5ce02bd'])
        self.assertEqual(census['builder'], [])
        self.assertEqual(census['top_a1_ct'], [])
        self.assertEqual(census['top_a2_ct'], [])
        rrefs = self.records['rela_refs']
        self.assertEqual(
            rrefs['builder'],
            [{'slot': '0x64e1760', 'type': 8}])
        self.assertEqual(
            rrefs['top_a1_ct'],
            [{'slot': '0x64e1790', 'type': 8}])
        self.assertEqual(
            rrefs['top_a2_ct'],
            [{'slot': '0x64e1798', 'type': 8}])
        for role, hits in rrefs.items():
            if role not in ('builder', 'top_a1_ct', 'top_a2_ct'):
                self.assertEqual(hits, [], role)
        for role, hits in self.records['stored_ptr_refs'].items():
            self.assertEqual(hits, [], role)

    def test_slots(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64eb060'],
                         {'kind': 'glob_dat',
                          'value': 'epoll_wait'})
        self.assertEqual(slots['0x64eb080'],
                         {'kind': 'glob_dat', 'value': 'recv'})
        self.assertEqual(slots['0x64df508'],
                         {'kind': 'glob_dat', 'value': 'memcpy'})
        self.assertEqual(slots['0x64e01f8'],
                         {'kind': 'relative',
                          'value': '0x5bb59d0'})
        self.assertEqual(slots['0x64ecba8'],
                         {'kind': 'relative',
                          'value': '0x5cfcc50'})

    def test_locations(self):
        locs = self.records['locations']
        self.assertEqual(
            [(l['path'].rsplit('/', 1)[-1], l['line'], l['col'])
             for l in locs['sel_park']],
            [('driver.rs', 160, 32)])
        self.assertEqual(
            [(l['path'].rsplit('/', 1)[-1], l['line'], l['col'])
             for l in locs['sel_timeout']],
            [('driver.rs', 165, 32)])
        self.assertEqual(
            [(l['path'].rsplit('/', 1)[-1], l['line'], l['col'])
             for l in locs['slow_a_poll']],
            [('events.rs', 212, 9), ('driver.rs', 221, 17),
             ('driver.rs', 196, 23)])
        self.assertEqual(
            [(l['path'].rsplit('/', 1)[-1], l['line'], l['col'])
             for l in locs['slow_b_signal']],
            [('mod.rs', 118, 26), ('mod.rs', 121, 27)])
        self.assertEqual(locs['slow_c_refresh'], [])
        self.assertEqual(
            [(l['path'].rsplit('/', 1)[-1], l['line'], l['col'])
             for l in locs['top_a1_ct']],
            [('mod.rs', 449, 45)])

    def test_sentinel_sites(self):
        sites = self.records['sentinel_sites']
        self.assertEqual(sites['ctor'],
                         ['0x5ce02c4', '0x5ce036f'])
        self.assertEqual(sites['sel_timeout'], [])
        self.assertEqual(sites['sel_park'], [])
        self.assertEqual(sites['poll_new'],
                         ['0x5ceebab', '0x5ceebe2', '0x5ceec1d'])
        self.assertEqual(sites['forwarder'],
                         ['0x5cfdd8e', '0x5cfdf65'])

    def test_pins_and_messages(self):
        pins = self.records['pins']
        self.assertEqual(pins['0x5ce06a4'], '48c70303000000')
        self.assertEqual(pins['0x5cf967e'], '4983fc03')
        self.assertEqual(pins['0x5cf9700'], '4983fc03')
        messages = self.records['messages']
        self.assertEqual(messages['0x94db81'], 'driver missing')
        self.assertEqual(messages['0x454b60'],
                         'EOF on self-pipe')
        self.assertTrue(
            messages['0x94ca03'].startswith(
                'A Tokio 1.x context was found, but IO is '
                'disabled.'))

    def test_packet_files_match(self):
        expected = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(self.records, expected)


if __name__ == '__main__':
    unittest.main()
