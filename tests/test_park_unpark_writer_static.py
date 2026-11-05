"""Tests for the RE-005 park unpark-writer packet.

The tool re-derives, from the authenticated hl-node 115
artifact only: the identity of the unpark body
0x5ce3580 (the vendored tokio multi-thread scheduler
park module, from its own panic Location at
multi_thread/park.rs line 288), its swap of state
value 3 into the per-thread park cell, the four
old-value arms (latch, fallback-loop wake, driver
signal tail jump, already-notified), its six direct
entry points and the absence of any indirect route,
the module-wide Location census, and the uniqueness
of the xchg store pattern.  Any drift in a body hash,
census, Location, message, jump table or instruction
pin must fail the suite rather than silently rewrite
the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'park_unpark_writer_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-park-unpark-writer')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'park_unpark_writer_static', TOOL)
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
class ParkUnparkWriterPacketTests(unittest.TestCase):

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

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(owners['unpark']['start'],
                         '0x5ce3580')
        self.assertEqual(owners['unpark']['end'],
                         '0x5ce3662')
        self.assertEqual(owners['unpark']['bytes'], 226)
        self.assertEqual(owners['inner_unpark']['start'],
                         '0x5ce09a0')
        self.assertEqual(owners['inner_unpark']['bytes'],
                         258)

    def test_pinned_bodies(self):
        pinned = self.records['pinned_bodies']
        expect = {
            'contention_fallback': ('0x5ce30d0', 854),
            'registration_b': ('0x5cec8b0', 936),
            'wrapper_state': ('0x5ce2fd0', 247),
            'signal_arg': ('0x5ce3fd0', 796),
            'signal_pop_call': ('0x5ce4430', 377),
            'signal_pop_jmp_a': ('0x5ce45b0', 368),
            'signal_pop_jmp_b': ('0x5ce4720', 622),
            'signal_pop_call_b': ('0x5ce4990', 409),
            'signal_all': ('0x5cfadf0', 271),
        }
        for role, (start, size) in expect.items():
            self.assertEqual(pinned[role]['start'], start)
            self.assertEqual(pinned[role]['bytes'], size)

    def test_unpark_census(self):
        census = self.records['call_census']['unpark']
        self.assertEqual(census['calls'],
                         ['0x5ce450e', '0x5ce4a88',
                          '0x5cfaec8'])
        self.assertEqual(census['jmps'],
                         ['0x5ce4235', '0x5ce468f',
                          '0x5ce48cb'])

    def test_pointer_references(self):
        refs = self.records['rela_refs']
        self.assertEqual(
            refs['unpark_relative_addend_hits'], [])
        self.assertEqual(
            refs['unpark_raw_pointer_hits'], [])

    def test_writer_pattern_unique(self):
        census = self.records['writer_pattern_census']
        self.assertEqual(census['xchg3_sites'],
                         ['0x5ce358a'])

    def test_old_value_switch(self):
        table = self.records['old_value_switch']
        self.assertEqual(table['base'], '0x94cb20')
        self.assertEqual(table['targets'],
                         ['0x5ce35c7', '0x5ce35a4',
                          '0x5ce35cd', '0x5ce35c7'])

    def test_locations_and_message(self):
        locs = self.records['module_locations']
        self.assertEqual(locs['line288']['line'], 288)
        self.assertEqual(locs['line288']['col'], 23)
        self.assertEqual(locs['line288']['lea_refs'],
                         ['0x5ce35fc'])
        self.assertEqual(locs['line179']['lea_refs'],
                         ['0x5ce3357'])
        self.assertEqual(locs['line271']['lea_refs'],
                         ['0x5ce3081', '0x5cec9ad'])
        self.assertTrue(
            locs['line288']['file'].endswith(
                'multi_thread/park.rs'))
        msg = self.records['messages'][
            'unpark_inconsistent']
        self.assertEqual(
            msg['text'],
            'inconsistent state in unpark; actual = ')
        self.assertEqual(msg['len'], 39)

    def test_pins(self):
        pins = self.records['pins']
        self.assertEqual(pins['0x5ce3585'], 'b803000000')
        self.assertEqual(pins['0x5ce358a'], '48874718')
        self.assertEqual(pins['0x5ce365c'],
                         'ff25268b8000')
        self.assertEqual(pins['0x5ce09c7'], '48874310')

    def test_findings_and_open_edges(self):
        findings = self.records['findings']
        for role in ('writer', 'old_value_arms',
                     'inner_arm', 'entry_points',
                     'handle_neighbour'):
            self.assertIn(role, findings)
            self.assertTrue(
                findings[role].startswith(
                    ('SETTLED', 'CONTEXT')))
        self.assertEqual(
            len(self.records['open_edges']), 3)

    def test_packet_records_match(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(self.records, on_disk)


if __name__ == '__main__':
    unittest.main()
