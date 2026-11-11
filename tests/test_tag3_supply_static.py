"""Tests for the RE-005 tag-3 supply packet.

The tool re-derives, from the authenticated hl-node
115 artifact only: that the tag-3 arm of
driver_ctor 0x5ce01f0 is its failure encoding
(the tail at 0x5ce06a0 writes no driver field),
that only the poll variant reaches it, that its
whole supply is two OS-failure routes
(Poll::new 0x5ceeae0 failing, the signal-attach
body 0x5ce71f0 failing) carrying
(errno << 32) | 2, that the third branch into
the tail is value-unreachable, and that every
runtime build reaches the ctor through the
builder 0x5cf9600 and its GOT slot from two
wrapper bodies whose config constructor fixes
variant byte 1 / tag byte 1 / capacity 0x400.
Any drift in a body hash, census, register-write
scan or instruction pin must fail the suite
rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'tag3_supply_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-tag3-supply')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'tag3_supply_static', TOOL)
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
class Tag3SupplyPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'],
                         TOOL_MOD.TARGET_SIZE)
        self.assertEqual(self.records['artifact']['sha256'],
                         TOOL_MOD.TARGET_SHA256)

    def test_records_match_disk(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(self.records, on_disk)

    def test_owner_bodies(self):
        owners = self.records['owners']
        self.assertEqual(
            owners['driver_ctor']['start'], '0x5ce01f0')
        self.assertEqual(owners['driver_ctor']['bytes'], 1627)
        self.assertEqual(
            owners['signal_attach']['start'], '0x5ce71f0')
        self.assertEqual(owners['signal_attach']['bytes'], 388)
        self.assertEqual(owners['builder']['start'], '0x5cf9600')
        self.assertEqual(owners['builder']['bytes'], 4785)
        self.assertEqual(owners['cfg_ctor']['start'], '0x5cf93f0')
        self.assertEqual(owners['cfg_ctor']['bytes'], 431)
        self.assertEqual(owners['poll_new']['start'], '0x5ceeae0')
        self.assertEqual(owners['poll_new']['bytes'], 576)

    def test_ctor_callers_are_builder_only(self):
        census = self.records['call_census']['driver_ctor']
        self.assertEqual(census['calls'],
                         ['0x5cf9669', '0x5cf96eb'])
        self.assertEqual(census['jmps'], [])

    def test_helper_callers(self):
        census = self.records['call_census']
        self.assertEqual(census['signal_attach']['calls'],
                         ['0x5ce02bd'])
        self.assertEqual(census['poll_new']['calls'],
                         ['0x5ce0218'])
        self.assertEqual(census['cfg_ctor']['calls'],
                         ['0x15d7007', '0x15d70a3', '0x2ae16d1'])

    def test_builder_reachable_only_via_got_slot(self):
        census = self.records['call_census']['builder']
        self.assertEqual(census, {'calls': [], 'jmps': []})
        slot = self.records['builder_got_slot']
        self.assertEqual(slot['slot'], '0x64e1760')
        self.assertEqual(
            [hit['site'] for hit in slot['indirect_calls']],
            ['0x15d7026', '0x15d70c2', '0x2ae16f2'])
        self.assertEqual(
            [hit['body'] for hit in slot['indirect_calls']],
            ['wrapper_a', 'wrapper_a', 'wrapper_b'])
        self.assertEqual(len(slot['rela']), 1)
        self.assertEqual(slot['rela'][0]['addend'], '0x5cf9600')
        self.assertEqual(
            slot['imm64_occurrences']['builder'],
            [slot['rela'][0]['addend_file_offset']])
        for role, hits in slot['imm64_occurrences'].items():
            if role != 'builder':
                self.assertEqual(hits, [], role)

    def test_tail_census(self):
        tail = self.records['tail_census']
        self.assertEqual(tail['verified'],
                         {'0x5ce022c': 'jo', '0x5ce0670': 'je'})
        self.assertIn('0x5ce069e', tail['raw_candidates'])
        self.assertNotIn('0x5ce069e', tail['verified'])
        self.assertEqual(tail['fallthrough']['predecessor'],
                         '0x5ce069a')
        self.assertEqual(tail['fallthrough']['lands_on'],
                         '0x5ce06a0')

    def test_tag3_store_unique(self):
        self.assertEqual(self.records['tag3_store_census'],
                         ['0x5ce06a4'])

    def test_cfg_reads(self):
        self.assertEqual(self.records['cfg_read_census'],
                         ['0x5ce0207', '0x5ce0211', '0x5ce03f6'])

    def test_r3_provenance_scans(self):
        writes = self.records['register_writes']
        self.assertEqual(
            writes['rcx_block_0x5ce0543_0x5ce066a'], [])
        self.assertEqual(
            writes['rdx_span_0x5ce02cd_0x5ce05ca'], [])
        self.assertEqual(
            writes['rcx_ctor_span_0x5ce02c2_0x5ce0672'],
            ['0x5ce02c2', '0x5ce0377', '0x5ce0442',
             '0x5ce0482', '0x5ce066a'])

    def test_wrapper_config_constant_pins(self):
        pins = self.records['pins']
        for va in ('0x15d700c', '0x15d70a8', '0x2ae16d6'):
            self.assertTrue(pins[va].endswith('0101'), va)
        self.assertEqual(pins['0x5cf94a3'],
                         '48c7436000040000')
        self.assertEqual(pins['0x5cf9521'],
                         'c783e500000000000000')

    def test_error_encoding_pins(self):
        pins = self.records['pins']
        self.assertEqual(pins['0x5ce06a4'], '48c70303000000')
        self.assertEqual(pins['0x5ce06a0'], '4c897b08')
        self.assertEqual(pins['0x5cf970e'], '48c70302000000')


if __name__ == '__main__':
    unittest.main()
