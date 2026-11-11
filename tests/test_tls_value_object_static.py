"""Tests for the RE-005 TLS value-object packet tool.

The tool re-derives, from the authenticated hl-node 115
artifact only: the identity of the 0x28-byte value
object the lazy thread-local getter 0x5cdf300 creates
for the dispatcher's cell at TLS base -0x418 (the
shared parker state of the vendored tokio park
module), its Arc-style layout and drop chain, the
park / park_timeout / unpark state-word protocol, the
complete direct-call census of every protocol body
and of the getter itself (the consumer mapping), the
drop-helper slot reference census, and the dispatcher
rows that form and use the {vtable, payload} handle.
Any drift in a body hash, slot resolution, vtable
entry, Location static, message text, call census or
instruction pin must fail the suite rather than
silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'tls_value_object_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-tls-value-object')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'tls_value_object_static', TOOL)
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
class TlsValueObjectPacketTests(unittest.TestCase):

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
                         'RE-005-node115-tls-value-object')

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(owners['drop_helper']['bytes'], 30)
        self.assertEqual(owners['park']['bytes'], 321)
        self.assertEqual(owners['park_timeout']['bytes'], 493)
        self.assertEqual(owners['unpark']['bytes'], 160)
        self.assertEqual(owners['unpark_release']['bytes'], 209)
        self.assertEqual(owners['release']['bytes'], 27)
        self.assertEqual(owners['clone_wrap']['bytes'], 20)
        self.assertEqual(owners['dealloc']['bytes'], 165)
        self.assertEqual(owners['clock']['bytes'], 201)
        self.assertEqual(owners['wait_fn']['bytes'], 1677)
        self.assertEqual(owners['wake_fn']['bytes'], 899)
        self.assertEqual(owners['wait_fn']['start'], '0x5bb4670')
        self.assertEqual(owners['park']['start'], '0x5cfdb90')
        self.assertEqual(
            owners['wait_fn']['sha256'],
            '65c70b3e926bbf20a45563b947502e17d87ead0455'
            '6451512587b556e9f57f1d')

    def test_pinned_bodies(self):
        pinned = self.records['pinned_bodies']
        self.assertEqual(pinned['dispatcher']['bytes'], 4386)
        self.assertEqual(pinned['loop_getter']['bytes'], 223)
        self.assertEqual(pinned['dtor_glue']['bytes'], 43)
        self.assertEqual(pinned['byte_wait']['bytes'], 1693)
        self.assertEqual(pinned['byte_notify']['bytes'], 885)
        self.assertEqual(
            pinned['byte_notify']['sha256'],
            '4eda0eff3310a0ba59b0a0fa1f208cf48e2ec5'
            '499b3ad5e48c99b8b93df628de')

    def test_slots_resolve(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64e17f8'], '0x5ce9190')
        self.assertEqual(slots['0x64df4a0'], '0x635de30')
        self.assertEqual(slots['0x64e73b8'], '0x5bb4670')
        self.assertEqual(slots['0x64ec188'], '0x5bb42e0')
        self.assertEqual(slots['0x64e01f8'], '0x5bb59d0')
        self.assertEqual(slots['0x64e0f38'], '0x5bb5650')

    def test_vtable(self):
        vtable = self.records['vtable']
        self.assertEqual(vtable['static'], '0x64c6ef8')
        self.assertEqual(vtable['entries'],
                         ['0x5cfdce0', '0x5cfd8c0',
                          '0x5cfd600', '0x5cfd5e0'])
        self.assertEqual(vtable['methods'],
                         ['clone', 'unpark_then_release',
                          'unpark', 'release'])

    def test_locations(self):
        locs = self.records['locations']
        park_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                   'tokio/src/runtime/park.rs')
        for role in ('park', 'park_timeout_a',
                     'park_timeout_b', 'unpark'):
            self.assertEqual(locs[role]['file'], park_rs)
        self.assertEqual((locs['park']['line'],
                          locs['park']['col']), (107, 28))
        self.assertEqual((locs['park_timeout_a']['line'],
                          locs['park_timeout_a']['col']),
                         (153, 28))
        self.assertEqual((locs['park_timeout_b']['line'],
                          locs['park_timeout_b']['col']),
                         (173, 18))
        self.assertEqual((locs['unpark']['line'],
                          locs['unpark']['col']), (187, 18))

    def test_consumer_census(self):
        census = self.records['call_census']
        # The getter's consumers: exactly 20 direct call
        # sites form the consumer set of the TLS cell.
        self.assertEqual(len(census['loop_getter']['calls']), 20)
        self.assertEqual(census['loop_getter']['jmps'], [])
        self.assertEqual(
            census['park'],
            {'calls': ['0x158e6dc', '0x158f415', '0x2ae1ac7',
                       '0x2b14bb4', '0x5ab7137', '0x5cfd7f5',
                       '0x5cfdf8b'],
             'jmps': ['0x5ce087c']})
        self.assertEqual(
            census['park_timeout'],
            {'calls': ['0x5cf29c8', '0x5cfdeab', '0x5cfdfa5'],
             'jmps': ['0x5ce0193']})
        # unpark is called directly only by the two
        # open-coding caller bodies.
        self.assertEqual(
            census['unpark'],
            {'calls': ['0x5a34bc8', '0x5a358b9'], 'jmps': []})
        self.assertEqual(len(census['release']['calls']), 6)
        self.assertEqual(census['release']['jmps'], [])
        # Vtable-only and slot-only bodies: no direct
        # call or jump anywhere in .text.
        for role in ('unpark_release', 'clone_wrap', 'wait_fn',
                     'wake_fn', 'drop_helper', 'dealloc'):
            self.assertEqual(census[role],
                             {'calls': [], 'jmps': []}, role)

    def test_drop_slot_refs(self):
        refs = self.records['drop_slot_refs']
        self.assertEqual(len(refs['calls']), 9)
        self.assertEqual(len(refs['jmps']), 9)
        for site in ('0x5cdf38a', '0x5cdf3f6', '0x5cfd5f3',
                     '0x5cfd933'):
            self.assertIn(site, refs['calls'])
        self.assertIn('0x5cfd97d', refs['calls'])

    def test_findings_and_open_edges(self):
        findings = self.records['findings']
        self.assertIn('tokio', findings['identity'])
        self.assertIn('park.rs', findings['identity'])
        self.assertIn('SETTLED', findings['drop_chain'])
        self.assertIn('SETTLED', findings['state_word'])
        self.assertIn('SETTLED', findings['counts_byte_token'])
        self.assertEqual(len(self.records['open_edges']), 4)

    def test_packet_records_match(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(on_disk, self.records)


if __name__ == '__main__':
    unittest.main()
