"""Tests for the RE-005 park_timeout provenance packet.

The tool re-derives, from the authenticated hl-node 115
artifact only: the complete direct-reference graph
above park_timeout 0x5cfd9a0 (three calls, one tail
jump), the (secs, nanos) register-pair representation
with the nanos == 0x3b9aca00 infinity sentinel, the
forwarder's wheel-period cap (min of the caller's
pair and the time left in the context's current
wheel period), the loop body's deadline-minus-now
value and the fact that its chain is only ever
supplied the sentinel, and the six registration call
sites' supply set {0, sentinel} with secs hardwired
to 0.  Any drift in a body hash, census, Location,
message, rela census or instruction pin must fail
the suite rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'park_timeout_provenance_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-park-timeout-provenance')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'park_timeout_provenance_static', TOOL)
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
class ParkTimeoutProvenancePacketTests(unittest.TestCase):

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
                         'RE-005-node115-park-timeout-provenance')

    def test_owners(self):
        owners = self.records['owners']
        self.assertEqual(owners['selector_timeout']['bytes'], 137)
        self.assertEqual(owners['selector_park']['bytes'], 140)
        self.assertEqual(owners['wrapper_state']['bytes'], 247)
        self.assertEqual(owners['dispatch']['bytes'], 286)
        self.assertEqual(owners['forwarder']['bytes'], 1001)
        self.assertEqual(owners['loop_body']['bytes'], 747)
        self.assertEqual(owners['registration_a']['bytes'], 409)
        self.assertEqual(owners['registration_b']['bytes'], 936)
        self.assertEqual(owners['wheel_resolve']['bytes'], 237)
        self.assertEqual(owners['instant_sub']['bytes'], 198)
        self.assertEqual(owners['forwarder']['start'], '0x5cfdd00')
        self.assertEqual(
            owners['selector_timeout']['sha256'],
            'f0eb5ff4372093ba8f617e6f52555f35e6f4e77659'
            'dc9928372825790444357b')

    def test_pinned_bodies(self):
        pinned = self.records['pinned_bodies']
        self.assertEqual(pinned['park_timeout']['bytes'], 493)
        self.assertEqual(pinned['park_wrap']['bytes'], 1366)
        self.assertEqual(pinned['top_reg_b']['bytes'], 4274)
        self.assertEqual(pinned['park_wrapper_a']['bytes'], 268)
        self.assertEqual(pinned['park_wrapper_b']['bytes'], 268)
        self.assertEqual(pinned['park_wrapper_c']['bytes'], 268)
        # Same digest the TLS value-object packet pinned
        # for park_timeout itself.
        self.assertEqual(
            pinned['park_timeout']['sha256'],
            '411cc42aff700d68883fd2371a63226cf62e426c5530'
            'e188ed619f6fb98cbef5')

    def test_park_timeout_census(self):
        census = self.records['call_census']
        self.assertEqual(
            census['park_timeout'],
            {'calls': ['0x5cf29c8', '0x5cfdeab', '0x5cfdfa5'],
             'jmps': ['0x5ce0193']})
        self.assertEqual(
            census['forwarder'],
            {'calls': [], 'jmps': ['0x5ce019f', '0x5ce088d']})
        self.assertEqual(
            census['selector_timeout'],
            {'calls': ['0x5ce2ff3', '0x5ce3045', '0x5cfb801'],
             'jmps': []})
        self.assertEqual(
            census['selector_park'],
            {'calls': ['0x5ce3022', '0x5cec986', '0x5cfb7f6'],
             'jmps': []})

    def test_chain_census(self):
        census = self.records['call_census']
        self.assertEqual(census['wrapper_state'],
                         {'calls': ['0x5cec9d9'], 'jmps': []})
        self.assertEqual(
            census['registration_a'],
            {'calls': ['0x5cfb680', '0x5cfba84', '0x5cfbbf3'],
             'jmps': []})
        self.assertEqual(
            census['registration_b'],
            {'calls': ['0x5cece59', '0x5ced567', '0x5ced78d'],
             'jmps': []})
        self.assertEqual(census['dispatch'],
                         {'calls': ['0x5cf414e'], 'jmps': []})
        self.assertEqual(census['loop_body'],
                         {'calls': ['0x5cf6b60'], 'jmps': []})
        self.assertEqual(
            census['park_wrap'],
            {'calls': ['0x15deecd', '0x2abbafd', '0x5cf864d'],
             'jmps': []})

    def test_pointer_references(self):
        rela = self.records['rela_refs']
        # Only the two top registration bodies appear in a
        # function-pointer table; both hardwire their
        # supplies, and no duration-receiving body has a
        # pointer reference at all.
        self.assertEqual(
            rela['relative_addend_hits'],
            [{'offset': '0x64e1790', 'addend': '0x5cfb610'},
             {'offset': '0x64e1798', 'addend': '0x5cfb920'}])
        self.assertEqual(len(rela['chain_bodies']), 19)

    def test_locations_and_messages(self):
        locs = self.records['locations']
        io_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                 'tokio/src/runtime/io/driver.rs')
        time_rs = ('/home/ubuntu/hl/code_Mainnet/z_vendor/'
                   'tokio/src/runtime/time/mod.rs')
        self.assertEqual(locs['selector_timeout']['file'], io_rs)
        self.assertEqual((locs['selector_timeout']['line'],
                          locs['selector_timeout']['col']),
                         (165, 32))
        self.assertEqual((locs['selector_park']['line'],
                          locs['selector_park']['col']),
                         (160, 32))
        self.assertEqual(locs['forwarder_time']['file'], time_rs)
        self.assertEqual((locs['forwarder_time']['line'],
                          locs['forwarder_time']['col']),
                         (214, 32))
        self.assertEqual((locs['forwarder_shutdown']['line'],
                          locs['forwarder_shutdown']['col']),
                         (217, 9))
        msgs = self.records['messages']
        self.assertTrue(msgs['timers_disabled']['text']
                        .startswith('A Tokio 1.x context'))
        self.assertEqual(msgs['is_shutdown']['text'],
                         'assertion failed: !handle.is_shutdown()')

    def test_pins(self):
        self.assertGreaterEqual(len(self.records['pins']), 50)

    def test_findings_and_open_edges(self):
        findings = self.records['findings']
        self.assertIn('SETTLED', findings['representation'])
        self.assertIn('0x3b9aca00',
                      findings['representation'])
        self.assertIn('SETTLED', findings['site_loop_body'])
        self.assertIn('SETTLED', findings['site_forwarder_capped'])
        self.assertEqual(len(self.records['open_edges']), 5)

    def test_packet_records_match(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(on_disk, self.records)


if __name__ == '__main__':
    unittest.main()
