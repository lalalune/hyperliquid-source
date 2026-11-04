import tempfile
import unittest
from pathlib import Path

from tools import gate_callee_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-gate-callee')


def _flip(data, offset):
    mutated = bytearray(data)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


def _file_offset(data, va):
    """File offset of a virtual address, via the section table."""
    for sec in packet.sections(data):
        if sec['type'] != 8 and sec['address'] <= va \
                < sec['address'] + sec['size']:
            return sec['offset'] + (va - sec['address'])
    raise AssertionError(f'no section covers {va:#x}')


class GateCalleePacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()

    def test_generates_committed_packet_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet.generate(self.data, tmp)
            generated = {p.name: p.read_bytes()
                         for p in Path(tmp).iterdir()}
        committed = {p.name: p.read_bytes()
                     for p in PACKET_DIR.iterdir()
                     if p.name != 'README.md' and p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(generated), set(committed))
        for name in generated:
            self.assertEqual(generated[name], committed[name], name)

    def test_counters_and_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = packet.generate(self.data, tmp)
        counters = records['counters']
        self.assertEqual(counters['bodies'], 45)
        self.assertEqual(counters['exported_bodies'], 8)
        self.assertEqual(counters['census_sites'], 89)
        self.assertEqual(counters['census_fdes'], 43)
        self.assertEqual(counters['family_sites'], 36)
        self.assertEqual(counters['flag_zero'], 64)
        self.assertEqual(counters['flag_one'], 24)
        self.assertEqual(counters['flag_register'], 1)
        self.assertEqual(counters['rdx_used_sites'], 89)
        self.assertEqual(counters['select_sites'], 15)
        gate = records['gate']
        self.assertEqual(gate['stores'], [])
        self.assertEqual(gate['direct_calls'], {})
        self.assertEqual(gate['r9_refs'], [])
        self.assertEqual(gate['rets'], ['0x434f853'])
        self.assertEqual(len(gate['reads']), 4)
        self.assertEqual(gate['slot_calls'], {
            '0x434f7f3': '0x64dfaf8',
            '0x434f8ee': '0x64df830',
            '0x434f8fb': '0x64df830'})
        bounds = gate['descriptors']['bounds']
        self.assertEqual(bounds['file'], 'l1/src/spot_meta.rs')
        self.assertEqual((bounds['line'], bounds['col']), (119, 33))
        scale = gate['descriptors']['scale']
        self.assertEqual(scale['file'], 'l1/src/spot_meta.rs')
        self.assertEqual((scale['line'], scale['col']), (1206, 57))
        self.assertEqual(gate['threshold_decimal'], (2 ** 64) // 100)
        stub = records['unwrap_stub']
        self.assertEqual(stub['fmt'],
                         'called `Option::unwrap()` on a `None` value')
        self.assertEqual(stub['byte_after_body'], 'cc')
        self.assertIn('checked decimal-scaling primitive',
                      records['verdict'])

    def test_wrong_artifact_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            with self.assertRaises(packet.PacketError):
                packet.generate(b'\x00' * 1024, out)
            self.assertFalse(out.exists())

    def test_digest_drift_in_gate_body(self):
        off = _file_offset(self.data, 0x434F790)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 10))

    def test_pin_drift_at_inner_site(self):
        # the pinned gate-slot call at 0x2bbc0cc in inner_ca
        off = _file_offset(self.data, 0x2BBC0CC)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off))

    def test_drift_in_census_only_fde(self):
        off = _file_offset(self.data, 0x369D2C0)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 50))


if __name__ == '__main__':
    unittest.main()
