import tempfile
import unittest
from pathlib import Path

from tools import inner_bodies_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-inner-bodies')


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


class InnerBodiesPacketTests(unittest.TestCase):
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
        self.assertEqual(counters['bodies'], 21)
        self.assertEqual(counters['exported_bodies'], 14)
        self.assertEqual(counters['inner_bodies'], 2)
        self.assertEqual(counters['inner_call_sites'], 6)
        self.assertEqual(counters['producer_helpers'], 6)
        self.assertEqual(counters['producer_sites'], 14)
        self.assertEqual(counters['inspector_helpers'], 2)
        self.assertEqual(counters['inspector_stores'], 0)
        self.assertEqual(counters['inner_memcpy_slot_refs'], 0)
        self.assertEqual(counters['inner_non_frame_stores'], 24)
        for name in ('inner_ca', 'inner_s3'):
            inner = records['inner_bodies'][name]
            self.assertEqual(inner['memcpy_slot_refs'], [])
            self.assertEqual(inner['exit']['success']['tag_value'], 0)
            self.assertEqual(len(inner['exit']['success']['stores']), 6)
            self.assertEqual(inner['exit']['failure']['tag_value'], 1)
            self.assertEqual(
                sorted(inner['exit']['failure_arms'].values()),
                [2, 3, 3, 7, 7, 9])
        for name in ('help_e850', 'help_563'):
            self.assertEqual(
                records['producer_helpers'][name]['store_total'], 0)
        self.assertIn('zero-store serialised-form inspectors',
                      records['verdict'])

    def test_wrong_artifact_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            with self.assertRaises(packet.PacketError):
                packet.generate(b'\x00' * 1024, out)
            self.assertFalse(out.exists())

    def test_digest_drift_in_inner_body(self):
        off = _file_offset(self.data, 0x2BBBBA0)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 10))

    def test_pin_drift_at_inspector_site(self):
        # the pinned `call 0x5630000` at 0x558374b in bwc_b2
        off = _file_offset(self.data, 0x558374B)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off))

    def test_drift_in_inspector_body(self):
        off = _file_offset(self.data, 0x5630000)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 50))


if __name__ == '__main__':
    unittest.main()
