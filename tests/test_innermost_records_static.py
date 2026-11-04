import hashlib
import tempfile
import unittest
from pathlib import Path

from tools import innermost_records_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-innermost-records')


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


class InnermostRecordsPacketTests(unittest.TestCase):
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
        self.assertEqual(counters['bodies'], 33)
        self.assertEqual(counters['exported_bodies'], 20)
        self.assertEqual(counters['decode_call_sites'], 18)
        self.assertEqual(counters['b_wrapper_call_sites'], 14)
        self.assertEqual(counters['giant_call_sites'], 12)
        self.assertEqual(counters['b_wrapper_site_records'], 14)
        self.assertEqual(counters['giant_caller_site_records'], 9)
        self.assertEqual(counters['memcpy_call_sites'], 32)
        self.assertEqual(counters['decode_stores'], 0)
        self.assertEqual(counters['giant_tail_stores'], 0)
        self.assertEqual(records['decode_body']['stores'], 0)
        self.assertEqual(records['staging']['sublookup_ca_middle'], [])
        self.assertEqual(
            len(records['staging']['sublookup_ca_staging']), 9)
        self.assertEqual(
            len(records['staging']['sublookup_jc1_staging']), 9)
        self.assertEqual(records['rela_named_targets'], [])
        self.assertEqual(records['lea_named_targets'], [])
        self.assertIn('parking buffer',
                      records['verdict']['giants_tail_source'])

    def test_wrong_artifact_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            with self.assertRaises(packet.PacketError):
                packet.generate(b'\x00' * 1024, out)
            self.assertFalse(out.exists())

    def test_digest_drift_in_decode_body(self):
        off = _file_offset(self.data, 0x24CB0A0)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 10))

    def test_full_pin_drift_in_wrapper(self):
        off = _file_offset(self.data, 0x55A03C0)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 100))

    def test_partial_pin_drift_in_sublookup(self):
        # the pinned final tag store `mov %r12,(%rbx)` at 0x2bb97ca
        off = _file_offset(self.data, 0x2BB97CA)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off))

    def test_memcpy_table_drift_in_helper(self):
        # the edx size load just before the first memcpy in helper_s3b
        site = packet.EXPECTED['memcpy_census']['helper_s3b']['call_sites'][0]
        off = _file_offset(self.data, int(site, 16) - 16)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off))


if __name__ == '__main__':
    unittest.main()
