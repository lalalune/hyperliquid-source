import tempfile
import unittest
from pathlib import Path

from tools import family_callers_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-family-callers')


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


class FamilyCallersPacketTests(unittest.TestCase):
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
        self.assertEqual(counters['bodies'], 25)
        self.assertEqual(counters['exported_bodies'], 18)
        self.assertEqual(counters['target_bodies'], 4)
        self.assertEqual(counters['control_bodies'], 2)
        self.assertEqual(counters['caller_fdes'], 19)
        self.assertEqual(counters['target_sites'], 29)
        self.assertEqual(counters['control_sites'], 6)
        self.assertEqual(counters['total_sites'], 35)
        for kind in ('jmp_sites', 'lea_refs', 'load_refs',
                     'slot_refs', 'rela_addends'):
            self.assertEqual(counters[kind], 0, kind)
        censuses = records['censuses']
        self.assertEqual(censuses['inner_ca']['by_caller'],
                         {'0x2bb7270': 3})
        self.assertEqual(censuses['inner_s3']['by_caller'],
                         {'0x2c62820': 3})
        self.assertEqual(censuses['inner_fam_b1']['by_caller'],
                         {'0x55defd0': 3})
        self.assertEqual(censuses['inner_fam_b2']['by_caller'],
                         {'0x55e16d0': 3})
        self.assertEqual(censuses['inner_c750']['by_caller'], {
            '0x2a8a000': 1, '0x2a8a360': 1, '0x2bb98a0': 1,
            '0x2bba100': 2, '0x2bbbb40': 1, '0x2bdf8f0': 3})
        self.assertEqual(censuses['inner_fam_b3']['by_caller'], {
            '0x548ebd0': 1, '0x548f430': 2, '0x5493020': 1,
            '0x54a9c70': 3, '0x54b66b0': 3, '0x55a1de0': 1,
            '0x55a2050': 1, '0x55a22c0': 1, '0x55a2550': 1})
        site = censuses['inner_fam_b3']['sites']['0x54b3288']
        rcx = site['bindings']['rcx']
        self.assertEqual(rcx['form'], 'lea_other')
        self.assertEqual(rcx['src'], '0x90(%rbx)')
        shim = censuses['inner_c750']['sites']['0x2bbbb53']
        self.assertEqual(shim['caller_fde'], '0x2bbbb40')
        self.assertEqual(shim['bindings']['rcx']['reg'], 'rdx')
        self.assertIn('caller map is complete', records['verdict'])
        self.assertIn('86-byte shims', records['verdict'])

    def test_wrong_artifact_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            with self.assertRaises(packet.PacketError):
                packet.generate(b'\x00' * 1024, out)
            self.assertFalse(out.exists())

    def test_digest_drift_in_family_body(self):
        off = _file_offset(self.data, 0x5494720)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 10))

    def test_pin_drift_at_shim_call_site(self):
        off = _file_offset(self.data, 0x2BBBB53)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off))

    def test_drift_in_digest_only_caller_fde(self):
        off = _file_offset(self.data, 0x54A9C70)
        with self.assertRaises(AssertionError):
            packet.analyze(_flip(self.data, off + 50))


if __name__ == '__main__':
    unittest.main()
