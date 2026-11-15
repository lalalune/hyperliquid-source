"""Node #115 ExchangeMisc scalar field readers. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import exchange_misc_readers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-exchange-misc-readers-115/evidence.json'


class ExchangeMiscReadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        c = self.result['census']
        self.assertEqual({k: (len(v['A']['sites']), len(v['B']['sites'])) for k, v in c.items()},
                         {'aci': (9, 2), 'mtpt': (7, 3), 'pmc': (6, 2), 'tde': (7, 3), 'tce': (9, 5)})
        self.assertIn('0x5a07ec0', c['aci']['A']['functions'])
        self.assertIn('0x5a08720', c['aci']['B']['functions'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_epoch_date(self):
        self.assertEqual(packet.naive_date(packet.EPOCH_DATE), (1970, 1))

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        b = bytearray(self.data)
        b[off:off + len(new)] = new
        return bytes(b)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_aci_offset_rejected(self):
        self._rejects(self._patch(0x5a07f85 + 3, b'\xd0'))      # +0x39c8 -> +0x39d0

    def test_div_rejected(self):
        self._rejects(self._patch(0x5a07f9d + 2, b'\xf3'))      # div rcx -> div rbx

    def test_range_low_rejected(self):
        self._rejects(self._patch(0x57c9f7e + 3, b'\x9e'))      # -0x2761 -> -0x2762

    def test_error_tag_rejected(self):
        self._rejects(self._patch(0x57c9f9c + 3, b'\xde'))      # 0xdd -> 0xde

    def test_tde_offset_rejected(self):
        self._rejects(self._patch(0x57ca27c + 2, b'\xfd'))      # +0x39fc -> +0x39fd

    def test_epoch_store_rejected(self):
        self._rejects(self._patch(0x54bfe47 + 7, b'\x1b'))      # 0xf6401a -> 0xf6401b

    def test_600_rejected(self):
        self._rejects(self._patch(packet.F600[0] + 6, b'\x83'))  # 600.0 -> other

    def test_dispatcher_store_rejected(self):
        self._rejects(self._patch(0x539e19c + 3, b'\x40'))      # +0x4538 -> +0x4540


if __name__ == '__main__':
    unittest.main()
