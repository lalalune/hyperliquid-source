"""Node #115 +0x208 / +0x218 census sites. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import observer_day_field_sites_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-observer-day-field-sites-115/evidence.json'


class ObserverDayFieldSitesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census_complete(self):
        census = self.result['census']
        self.assertEqual((census['owner_functions'], census['plus_0x208'], census['plus_0x218']), (77, 17, 13))
        self.assertEqual(census['classified_here'], 23)
        self.assertEqual(self.result['shape_counts'], {'A': 2, 'B': 5, 'C': 3, 'D': 6, 'E': 7})
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_move_offset_rejected(self):
        # A: movups [rbx+0x208] -> [rbx+0x210]
        self._rejects(self._patch(0x2f195a7 + 3, b'\x10'))

    def test_window_limit_rejected(self):
        # A: observer +0x1f8 = 6000 -> 6001
        self._rejects(self._patch(0x2f19603 + 7, b'\x71'))

    def test_observer_name_rejected(self):
        # A: handle_request_rate_limiter -> handle_request_rate_limiteR
        self._rejects(self._patch(packet.NAME[0] + 26, b'R'))

    def test_lazy_offset_rejected(self):
        # B: add rax, 0x110 -> 0x118
        self._rejects(self._patch(0x2be19a7 + 2, b'\x18'))

    def test_niche_compare_rejected(self):
        # C: 0x8000000000000000 -> 0x8100000000000000
        self._rejects(self._patch(0x2be5ecd + 9, b'\x81'))

    def test_item_stride_rejected(self):
        # D: lea rcx, [rax+rcx*4] -> [rax+rcx*8]
        self._rejects(self._patch(0x2cc80f7 + 3, b'\xc8'))

    def test_reset_value_rejected(self):
        # E: +0x210 = 8 -> 9
        self._rejects(self._patch(0x422acf7 + 7, b'\x09'))

    def test_unclassified_site_rejected(self):
        # the census must equal the 7 named sites plus the 23 classified here
        from unittest import mock
        trimmed = dict(packet.SITES)
        del trimmed[0x2cc8b73]
        with mock.patch.object(packet, 'SITES', trimmed):
            self._rejects(self.data)


if __name__ == '__main__':
    unittest.main()
