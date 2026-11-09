"""Node #115 periodic abci state paths and blocking wrapper. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import periodic_state_path_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-periodic-state-path-115/evidence.json'


class PeriodicStatePathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_paths(self):
        paths = self.result['periodic_paths']
        self.assertIn('periodic_abci_states/{%Y%m%d}/{height}.rmp', paths['result_plus_0x0'])
        self.assertIn('periodic_abci_state_statuses/{%Y%m%d}/{height}', paths['result_plus_0x18'])
        self.assertEqual(self.result['state_path']['from_step'], 'abci_state -> {root}/hyperliquid_data/abci_state.rmp')
        self.assertEqual(self.result['state_path']['samples']['abci_states'], 'json')
        self.assertFalse(self.result['gates_changed'])

    def test_census(self):
        census = self.result['census']
        self.assertEqual(census['0x4e45a30 direct'], ['0x548604b'])
        self.assertEqual(len(census['0x5942870 direct']), 4)
        self.assertEqual(census['0x38d8240 via slot 0x64e4f30'], 4)

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

    def test_date_format_rejected(self):
        # "%Y%m%d" -> "%Y-m%d"
        self._rejects(self._patch(0x465bc9 + 2, b'-'))

    def test_rmp_template_rejected(self):
        # "{}/{}/{}.rmp" -> ".rmq"
        self._rejects(self._patch(0x432d1a + 9, b'q'))

    def test_name_compare_rejected(self):
        # cmp qword [rsi+8], 10 -> 11
        self._rejects(self._patch(0x594288d + 4, b'\x0b'))

    def test_extension_rejected(self):
        # "json" -> "jsom"
        self._rejects(self._patch(0x459f60 + 3, b'm'))

    def test_wrapper_flag_rejected(self):
        # mov edx, 1 -> 0
        self._rejects(self._patch(0x5486046 + 1, b'\x00'))

    def test_wrapper_branch_rejected(self):
        # je -> jne at 0x4e45a41
        self._rejects(self._patch(0x4e45a41, b'\x75'))

    def test_location_line_rejected(self):
        # base/src/u.rs:531 -> 532
        self._rejects(self._patch(0x649db00 + 16, b'\x14'))

    def test_statuses_name_rejected(self):
        # periodic_abci_state_statuses -> ...statuseS
        self._rejects(self._patch(0x7a1586 + 27, b'S'))


if __name__ == '__main__':
    unittest.main()
