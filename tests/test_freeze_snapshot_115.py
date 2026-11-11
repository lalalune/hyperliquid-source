"""Node #115 freeze height, snapshot divisor and periodic path. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import freeze_snapshot_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-freeze-snapshot-115/evidence.json'


class FreezeSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['freeze_height']['stores'],
                         {'+0x1c58': ['0x54c9be2'], '+0x1c60': ['0x54c9bed']})
        self.assertEqual(self.result['freeze_height']['setter_direct_calls'], ['0x5399650'])
        self.assertEqual(self.result['snapshot_divisor']['store'], ['0x539e19c'])
        self.assertEqual(self.result['freeze_file']['slot_users'], ['0x5443930', '0x59ec200'])
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

    def test_window_rejected(self):
        # add rcx, 50000 -> 50001
        self._rejects(self._patch(0x54c9bb7 + 3, b'\x51'))

    def test_existing_compare_rejected(self):
        # jae -> jb on the Some(old) compare
        self._rejects(self._patch(0x54c9ba0, b'\x72'))

    def test_ok_tag_rejected(self):
        # 0x1a2 -> 0x1a3
        self._rejects(self._patch(0x54c9bf4 + 3, b'\xa3'))

    def test_divisor_constant_rejected(self):
        # mov eax, 10000 -> 10001
        self._rejects(self._patch(0x5398318 + 1, b'\x11'))

    def test_divisor_error_tag_rejected(self):
        # 0x155 -> 0x156
        self._rejects(self._patch(0x539832f + 4, b'\x56'))

    def test_freeze_path_rejected(self):
        # freeze_abci_height -> freeze_abci_heighT
        self._rejects(self._patch(0x445085 + 37, b'T'))

    def test_hour_gate_rejected(self):
        # cmp al, 2 -> cmp al, 3
        self._rejects(self._patch(0x5a08930 + 1, b'\x03'))

    def test_day_shift_rejected(self):
        # mov esi, -1 -> -2
        self._rejects(self._patch(0x5a089ba + 1, b'\xfe'))

    def test_extra_store_rejected(self):
        # turn the +0x1c60 load at 0x54c9b96 into a store (8b -> 89): census must change
        self._rejects(self._patch(0x54c9b96 + 1, b'\x89'))


if __name__ == '__main__':
    unittest.main()
