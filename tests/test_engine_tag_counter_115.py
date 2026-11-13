"""Node #115 engine value tag, height assert and 3.0 s gate. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import engine_tag_counter_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-engine-tag-counter-115/evidence.json'


class EngineTagCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['fill']['slot_calls'], ['0x2d2760c', '0x5a08fbc', '0x5a6c104'])
        self.assertEqual(len(self.result['mismatch']['slot_calls']), 7)
        self.assertEqual(self.result['slow_lock_gate']['levels'], [14, 15, 19, 20, 21, 22, 32])
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

    def test_fill_tag_compare_rejected(self):
        # cmp dword [rsi], 2 -> 3
        self._rejects(self._patch(0x38c65aa + 2, b'\x03'))

    def test_fast_tag_rejected(self):
        # mov [rsp+0xe20], 2 -> 1
        self._rejects(self._patch(0x5a6c0e0 + 8, b'\x01'))

    def test_catch_up_tag_rejected(self):
        # mov [rsp+0x200], 2 -> 1
        self._rejects(self._patch(0x2b1e1d9 + 8, b'\x01'))

    def test_singleton_name_rejected(self):
        # abci_engine -> abci_enginE
        self._rejects(self._patch(0x7a14dc + 10, b'E'))

    def test_assert_kind_rejected(self):
        # xor edi, edi -> xor esi, esi
        self._rejects(self._patch(0x5a0563a + 1, b'\xf6'))

    def test_assert_location_rejected(self):
        # line 262 -> 263
        self._rejects(self._patch(packet.LOC_ENGINE + 16, b'\x07'))

    def test_level_mask_rejected(self):
        # mask bit 14 -> bit 13
        self._rejects(self._patch(0x4fc18df + 3, b'\x20'))

    def test_threshold_rejected(self):
        # 3.0 -> 3.5
        self._rejects(self._patch(packet.THRESHOLD + 6, b'\x0c'))


if __name__ == '__main__':
    unittest.main()
