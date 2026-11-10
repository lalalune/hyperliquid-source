"""Node #115 per-user p.p and D item layouts. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_state_items_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-state-items-115/evidence.json'


class UserStateItemsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_layouts(self):
        r = self.result
        self.assertEqual(list(r['p_p_value_fields']), ['s', 'l', 'M', 'f', 'e'])
        self.assertEqual(r['p_p_item']['key']['type'], 'u64')
        self.assertEqual(r['p_p_value_fields']['M']['type'], 'u32')
        self.assertEqual(list(r['f_fields']), ['a', 'o', 'c'])
        self.assertEqual(list(r['d_value_fields']), ['a', 'c'])
        self.assertEqual(r['d_item']['size'], '0x18')
        self.assertFalse(r['gates_changed'])

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
            packet.bind(data)

    def test_pp_stride_rejected(self):
        # 0x8e38e38e38e38e39 -> ...3a
        self._rejects(self._patch(0x46344ca, b'\x3a'))

    def test_pp_key_load_rejected(self):
        # mov rsi,[rax] -> mov rsi,[rcx]
        self._rejects(self._patch(0x4634780, b'\x31'))

    def test_m_default_rejected(self):
        # cmp r8d,0x14 -> cmp r8d,0x15
        self._rejects(self._patch(0x448ae85, b'\x15'))

    def test_field_name_rejected(self):
        # 'f' -> 'g'
        self._rejects(self._patch(0x7d13cd, b'g'))

    def test_f_offset_rejected(self):
        # o = [rdi+0x8] -> [rdi+0x18]
        self._rejects(self._patch(0x448b435, b'\x18'))

    def test_d_stride_rejected(self):
        # lea rcx,[rax+0x18] -> [rax+0x20]
        self._rejects(self._patch(0x45fa378, b'\x20'))

    def test_d_key_date_slot_rejected(self):
        # retarget the Display tail jump by one byte
        self._rejects(self._patch(0x44dbf1b, b'\x3a'))

    def test_u32_formatter_rejected(self):
        # mov eax,0xa -> mov eax,0xb
        self._rejects(self._patch(0x46ef432, b'\x0b'))


if __name__ == '__main__':
    unittest.main()
