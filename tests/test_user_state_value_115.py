"""Node #115 per-user state value fields and types. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_state_value_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-state-value-115/evidence.json'


class UserStateValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_fields(self):
        f = self.result['fields']
        self.assertEqual(list(f), ['u', 'p', 'D', 'l', 'S', 'r'])
        self.assertEqual(f['u']['type'], 'i64')
        self.assertEqual(f['r']['type'], 'u64')
        self.assertEqual(self.result['p_struct']['n']['offset'], '+0x20')
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
            packet.bind(data)

    def test_signed_writer_rejected(self):
        # neg rcx -> not rcx
        self._rejects(self._patch(0x41d5392, b'\xd1'))

    def test_unsigned_formatter_rejected(self):
        # mov eax,0x14 -> mov eax,0x15
        self._rejects(self._patch(0x46ef582, b'\x15'))

    def test_field_name_rejected(self):
        # 'D' -> 'E'
        self._rejects(self._patch(0x7bad69, b'E'))

    def test_u_offset_rejected(self):
        # [rdi+0x48] -> [rdi+0x50]
        self._rejects(self._patch(0x3beac17, b'\x50'))

    def test_p_item_stride_rejected(self):
        # rcx*9 -> rcx*5
        self._rejects(self._patch(0x4664a56, b'\x89'))

    def test_d_item_stride_rejected(self):
        # rcx*3 -> rcx*5
        self._rejects(self._patch(0x464d146, b'\x89'))

    def test_l_display_rejected(self):
        # 'T' -> 'U'
        self._rejects(self._patch(0x46dd745, b'\x55'))

    def test_s_writer_call_rejected(self):
        # retarget the S call by one byte
        self._rejects(self._patch(0x3beafea, b'\x00'))


if __name__ == '__main__':
    unittest.main()
