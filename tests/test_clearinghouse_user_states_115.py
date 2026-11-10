"""Node #115 Clearinghouse.user_states fields and per-user entries. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import clearinghouse_user_states_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-user-states-115/evidence.json'


class ClearinghouseUserStatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_fields(self):
        names = {f['name']: f['offset'] for f in self.result['user_states_fields']}
        self.assertEqual(names, {'user_to_state': '0x0', 'open_order_tracker': '0x48', 'asset_to_oi_szi': '0x90',
                                 'users_with_positions': '0xb0', 'ar': '0xc8',
                                 'check_all_users_for_liquidatables': '0xe0'})
        values = {f['name']: f['offset'] for f in self.result['per_user_value_fields']}
        self.assertEqual(values, {'u': '0x48', 'p': '0x0', 'D': '0x28', 'l': '0x68', 'S': '0x50', 'r': '0x60'})
        self.assertEqual(self.result['user_to_state']['entry_stride'], '0x98')

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data)

    def test_caller_offset_rejected(self):
        # lea rdi,[rbx+0x60] -> [rbx+0x68]
        self._rejects(self._patch(0x4482247, b'\x68'))

    def test_field_offset_rejected(self):
        # users_with_positions lea rsi,[rbx+0xb0] -> +0xb8
        self._rejects(self._patch(0x446b6bc, b'\xb8'))

    def test_field_name_rejected(self):
        # user_to_state -> user_to_statf
        self._rejects(self._patch(0x7d1614 + 12, b'f'))

    def test_helper_offset_rejected(self):
        # open_order_tracker lea rsi,[rbx+0x48] -> +0x50
        self._rejects(self._patch(0x446b757, b'\x50'))

    def test_entry_stride_rejected(self):
        # imul rax,rbx,0x98 -> 0x90
        self._rejects(self._patch(0x4663fd4, b'\x90'))

    def test_key_offset_rejected(self):
        # add rax,0x80 -> 0x88
        self._rejects(self._patch(0x4664114, b'\x88'))

    def test_value_field_name_rejected(self):
        # 'u' -> 'v'
        self._rejects(self._patch(0x7ba759, b'v'))

    def test_value_field_offset_rejected(self):
        # lea rbx,[r13+0x68] -> +0x70
        self._rejects(self._patch(0x3beaf29, b'\x70'))


if __name__ == '__main__':
    unittest.main()
