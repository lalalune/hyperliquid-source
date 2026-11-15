"""Node #115 position item and CumFunding long field names. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import user_state_long_names_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-state-long-names-115/evidence.json'


class UserStateLongNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_tables(self):
        pos = {k: v['long'] for k, v in self.result['position_item']['short_to_long'].items()}
        self.assertEqual(pos, {'s': 'szi', 'l': 'leverage', 'M': 'margin_table_id',
                               'f': 'cum_funding', 'e': 'entry_ntl'})
        cum = {k: v['long'] for k, v in self.result['f_struct']['short_to_long'].items()}
        self.assertEqual(cum, {'a': 'all_time', 'o': 'since_open', 'c': 'since_change'})
        sizes = [f['vtable_size'] for f in self.result['position_item']['debug_fields_in_order']]
        self.assertEqual(sizes, [8, 16, 4, 24, 8])
        self.assertEqual(len(self.result['field5_slot_calls']), 6)
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

    def test_swapped_debug_offset_rejected(self):
        # lea r9, [r10+0x10] -> [r10+0x20]: szi no longer lands on the s offset
        self._rejects(self._patch(0x44dbc44 + 3, b'\x20'))

    def test_debug_name_length_rejected(self):
        # push 0xf -> push 0xe: margin_table_id read as margin_table_i
        self._rejects(self._patch(0x44dbcb1 + 1, b'\x0e'))

    def test_debug_push_order_rejected(self):
        # push r13 -> push r12 (cum_funding value replaced by a vtable)
        self._rejects(self._patch(0x44dbca5 + 1, b'\x54'))

    def test_struct_name_rejected(self):
        # "Position" -> "Positiom"
        self._rejects(self._patch(0x458d20 + 7, b'm'))

    def test_serde_f_offset_rejected(self):
        # lea rdi, [rbx+0x18] -> [rbx+0x20]
        self._rejects(self._patch(0x448b08e + 3, b'\x20'))

    def test_serde_key_rejected(self):
        # key "M" -> "N"
        self._rejects(self._patch(0x7d13c1, b'N'))

    def test_cum_debug_field_rejected(self):
        # lea rbx, [rdi+0x8] -> [rdi+0x10]: since_open moves
        self._rejects(self._patch(0x44e85d3 + 3, b'\x10'))

    def test_leverage_tag_rejected(self):
        # cmp dword [rdi], 1 -> 2
        self._rejects(self._patch(0x44e7cce + 2, b'\x02'))


if __name__ == '__main__':
    unittest.main()
