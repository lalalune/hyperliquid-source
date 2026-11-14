"""Node #115 cls element +0x58 = Clearinghouse.meta.collateralToken. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import clearinghouse_field_58_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-field-58-115/evidence.json'


class ClearinghouseField58Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_field(self):
        self.assertEqual(self.result['field_58'], 'Clearinghouse.meta.collateralToken')
        self.assertEqual(self.result['perp_meta_layout']['collateralToken'], '+0x58')
        self.assertEqual(self.result['clearinghouse_layout']['total_net_deposit'], '+0x4a8')
        self.assertEqual(self.result['clearinghouse_matcher']['indices']['halted_assets'], 9)
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

    def test_serializer_offset_rejected(self):
        # lea rcx, [rbx+0x58] -> [rbx+0x60]
        self._rejects(self._patch(0x3c40503 + 3, b'\x60'))

    def test_field_name_rejected(self):
        # collateralToken -> collateralTokeN
        self._rejects(self._patch(0x7bbf0d + 14, b'N'))

    def test_seq_store_rejected(self):
        # mov [r14+0x58], r12 -> [r14+0x50]
        self._rejects(self._patch(0x2f884ab + 3, b'\x50'))

    def test_map_store_rejected(self):
        # mov [rbx+0x58], rax -> [rbx+0x60]
        self._rejects(self._patch(0x30eaddb + 3, b'\x60'))

    def test_element_index_rejected(self):
        # invalid_length(3) -> (4)
        self._rejects(self._patch(0x2f88574 + 1, b'\x04'))

    def test_matcher_index_rejected(self):
        # halted_assets -> index 10
        self._rejects(self._patch(0x445deae + 1, b'\x0a'))

    def test_balance_offset_rejected(self):
        # mov rsi, [rbx+0x4a8] -> [rbx+0x4b0]
        self._rejects(self._patch(0x4482341 + 3, b'\xb0'))

    def test_matcher_immediate_rejected(self):
        # 'halted_a' -> 'halted_b'
        self._rejects(self._patch(0x445de8a + 9, b'b'))


if __name__ == '__main__':
    unittest.main()
