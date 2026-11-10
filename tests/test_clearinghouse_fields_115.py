"""Node #115 Clearinghouse and PerpMeta field tables. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import clearinghouse_fields_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-fields-115/evidence.json'


class ClearinghouseFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_tables(self):
        fields = self.result['clearinghouse']['fields']
        self.assertEqual(len(fields), 19)
        by_name = {f['name']: f for f in fields}
        self.assertEqual(by_name['total_net_deposit']['offset'], '0x4a8')
        self.assertEqual(by_name['halted_assets']['index'], 9)
        self.assertEqual(by_name['moh']['index'], 17)
        meta = {f['name']: f['offset'] for f in self.result['perp_meta']['fields']}
        self.assertEqual(meta, {'universe': '0x0', 'pdi': '0x50', 'marginTableIdToMarginTable': '0x30',
                                'collateralToken': '0x58', 'collateralTokenName': '0x18'})
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

    def test_name_byte_rejected(self):
        # total_net_deposit -> uotal_net_deposit
        self._rejects(self._patch(0x7d19e3, b'u'))

    def test_offset_rejected(self):
        # mov rsi,[rbx+0x4a8] -> [rbx+0x4b0]
        self._rejects(self._patch(0x4482341 + 3, b'\xb0'))

    def test_index_rejected(self):
        # halted_assets index 9 -> 8
        self._rejects(self._patch(0x445deae + 1, b'\x08'))

    def test_unknown_index_rejected(self):
        self._rejects(self._patch(0x445e0da + 1, b'\x14'))

    def test_helper_call_rejected(self):
        # call 0x44f46e0 retargeted by one byte
        self._rejects(self._patch(0x448240d + 1, b'\x00'))

    def test_meta_call_rejected(self):
        self._rejects(self._patch(0x4482213 + 1, b'\x00'))

    def test_perp_meta_offset_rejected(self):
        # lea rcx,[rbx+0x58] -> [rbx+0x60]
        self._rejects(self._patch(0x3c40503 + 3, b'\x60'))

    def test_perp_meta_name_rejected(self):
        # collateralToken -> CollateralToken
        self._rejects(self._patch(0x7bbf0d, b'C'))


if __name__ == '__main__':
    unittest.main()
