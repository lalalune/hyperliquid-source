"""Node #115 ExchangeMisc field i as Option<(u64, bool)>. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import field_i_stop_kind_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-field-i-stop-kind-115/evidence.json'


class FieldIStopKindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_type_and_arms(self):
        self.assertTrue(self.result['type'].startswith('Option<(u64, bool)>'))
        self.assertEqual(self.result['arm_table']['1']['begin A'], True)
        self.assertEqual(self.result['arm_table']['0']['quorum-entry builder A'], True)
        self.assertFalse(any(self.result['arm_table']['2'].values()))
        self.assertEqual(self.result['sha256'], packet.SHA256)

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

    def test_none_byte_rejected(self):
        self._rejects(self._patch(0x47923c3 + 3, b'\x03'))

    def test_false_arm_rejected(self):
        self._rejects(self._patch(0x3482435, b'\xb0\x00'))

    def test_true_arm_rejected(self):
        self._rejects(self._patch(0x3482549 + 1, b'\x02'))

    def test_and_mask_rejected(self):
        self._rejects(self._patch(0x47929d6 + 1, b'\x03'))

    def test_tuple_text_rejected(self):
        self._rejects(self._patch(0x7a0390 + 2, b'T'))

    def test_bool_table_rejected(self):
        self._rejects(self._patch(packet.BOOL_TABLE + 2 * 4, b'\x00'))

    def test_begin_site_rejected(self):
        self._rejects(self._patch(0x5483903 + 7, b'\x02'))

    def test_builder_site_rejected(self):
        self._rejects(self._patch(0x548bfc9 + 8, b'\x01'))


if __name__ == '__main__':
    unittest.main()
