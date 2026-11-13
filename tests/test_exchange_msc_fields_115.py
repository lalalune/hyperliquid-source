"""Node #115 Exchange field `msc` type and field names. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import exchange_msc_fields_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-exchange-msc-fields-115/evidence.json'


class ExchangeMscFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_fields(self):
        self.assertEqual([f['name'] for f in self.result['fields']],
                         ['uta', 'mou', 'sgd', 'sog', 'tde', 'tce', 'i', 'mtpt', 'pmc', 'sre', 'vpv', 'aci'])
        self.assertEqual(self.result['type']['expecting'], 'struct ExchangeMisc with 12 elements')
        self.assertEqual(self.result['field_i']['box_layout_a'], {'+0x39a8': 'i u64', '+0x39b0': 'i byte'})
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

    def test_expecting_string_rejected(self):
        # "12 elements" -> "13 elements"
        self._rejects(self._patch(0x90f523 + 21, b'3'))

    def test_field_name_rejected(self):
        # field 6 name 'i' -> 'j'
        self._rejects(self._patch(0x90e933, b'j'))

    def test_name_length_rejected(self):
        # field 7 name length 4 -> 5
        self._rejects(self._patch(0x491017a + 17, b'\x05'))

    def test_jump_table_rejected(self):
        # jump table entry 6 retargeted
        self._rejects(self._patch(0x825408 + 4 * 6, b'\x00'))

    def test_none_byte_rejected(self):
        # nil -> byte 2 becomes 3
        self._rejects(self._patch(0x47923c3 + 3, b'\x03'))

    def test_output_offset_rejected(self):
        # mov [rsp+0x388], rsi -> [rsp+0x380]
        self._rejects(self._patch(0x490f290 + 4, b'\x80'))

    def test_unset_default_rejected(self):
        # mov edx, 2 -> mov edx, 1
        self._rejects(self._patch(0x490f0bd + 1, b'\x01'))

    def test_copy_size_rejected(self):
        # 0xf8-byte copy -> 0xf0
        self._rejects(self._patch(0x490f342 + 1, b'\xf0'))


if __name__ == '__main__':
    unittest.main()
