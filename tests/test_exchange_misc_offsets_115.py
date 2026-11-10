"""Node #115 ExchangeMisc field offsets and field `i` stop byte. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import exchange_misc_offsets_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-exchange-misc-offsets-115/evidence.json'


class ExchangeMiscOffsetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_field_table(self):
        got = {f['name']: (f['struct_offset'], f['box_offset_A']) for f in self.result['fields']}
        self.assertEqual(got['i'], ('0xa0', '0x39a8'))
        self.assertEqual(got['sgd'], ('0x0', '0x3908'))
        self.assertEqual(got['mou'], ('0x10', '0x3918'))
        self.assertEqual(got['tce'], ('0xf5', '0x39fd'))
        self.assertEqual(len(got), 12)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_panic_polarity(self):
        rules = [s['arms_on'] for s in self.result['panic_sites']]
        self.assertEqual(rules.count('byte & 1 != 0'), 3)
        self.assertEqual(rules.count('byte == 0'), 3)
        for s in self.result['panic_sites']:
            self.assertFalse(s['arms_for_byte']['2'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_jump_table_rejected(self):
        # field 6 (i) case entry +1
        off = packet.JUMP_TABLE + 4 * 6
        raw = bytearray(packet.read_va(self.data, off, 4))
        raw[0] = (raw[0] + 1) & 0xff
        self._rejects(self._patch(off, bytes(raw)))

    def test_i_decoder_call_rejected(self):
        # call 47922c0 -> call 47922c1
        self._rejects(self._patch(0x490e0e9 + 1, b'\xd3'))

    def test_output_store_rejected(self):
        # mov [rsp+0x388],rsi -> [rsp+0x389]
        self._rejects(self._patch(0x490f290 + 4, b'\x89'))

    def test_copy_size_rejected(self):
        # mov edx,0xf8 -> 0xf0
        self._rejects(self._patch(0x490f342 + 1, b'\xf0'))

    def test_nil_byte_rejected(self):
        # nil writes 2 -> 3
        self._rejects(self._patch(0x47923c3 + 3, b'\x03'))

    def test_begin_test_rejected(self):
        # test byte [r13+0x39b0],1 -> ,2
        self._rejects(self._patch(0x5483903 + 7, b'\x02'))

    def test_builder_cmp_rejected(self):
        # cmp byte [r12+0x39b0],0 -> ,1
        self._rejects(self._patch(0x548bfc9 + 8, b'\x01'))

    def test_field_name_rejected(self):
        # 'uta' -> 'vta'
        self._rejects(self._patch(packet.NAMES[0], b'v'))


if __name__ == '__main__':
    unittest.main()
