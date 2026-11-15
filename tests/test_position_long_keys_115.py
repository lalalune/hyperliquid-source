"""Node #115 position decoder long key names. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_long_keys_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-long-keys-115/evidence.json'


class PositionLongKeysTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_both_matchers_accept_the_same_keys(self):
        want = {'s': 0, 'szi': 0, 'l': 1, 'leverage': 1, 'M': 2, 'f': 3, 'cum_funding': 3,
                'e': 4, 'entry_ntl': 4}
        for name in ('bytes', 'string'):
            m = self.result['matchers'][name]
            self.assertEqual(m['keys'], want)
            self.assertEqual((m['max_key_length'], m['other_index']), (11, 5))
        self.assertGreater(len('margin_table_id'), 11)

    def test_fields_and_defaults(self):
        entries = self.result['field_table']['entries']
        self.assertEqual([entries[str(i)]['field'] for i in range(6)], ['s', 'l', 'M', 'f', 'e', 'skip'])
        self.assertEqual(self.result['defaults']['M'], 20)
        self.assertEqual(self.result['defaults']['l'], {'tag': 0, 'leverage': 20})
        names = {v['text'] for v in self.result['strings'].values()}
        self.assertTrue({'s', 'l', 'M', 'f', 'e', 'Szi', 'Ntl', 'MarginTableId'} <= names)
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

    def _rejects(self, data, *drop):
        saved = packet.PINS
        packet.PINS = {k: v for k, v in saved.items() if k not in drop}
        try:
            with self.assertRaises(ValueError):
                packet.bind(data)
        finally:
            packet.PINS = saved

    def test_pin_alone_rejects(self):
        self._rejects(self._patch(0x183e05f, b'\x66'))

    def test_byte_matcher_spelling_rejected(self):
        # leverage: cmp [rsi+1],'e' -> 'f'
        self._rejects(self._patch(0x183e05f, b'\x66'), 0x183e010)

    def test_string_matcher_spelling_rejected(self):
        # cum_funding second qword: '_funding' -> '_fundinh'
        self._rejects(self._patch(0x2d12a87, b'\x68'), 0x2d129d0)

    def test_length_cap_rejected(self):
        # dec edx; cmp edx,0xa -> cmp edx,0xe (keys up to 15 bytes)
        self._rejects(self._patch(0x183e014, b'\x0e'), 0x183e010)

    def test_key_index_rejected(self):
        # leverage -> index 2 in the string matcher
        self._rejects(self._patch(0x2d12a28, b'\x02'), 0x2d129d0)

    def test_field_table_rejected(self):
        # swap index 1 and index 2 arms in the field table
        raw = packet.read_va(self.data, 0x59c45c + 4, 8)
        self._rejects(self._patch(0x59c45c + 4, raw[4:] + raw[:4]))

    def test_length_table_rejected(self):
        # string matcher: length 4 now goes to the leverage arm
        rel = (0x2d12a18 - 0x60fc28).to_bytes(4, 'little', signed=True)
        self._rejects(self._patch(0x60fc28 + 4 * 3, rel))

    def test_field_name_rejected(self):
        # Szi -> Szj
        self._rejects(self._patch(0x5f420f, b'j'))

    def test_default_rejected(self):
        # mov ecx,0x14 -> mov ecx,0x15 at the end-of-map defaults
        self._rejects(self._patch(0x1bb7b50, b'\x15'), 0x1bb7b1b)


if __name__ == '__main__':
    unittest.main()
