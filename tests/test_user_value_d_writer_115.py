"""Node #115 per-user value D writer. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_d_writer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-d-writer-115/evidence.json'


class UserValueDWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_writer_matches_decoder_layout(self):
        r = self.result
        self.assertEqual(r['pairs_writer']['key_pointer'], 'entry + 0x0')
        self.assertEqual(r['pairs_writer']['value_pointer'], 'entry + 0x8')
        self.assertEqual(r['value_writer']['order'], ['a', 'c'])
        self.assertEqual((r['value_writer']['a']['entry_offset'], r['value_writer']['c']['entry_offset']),
                         (r['link_6319']['a'], r['link_6319']['c']))
        self.assertEqual(r['forms']['small']['entry_size'], r['link_6319']['entry_size'])
        self.assertEqual(r['names'], {'0x79d2d7': 'a', '0x79d2d8': 'c'})
        self.assertEqual(r['key_writer']['date_slot'], '0x64e1158')
        self.assertFalse(r['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, va, new):
        off = self._off(va)
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

    def test_rejects_changed_a_name(self):
        self._rejects(self._patch(0x79d2d7, b'b'))

    def test_rejects_changed_small_form_tag(self):
        self._rejects(self._patch(0x464d15e, b'\x03'))

    def test_rejects_changed_entry_stride(self):
        self._rejects(self._patch(0x45fa378, b'\x20'))

    def test_rejects_changed_value_pointer(self):
        self._rejects(self._patch(0x45fa381, b'\x10'))

    def test_rejects_changed_value_writer_call(self):
        raw = self.data[self._off(0x45fa60e):self._off(0x45fa60e) + 1]
        self._rejects(self._patch(0x45fa60e, bytes([(raw[0] + 1) & 0xff])))

    def test_rejects_changed_skip_a_target(self):
        self._rejects(self._patch(0x3674e0a, b'\x2a'))

    def test_rejects_changed_date_slot(self):
        self._rejects(self._patch(0x44dbf1b, b'\x41'))

    def test_rejects_changed_outer_bracket(self):
        self._rejects(self._patch(0x45fa2f0, b'\x7b'))

    def test_rejects_changed_c_offset(self):
        self._rejects(self._patch(0x3674dc5, b'\x10'))

    def test_rejects_changed_separator(self):
        self._rejects(self._patch(0x45fa582, b'\x3a'))

    def test_rejects_changed_form_test(self):
        # neg rcx -> not rcx: only the pin can see it
        self._rejects(self._patch(0x464d0e2, b'\xd1'))


if __name__ == '__main__':
    unittest.main()
