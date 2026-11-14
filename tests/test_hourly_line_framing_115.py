"""Node #115 hourly line framing. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
import hourly_line_framing_115 as packet  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-008-hourly-line-framing-115/evidence.json'


class HourlyLineFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        c = self.result['line_writer_census']
        self.assertEqual((c['call_sites'], c['functions']), (96, 96))
        self.assertEqual(c['classes'], {'bracket_no_time': 39, 'other': 36, 'time_framed': 21})
        self.assertEqual(self.result['time_writer']['direct_calls'], 27)
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

    def test_open_bracket_rejected(self):
        self._rejects(self._patch(0x50e50ed + 2, b'\x7b'))      # '[' -> '{'

    def test_comma_rejected(self):
        self._rejects(self._patch(0x50e513d + 3, b'\x3b'))      # ',' -> ';'

    def test_close_bracket_rejected(self):
        self._rejects(self._patch(0x50e51d4 + 3, b'\x7d'))      # ']' -> '}'

    def test_quote_rejected(self):
        self._rejects(self._patch(0x4fcd889 + 3, b'\x27'))      # '"' -> "'"

    def test_date_time_separator_rejected(self):
        self._rejects(self._patch(0x57a6f34 + 1, b'\x20'))      # 'T' -> ' '

    def test_date_dash_rejected(self):
        self._rejects(self._patch(0x1628d09 + 1, b'\x2f'))      # '-' -> '/'

    def test_bare_newline_rejected(self):
        self._rejects(self._patch(0x50e60bb + 3, b'\x0d'))      # '\n' -> '\r'

    def test_visor_writer_call_rejected(self):
        self._rejects(self._patch(0x4e3ff5c + 1, b'\x50'))      # retarget call


if __name__ == '__main__':
    unittest.main()
