"""Node #115 position field M: value encoder writes decimal text. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_m_encoder_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-m-encoder-115/evidence.json'


class PositionMEncoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_encoder_chain(self):
        self.assertEqual(self.result['calls'], {'0x448b010': '0x4648d30', '0x4648d41': '0x4713ba0',
                                                '0x4648d7f': '0x46ef430'})
        self.assertEqual(self.result['encoder']['copy'], {'slot': '0x64df508', 'symbol': 'memcpy'})
        self.assertEqual(self.result['writer_m_site']['key']['text'], 'M')
        self.assertEqual(self.result['formatter']['max_digits'], 10)
        self.assertFalse(self.result['result']['value_changed'])
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, data, va, new):
        sec = next(s for s in sections(data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(data)
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
        self._rejects(self._patch(self.data, 0x4648d6c, b';'))

    def test_separator_rejected(self):
        # ": " -> "; "
        self._rejects(self._patch(self.data, 0x4648d6c, b';'), 0x4648d64)

    def test_later_entry_separator_rejected(self):
        # ",\n" -> ";\n"
        self._rejects(self._patch(self.data, 0x4713c11, b';'), 0x4713c07)

    def test_value_width_rejected(self):
        # mov edi,[rbx] -> movzx-like byte change of the opcode
        self._rejects(self._patch(self.data, 0x4648d76, b'\x8a'), 0x4648d64)

    def test_formatter_call_rejected(self):
        rel = packet.read_va(self.data, 0x4648d80, 4)
        new = struct.pack('<i', struct.unpack('<i', rel)[0] + 1)
        self._rejects(self._patch(self.data, 0x4648d80, new), 0x4648d64)

    def test_division_rejected(self):
        # 0xd1b71759 -> 0xd1b7175a
        self._rejects(self._patch(self.data, 0x46ef448, b'\x5a'), 0x46ef431)

    def test_loop_bound_rejected(self):
        # 99999999 -> 99999998
        self._rejects(self._patch(self.data, 0x46ef4c8, b'\xfe'), 0x46ef4c6)

    def test_ascii_digit_rejected(self):
        # or cl,0x30 -> or cl,0x31
        self._rejects(self._patch(self.data, 0x46ef4e6, b'\x31'), 0x46ef4e4)

    def test_digit_table_rejected(self):
        # "05" -> "0x" in the table (not pinned)
        self._rejects(self._patch(self.data, 0x7d9d8e + 11, b'x'))

    def test_key_rejected(self):
        # key "M" -> "N" (not pinned)
        self._rejects(self._patch(self.data, 0x7d13c1, b'N'))

    def test_memcpy_symbol_rejected(self):
        # GOT slot relocation bound to a different symbol: change its symbol index
        secs = [s for s in sections(self.data) if s['type'] == 4]
        for sec in secs:
            body = self.data[sec['offset']:sec['offset'] + sec['size']]
            for i, (va, info, add) in enumerate(struct.iter_unpack('<QQq', body)):
                if va == packet.MEMCPY_SLOT:
                    off = sec['offset'] + 24 * i + 8
                    broken = bytearray(self.data)
                    struct.pack_into('<Q', broken, off, ((info >> 32) + 1) << 32 | (info & 0xffffffff))
                    self._rejects(bytes(broken))
                    return
        self.fail('no relocation for the memcpy slot')


if __name__ == '__main__':
    unittest.main()
