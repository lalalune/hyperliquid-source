"""Node #115 per-user value text writer is pretty JSON. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_text_writer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-text-writer-115/evidence.json'


class UserValueTextWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_result(self):
        self.assertEqual(self.result['entry']['rmp_extension'], '0x3c13960')
        self.assertEqual(self.result['entry']['other_extension'], '0x3c136f0')
        self.assertEqual(self.result['entry']['indent'], '  ')
        self.assertEqual(list(self.result['position_keys'].values()), ['s', 'l', 'M', 'f', 'e'])
        self.assertEqual([r['callee'] for r in self.result['chain']['path']][-1], '0x3beac00')
        self.assertEqual(self.result['json_reader']['matcher']['fields'],
                         {'s': 0, 'l': 1, 'M': 2, 'f': 3, 'e': 4,
                          'szi': 0, 'leverage': 1, 'entry_ntl': 4, 'cum_funding': 3})
        self.assertFalse(self.result['result']['output_only'])
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

    def _rejects(self, data, *drop, message=None):
        saved = packet.PINS
        packet.PINS = {k: v for k, v in saved.items() if k not in drop}
        try:
            with self.assertRaises(ValueError) as ctx:
                packet.bind(data)
            if message:
                self.assertIn(message, str(ctx.exception))
        finally:
            packet.PINS = saved

    def _rel_plus_one(self, call_site):
        rel = struct.unpack('<i', packet.read_va(self.data, call_site + 1, 4))[0]
        return self._patch(self.data, call_site + 1, struct.pack('<i', rel + 1))

    def test_first_key_newline_pin(self):
        # movb [rax+r13],0x0a -> 0x0d
        self._rejects(self._patch(self.data, 0x4713beb, b"\x0d"), message='0x4713bd3')

    def test_rmp_string_rejected(self):
        self._rejects(self._patch(self.data, packet.RMP + 2, b'q'), message='rmp')

    def test_indent_string_rejected(self):
        self._rejects(self._patch(self.data, packet.INDENT + 1, b'x'), message=hex(packet.INDENT))

    def test_extension_length_rejected(self):
        # mov ecx,3 -> mov ecx,4 (inside a pin, so drop the pin)
        self._rejects(self._patch(self.data, 0x422ee30, b'\x04'), 0x422ee28,
                      message='extension length')

    def test_json_serializer_call_rejected(self):
        # call 0x3c136f0 -> 0x3c136f1: the chain census loses the only caller
        self._rejects(self._rel_plus_one(0x422ef08), 0x422eedd, message='0x3c136f0 direct callers')

    def test_matcher_call_rejected(self):
        self._rejects(self._rel_plus_one(0x402ea50), 0x402ea50, message='0x4455890')

    def test_m_byte_arm_rejected(self):
        # 1-byte key table entry for 'M' points 1 byte later
        entry = struct.unpack('<i', packet.read_va(self.data, packet.CHAR_TABLE, 4))[0]
        data = self._patch(self.data, packet.CHAR_TABLE, struct.pack('<i', entry + 1))
        self._rejects(data, message="'M'")

    def test_long_key_length_arm_rejected(self):
        # length 11 ("cum_funding") table entry points elsewhere
        slot = packet.LEN_TABLE + 4 * 10
        entry = struct.unpack('<i', packet.read_va(self.data, slot, 4))[0]
        self._rejects(self._patch(self.data, slot, struct.pack('<i', entry + 1)), message='length 11')

    def test_length_bound_rejected(self):
        # cmp rdx,0x0a -> 0x0b (inside a pin, so drop the pin)
        self._rejects(self._patch(self.data, 0x4455899, b'\x0b'), 0x4455890, message='length bound')

    def test_position_key_rejected(self):
        self._rejects(self._patch(self.data, 0x7d082f, b't'), message='0x7d082f')

    def test_position_key_length_rejected(self):
        # mov edx,1 -> mov edx,2 for key l
        self._rejects(self._patch(self.data, 0x448af94, b'\x02'), message='length 1')

    def test_chain_string_rejected(self):
        # "user_states" -> "user_statez"
        self._rejects(self._patch(self.data, 0x7d07c9 + 10, b'z'), message='user_states')


if __name__ == '__main__':
    unittest.main()
