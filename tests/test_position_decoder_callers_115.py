"""Node #115 callers of the second MessagePack position decoder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_decoder_callers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-decoder-callers-115/evidence.json'


class PositionDecoderCallersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_both_callers_are_one_map_decoder_of_the_p_value(self):
        r = self.result
        self.assertEqual((r['map_decoder']['fixmap'], r['map_decoder']['fixarray']),
                         ('0x372f280', '0x37b7a80'))
        self.assertEqual(r['direct_callers']['0x32d3c90'], ['0x318126c', '0x372f3ae'])
        self.assertEqual(r['p_decoder']['keys'],
                         {'p': 0, 'n': 1, 'perp_to_position': 0, 'n_open_positions': 1})
        self.assertEqual(r['leas']['0x372f384']['text'], 'Perp')
        self.assertFalse(r['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, data, va):
        sec = next(s for s in sections(data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, data, va, new):
        off = self._off(data, va)
        broken = bytearray(data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _bump_rel32(self, data, va):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + 1))

    def _rejects(self, data, *drop, matcher=True, jumps=(), why):
        saved = packet.PINS, packet.MATCHER_BYTES, packet.JUMPS
        packet.PINS = {k: v for k, v in saved[0].items() if k not in drop}
        packet.JUMPS = {k: v for k, v in saved[2].items() if k not in jumps}
        if not matcher:
            body = packet.read_va(data, packet.P_MATCHER, packet.P_MATCHER_END - packet.P_MATCHER)
            packet.MATCHER_BYTES = body.hex()
        try:
            with self.assertRaisesRegex(ValueError, why):
                packet.bind(data)
        finally:
            packet.PINS, packet.MATCHER_BYTES, packet.JUMPS = saved

    def test_pin_alone_rejects(self):
        # map visitor entry stride: lea rcx,[rbx+rbx*8] -> [rbx+rbx*4]
        self._rejects(self._patch(self.data, 0x372f308, b'\x9b'), why='0x372f305')

    def test_matcher_pin_rejects(self):
        self._rejects(self._patch(self.data, 0x2fd3224, b'\x66'), why='p key matcher')

    def test_long_key_spelling_rejected(self):
        # perp_to_position -> pfrp_to_position, with the matcher pin taken from the copy
        self._rejects(self._patch(self.data, 0x2fd3224, b'\x66'), matcher=False,
                      why='long keys spell')

    def test_first_byte_compare_rejected(self):
        # cmp eax,'p' -> cmp eax,'q'
        self._rejects(self._patch(self.data, 0x2fd321a, b'\x71'), matcher=False,
                      why='first-byte compares')

    def test_perp_name_rejected(self):
        self._rejects(self._patch(self.data, 0x45a0d0, b'Q'), why='0x45a0d0')

    def test_map_form_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x314bcd6), 0x314bcc2, why='0x314bcd5')

    def test_array_form_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x314bd84), 0x314bd70, why='0x314bd83')

    def test_marker_split_rejected(self):
        # jae 0x314bc03 -> jae 0x314bc04
        self._rejects(self._patch(self.data, 0x314bbf8, b'\x0b'), 0x314bbf5, why='0x314bbf7')

    def test_element_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x37b7b6f), 0x37b7b61, why='0x37b7b6e')

    def test_decoder_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x318126d), 0x318125f, why='0x318126c')

    def test_caller_census_rejected(self):
        # move one call to 0x314bba0; pins and the branch entry removed, so the census must catch it
        self._rejects(self._bump_rel32(self.data, 0x3184dec), 0x3184dd6,
                      jumps=(0x3184deb,), why='direct callers of 0x314bba0')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x372f3ae: packet.SEQ_VISITOR}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
