"""Node #115 per-user value: visitor-to-layout link. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_value_visitor_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-value-visitor-115/evidence.json'


class UserValueVisitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_fields_land_on_writer_offsets(self):
        layout = self.result['layout']
        self.assertEqual({k: v['output_offset'] for k, v in layout.items()},
                         {'u': '0x48', 'p': '0x0', 'D': '0x28', 'l': '0x68', 'S': '0x50', 'r': '0x60'})
        self.assertEqual({k: v['index'] for k, v in layout.items()},
                         {'u': 0, 'p': 1, 'D': 2, 'l': 3, 'S': 4, 'r': 5})
        self.assertEqual(self.result['final_copy'], [{'from_rsp': '0x138', 'to_rbx': '0x0', 'width': 120}])
        self.assertEqual(self.result['l_default']['value'], '0xf6401a')

    def test_p_and_s_keys(self):
        sub = self.result['sub_decoders']
        self.assertEqual(sub['sixteen_byte_key_index'], {'perp_to_position': 0, 'n_open_positions': 1})
        self.assertEqual(sub['byte_key_fallback']['keys'], ['n_open_positions', 'perp_to_position'])
        self.assertEqual(sub['pcmpeqb_rip_sites'], {'p_decoder': 2, 's_decoder': 0})
        self.assertFalse(sub['s_decoder']['long_key_compare'])
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

    def _rejects(self, data, pins=None):
        saved = packet.PINS
        if pins is not None:
            packet.PINS = pins
        try:
            with self.assertRaises(ValueError):
                packet.bind(data)
        finally:
            packet.PINS = saved

    def _without(self, *vas):
        return {k: v for k, v in packet.PINS.items() if k not in vas}

    def test_pinned_byte_rejected(self):
        # S arm: cmp [rsp+0x108],1 -> cmp [rsp+0x108],2
        self._rejects(self._patch(0x1a220d5 + 8, b'\x02'))

    def test_index_table_arm_rejected(self):
        # table entry for index 0 (u) given the entry of index 1 (p)
        sec = next(s for s in sections(self.data) if s['address'] <= 0x5227e0 < s['address'] + s['size'])
        off = sec['offset'] + 0x5227e0 - sec['address']
        p_entry = self.data[off + 4:off + 8]
        self._rejects(self._patch(0x5227e0, p_entry))

    def test_final_copy_offset_rejected(self):
        # movups [rbx+0x50],xmm0 -> [rbx+0x58]; the copy pin is dropped so the decoder must catch it
        self._rejects(self._patch(0x1a227ef + 3, b'\x58'), self._without(0x1a227bb))

    def test_relay_copy_rejected(self):
        # second exit: movaps [rsp+0xd0],xmm0 -> [rsp+0xc0] (S staged over the D tail)
        self._rejects(self._patch(0x1a228e1 + 4, b'\xc0'), self._without(0x1a2289d))

    def test_l_default_rejected(self):
        # visitor l default 0xf6401a -> 0xf6401b (writer keeps 0xf6401a)
        self._rejects(self._patch(0x1a2270f + 2, b'\x1b'), self._without(0x1a226da))

    def test_alias_string_rejected(self):
        # perp_to_position -> perp_to_positiom in the 16-byte constant
        self._rejects(self._patch(0x456010 + 15, b'm'))

    def test_byte_key_chain_rejected(self):
        # byte-key fallback: cmp byte [rsi+0xf],'n' (perp_to_position) -> 'm'
        self._rejects(self._patch(0x184ca71 + 3, b'm'))

    def test_decoder_call_rejected(self):
        # S arm call target moved by one byte; the S arm pin is dropped
        sec = next(s for s in sections(self.data) if s['address'] <= 0x1a220f1 < s['address'] + s['size'])
        off = sec['offset'] + 0x1a220f1 - sec['address']
        rel = struct.unpack_from('<i', self.data, off + 1)[0] + 1
        self._rejects(self._patch(0x1a220f1 + 1, struct.pack('<i', rel)), self._without(0x1a220d5))


if __name__ == '__main__':
    unittest.main()
