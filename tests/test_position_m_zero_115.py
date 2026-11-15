"""Node #115 position field M: zero rejected, 20 skipped. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_m_zero_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-m-zero-115/evidence.json'


class PositionMZeroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_every_integer_marker_rejects_zero(self):
        zero = self.result['m_value_decoder']['zero_rejected']
        self.assertEqual(sorted(zero), ['0xcc', '0xcd', '0xce', '0xcf', '0xd0', '0xd1', '0xd2',
                                        '0xd3', '0xe0', 'fixint'])
        texts = {v['text'] for k, v in self.result['strings'].items() if k != 'template'}
        self.assertIn('a nonzero u32', texts)
        self.assertIn('MarginTableId', texts)

    def test_writer_skips_default_and_decoder_fills_it(self):
        self.assertEqual(self.result['writer_m']['skips_when'], 20)
        self.assertEqual(self.result['decoder_m'], {'arm': '0x1bb6f07', 'not_seen': 0, 'default': 20})
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
        # u32: je error -> jne error
        self._rejects(self._patch(self.data, 0x34862ad, b'\x85'))

    def test_u32_zero_branch_rejected(self):
        self._rejects(self._patch(self.data, 0x34862ad, b'\x85'), 0x3486286)

    def test_u8_zero_test_rejected(self):
        # test ecx,ecx -> test eax,eax
        self._rejects(self._patch(self.data, 0x34862df, b'\xc0'), 0x34862bc)

    def test_i32_jmp_target_rejected(self):
        # jmp 0x34864d7 -> one byte later
        rel = packet.read_va(self.data, 0x3486282, 4)
        new = struct.pack('<i', struct.unpack('<i', rel)[0] + 1)
        self._rejects(self._patch(self.data, 0x3486282, new), 0x3486254)

    def test_u64_range_rejected(self):
        # movabs rcx,0xffffffff00000000 -> 0xfffffffe00000000 (accepts more)
        self._rejects(self._patch(self.data, 0x348644e, b'\xfe'), 0x3486432)

    def test_marker_table_rejected(self):
        # marker 0xce (u32) now goes to the 0xcc (u8) arm
        rel = (0x34862bc - 0x78db10).to_bytes(4, 'little', signed=True)
        self._rejects(self._patch(self.data, 0x78db10 + 4 * 0x0e, rel))

    def test_expected_text_rejected(self):
        # a nonzero u32 -> a nonzero u33
        self._rejects(self._patch(self.data, 0x9451ad + 12, b'3'))

    def test_writer_skip_value_rejected(self):
        # cmp [rsp+0x24],0x14 -> 0x15
        self._rejects(self._patch(self.data, 0x448aff8, b'\x15'), 0x448aff4)

    def test_writer_field_offset_rejected(self):
        # mov r8d,[rbx+0x38] -> [rbx+0x3c]
        self._rejects(self._patch(self.data, 0x448ae60, b'\x3c'), 0x448ae5d)

    def test_decoder_not_seen_rejected(self):
        # cmp [rsp+0x48],0 -> cmp [rsp+0x48],1
        self._rejects(self._patch(self.data, 0x1bb6f0b, b'\x01'), 0x1bb6f07)

    def test_slot_relocation_rejected(self):
        rel = packet.relative_relocations(self.data)
        self.assertEqual(rel[packet.INT_SLOT], packet.INT_READ)
        for sec in sections(self.data):
            if sec['type'] != 4:
                continue
            for i, (va, info, addend) in enumerate(struct.iter_unpack(
                    '<QQq', self.data[sec['offset']:sec['offset'] + sec['size']])):
                if va == packet.INT_SLOT and info & 0xffffffff == 8:
                    off = sec['offset'] + 24 * i + 16
                    broken = bytearray(self.data)
                    broken[off:off + 8] = struct.pack('<q', addend + 0x10)
                    self._rejects(bytes(broken))
                    return
        self.fail('slot relocation not found')


if __name__ == '__main__':
    unittest.main()
