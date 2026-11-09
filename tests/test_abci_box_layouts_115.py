"""Node #115 abci box layouts differing by a 0xb70-byte insertion. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_box_layouts_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-box-layouts-115/evidence.json'


class AbciBoxLayoutsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_pairs(self):
        p = self.result['pairs']
        self.assertEqual(p['step']['shifted_box_offsets_a'], ['0xb9a', '0x10e8', '0x10f0', '0x2c20', '0x39c8'])
        self.assertEqual(p['freeze_setter']['shifted_box_offsets_a'], ['0x10e8', '0x10f0'])
        self.assertEqual(p['dispatcher']['counts']['field'], 175)
        self.assertIn(['0x54c9a90', '0x54c9b80'], [list(x) for x in p['dispatcher']['paired_functions']])
        self.assertEqual(self.result['shifted_offset_range_a'], ['0x7c0', '0x42af'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _offset(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off = self._offset(va)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_sibling_setter_offset_rejected(self):
        # mov qword [rsi+0x10e8], 1 -> [rsi+0x10e0]
        self._rejects(self._patch(0x54c9af2 + 3, b'\xe0'))

    def test_step_shift_rejected(self):
        # first differing disp in 0x5a08720 moves by 8: no longer a 0xb70 shift
        a0, b0, n = packet.PAIRS['step']
        r = packet.classify(self.data, a0, b0, n, {f['start'] for f in self.fdes})
        s, va, vb = r['field'][0]
        self._rejects(self._patch(b0 + s, struct.pack('<i', vb + 8)))

    def test_dispatcher_exception_rejected(self):
        # add rbx, 0x7c0 -> 0x7c8
        self._rejects(self._patch(0x53a0da6 + 3, b'\xc8'))

    def test_box_size_rejected(self):
        # mov edi, 0x4e38 -> 0x4e40
        self._rejects(self._patch(0x548d82f + 1, b'\x40'))

    def test_insert_offset_rejected(self):
        # lea rdi, [rsp+0x7e0] -> [rsp+0x7e8]
        self._rejects(self._patch(0x548d6f5 + 4, b'\xe8'))

    def test_insert_length_rejected(self):
        # mov edx, 0xb70 -> 0xb78
        self._rejects(self._patch(0x548d6fd + 1, b'\x78'))

    def test_old_box_free_rejected(self):
        # mov esi, 0x42c8 -> 0x42d0
        self._rejects(self._patch(0x548d858 + 1, b'\xd0'))

    def test_setter_call_rejected(self):
        # retarget the sibling setter's only call by one byte
        raw = self.data[self._offset(0x538e830):self._offset(0x538e830) + 5]
        rel = struct.unpack_from('<i', raw, 1)[0]
        self._rejects(self._patch(0x538e831, struct.pack('<i', rel + 0x10)))


if __name__ == '__main__':
    unittest.main()
