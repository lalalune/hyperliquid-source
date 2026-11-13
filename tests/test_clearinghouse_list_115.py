"""Node #115 Locus cls clearinghouse lookup and ctr flag. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import clearinghouse_list_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-list-115/evidence.json'


class ClearinghouseListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_locations(self):
        locs = self.result['locations']
        self.assertEqual(locs['0x648b990']['line'], 11)
        self.assertEqual(locs['0x648b990']['col'], 29)
        self.assertEqual(locs['0x648b990']['lea_refs'], 404)
        self.assertEqual(locs['0x648b9a8']['lea_refs'], 152)
        self.assertEqual(locs['0x64768a8']['file'], 'l1/src/perp_meta.rs')
        self.assertFalse(self.result['gates_changed'])

    def test_callers(self):
        callers = self.result['callers']
        self.assertEqual(len(callers['0x5582180']), 4)
        self.assertEqual(len(callers['0x55817e0']), 4)
        self.assertEqual(len(callers['0x558b730']), 2)
        self.assertEqual(len(callers['0x5588d90']), 19)

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

    def test_divisor_rejected(self):
        # magic constant low byte 0x4b -> 0x4c
        self._rejects(self._patch(0x57c9fb6, b'\x4c'))

    def test_shift_rejected(self):
        # shr r12, 11 -> 12
        self._rejects(self._patch(0x57c9fca, b'\x0c'))

    def test_element_size_rejected(self):
        # imul r14, r12, 0x510 -> 0x518
        self._rejects(self._patch(0x57ca003, b'\x18'))

    def test_error_tag_rejected(self):
        # mov word [rsp+0x30], 0x156 -> 0x157
        self._rejects(self._patch(0x57ca4b8, b'\x57'))

    def test_location_line_rejected(self):
        # clearinghouses.rs 11:29 -> 12:29
        self._rejects(self._patch(0x648b990 + 16, b'\x0c'))

    def test_flag_set_rejected(self):
        # mov al, 1 -> mov al, 0
        self._rejects(self._patch(0x5583121, b'\x00'))

    def test_ctr_offset_rejected(self):
        # mov [r13+0xab0], rax -> +0xab8
        self._rejects(self._patch(0x558328b, b'\xb8'))

    def test_flag_call_rejected(self):
        # call 0x55817e0 retargeted by one byte
        self._rejects(self._patch(0x5583118, b'\xc5'))


if __name__ == '__main__':
    unittest.main()
