"""Node #115 channel.rs:16:9 forwarders and lu.rs unfold poll sites. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import lu_unfold_channel_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-lu-unfold-channel-115/evidence.json'


class LuUnfoldChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_forwarders(self):
        f = self.result['forwarders']
        self.assertEqual(f['0x2e071c0']['builder_calls'], ['0x2af0b57', '0x2cbc15c'])
        self.assertEqual(f['0x2e075f0']['builder_calls'], ['0x2ace102', '0x2ad211e'])
        self.assertEqual(f['0x2e071c0']['box_size'], '0x118')
        self.assertIn('{}_forwarder', f['task_name_template'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_unfold_and_sleep_census(self):
        self.assertEqual([c[1] for c in self.result['unfold']['direct_calls']],
                         ['0x2cdca20', '0x2cdca20', '0x2ce0de0', '0x2ce0de0'])
        self.assertEqual(len(self.result['sleep_calls']), 4)

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

    def test_capacity_rejected(self):
        # mov ecx, 5000 -> 5001
        self._rejects(self._patch(0x2e06e6e + 1, b'\x89'))

    def test_box_size_rejected(self):
        # mov edi, 0x118 -> 0x110
        self._rejects(self._patch(0x2e06ffd + 1, b'\x10'))

    def test_vtable_size_rejected(self):
        # vtable 0x6451ad8 size 0x118 -> 0x110
        self._rejects(self._patch(packet.VT_118 + 8, b'\x10'))

    def test_template_rejected(self):
        # {}_forwarder -> {}_Forwarder
        self._rejects(self._patch(packet.TEMPLATE[0] + 3, b'F'))

    def test_name_flag_rejected(self):
        # mov ecx, 1 -> 0 at the first client block or tx call
        self._rejects(self._patch(0x2af0b52 + 1, b'\x00'))

    def test_payload_offset_rejected(self):
        # movupd [rbx+0x108] -> [rbx+0x100] in the store
        self._rejects(self._patch(0x2e0742b + 4, b'\x00'))

    def test_max_rejected(self):
        # maxsd -> minsd
        self._rejects(self._patch(0x2e074ba + 2, b'\x5d'))

    def test_location_line_rejected(self):
        # channel.rs:20:33 -> 21:33
        self._rejects(self._patch(packet.LOC_20 + 16, b'\x15'))


if __name__ == '__main__':
    unittest.main()
