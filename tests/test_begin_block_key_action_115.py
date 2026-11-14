"""Node #115 begin_block A per-key action and record gates. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import begin_block_key_action_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-begin-block-key-action-115/evidence.json'


class BeginBlockKeyActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(sorted(self.result['action']['call_sites']),
                         ['0x54c0345', '0x5588e32', '0x558b7c6', '0x558b9a0'])
        self.assertEqual(self.result['gate']['direct_calls'], 0)
        self.assertEqual(self.result['action']['locations']['0x648b990'],
                         'l1/src/dex_registry/clearinghouses.rs:11:29')
        self.assertEqual(self.result['sha256'], packet.SHA256)
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

    def test_record_kind_rejected(self):
        # cmp byte [r13+0x3c], 4 -> 5
        self._rejects(self._patch(0x54c00ef + 4, b'\x05'))

    def test_flag_bit_rejected(self):
        # test byte [rax+0x7b8], 1 -> 2
        self._rejects(self._patch(0x54c00ff + 6, b'\x02'))

    def test_mode_compare_rejected(self):
        # cmp r8, 1 -> 2
        self._rejects(self._patch(0x55821b4 + 3, b'\x02'))

    def test_ring_stride_rejected(self):
        # imul rdi, rcx, 0xb8 -> 0xb0
        self._rejects(self._patch(0x5582279 + 3, b'\xb0'))

    def test_counter_offset_rejected(self):
        # mov [r13+0xab0], rax -> [r13+0xab8]
        self._rejects(self._patch(0x5583288 + 3, b'\xb8'))

    def test_counter_saturation_rejected(self):
        # cmove -> cmovne
        self._rejects(self._patch(0x5583284 + 2, b'\x45'))

    def test_gate_slot_rejected(self):
        # retarget the slot load at 0x54c010f
        self._rejects(self._patch(0x54c010f + 2, b'\x00\x00\x00\x00'))

    def test_gate_field_rejected(self):
        # cmp qword [rcx+0x10], 0 -> [rcx+0x18]
        self._rejects(self._patch(0x3693150 + 3, b'\x18'))


if __name__ == '__main__':
    unittest.main()
