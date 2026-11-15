"""Node #115 'slow abci block' handle sender. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_block_sender_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-block-sender-115/evidence.json'


class SlowAbciBlockSenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_handle_and_send(self):
        self.assertIn('5000', self.result['handle']['+0x20'])
        self.assertIn('none', self.result['send']['capacity_check'])
        self.assertIn('0x2aed2f5, 0x2cb8915', self.result['handle']['builder'])
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

    def test_capacity_rejected(self):
        # mov qword [rsp+0x60], 5000 -> 5001
        self._rejects(self._patch(0x5a6cd68 + 5, struct.pack('<I', 5001)))

    def test_closed_bit_rejected(self):
        # test al, 1 -> test al, 2
        self._rejects(self._patch(0x5a6fda1, b'\x02'))

    def test_permit_step_rejected(self):
        # lea rdx, [rax+2] -> [rax+4]
        self._rejects(self._patch(0x5a6fdb5, b'\x04'))

    def test_push_target_rejected(self):
        # call 0x581a2d0 -> call 0x581a2d1
        rel = struct.unpack('<i', bytes(packet.read_va(self.data, 0x5a6fe25, 4)))[0]
        self._rejects(self._patch(0x5a6fe25, struct.pack('<i', rel + 1)))

    def test_handle_offset_rejected(self):
        # lea r12, [rbx+0xaf0] -> [rbx+0xaf8]
        self._rejects(self._patch(0x2aecf81, b'\xf8'))

    def test_task_name_rejected(self):
        # 'node handle client blocks' -> 'node handle client blockz'
        self._rejects(self._patch(0x605bc9 + 24, b'z'))

    def test_fast_threshold_rejected(self):
        # 0.35 -> 0.36
        self._rejects(self._patch(0x458f50, struct.pack('<d', 0.36)))

    def test_capacity_read_rejected(self):
        # write mov rax, [r13+0x20] over mov r13, rcx: the pin and the +0x20 census both reject it
        self._rejects(self._patch(0x5a6e1f4, b'\x49\x8b\x45\x20'))


if __name__ == '__main__':
    unittest.main()
