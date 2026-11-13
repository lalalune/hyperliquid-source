"""Node #115 l1 hash input and callers. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from elf_index import sections
import l1_hash_input_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-l1-hash-input-115/evidence.json'


class L1HashInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_shape(self):
        l1 = self.result['l1_hash']
        self.assertEqual(l1['formula'], 'BLAKE3(BLAKE3(bytes[ptr..ptr+len]) || digest32)')
        self.assertEqual(l1['direct_calls'], ['0x452ac61', '0x452ad4f'])
        self.assertEqual(self.result['helper']['direct_calls'], 7)
        self.assertEqual(len(self.result['call_sites']), 7)
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

    def test_len_field_rejected(self):
        # mov r13, [r14+8] -> [r14+0x18]
        self._rejects(self._patch(0x457cf8d + 3, b'\x18'))

    def test_digest_pointer_rejected(self):
        # mov rax, [r14+0x10] -> [r14+0x18]
        self._rejects(self._patch(0x457d066 + 3, b'\x18'))

    def test_second_update_length_rejected(self):
        # mov edx, 0x20 -> 0x10
        self._rejects(self._patch(0x457d171 + 1, b'\x10'))

    def test_output_store_rejected(self):
        # movupd [rbx+0x10] -> [rbx+0x18]
        self._rejects(self._patch(0x457d195 + 4, b'\x18'))

    def test_helper_passthrough_rejected(self):
        # mov rsi, r15 -> mov rsi, r14
        self._rejects(self._patch(0x452ac5e + 2, b'\xf6'))

    def test_worker_height_rejected(self):
        # mov r15, [rbx+0x28] -> [rbx+0x30]
        self._rejects(self._patch(0x5484687 + 3, b'\x30'))

    def test_worker_digest_source_rejected(self):
        # movups xmm0, [rsp+0x80] -> [rsp+0x88]
        self._rejects(self._patch(0x548475b + 4, b'\x88'))

    def test_log_template_rejected(self):
        # 'computed l1 hash' -> 'computed l2 hash'
        self._rejects(self._patch(packet.LOG[0] + 11, b'2'))


if __name__ == '__main__':
    unittest.main()
