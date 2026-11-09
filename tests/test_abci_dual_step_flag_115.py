"""Node #115 engine value flag +0x46d, its source and the two step results. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_dual_step_flag_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-dual-step-flag-115/evidence.json'


class AbciDualStepFlagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_flag_paths(self):
        census = self.result['direct_call_census']
        self.assertEqual(census['0x56141f0'], ['0x5a08485'])
        self.assertEqual(census['0x56150d0'], ['0x5a08ce5'])
        self.assertEqual(census['0x5a08f80'], ['0x5a6c5f8'])
        self.assertIn('constant 0', self.result['flag_source']['value'])
        self.assertFalse(self.result['results_in_run']['compared'])
        self.assertEqual(self.result['flag_in_steps']['hour_buckets'], [h // 3 for h in range(24)])
        self.assertEqual(self.result['sha256'], packet.SHA256)

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

    def test_flag_offset_rejected(self):
        # movzx ebp, byte [r14+0x46d] -> [r14+0x46e]
        self._rejects(self._patch(0x5a0836d + 4, b'\x6e'))

    def test_bucket_divisor_rejected(self):
        # imul ecx, ecx, 0xab -> 0xac
        self._rejects(self._patch(0x5a083bc + 2, b'\xac'))

    def test_body_flag_mask_rejected(self):
        # and esi, 1 -> and esi, 3
        self._rejects(self._patch(0x561f9d8 + 2, b'\x03'))

    def test_body_skip_rejected(self):
        # test esi, esi; je -> jne
        self._rejects(self._patch(0x4d98c63 + 1, b'\x85'))

    def test_tar_text_rejected(self):
        self._rejects(self._patch(packet.TAR_TEXT[0], b'x'))

    def test_poller_read_offset_rejected(self):
        # movzx eax, byte [rbx+0xb00] -> [rbx+0xb01]
        self._rejects(self._patch(0x2aebfa6 + 3, b'\x01'))

    def test_b_engine_flag_rejected(self):
        # mov byte [rsp+0x16ad], 0 -> 1
        self._rejects(self._patch(0x5a6c157 + 7 - 1, b'\x01'))

    def test_setter_zero_rejected(self):
        # #5892 build run: mov byte [rbx+0xa8], 0 -> 1
        self._rejects(self._patch(0x2aebb5c + 6, b'\x01'))


if __name__ == '__main__':
    unittest.main()
