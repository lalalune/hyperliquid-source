"""Node #115 move_token 0x5580d10 call census. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import move_token_callers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-move-token-callers-115/evidence.json'


class MoveTokenCallersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        mt = self.result['move_token']
        self.assertEqual((mt['calls'], mt['functions']), (51, 21))
        self.assertEqual(self.result['totals'], {'can-move': 23, 'early-exit': 3,
                                                 'early-exit (via #6213 caller)': 1, 'unresolved': 24})
        exits = sorted(r['site'] for r in self.result['sites'] if r['class'] == 'early-exit')
        self.assertEqual(exits, ['0x557c492', '0x557c5c3', '0x560abd9'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_classifier(self):
        self.assertEqual(packet.classify(('const', 1), ('const', 0)), 'can-move')
        self.assertEqual(packet.classify(('const', 0), ('const', 0)), 'early-exit')
        self.assertEqual(packet.classify(('sete', (0, 1)), ('const', 1)), 'can-move')
        self.assertEqual(packet.classify(('const', 1), ('value', None)), 'unresolved')

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

    def test_early_exit_compare_rejected(self):
        # cmp r15, [rsp+0x1b0] -> [rsp+0x1b8]
        self._rejects(self._patch(0x5580d7e + 4, b'\xb8'))

    def test_zero_test_rejected(self):
        # test r15, r15 -> test r14, r14
        self._rejects(self._patch(0x5580d88, b'\x4d\x85\xf6'))

    def test_frame_size_rejected(self):
        # sub rsp, 0x178 -> 0x180 moves the stack-argument offsets
        self._rejects(self._patch(0x5580d1a + 3, b'\x80'))

    def test_exit_site_r8_rejected(self):
        # 0x557c492: xor r8d, r8d -> xor r8d, r9d
        va = next(va for r, va, _ in packet.SITES[0x557c492] if r == 'r8')
        self._rejects(self._patch(va, b'\x45\x31\xc8'))

    def test_exit_site_arg0_rejected(self):
        # 0x560abd9: mov qword [rsp], 0 -> 1
        va = next(va for r, va, _ in packet.SITES[0x560abd9] if r == 'a0')
        self._rejects(self._patch(va + 4, b'\x01'))

    def test_push_arg0_rejected(self):
        # 0x558314a: push 0x1 (argument 0) -> push 0x0
        va = next(va for r, va, _ in packet.SITES[0x558314a] if r == 'a0')
        self._rejects(self._patch(va + 1, b'\x00'))

    def test_sete_site_rejected(self):
        # 0x54d78f5: sete r8b -> setne r8b
        va = next(va for r, va, _ in packet.SITES[0x54d78f5] if r == 'r8')
        self._rejects(self._patch(va + 2, b'\x95'))

    def test_call_site_rejected(self):
        # retarget the call at 0x5593ce5 (census drops to 50)
        self._rejects(self._patch(0x5593ce5 + 1, b'\x00'))


if __name__ == '__main__':
    unittest.main()
