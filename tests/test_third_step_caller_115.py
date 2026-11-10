"""Node #115 third abci step 0x2d25620. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import third_step_caller_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-third-step-caller-115/evidence.json'


class ThirdStepCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_reached_and_layout(self):
        r = self.result['reached_from']
        self.assertEqual(r['direct_callers'], ['0x2d24ed9', '0x2d2766f'])
        self.assertIn('0x6449fb0', r['poll'])
        self.assertIn('layout A', self.result['step']['box'])
        self.assertEqual(self.result['census']['slot_builder_0x2666c80_calls_in_step'], 45)
        self.assertFalse(self.result['gates_changed'])

    def test_digest_twin(self):
        t = self.result['digest_step_twin']
        self.assertEqual((t['fn'], t['equal_to'], t['size']), ('0x2bb37c0', '0x548dad0', '0x203'))
        self.assertEqual(t['location'], 'l1/src/abci/abci_hash.rs:28:37')
        self.assertEqual(t['differing_bytes'], 82)

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

    def test_opening_rejected(self):
        # mov rsi, [rsi+0x450] -> [rsi+0x458]
        self._rejects(self._patch(0x2d25637 + 3, b'\x58'))

    def test_freeze_offset_rejected(self):
        # cmp dword [rsi+0x10e8], 1 -> [rsi+0x10ec]
        self._rejects(self._patch(0x2d25663 + 2, b'\xec'))

    def test_label_string_rejected(self):
        # 'freeze' -> 'freezE'
        self._rejects(self._patch(0x616bb1 + 5, b'E'))

    def test_l1_mode_rejected(self):
        # mov edx, 1 -> 0
        self._rejects(self._patch(0x2d2638c + 1, b'\x00'))

    def test_digest_twin_body_rejected(self):
        # a non-call byte inside the twin digest step
        self._rejects(self._patch(0x2bb37c0 + 0x10, b'\x90'))

    def test_poll_string_rejected(self):
        # 'non-validator' -> 'Non-validator'
        self._rejects(self._patch(0x606039, b'N'))

    def test_hour_gate_rejected(self):
        # cmp al, 2 -> cmp al, 3
        self._rejects(self._patch(0x2d263a8 + 1, b'\x03'))

    def test_digest_call_rejected(self):
        # call 0x2bb37c0 -> call +1
        self._rejects(self._patch(0x2d25712 + 1, b'\xaa'))


if __name__ == '__main__':
    unittest.main()
