"""Node #115 fast_abci_engine step and block-step sampler gate. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import fast_abci_engine_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-fast-abci-engine-115/evidence.json'


class FastAbciEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_step_triggers(self):
        step = self.result['step_0x5a08720']
        self.assertIn('exchange.rs:607:17', step['freeze_below_height_panics'])
        self.assertIn("'freeze' (6)", step['label'])
        self.assertIn("'periodic' (8)", step['label'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_sampler_gate(self):
        self.assertEqual(self.result['sampler_sites'],
                         {'0x5486544': 0, '0x5a067ec': 1, '0x5a06b29': 2, '0x5a06e11': 3, '0x5a0784c': 4})
        self.assertIn('0x8000000000000001', self.result['setter_optionals']['none'])
        self.assertEqual(self.result['displacement_counts']['0x5a06600'], {'0x12a0': 9, '0x12d8': 0})

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
            packet.bind(data)

    def test_freeze_compare_rejected(self):
        # jb (freeze < height -> panic) -> jbe
        self._rejects(self._patch(0x5a08773 + 1, b'\x86'))

    def test_assertion_text_rejected(self):
        # freeze_height >= ... -> freeze_height <= ...
        self._rejects(self._patch(packet.ASSERTION[0] + 32, b'<'))

    def test_label_length_rejected(self):
        # lea rcx, [rax*2+6] -> [rax*2+7]
        self._rejects(self._patch(0x5a0885b + 4, b'\x07'))

    def test_sampler_none_rejected(self):
        # movabs rax, 0x8000000000000001 -> 0x8000000000000002
        self._rejects(self._patch(0x5486523 + 2, b'\x02'))

    def test_sampler_offset_rejected(self):
        # cmp [rdi+0x12a0] -> [rdi+0x12d8] at the tag-1 site
        self._rejects(self._patch(0x5a067ca + 3, b'\xd8'))

    def test_sampler_tag_rejected(self):
        # mov esi, 4 -> mov esi, 5
        self._rejects(self._patch(0x5a07847 + 1, b'\x05'))

    def test_setter_none_rejected(self):
        # lea rax, [rbp+1] -> [rbp+2]
        self._rejects(self._patch(0x51d08bc + 3, b'\x02'))

    def test_fifteen_rejected(self):
        # 15.0 -> 15.5 (0x402f000000000000)
        self._rejects(self._patch(0x51d0874 + 8, b"\x2f"))

    def test_engine_value_offset_rejected(self):
        # lea rbx, [r15+0x450] -> [r15+0x458]
        self._rejects(self._patch(0x5a067a0 + 3, b'\x58'))


if __name__ == '__main__':
    unittest.main()
