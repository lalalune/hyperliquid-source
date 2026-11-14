"""Node #115 shared counter start value and compare order. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import counter_height_invariant_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-counter-height-invariant-115/evidence.json'


class CounterHeightInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_result(self):
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertTrue(self.result['wrapper_order']['height_read_precedes_step'])
        self.assertEqual(self.result['step_direct_callers'],
                         {'step_A': ['0x5a05fc9', '0x5a0901f'], 'step_B': ['0x5a077e1', '0x5a6c16a']})
        self.assertTrue(all(v == [] for v in self.result['height_store_census'].values()))

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _offset(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _rejects(self, va, new):
        broken = bytearray(self.data)
        off = self._offset(va)
        broken[off:off + len(new)] = new
        with self.assertRaises(ValueError):
            packet.bind(bytes(broken), self.fdes)

    def test_counter_start_offset(self):
        # mov r15, [rax+0x28] -> [rax+0x30]
        self._rejects(0x5a6c0b2 + 3, b'\x30')

    def test_counter_store(self):
        # mov [rax+0x10], r15 -> [rax+0x18]
        self._rejects(0x5a6c0dc + 3, b'\x18')

    def test_wrapper_b_height_offset(self):
        # mov rax, [rdi+0x28] -> [rdi+0x30]
        self._rejects(0x5a06e1e + 3, b'\x30')

    def test_wrapper_b_tag(self):
        # cmp dword [r15], 2 -> 3
        self._rejects(0x5a06e2a + 3, b'\x03')

    def test_wrapper_b_step_target(self):
        # call 0x5a08720 -> 0x5a08721
        self._rejects(0x5a077e1 + 1, b'\x3b')

    def test_wrapper_a_compare(self):
        # cmp rax, rcx -> cmp rcx, rax
        self._rejects(0x5a0561a + 1, b'\x39\xc1')

    def test_wrapper_a_step_target(self):
        # call 0x5a07ec0 -> 0x5a07ec1
        self._rejects(0x5a05fc9 + 1, b'\xf3')

    def test_height_load_becomes_store(self):
        # mov rax, [rdi+0x28] (48 8b 47 28) -> mov [rdi+0x28], rax (48 89 47 28)
        self._rejects(0x5a06e1e + 1, b'\x89')


if __name__ == '__main__':
    unittest.main()
