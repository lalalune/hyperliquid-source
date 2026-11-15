"""Node #115 replica_cmds line count and startup check flag. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import replica_cmds_line_count_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-replica-cmds-line-count-115/evidence.json'


class ReplicaCmdsLineCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['line_count']['direct_calls'], [])
        self.assertEqual(self.result['startup_flag']['startup_direct_calls'], ['0x2af0a5f', '0x2cbc06b'])
        self.assertEqual(self.result['startup_flag']['caller_direct_calls'], ['0x2aec151'])
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

    def test_suffix_rejected(self):
        # '.lz4' -> '.lz5'
        self._rejects(self._patch(0x1500e71 + 7, b'\x35'))

    def test_wc_string_rejected(self):
        # "wc" -> "wd"
        self._rejects(self._patch(0x4659f3, b'd'))

    def test_line_flag_rejected(self):
        # "-l" -> "-c"
        self._rejects(self._patch(0x4659f5, b'c'))

    def test_shell_string_rejected(self):
        # "/bin/sh" -> "/bin/zh"
        self._rejects(self._patch(0x466ae1, b'z'))

    def test_separator_rejected(self):
        # join separator ' ' -> '_'
        self._rejects(self._patch(0x468cca, b'_'))

    def test_lz4_jump_back_rejected(self):
        # jmp 0x1500e89 -> jmp 0x1500e8a
        self._rejects(self._patch(0x1501268 + 1, b'\x1d'))

    def test_startup_flag_compare_rejected(self):
        # cmp r12b, 1 -> cmp r12b, 0
        self._rejects(self._patch(0x2b41d32 + 3, b'\x00'))

    def test_state_copy_rejected(self):
        # mov [rbx+0x29], rdx -> mov [rbx+0x2a], rdx
        self._rejects(self._patch(0x2af082f + 3, b'\x2a'))


if __name__ == '__main__':
    unittest.main()
