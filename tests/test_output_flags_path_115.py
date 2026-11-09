"""Node #115 output flags -> setter argument conversion. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import output_flags_path_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-output-flags-path-115/evidence.json'


class OutputFlagsPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_setter_bytes(self):
        b = self.result['setter_bytes']
        self.assertEqual(b['0x18'], 'constant 0')
        self.assertEqual(b['0x20'], 'argument 0x1f = disable-output-file-buffering')
        self.assertEqual(b['0x21'], 'argument 0x20 = batch-by-block')
        self.assertEqual(b['0x22'], 'argument 0x21 = stream-with-block-info')
        self.assertEqual(b['0x23'], 'argument 0x22 = serve-evm-rpc')
        self.assertEqual(len(self.result['gates_line_up']), 7)
        self.assertEqual(sorted(self.result['setter_calls']), ['0x2aec025', '0x2cb7645'])
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
            packet.bind(data)

    def test_zero_byte_rejected(self):
        # mov byte [rbx+0xa8], 0 -> 1 (first poller)
        self._rejects(self._patch(0x2aebb5c + 6, b'\x01'))

    def test_qword_store_offset_rejected(self):
        # movq [rbx+0xa9], xmm1 -> [rbx+0xa8] (second poller)
        self._rejects(self._patch(0x2cb7183 + 4, b'\xa8'))

    def test_dword_store_offset_rejected(self):
        # movd [rbx+0xb1], xmm2 -> [rbx+0xb2]
        self._rejects(self._patch(0x2aebb6b + 4, b'\xb2'))

    def test_flag_load_offset_rejected(self):
        # mov r13, [rbx+0x60] -> [rbx+0x61]
        self._rejects(self._patch(0x2aeb5c6 + 3, b'\x61'))

    def test_initial_copy_rejected(self):
        # movupd [rbx+0x48], xmm0 -> [rbx+0x40] (second poller)
        self._rejects(self._patch(0x2cb658c + 4, b'\x40'))

    def test_setter_argument_copy_rejected(self):
        # mov rax, [r13+0x20] -> [r13+0x28]
        self._rejects(self._patch(0x2aebfe9 + 3, b'\x28'))

    def test_style_branch_rejected(self):
        # je -> jne at the style-2 branch
        self._rejects(self._patch(0x2aeb5dc + 1, b'\x85'))

    def test_reader_order_rejected(self):
        # reader saves write-trades to [rsp+0xd] instead of [rsp+0xe]
        self._rejects(self._patch(0x564d3b8 + 3, b'\x0d'))

    def test_gate_name_rejected(self):
        # node_trades -> node_tradez
        self._rejects(self._patch(0x91fcc0 + 10, b'z'))


if __name__ == '__main__':
    unittest.main()
