"""Node #115 boxed output-setter result: engine value, runner and shared owner. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import output_setter_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-output-setter-state-115/evidence.json'


class OutputSetterStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_owner_chain(self):
        self.assertIn("'fast_abci_engine'", self.result['runner']['name'])
        self.assertIn('node/src/node.rs:608:9', self.result['runner']['location'])
        self.assertIn('box pointer at +0xb00', self.result['runner']['layout'])
        self.assertIn('box pointer at +0xb10', self.result['shared']['allocation'])
        self.assertIn('node/src/node.rs:623:40', self.result['shared']['fast_height'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_divisor(self):
        self.assertEqual(packet.divisor(packet.MAGIC, packet.LIMIT), 10000)
        self.assertIn('% 10000 == 0', self.result['engine_value']['check'])

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

    def test_box_slot_rejected(self):
        # mov [rsp+0x1690], r14 -> [rsp+0x1698]
        self._rejects(self._patch(0x5a6c10a + 4, b'\x98'))

    def test_engine_name_rejected(self):
        # fast_abci_engine -> fast_abci_enginE
        self._rejects(self._patch(packet.ENGINE_NAME[0] + 15, b'E'))

    def test_name_length_rejected(self):
        # mov ecx, 16 -> 15
        self._rejects(self._patch(0x5a6c214 + 1, b'\x0f'))

    def test_location_line_rejected(self):
        # node.rs:608 -> 609
        self._rejects(self._patch(0x64b89d0 + 16, struct.pack('<I', 609)))

    def test_runner_offset_rejected(self):
        # lea rdi, [r13+0x6a8] -> [r13+0x6b0]
        self._rejects(self._patch(0x567c0c7 + 3, b'\xb0'))

    def test_divisor_magic_rejected(self):
        # multiplier low byte 0x91 -> 0x93
        self._rejects(self._patch(0x5a08742 + 2, b'\x93'))

    def test_box_reload_rejected(self):
        # mov rsi, [rsi+0x450] -> [rsi+0x458]
        self._rejects(self._patch(0x5a08737 + 3, b'\x58'))

    def test_height_name_rejected(self):
        # fast_height -> fast_weight
        self._rejects(self._patch(packet.HEIGHT_NAME[0] + 5, b'w'))


if __name__ == '__main__':
    unittest.main()
