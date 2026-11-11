"""Node #115 output command-line flags and the setter's struct bytes. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import output_flags_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-output-flags-115/evidence.json'


class OutputFlagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_reader(self):
        reader = self.result['reader']
        self.assertEqual([c['subcommand'] for c in reader['callers']], ['run-non-validator', 'run-validator'])
        offsets = {l['name']: l['offset'] for l in reader['lookups']}
        self.assertEqual(offsets['disable-output-file-buffering'], '+0x1f')
        self.assertEqual(offsets['batch-by-block'], '+0x20')
        self.assertEqual(offsets['stream-with-block-info'], '+0x21')
        self.assertEqual(len(reader['lookups']), 14)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_setter_gates(self):
        gates = [(g['setter_byte'], g['writer_name']) for g in self.result['setter']['gates']]
        self.assertEqual(gates[0], ('+0x19', 'node_trades'))
        self.assertEqual(gates[-1], ('+0x1f', 'system_and_core_writer_actions'))

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

    def test_flag_name_rejected(self):
        # disable-output-file-buffering -> disable-output-file-bufferinG
        self._rejects(self._patch(0x92ac06 + 28, b'G'))

    def test_lookup_store_rejected(self):
        # mov [rsp+0x7], al -> mov [rsp+0x6], al (disable-output-file-buffering result slot)
        self._rejects(self._patch(0x564d4d5 + 3, b'\x06'))

    def test_assembly_rejected(self):
        # mov [rbx+0x20], cl -> mov [rbx+0x21], cl
        self._rejects(self._patch(0x564d616 + 2, b'\x21'))

    def test_setter_global_byte_rejected(self):
        # cmp byte [rsi+0x20], 0 -> [rsi+0x1f]
        self._rejects(self._patch(0x51cf3da + 2, b'\x1f'))

    def test_setter_pair_rejected(self):
        # movzx edx, byte [rsi+0x21] -> [rsi+0x20]
        self._rejects(self._patch(0x51cf3cd + 3, b'\x20'))

    def test_gate_rejected(self):
        # cmp byte [rsp+0x14], 0 -> [rsp+0x15] (system_and_core_writer_actions gate)
        self._rejects(self._patch(0x51d0262 + 3, b'\x15'))

    def test_style_value_rejected(self):
        # actions-and-responses -> actions-and-responseS
        self._rejects(self._patch(0x454130 + 15, b'S'))

    def test_subcommand_tag_rejected(self):
        # mov qword [rbx], 3 -> 4
        self._rejects(self._patch(0x56551ef + 3, b'\x04'))


if __name__ == '__main__':
    unittest.main()
