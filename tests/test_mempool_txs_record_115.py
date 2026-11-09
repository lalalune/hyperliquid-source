"""Node #115 global extra-flush byte and the mempool_txs record. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import mempool_txs_record_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-mempool-txs-record-115/evidence.json'


class MempoolTxsRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_global_census(self):
        g = self.result['global_byte']
        self.assertEqual((g['slot_loads'], g['reads_movzx_byte'], g['read_functions']), (101, 100, 88))
        self.assertEqual(g['writes'], ['0x51cf3e0 slot load, 0x51cf3e7 mov byte [rsi], 1'])
        self.assertEqual(self.result['setter']['calls'], ['0x2aec025', '0x2cb7645'])
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

    def test_setter_field_rejected(self):
        # cmp byte [rsi+0x20], 0 -> [rsi+0x21]
        self._rejects(self._patch(0x51cf3da + 2, b'\x21'))

    def test_setter_value_rejected(self):
        # mov byte [rsi], 1 -> 0
        self._rejects(self._patch(0x51cf3e7 + 2, b'\x00'))

    def test_panic_text_rejected(self):
        # batch_by_block -> batch_by_blocK
        self._rejects(self._patch(packet.PANIC[0] + 29, b'K'))

    def test_message_offset_rejected(self):
        # mov r15, [rbx+0x2d68] -> [rbx+0x2d60]
        self._rejects(self._patch(0x5a886a4 + 3, b'\x60'))

    def test_input_length_rejected(self):
        # mov rdx, [r15+0x20] -> [r15+0x28]
        self._rejects(self._patch(0x5a886b7 + 3, b'\x28'))

    def test_sponge_rate_rejected(self):
        # 0x88 -> 0x48
        self._rejects(self._patch(0x5a88746 + 8, b'\x48'))

    def test_ok_tag_rejected(self):
        # cmp word [rsp+0x5c0], 0x1a2 -> 0x1a3
        self._rejects(self._patch(0x5a887ec + 8, b'\xa3'))

    def test_item_size_rejected(self):
        # imul rsi, r14, 0x168 -> 0x170
        self._rejects(self._patch(0x5a8887a + 3, b'\x70'))

    def test_extra_global_writer_rejected(self):
        # turn one read (movzx eax, byte [rax]) into a store shape
        self._rejects(self._patch(0x4e3ec3d, b'\xc6\x06\x01'))


if __name__ == '__main__':
    unittest.main()
