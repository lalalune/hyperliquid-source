"""Node #115 abci_digest_quorum line writer and its record. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_digest_quorum_log_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-digest-quorum-log-115/evidence.json'


class AbciDigestQuorumLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bindings(self):
        self.assertEqual(self.result['writes']['calls'], {'0x5a05c5e': '0x5a04e40', '0x5a0748e': '0x5a06600'})
        self.assertEqual(self.result['engine_value']['abci_digest_quorum_writer'], '+0x280')
        self.assertEqual(self.result['engine_value']['abci_hashes_writer'], '+0x330')
        self.assertFalse(self.result['creation']['flush_byte_set'])
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

    def test_writer_name_rejected(self):
        # abci_digest_quorum -> abci_digest_quorUm
        self._rejects(self._patch(0x93a6d8 + 15, b'U'))

    def test_engine_offset_rejected(self):
        # lea rbx, [r12+0x280] -> [r12+0x330] in wrapper A
        self._rejects(self._patch(0x5a05c14 + 4, b'\x30\x03'))

    def test_record_height_slot_rejected(self):
        # mov [rsp+0x30], rax -> [rsp+0x28] (height no longer at record +0x20)
        self._rejects(self._patch(0x5a05c50 + 4, b'\x28'))

    def test_quorum_digest_offset_rejected(self):
        # movdqu xmm0, [r13+0x48] -> [r13+0x40] in wrapper B
        self._rejects(self._patch(0x5a07474 + 5, b'\x40'))

    def test_field_name_rejected(self):
        # "height" -> "heighT"
        self._rejects(self._patch(0x924ed9 + 5, b'T'))

    def test_hex_length_rejected(self):
        # mov ecx, 0x20 -> 0x14 (a 20-byte value)
        self._rejects(self._patch(0x5073bee + 1, b'\x14'))

    def test_flush_store_rejected(self):
        # plant a mov byte [rsp+0xaa], 1 shape between the conversions and the copies
        self._rejects(self._patch(0x5a6c4c4, b'\xc6\x84\x24\xaa\x00\x00\x00\x01'))

    def test_writer_slot_rejected(self):
        # retarget the daily constructor call for abci_digest_quorum
        self._rejects(self._patch(0x5a6c42c + 2, b'\x00\x00\x00\x00'))


if __name__ == '__main__':
    unittest.main()
