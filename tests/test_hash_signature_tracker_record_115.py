"""Node #115 hash_signature_tracker default record, sender replace and tag recorder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import hash_signature_tracker_record_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hash-signature-tracker-record-115/evidence.json'


class HashSignatureTrackerRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_findings(self):
        self.assertEqual(self.result['default_height_value']['flag_plus_0x20'], 1)
        self.assertEqual(self.result['sender_insert']['key_bytes'], 20)
        recorder = self.result['recorder']
        self.assertEqual(recorder['slot_calls'], 1047)
        self.assertEqual(recorder['map_references'], 30)
        self.assertEqual(recorder['locations']['0x64bc860'], 'l1/src/abci/hash_signature_tracker.rs:107:28')
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

    def test_default_flag_rejected(self):
        # mov byte [rsp+0x28], 1 -> 0
        self._rejects(self._patch(0x4da621d + 4, b'\x00'))

    def test_twin_default_flag_rejected(self):
        self._rejects(self._patch(0x4da4bbd + 4, b'\x00'))

    def test_sender_key_length_rejected(self):
        # memcmp length 0x14 -> 0x20
        self._rejects(self._patch(0x4dd5372 + 1, b'\x20'))

    def test_sender_replace_rejected(self):
        # mov [r13+0x40], rcx -> mov [r13+0x48], rcx
        self._rejects(self._patch(0x4dd5447 + 3, b'\x48'))

    def test_sender_tag_rejected(self):
        # mov ecx, 1 -> 0
        self._rejects(self._patch(0x4dd544b + 1, b'\x00'))

    def test_recorder_tag_rejected(self):
        # mov edi, 10 -> 12
        self._rejects(self._patch(0x5afaa83 + 1, b'\x0c'))

    def test_location_line_rejected(self):
        # Location line 107 -> 108
        self._rejects(self._patch(0x64bc860 + 0x10, struct.pack('<I', 108)))

    def test_map_target_rejected(self):
        # lea rsi, [MAP] -> [MAP+0x10]
        raw = packet.read_va(self.data, 0x4524e91, 7)
        disp = struct.unpack_from('<i', raw, 3)[0] + 0x10
        self._rejects(self._patch(0x4524e91 + 3, struct.pack('<i', disp)))


if __name__ == '__main__':
    unittest.main()
