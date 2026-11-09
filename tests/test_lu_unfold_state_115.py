"""Node #115 lu.rs unfold seed, tick and tick action. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import lu_unfold_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-lu-unfold-state-115/evidence.json'


class LuUnfoldStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_seed_and_tick(self):
        seed = self.result['seed_builders']['seed_values']
        self.assertEqual(seed['+0xd0'], 10.0)
        self.assertEqual(seed['+0xe0'], 0)
        tick = self.result['tick_action']
        self.assertEqual(tick['request_name'], 'verify_peer')
        self.assertEqual(tick['word_at_plus_0x26'], 4001)
        self.assertEqual(self.result['seed_qword']['hash_constants'], 'somepseudorandomlygeneratedbytes')
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
            packet.bind(data)

    def test_interval_rejected(self):
        # 10.0 -> 11.0 in the first builder
        self._rejects(self._patch(0x2acf366, struct.pack('<d', 11.0)))

    def test_builders_disagree_rejected(self):
        # 10.0 -> 11.0 in the second builder only
        self._rejects(self._patch(0x2ad3333, struct.pack('<d', 11.0)))

    def test_sleep_flag_rejected(self):
        # mov byte [rsp+0x3b0], 0 -> 1
        self._rejects(self._patch(0x2acf37e + 7, b'\x01'))

    def test_toggle_xor_rejected(self):
        # xor al, 1 -> xor al, 0
        self._rejects(self._patch(0x2cf095d + 1, b'\x00'))

    def test_tick_output_rejected(self):
        # mov word [rbx], 0x101 -> 0x100
        self._rejects(self._patch(0x2ce0f16 + 3, b'\x00'))

    def test_request_name_rejected(self):
        # verify_peer -> verify_pees
        self._rejects(self._patch(packet.NAME[0] + 10, b's'))

    def test_port_word_rejected(self):
        # 0xfa1 -> 0xfa2
        self._rejects(self._patch(0x2ae0b6f, b'\xa2'))

    def test_siphash_constant_rejected(self):
        # first SipHash word byte 'u' -> 'v'
        self._rejects(self._patch(0x1564669, b'v'))

    def test_resume_table_rejected(self):
        # first resume table entry + 1
        raw = packet.read_va(self.data, packet.JUMP_TABLE, 4)
        self._rejects(self._patch(packet.JUMP_TABLE, struct.pack('<i', struct.unpack('<i', raw)[0] + 1)))


if __name__ == '__main__':
    unittest.main()
