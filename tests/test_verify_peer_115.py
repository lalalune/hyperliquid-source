"""Node #115 verify_peer future and its caller. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import verify_peer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-verify-peer-115/evidence.json'


class VerifyPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_request_and_timeout(self):
        self.assertEqual(self.result['request']['timeout_seconds'], 5.0)
        self.assertIn('0xfa1 (4001)', self.result['request']['address'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_census(self):
        census = self.result['census']
        self.assertEqual(census['direct_calls_to_verify'], ['0x2acd8c1', '0x2ad028b', '0x2ad17db', '0x2ad42b3'])
        self.assertEqual(census['direct_calls_to_gossip_rpc'], ['0x2adacc4', '0x2adee64', '0x2ae097f'])
        self.assertEqual(census['direct_calls_to_mark_verified'], [])

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

    def test_port_rejected(self):
        # word 0xfa1 -> 0xfa2
        self._rejects(self._patch(0x2ae0b6b + 4, b'\xa2'))

    def test_timeout_constant_rejected(self):
        # 5.0 -> 6.0 in the rodata copy
        self._rejects(self._patch(packet.FIVE, struct.pack('<d', 6.0)))

    def test_address_source_rejected(self):
        # mov eax, [rbx+5] -> [rbx+9]
        self._rejects(self._patch(0x2ae0b4c + 2, b'\x09'))

    def test_continue_tag_rejected(self):
        # cmp bpl, 0x44 -> 0x43
        self._rejects(self._patch(0x2ae0b0e + 3, b'\x43'))

    def test_counter_saturation_rejected(self):
        # cmovne -> cmove
        self._rejects(self._patch(0x2ad0343 + 2, b'\x44'))

    def test_failure_text_rejected(self):
        # dropping connection -> dropping connectiom
        self._rejects(self._patch(0x6056de + 18, b'm'))

    def test_verified_text_rejected(self):
        # marking node_ip as verified -> ... verifieD
        self._rejects(self._patch(0x919921 + 26, b'D'))

    def test_resume_table_rejected(self):
        # first resume entry moved by one byte
        raw = self.data
        sec = next(s for s in sections(raw) if s['address'] <= packet.RESUME_TABLE < s['address'] + s['size'])
        off = sec['offset'] + packet.RESUME_TABLE - sec['address']
        value = struct.unpack_from('<i', raw, off)[0] + 1
        self._rejects(self._patch(packet.RESUME_TABLE, struct.pack('<i', value)))


if __name__ == '__main__':
    unittest.main()
