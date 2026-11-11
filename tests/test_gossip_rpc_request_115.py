"""Node #115 gossip_rpc_request step before verify_peer. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import gossip_rpc_request_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-gossip-rpc-request-115/evidence.json'


class GossipRpcRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_summary(self):
        self.assertIn('4002', self.result['inner_future']['connect_address'])
        self.assertIn('10.0', self.result['gossip_rpc_request']['limit'])
        self.assertEqual(self.result['caller_plus_0x1268']['stores'], [])
        self.assertEqual(len(self.result['caller_plus_0x1268']['loads']), 8)
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

    def test_port_rejected(self):
        # 0xfa2 (4002) -> 0xfa1 (4001)
        self._rejects(self._patch(0x2b69dbb + 7, b'\xa1'))

    def test_limit_rejected(self):
        # 10.0 -> 20.0
        self._rejects(self._patch(0x2ae0175 + 2, struct.pack('<d', 20.0)))

    def test_pending_tag_rejected(self):
        # cmp bpl, 0x46 -> 0x47
        self._rejects(self._patch(0x2ae0461 + 3, b'\x47'))

    def test_timeout_tag_rejected(self):
        # mov bpl, 0x2f -> 0x30
        self._rejects(self._patch(0x2ae05c7 + 2, b'\x30'))

    def test_retry_count_rejected(self):
        # 11 -> 12
        self._rejects(self._patch(0x2b69e4d + 7, b'\x0c'))

    def test_send_limit_rejected(self):
        # 60.0 -> 30.0
        self._rejects(self._patch(0x2b6a676 + 2, struct.pack('<d', 30.0)))

    def test_name_rejected(self):
        # gossip_rpc_request -> gossip_rpc_requesT
        self._rejects(self._patch(0x605aac + 17, b'T'))

    def test_caller_store_rejected(self):
        # turn the load at 0x2aceafc (mov eax, [rbx+0x1268]) into a store
        self._rejects(self._patch(0x2aceafc, b'\x89'))


if __name__ == '__main__':
    unittest.main()
