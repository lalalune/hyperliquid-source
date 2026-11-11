"""Node #115 bucket_guard observer names: getters, census, names and pairs. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import bucket_guard_names_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-bucket-guard-names-115/evidence.json'


class BucketGuardNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census_and_names(self):
        r = self.result
        self.assertEqual(r['calls'], {'0x26d4660': 11, '0x3704070': 8, '0x4770930': 1, '0x51eaff0': 30})
        self.assertEqual(r['by_kind'], {'static': 36, 'wrapper': 14})
        self.assertEqual(r['distinct_names'], 22)
        self.assertEqual(r['wrapper_callers'], 24)
        self.assertEqual(r['names']['slow_abci_engine_read_increment'], 6)
        self.assertEqual(r['names']['begin_block'], 3)
        self.assertEqual(r['names']['median_risk_free_rate'], 1)
        self.assertEqual(sum(r['pairs'].values()), 60)
        self.assertEqual(r['sha256'], packet.SHA256)
        self.assertFalse(r['gates_changed'])

    def test_every_site_reads_clock_and_global(self):
        for site in self.result['sites']:
            self.assertGreaterEqual(site['clock_reads'], 2)
            self.assertTrue(site['record_call'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off, old = packet.read_va(self.data, va, len(new))
        self.assertEqual(len(old), len(new))
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_static_name_byte_rejected(self):
        # "begin_block" (0x60e193) -> "Begin_block"
        self._rejects(self._patch(0x60e193, b'B'))

    def test_static_name_length_rejected(self):
        # begin_block length 11 -> 12 at 0x2bdf457
        self._rejects(self._patch(0x2bdf457 + 8, b'\x0c'))

    def test_wrapper_caller_name_rejected(self):
        # "gas_auction_restart" first byte
        target = packet.rip(self.data, (0x2be1f6d, '488d05de8cbdfd'))
        self._rejects(self._patch(target, b'G'))

    def test_hop_name_rejected(self):
        # median_risk_free_rate length 0x15 -> 0x14 at the first hop caller
        self._rejects(self._patch(0x2be61fa + 4, b'\x14'))

    def test_pair_store_offset_rejected(self):
        # begin_block pair store [rsp+0x88] -> [rsp+0x90]
        self._rejects(self._patch(0x2bdf473 + 5, b'\x90'))

    def test_occupied_stride_rejected(self):
        # imul ..., 0x260 -> 0x268 in getter 0x51eaff0
        self._rejects(self._patch(0x51eb001 + 4, b'\x68'))

    def test_display_thunk_rejected(self):
        # mov rdx, [rdi+8] -> [rdi+0x10] in thunk 0x5616320
        self._rejects(self._patch(0x5616326 + 3, b'\x10'))

    def test_template_rejected(self):
        self._rejects(self._patch(packet.TEMPLATE + 1, b'B'))

    def test_getter_call_removed_rejected(self):
        # last slow_abci_engine_read_increment getter call becomes a 5-byte nop
        self._rejects(self._patch(0x564a276, b'\x0f\x1f\x44\x00\x00'))

    def test_wrapper_call_retargeted_rejected(self):
        # one gas_auction_restart caller moves 16 bytes
        disp = struct.unpack('<i', packet.read_va(self.data, 0x2be1fca + 1, 4)[1])[0]
        self._rejects(self._patch(0x2be1fca + 1, struct.pack('<i', disp + 16)))

    def test_global_load_rejected(self):
        # first site's global load points one slot later
        disp = struct.unpack('<i', packet.read_va(self.data, 0x2bdf746 + 3, 4)[1])[0]
        self._rejects(self._patch(0x2bdf746 + 3, struct.pack('<i', disp + 8)))

    def test_clock_id_rejected(self):
        # every mov edi, 1 before a clock read in the begin_block function becomes mov edi, 0
        broken = bytearray(self.data)
        off, raw = packet.read_va(self.data, 0x2bdf270, 0x2bdf8ee - 0x2bdf270)
        i = raw.find(b'\xbf\x01\x00\x00\x00\xe8')
        while i >= 0:
            broken[off + i + 1] = 0
            i = raw.find(b'\xbf\x01\x00\x00\x00\xe8', i + 1)
        self._rejects(bytes(broken))

    def test_btree_edge_offset_rejected(self):
        self._rejects(self._patch(0x2bdf739 + 4, b'\x40'))

    def test_wrong_digest_rejected(self):
        broken = bytearray(self.data)
        broken[-1] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'hl-node'
            path.write_bytes(bytes(broken))
            with self.assertRaises(Exception):
                packet.generate(binary=path, output=Path(tmp) / 'out')


if __name__ == '__main__':
    unittest.main()
