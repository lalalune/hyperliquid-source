"""Node #115 daily line writer owners. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import line_writer_owners_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-line-writer-owners-115/evidence.json'
STATIC = {
    '0x2af59e6': 'mempool_txs', '0x2cc2703': 'mempool_txs', '0x47809ae': 'tcp_traffic',
    '0x47833db': 'tcp_lz4_stats', '0x51d06f8': 'evm_block_and_receipts',
    '0x51d0918': 'dex_user_clearinghouse_states', '0x5a3965d': 'visor_abci_states',
    '0x5a6c42c': 'abci_digest_quorum', '0x5a6c45c': 'abci_hashes',
    '0x5a72050': 'validator_latency_ema', '0x5b57a6a': 'evm_block_and_receipts',
}


class LineWriterOwnersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_census(self):
        r = self.result
        self.assertEqual((r['daily_calls'], r['hourly_calls'], r['hourly_after_daily']), (32, 27, 27))
        self.assertEqual((r['static_names'], r['register_names']), (11, 21))
        self.assertEqual(r['flush_byte_set_after_hourly'], 12)
        self.assertEqual(r['sha256'], packet.SHA256)
        self.assertFalse(r['gates_changed'])

    def test_static_names(self):
        got = {s['call']: s['name'] for s in self.result['sites'] if s['name_kind'] == 'static'}
        self.assertEqual(got, STATIC)

    def test_daily_without_hourly(self):
        got = [s['call'] for s in self.result['sites'] if s['hourly'] is None]
        self.assertEqual(got, ['0x2e1caf1', '0x4771e53', '0x47833db', '0x51c9e3e', '0x5a72050'])

    def test_mixed_moves(self):
        moves = self.result['mixed_function_moves']
        self.assertEqual(moves['0x2af45f0']['daily_call'], '0x2af59e6')
        self.assertEqual(moves['0x2cc1120']['daily_call'], '0x2cc2703')

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

    def test_hourly_input_register_rejected(self):
        # mov rbx, rsi -> mov rbx, rdi
        self._rejects(self._patch(0x1546011 + 2, b'\xfb'))

    def test_hourly_takes_other_buffer_rejected(self):
        # 0x2af59f4 lea rsi, [rsp+0x240] -> [rsp+0x248]: hourly no longer takes the daily writer
        self._rejects(self._patch(0x2af59f4 + 4, b'\x48'))

    def test_hourly_without_daily_rejected(self):
        # retarget the daily call before 0x5b57a7b: that hourly call is left unpaired
        self._rejects(self._patch(0x5b57a6a + 2, b'\x00\x00\x00\x00'))

    def test_tail_length_rejected(self):
        # mov edx, 0xa8 -> 0xb0
        self._rejects(self._patch(0x2af5a22 + 1, b'\xb0'))

    def test_struct_slot_rejected(self):
        # mov [rsp+0x7e8], r15 -> [rsp+0x7e0]
        self._rejects(self._patch(0x2cc27c3 + 4, b'\xe0'))

    def test_flush_byte_rejected(self):
        # mov byte [rsp+0x175a], 1 -> 0: the mixed move no longer finds its flush-set row
        self._rejects(self._patch(0x2cc271f + 7, b'\x00'))


if __name__ == '__main__':
    unittest.main()
