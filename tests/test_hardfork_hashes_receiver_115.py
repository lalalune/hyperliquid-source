"""Node #115 hardfork_hashes channel: sender origin, push/pop census, l1 hash. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import hardfork_hashes_receiver_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-hardfork-hashes-receiver-115/evidence.json'


class HardforkHashesReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        ch = self.result['channel']
        self.assertEqual(ch['push_sites'], {'0x59ed370': '0x59ec200', '0x5a3459c': '0x5a34440',
                                            '0x5a6cb1d': '0x5a6c8f0', '0x5a6dc49': '0x5a6db30'})
        self.assertEqual(ch['callers_0x5a6db30'], ['0x5443930', '0x59ec200'])
        rx = self.result['receive']
        self.assertEqual(rx['pop_callers'], ['0x5a8b510', '0x5a8d5b0'])
        self.assertEqual(rx['second_pop_callers'], ['0x2c8f050', '0x2c92fb0', '0x2cda0b0', '0x2cdca20'])
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

    def test_closure_sender_offset_rejected(self):
        # driver: mov rbx, [rax+0x28] -> [rax+0x20]
        self._rejects(self._patch(0x5a3455d + 3, b'\x20'))

    def test_poller_state_offset_rejected(self):
        # lea rax, [rbx+0x9d0] -> [rbx+0x9d8]
        self._rejects(self._patch(0x2aed259 + 3, b'\xd8'))

    def test_closure_size_rejected(self):
        # mov edx, 0xb8 -> 0xb0
        self._rejects(self._patch(0x5a6ce43 + 1, b'\xb0'))

    def test_block_size_rejected(self):
        # push: mov edi, 0x520 -> 0x510
        self._rejects(self._patch(0x581a577 + 1, b'\x10'))

    def test_slot_stride_rejected(self):
        # pop: lea rdx, [rdx+rdx*4] -> [rdx+rdx*2]
        self._rejects(self._patch(0x58198f0 + 3, b'\x52'))

    def test_blocking_flag_rejected(self):
        # worker: mov edx, 1 -> 0
        self._rejects(self._patch(0x54847a5 + 1, b'\x00'))

    def test_l1_hash_string_rejected(self):
        # 'computed l1 hash' -> 'computed l2 hash'
        self._rejects(self._patch(0x431bdb + 10, b'2'))

    def test_second_pop_block_size_rejected(self):
        # second pop: mov esi, 0x520 -> 0x500
        self._rejects(self._patch(0x2ccf506 + 1, b'\x00'))


if __name__ == '__main__':
    unittest.main()
