"""Node #115 slow abci driver receive loop. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_driver_recv_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-driver-recv-115/evidence.json'


class SlowAbciDriverRecvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_receive_and_counter(self):
        self.assertEqual(self.result['driver_scan'], {'imm_5000': [], 'lock_inc_dec_plus_0x10': ['0x5a34558', '0x5a34cbd']})
        self.assertEqual(self.result['locations']['0x64a3648'], 'node/src/abci_latency_sampler.rs:60:41')
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_gap_model(self):
        self.assertEqual(self.result['per_message']['gap_samples'],
                         {'-1s': 0.0, '0.25s': 0.25, '59.5s': 59.5, '3600s': 60.0})

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        sec = next(s for s in sections(self.data) if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        off = sec['offset'] + va - sec['address']
        broken = bytearray(self.data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_counter_decrement_rejected(self):
        # lock dec [rax+0x10] -> lock inc [rax+0x10]
        self._rejects(self._patch(0x5a34cbd + 3, b'\x40'))

    def test_counter_field_rejected(self):
        # mov rax, [rax+0x88] -> [rax+0x90]
        self._rejects(self._patch(0x5a34cb6 + 3, b'\x90'))

    def test_take_amount_rejected(self):
        # lock sub [r14+0x1c0], 2 -> 4
        self._rejects(self._patch(0x5a34a10 + 8, b'\x04'))

    def test_park_timeout_rejected(self):
        # mov ecx, 1e9 -> 1e9 + 1
        self._rejects(self._patch(0x5a34b57, b'\x01'))

    def test_gap_cap_rejected(self):
        # 60.0 -> 62.0
        self._rejects(self._patch(0x459718 + 6, b'\x4f'))

    def test_minsd_rejected(self):
        # minsd -> maxsd
        self._rejects(self._patch(0x5a34d97 + 2, b'\x5f'))

    def test_location_line_rejected(self):
        # abci_latency_sampler.rs:60 -> 61
        self._rejects(self._patch(0x64a3648 + 16, b'\x3d'))

    def test_apply_name_rejected(self):
        # spawn_slow_abci_driver_apply_block -> ..._apply_blocK
        self._rejects(self._patch(0x93b00f + 33, b'K'))


if __name__ == '__main__':
    unittest.main()
