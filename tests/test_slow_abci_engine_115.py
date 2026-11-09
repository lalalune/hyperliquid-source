"""Node #115 node_slow_abci_engine runner. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import slow_abci_engine_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-slow-abci-engine-115/evidence.json'


class SlowAbciEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_call_site(self):
        site = self.result['call_site']
        self.assertEqual(site['slow_builder_slot_calls'], ['0x5a6c619'])
        self.assertEqual(site['slow_builder_direct_calls'], [])
        self.assertEqual(site['fast_builder_direct_calls'], ['0x5a6c21c'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_maps_and_pool(self):
        self.assertEqual(self.result['maps']['inserts'], {'0x51d4530': 0.05, '0x51d4df0': 0.35})
        self.assertIn('edi = 3, esi = 0x10', self.result['pool']['args'])

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

    def test_pool_threads_rejected(self):
        # mov edi, 3 -> 4
        self._rejects(self._patch(0x56496a4 + 1, b'\x04'))

    def test_threshold_rejected(self):
        # 0.05 -> 0.06
        self._rejects(self._patch(0x459038, struct.pack('<d', 0.06)))

    def test_map_key_rejected(self):
        # spawn_slow_abci -> spawn_slow_abcX
        self._rejects(self._patch(0x92a82b + 34, b'X'))

    def test_minutes_constant_rejected(self):
        # 525600 -> 525601
        self._rejects(self._patch(0x5649c4b + 7, b'\x21'))

    def test_slow_flag_offset_rejected(self):
        # setne [r14+0xb40] -> [r14+0xb41]
        self._rejects(self._patch(0x5649c61 + 4, b'\x41'))

    def test_part_flag_rejected(self):
        # mov ecx, 1 -> 2
        self._rejects(self._patch(0x5649b01 + 1, b'\x02'))

    def test_fast_layout_rejected(self):
        # lea rdi, [r13+0x6a8] -> [r13+0x6b0]
        self._rejects(self._patch(0x567c0c7 + 3, b'\xb0'))

    def test_lock_location_rejected(self):
        # rw_lock.rs:110 -> 111
        self._rejects(self._patch(packet.LOCATION + 16, b'\x6f'))


if __name__ == '__main__':
    unittest.main()
