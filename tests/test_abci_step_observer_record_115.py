"""Node #115 observer window-record sink 0x1546570. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_record_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-record-115/evidence.json'


class AbciStepObserverRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_sink_shape(self):
        sink = self.result['sink']
        self.assertEqual(sink['fde'], ['0x1546570', '0x15466f3'])
        self.assertEqual(sink['direct_calls'], 0)
        self.assertEqual(sink['slot_calls'], 104)
        self.assertEqual(sink['paths_inferred']['hourly'], '{dir}/hourly/{date:%Y%m%d}/{hour}')
        self.assertEqual(self.result['hour_helper']['slot_calls'], 28)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_observer_use(self):
        use = self.result['observer_use']
        self.assertEqual(use['rotation']['open_panic_location'], 'base/src/liner.rs:28:38')
        self.assertEqual(use['rotation']['cache'], {'+0x130': 'date', '+0x140': 'hourly', '+0x141': 'hour'})

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

    def test_hourly_offset_rejected(self):
        # cmp byte [rsi+0xa8], 1 -> [rsi+0xa9]
        self._rejects(self._patch(0x1546582 + 2, b'\xa9'))

    def test_cached_date_offset_rejected(self):
        # cmp ebp, [r14+0x98] -> [r14+0x9c]
        self._rejects(self._patch(0x15465a5 + 3, b'\x9c'))

    def test_none_niche_rejected(self):
        # movabs rax, 0x8000000000000000 -> 0x8000000000000001
        self._rejects(self._patch(0x154664c + 2, b'\x01'))

    def test_template_rejected(self):
        # /hourly/ -> /hourlz/
        self._rejects(self._patch(packet.HOURLY_TEMPLATE + 8, b'z'))

    def test_date_pattern_rejected(self):
        # %Y%m%d -> %Y%m%e
        self._rejects(self._patch(packet.DATE_PATTERN + 5, b'e'))

    def test_hour_divisor_rejected(self):
        # 0x91a2b3c5 -> 0x91a2b3c6 breaks seconds / 3600 somewhere below 90000
        self._rejects(self._patch(0x1567ae2 + 1, b'\xc6'))

    def test_hour_limit_rejected(self):
        # cmp ecx, 90000 -> 90001
        self._rejects(self._patch(0x1567af3 + 2, struct.pack('<I', 90001)))

    def test_cache_store_rejected(self):
        # mov [rbx+0x141], r13b -> [rbx+0x142]
        self._rejects(self._patch(0x1548982 + 3, b'\x42'))

    def test_writer_offset_rejected(self):
        # cmp [rbx+0xe0], r15 -> [rbx+0xe8]
        self._rejects(self._patch(0x15488ae + 3, b'\xe8'))

    def test_location_line_rejected(self):
        # base/src/liner.rs:28 -> :29
        self._rejects(self._patch(packet.OPEN_LOCATION + 16, struct.pack('<I', 29)))

    def test_sink_slot_census_rejected(self):
        # turn the observer's FF15 sink call into an E8 direct call to the sink
        disp = packet.SINK[0] - (0x15488a3 + 5)
        self._rejects(self._patch(0x15488a3, b'\xe8' + struct.pack('<i', disp) + b'\x90'))


if __name__ == '__main__':
    unittest.main()
