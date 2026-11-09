"""Node #115 shared value observer (first stage) and its wall-clock tuple provider. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-115/evidence.json'


class AbciStepObserver115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_observer_shape(self):
        obs = self.result['observer']
        self.assertEqual(obs['fde'], {'start_va': '0x1547530', 'end_va': '0x1548ba3'})
        self.assertEqual(obs['count_multiplier']['factor'], 50)
        self.assertEqual(obs['saturation_constant']['value'], 2.0 ** 64)
        self.assertEqual(obs['tuple_call']['target_va'], '0x1629690')
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_provider_and_census(self):
        prov = self.result['provider']
        self.assertEqual(prov['clock']['edi'], 0)
        self.assertEqual(prov['date_call']['target_va'], '0x1628f50')
        census = self.result['census']
        self.assertEqual(census['observer_slot_calls'], 68)
        self.assertEqual(census['observer_direct_calls'], 0)
        self.assertEqual(census['observer_relative_relocations'], ['0x64e1010'])
        self.assertIn('0x5b2a24c', census['slot_call_sites'])

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

    def test_multiplier_immediate_rejected(self):
        # mov ecx, 50 -> mov ecx, 49
        self._rejects(self._patch(0x15475ba + 1, b'\x31'))

    def test_rollover_compare_offset_rejected(self):
        # cmp [rbx+0x240], edi -> cmp [rbx+0x248], edi
        self._rejects(self._patch(0x1547562 + 2, b'\x48'))

    def test_daily_sum_store_rejected(self):
        # movsd [rbx+0x210], xmm1 -> movsd [rbx+0x218], xmm1
        self._rejects(self._patch(0x1547758 + 4, b'\x18'))

    def test_deque_push_front_rejected(self):
        # dec rsi -> inc rsi (push_back-like head move)
        self._rejects(self._patch(0x15477ad + 2, b'\xc6'))

    def test_running_max_rejected(self):
        # maxsd -> minsd
        self._rejects(self._patch(0x15478dc + 2, b'\x5d'))

    def test_provider_clock_id_rejected(self):
        # xor edi, edi -> xor esi, esi
        self._rejects(self._patch(0x162969d + 1, b'\xf6'))

    def test_provider_epoch_days_rejected(self):
        self._rejects(self._patch(0x162972a + 2, struct.pack('<I', 719162)))

    def test_extra_observer_slot_call_rejected(self):
        pad = packet.OBSERVER_END
        _, run = packet.read_va(self.data, pad, 6)
        if run != b'\xcc' * 6:
            self.skipTest('no int3 padding after the observer FDE')
        disp = packet.OBSERVER_SLOT - (pad + 6)
        self._rejects(self._patch(pad, b'\xff\x15' + struct.pack('<i', disp)))


if __name__ == '__main__':
    unittest.main()
