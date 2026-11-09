"""Node #115 shared value observer: 30-second window, constructor and x50 flag. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_window_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-window-115/evidence.json'


class AbciStepObserverWindow115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_window_shape(self):
        win = self.result['observer_window']
        self.assertEqual(win['window']['start_va'], '0x15478e8')
        self.assertEqual(win['deadline']['on_failure']['tuple'], [2147473118, 86399, 999999999])
        self.assertEqual(win['mean']['epsilon']['value'], -1e-15)
        tests = win['deadline']['range_tests']
        self.assertEqual(tests['test_2']['kept_half_open_interval'][1], 86400 * 2 ** 31)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_constructor_and_flag(self):
        ctor = self.result['constructor']
        self.assertEqual(ctor['fde'], {'start_va': '0x1548bb0', 'end_va': '0x1548f3d'})
        self.assertEqual(ctor['initial']['+0x220']['value'], 30.0)
        self.assertEqual(ctor['initial']['+0x1f8'], 2000)
        self.assertEqual(ctor['initial']['+0x25c'], 0)
        self.assertEqual(ctor['slot']['slot_calls'], 35)
        self.assertEqual(ctor['slot']['direct_calls'], 0)
        flag = self.result['flag_25c']
        self.assertEqual(len(flag['set_to_1_after_constructor']), 5)
        self.assertEqual(len(flag['byte_store_census']), 8)

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

    def test_window_length_rejected(self):
        # movabs rax, 30.0 -> 31.0 (0x403f000000000000)
        self._rejects(self._patch(0x1548de2 + 8, b'\x3f'))

    def test_sample_limit_rejected(self):
        # +0x1f8 = 2000 -> 2001
        self._rejects(self._patch(0x1548d56 + 7, b'\xd1'))

    def test_constructor_flag_value_rejected(self):
        # +0x25c = 0 -> 1
        self._rejects(self._patch(0x1548e0a + 7, b'\x01'))

    def test_strict_compare_rejected(self):
        # jb ROLLOVER -> jbe (deadline equal to now would roll over)
        self._rejects(self._patch(0x1547a74, b'\x76'))

    def test_rollover_start_offset_rejected(self):
        # mov [rbx+0x228], edi -> mov [rbx+0x220], edi
        self._rejects(self._patch(0x1547a87 + 2, b'\x20'))

    def test_vector_reset_rejected(self):
        # +0x68 = 8 -> 16
        self._rejects(self._patch(0x1547ad0 + 4, b'\x10'))

    def test_mean_divide_rejected(self):
        # divsd -> mulsd
        self._rejects(self._patch(0x1547b81 + 2, b'\x59'))

    def test_max_tuple_rejected(self):
        self._rejects(self._patch(packet.MAX_TUPLE + 4, struct.pack('<I', 86398)))

    def test_flag_setter_value_rejected(self):
        # the first setter writes 1 -> 2
        self._rejects(self._patch(0x16eeeca + 7, b'\x02'))

    def test_extra_flag_store_rejected(self):
        pad = packet.OBSERVER_END
        _, run = packet.read_va(self.data, pad, 8)
        if run != b'\xcc' * 8:
            self.skipTest('no int3 padding after the observer FDE')
        # mov byte [r14+0x25c], 1 in the padding
        self._rejects(self._patch(pad, bytes.fromhex('41c6865c02000001')))

    def test_extra_constructor_call_rejected(self):
        pad = packet.OBSERVER_END
        _, run = packet.read_va(self.data, pad, 6)
        if run != b'\xcc' * 6:
            self.skipTest('no int3 padding after the observer FDE')
        disp = packet.CTOR_SLOT - (pad + 6)
        self._rejects(self._patch(pad, b'\xff\x15' + struct.pack('<i', disp)))


if __name__ == '__main__':
    unittest.main()
