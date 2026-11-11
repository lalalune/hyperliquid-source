"""Node #115 observer value clamps and day/window sums. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import observer_value_range_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-observer-value-range-115/evidence.json'


class ObserverValueRangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_clamps(self):
        p = self.result['product_clamp']['samples']
        s = self.result['sum_clamp']['samples']
        self.assertEqual((p['1.5'], p['-2.0'], p['nan'], p['inf'], p['-0.0']), ('1.5', '0.0', '0.0', '0.0', '-0.0'))
        self.assertEqual((s['inf'], s['nan'], s['-inf']), ('1.8446744073709552e+19', '0.0', '0.0'))
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_census(self):
        census = self.result['census']
        self.assertEqual((census['owner_functions'], census['record_slot_calls'], census['constructor_slot_calls']),
                         (77, 68, 35))
        own = census['operands']
        self.assertEqual(len(own['0x208']['in_owner_functions']), 17)
        self.assertEqual(len(own['0x218']['in_owner_functions']), 13)
        record_208 = [a for a, f in own['0x208']['in_owner_functions'] if f == hex(packet.RECORD)]
        self.assertEqual(record_208, ['0x1547732', '0x1547740'])

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

    def test_x50_rejected(self):
        # mov ecx, 50 -> 51
        self._rejects(self._patch(0x15475ba + 1, b'\x33'))

    def test_overflow_saturation_rejected(self):
        # mov r14, -1 -> mov r14, 0x7fffffff
        self._rejects(self._patch(0x1548a0b + 3, b'\xff\xff\xff\x7f'))

    def test_normal_bound_rejected(self):
        # cmp edx, 0x3ff -> 0x3fe
        self._rejects(self._patch(0x1547634 + 2, b'\xfe'))

    def test_sign_branch_rejected(self):
        # jns -> js
        self._rejects(self._patch(0x154762f, b'\x78'))

    def test_saturation_constant_rejected(self):
        # 2^64 -> 2^65
        self._rejects(self._patch(packet.SATURATED + 6, b'\x00\x44'))

    def test_day_count_saturation_rejected(self):
        # cmovb rsi, rdx -> cmovae rsi, rdx
        self._rejects(self._patch(0x1547721 + 2, b'\x43'))

    def test_ring_limit_rejected(self):
        # mov [rbx+0x58], r12 -> [rbx+0x50]
        self._rejects(self._patch(0x15477cd + 3, b'\x50'))

    def test_window_sum_offset_rejected(self):
        # movsd [rbx+0x88], xmm0 -> [rbx+0x90]
        self._rejects(self._patch(0x1547898 + 4, b'\x90'))


if __name__ == '__main__':
    unittest.main()
