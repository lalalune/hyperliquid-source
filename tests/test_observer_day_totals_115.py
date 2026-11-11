"""Node #115 observer day totals and the first sampler's collect. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import observer_day_totals_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-observer-day-totals-115/evidence.json'


class ObserverDayTotalsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_fields(self):
        self.assertEqual(self.result['json_fields']['total_n']['record_offset'], '0x50')
        self.assertEqual(self.result['json_fields']['total_mean']['record_offset'], '0x58')
        refs = self.result['day_fields']['record_entry_rbx_disp32_modrm_sites']
        self.assertEqual(len(refs['0x208']), 2)
        self.assertEqual(refs['0x218'], [])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_collect_census(self):
        c = self.result['first_sampler_collect']
        self.assertEqual(c['callers'], ['0x5b29cba', '0x5b29e02'])
        self.assertEqual(self.result['iterator_callers'], ['0x5b70d4c', '0x5b70eb3', '0x5b9273c', '0x5b928a3'])
        self.assertEqual(self.result['second_sampler_collect_callers'], ['0x5b2a51a', '0x5b2a662'])

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

    def test_count_record_offset_rejected(self):
        # mov [rsp+0x128], rax -> [rsp+0x120]
        self._rejects(self._patch(0x15487e0 + 4, b'\x20'))

    def test_mean_record_offset_rejected(self):
        # movsd [rsp+0x130], xmm0 -> [rsp+0x138]
        self._rejects(self._patch(0x15487ee + 5, b'\x38'))

    def test_divide_rejected(self):
        # divsd -> mulsd
        self._rejects(self._patch(0x1547fdd + 2, b'\x59'))

    def test_sample_gate_rejected(self):
        # cmp r12, 10 -> 11
        self._rejects(self._patch(0x1547f4b + 3, b'\x0b'))

    def test_epsilon_rejected(self):
        # -1e-15 -> -2e-15
        self._rejects(self._patch(packet.EPSILON, struct.pack('<d', -2e-15)))

    def test_field_name_rejected(self):
        # total_mean -> total_meaN
        self._rejects(self._patch(packet.FIELDS[1][0] + 9, b'N'))

    def test_collect_free_rejected(self):
        # first sampler frees capacity * 8 -> * 16
        self._rejects(self._patch(0x5b29cce + 3, b'\x04'))

    def test_collect_caller_rejected(self):
        # retarget the second collect call by one byte
        self._rejects(self._patch(0x5b29e02 + 1, b'\xea'))

    def test_day_count_increment_rejected(self):
        # inc rcx -> dec rcx
        self._rejects(self._patch(0x1547737 + 2, b'\xc9'))


if __name__ == '__main__':
    unittest.main()
