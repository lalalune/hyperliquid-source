"""Node #115 Locus field pmu. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_pmu_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-pmu-115/evidence.json'


class LocusPmuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_pmu_is_required_u64(self):
        self.assertEqual(self.result['field']['key'], 'pmu')
        self.assertEqual(self.result['value']['reader']['relocated_to'], '0x14b7aa0')
        self.assertEqual(self.result['missing']['default'], 'none')
        self.assertEqual(self.result['value']['markers']['0xcf']['meaning'], 'u64')
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, data, va):
        sec = next(s for s in sections(data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, data, va, new):
        off = self._off(data, va)
        broken = bytearray(data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _bump_rel32(self, data, va, by=1):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + by))

    def _rejects(self, data, why):
        with self.assertRaisesRegex(ValueError, why):
            packet.bind(data)

    def test_seen_flag_rejected(self):
        # cmp [rsp+0xa0],1 -> 2
        self._rejects(self._patch(self.data, 0x332ca44, b'\x02'), 'seen flag compared')

    def test_result_tag_rejected(self):
        # cmp al,9 -> 8
        self._rejects(self._patch(self.data, 0x332d831, b'\x08'), 'result tag compared')

    def test_slot_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x332d81c, 8), 'not through slot')

    def test_duplicate_branch_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x332ca47), 'branch at 0x332ca45')

    def test_name_text_rejected(self):
        # pmu -> qmu
        self._rejects(self._patch(self.data, packet.NAME, b'q'), "string at 0x794eb4")

    def test_template_text_rejected(self):
        self._rejects(self._patch(self.data, packet.TEMPLATE + 1, b'n'), 'string at 0x4325c4')

    def test_missing_builder_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x332fbce), 'branch at 0x332fbcd')

    def test_u64_table_entry_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.TABLE + 4 * (0xcf - 0xc0)), 'marker 0xcf')

    def test_negative_check_rejected(self):
        # js -> jns at the fixint arm
        self._rejects(self._patch(self.data, 0x14b7ba1, b'\x89'), 'fixint >= 0')

    def test_float_tag_rejected(self):
        self._rejects(self._patch(self.data, 0x1516606, b'\x04'), 'unexpected float')

    def test_success_tag_rejected(self):
        self._rejects(self._patch(self.data, 0x14b7d10, b'\x08'), 'success tag 9')

    def test_relocation_rejected(self):
        saved = packet.READER
        packet.READER = saved + 1
        try:
            with self.assertRaisesRegex(ValueError, 'relocated to'):
                packet.slot_call(self.data)
        finally:
            packet.READER = saved

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, packet.SLOT_CALL: packet.READER}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
