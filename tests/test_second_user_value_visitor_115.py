"""Node #115 second per-user value visitor 0x30bcb40. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import second_user_value_visitor_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-second-user-value-visitor-115/evidence.json'


class SecondUserValueVisitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_keys_and_arms_are_the_per_user_value(self):
        r = self.result
        want = {'u': 0, 'p': 1, 'D': 2, 'l': 3, 'S': 4, 'r': 5}
        self.assertEqual(r['keys'], {'0x6857e0': want, '0x685718': want})
        self.assertEqual(r['branches']['0x30bd552'], '0x3184540')
        self.assertEqual(r['branches']['0x30be015'], '0x3184540')
        self.assertEqual(r['slots']['0x30bd79a'], '0x64e2580')
        self.assertEqual(r['leas']['0x30bce89']['text'], 'Ntli')
        self.assertEqual(r['leas']['0x30bd6c8']['text'], 'Time')
        self.assertEqual(r['direct_callers']['0x30bcb40'], ['0x3314f4e'])
        self.assertFalse(r['gates_changed'])

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

    def _bump_rel32(self, data, va):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + 1))

    def _rejects(self, data, *drop, jumps=(), why):
        saved = packet.PINS, packet.JUMPS
        packet.PINS = {k: v for k, v in saved[0].items() if k not in drop}
        packet.JUMPS = {k: v for k, v in saved[1].items() if k not in jumps}
        try:
            with self.assertRaisesRegex(ValueError, why):
                packet.bind(data)
        finally:
            packet.PINS, packet.JUMPS = saved

    def test_pin_alone_rejects(self):
        # sub ecx,0x44 -> sub ecx,0x45 in the key dispatch
        self._rejects(self._patch(self.data, 0x30bd11d, b'\xbb'), why='0x30bd0fb')

    def test_key_index_rejected(self):
        # p arm of table 0x6857e0: mov al,1 -> mov al,2 (not pinned)
        self._rejects(self._patch(self.data, 0x30bd4d2, b'\x02'), why='key table 0x6857e0')

    def test_key_table_entry_rejected(self):
        # the `p` entry of table 0x685718 points at the `r` arm
        entry = 0x685718 + 4 * (ord('p') - packet.KEY_BASE)
        r_arm = 0x685718 + struct.unpack('<i', packet.read_va(
            self.data, 0x685718 + 4 * (ord('r') - packet.KEY_BASE), 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', r_arm - 0x685718)),
                      why='key table 0x685718')

    def test_field_table_rejected(self):
        entry = packet.FIELD_TABLE + 4
        rel = struct.unpack('<i', packet.read_va(self.data, entry, 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', rel + 1)),
                      why='field table 0x6858a8 entry 1')

    def test_p_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30bd553), 0x30bd52f, why='0x30bd552')

    def test_ntli_name_rejected(self):
        self._rejects(self._patch(self.data, 0x45a098, b'M'), why='0x45a098')

    def test_time_name_rejected(self):
        self._rejects(self._patch(self.data, 0x459f78, b'X'), why='0x459f78')

    def test_duplicate_name_rejected(self):
        self._rejects(self._patch(self.data, 0x7936ed, b'v'), why='0x7936ed')

    def test_r_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30bd79c), 0x30bd789, why='0x30bd79a')

    def test_key_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30bd0fd), 0x30bd0fb, why='0x30bd0fb')

    def test_caller_census_rejected(self):
        # move the second call to 0x3184540; its branch entry is removed, so the census must catch it
        self._rejects(self._bump_rel32(self.data, 0x30be016), jumps=(0x30be015,),
                      why='direct callers of 0x3184540')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x3314f4e: packet.VISITOR}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
