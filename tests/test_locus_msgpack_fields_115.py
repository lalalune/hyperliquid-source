"""Node #115 Locus MessagePack field arms. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_msgpack_fields_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-msgpack-fields-115/evidence.json'


class LocusMsgpackFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_sixteen_arms_in_name_order(self):
        keys = [f['key'] for f in self.result['fields']]
        self.assertEqual(keys, ['ctx', 'cls', 'scl', 'ftr', 'ust', 'chn', 'pdl', 'uaR',
                                'blp', 'qus', 'ctr', 'uac', 'vlt', 'hcm', 'pmu', 'msc'])
        self.assertEqual(self.result['fields'][1]['decoder'], '0x2f4d3e0')
        self.assertIsNone(self.result['fields'][14]['decoder'])
        self.assertEqual(self.result['locus_expectation']['text'], 'struct Locus with 16 elements')
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

    def _rejects(self, data, why, arms=None):
        saved = packet.ARMS
        if arms is not None:
            packet.ARMS = arms
        try:
            with self.assertRaisesRegex(ValueError, why):
                packet.bind(data)
        finally:
            packet.ARMS = saved

    def _arm_without_pin(self, index):
        arm = list(packet.ARMS[index])
        arm[1] = arm[1][:2]   # keep only the first byte of the arm pin
        return {**packet.ARMS, index: tuple(arm)}

    def test_arm_pin_rejects(self):
        # field 3 arm: cmp offset 0x1ae0 -> 0x1ae1
        self._rejects(self._patch(self.data, 0x332cf76, b'\xe1'), 'field 3 arm')

    def test_table_entry_rejected(self):
        entry = packet.FIELD_TABLE + 4 * 7
        self._rejects(self._bump_rel32(self.data, entry), 'table 0x73da1c entry 7')

    def test_duplicate_branch_rejected(self):
        # field 5 already-seen branch moved by one byte; arm pin relaxed
        self._rejects(self._bump_rel32(self.data, 0x332d186), 'branch at 0x332d184',
                      arms=self._arm_without_pin(5))

    def test_duplicate_name_rejected(self):
        # field 9 duplicate block loads name 10 instead of name 9
        self._rejects(self._bump_rel32(self.data, 0x332ff29, 3), 'does not load name 9')

    def test_duplicate_length_rejected(self):
        # field 12 duplicate block stores length 4
        self._rejects(self._patch(self.data, 0x332fe9e + 23, b'\x04'), 'does not store length 3')

    def test_decoder_call_rejected(self):
        # field 13 decoder call moved by one byte; arm pin relaxed
        self._rejects(self._bump_rel32(self.data, 0x332d1d7), 'branch at 0x332d1d6',
                      arms=self._arm_without_pin(13))

    def test_name_block_rejected(self):
        # vlt -> vlu
        self._rejects(self._patch(self.data, 0x794eaa, b'u'), 'name block at 0x794e8a')

    def test_locus_text_rejected(self):
        # Locus -> Locuz
        self._rejects(self._patch(self.data, 0x794eba + 11, b'z'), "is not 'struct Locus")

    def test_locus_length_rejected(self):
        self._rejects(self._patch(self.data, packet.LOCUS_RECORD + 8, b'\x1e'),
                      'record 0x6464530 length')

    def test_locus_relocation_rejected(self):
        rela = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        body = self.data[rela['offset']:rela['offset'] + rela['size']]
        for i, (off, info, addend) in enumerate(struct.iter_unpack('<QQq', body)):
            if off == packet.LOCUS_RECORD:
                at = rela['offset'] + 24 * i + 16
                break
        broken = bytearray(self.data)
        broken[at:at + 8] = struct.pack('<q', packet.LOCUS_TEXT_VA + 1)
        self._rejects(bytes(broken), 'relocation at 0x6464530')

    def test_helper_call_rejected(self):
        # call to 0x2fc21d0 moved; its pin is part of PINS, so the pin rejects first
        self._rejects(self._bump_rel32(self.data, 0x332dd92), '0x332dd86')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x2fc2201: packet.STRUCT}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
