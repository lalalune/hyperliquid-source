"""Node #115 JSON position reader: M rejects 0 and defaults to 20. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_json_m_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-json-m-115/evidence.json'


class PositionJsonMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_m_arm_rules_match_msgpack(self):
        arm = self.result['m_arm']
        self.assertEqual((arm['not_seen'], arm['default'], arm['stored_at']), (0, 20, '+0x38'))
        self.assertEqual(self.result['field_table']['2'], '0x402eb63')
        self.assertEqual(self.result['m_read']['accepts'], '1..0xffffffff')
        self.assertEqual(self.result['leas']['0x38dbaab']['text'], 'a nonzero u32')
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

    def _bump_rel32(self, data, va):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + 1))

    def _rejects(self, data, *drop, why):
        saved = packet.PINS
        packet.PINS = {k: v for k, v in saved.items() if k not in drop}
        try:
            with self.assertRaisesRegex(ValueError, why):
                packet.bind(data)
        finally:
            packet.PINS = saved

    def test_pin_alone_rejects(self):
        # cmp dword [rsp+0x50],0 -> ,1
        self._rejects(self._patch(self.data, 0x402eb67, b'\x01'), why='0x402eb63')

    def test_field_table_rejected(self):
        # index 2 (M) now goes to the index 0 arm
        self._rejects(self._patch(self.data, packet.FIELD_TABLE + 8,
                                  packet.read_va(self.data, packet.FIELD_TABLE, 4)),
                      why='field table')

    def test_matcher_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x402ea51), 0x402ea4b, why='0x402ea50')

    def test_m_value_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x402ed0d), 0x402ecec, why='0x402ed0c')

    def test_sequence_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x402ef80), 0x402ef75, why='0x402ef7f')

    def test_unsigned_range_branch_rejected(self):
        # jb error -> jae error
        self._rejects(self._patch(self.data, 0x3ef33d9, b'\x73'), 0x3ef3394, why='kind 1')

    def test_invalid_value_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3ef343a), 0x3ef341d, why='0x3ef3438')

    def test_expected_vtable_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3ef342a), 0x3ef341d, why='0x3ef3427')

    def test_duplicate_name_rejected(self):
        self._rejects(self._patch(self.data, 0x7c26e9, b'N'), why='0x7c26e9')

    def test_expected_text_rejected(self):
        self._rejects(self._patch(self.data, 0x9451ad, b'b'), why='0x9451ad')

    def test_relocation_rejected(self):
        # addend of the relocation for slot 0x64e0910 + 1
        want = struct.pack('<Q', packet.INVALID_VALUE_SLOT)
        for sec in sections(self.data):
            if sec['type'] != 4:
                continue
            body = self.data[sec['offset']:sec['offset'] + sec['size']]
            for i in range(0, len(body), 24):
                if body[i:i + 8] == want and body[i + 8:i + 12] == b'\x08\x00\x00\x00':
                    off = sec['offset'] + i + 16
                    broken = bytearray(self.data)
                    broken[off:off + 8] = struct.pack('<q', 0x5c54c31)
                    self._rejects(bytes(broken), why='0x64e0910')
                    return
        self.fail('relocation for slot 0x64e0910 not found')

    def test_second_matcher_tag_rejected(self):
        self._rejects(self._patch(self.data, 0x44559b6, b'\x08'), why='ok tag')


if __name__ == '__main__':
    unittest.main()
