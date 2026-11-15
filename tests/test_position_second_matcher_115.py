"""Node #115 second position key matcher: a second MessagePack decoder. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import position_second_matcher_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-position-second-matcher-115/evidence.json'


class PositionSecondMatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_second_decoder_shares_rules(self):
        r = self.result
        self.assertEqual(r['matchers']['ok_tag_bytes'], 6)
        self.assertEqual([r['field_table'][str(i)]['field'] for i in range(6)],
                         ['s', 'l', 'M', 'f', 'e', 'other'])
        self.assertEqual((r['m_arm']['integer_read'], r['m_arm']['default']), ('0x34861d0', 20))
        self.assertEqual(r['leas']['0x4483100']['text'], 'MarginTableId')
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

    def _rejects(self, data, *drop, why):
        saved = packet.PINS
        packet.PINS = {k: v for k, v in saved.items() if k not in drop}
        try:
            with self.assertRaisesRegex(ValueError, why):
                packet.bind(data)
        finally:
            packet.PINS = saved

    def test_pin_alone_rejects(self):
        # end of map: mov ecx,0x14 -> 0x15
        self._rejects(self._patch(self.data, 0x32d4c50, b'\x15'), why='0x32d4c4f')

    def test_matcher_extra_difference_rejected(self):
        # a key compare byte in the second matcher only
        self._rejects(self._patch(self.data, packet.SECOND_MATCHER + 0x50,
                                  bytes([packet.read_va(self.data, packet.SECOND_MATCHER + 0x50, 1)[0] ^ 1])),
                      why='outside the ok tag')

    def test_matcher_tag_rejected(self):
        # one ok tag 9 -> 0 leaves five tag differences
        self._rejects(self._patch(self.data, packet.SECOND_MATCHER + 0x46, b'\x00'), why='ok tag differences')

    def test_matcher_jump_table_rejected(self):
        table = packet.rel_target(self.data, packet.SECOND_MATCHER + 0x10, 7)
        self._rejects(self._bump_rel32(self.data, table), why='jump table')

    def test_field_table_rejected(self):
        # index 2 (M) now goes to the index 0 arm
        self._rejects(self._patch(self.data, packet.FIELD_TABLE + 8,
                                  packet.read_va(self.data, packet.FIELD_TABLE, 4)),
                      why='field table')

    def test_second_matcher_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x32d4347), 0x32d42fc, why='0x32d4346')

    def test_m_read_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x32d4019), 0x32d4007, why='0x32d4018')

    def test_duplicate_branch_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x32d40a1), why='0x32d409f')

    def test_integer_slot_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x2f6e45f), 0x2f6e45d, why='0x2f6e45d')

    def test_m_name_rejected(self):
        self._rejects(self._patch(self.data, 0x7d251f, b'N'), why='0x7d251f')

    def test_duplicate_name_rejected(self):
        self._rejects(self._patch(self.data, 0x793e6c, b'N'), why='0x793e6c')

    def test_relocation_rejected(self):
        want = struct.pack('<Q', packet.INT_SLOT)
        for sec in sections(self.data):
            if sec['type'] != 4:
                continue
            body = self.data[sec['offset']:sec['offset'] + sec['size']]
            for i in range(0, len(body), 24):
                if body[i:i + 8] == want and body[i + 8:i + 12] == b'\x08\x00\x00\x00':
                    off = sec['offset'] + i + 16
                    broken = bytearray(self.data)
                    broken[off:off + 8] = struct.pack('<q', packet.INT_READ + 1)
                    self._rejects(bytes(broken), why='0x64e25d8')
                    return
        self.fail('relocation for slot 0x64e25d8 not found')


if __name__ == '__main__':
    unittest.main()
