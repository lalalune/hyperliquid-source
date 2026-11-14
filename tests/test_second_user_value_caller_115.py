"""Node #115 path above the second per-user value visitor. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import second_user_value_caller_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-second-user-value-caller-115/evidence.json'


class SecondUserValueCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_chain_is_user_states_user_to_state(self):
        r = self.result
        self.assertEqual(r['keys']['0x445d0d0'], {'user_states': 1})
        self.assertEqual(r['keys']['0x4458570']['user_to_state'], 0)
        self.assertEqual(r['tables'], {'0x723d40[0]': '0x32db332', '0x706280[1]': '0x3275984'})
        self.assertEqual(r['leas']['0x46dd93b']['text'], 'a sequenced map')
        self.assertEqual(r['leas']['0x38db60b']['text'], 'a tuple of size 2')
        self.assertEqual(r['direct_callers']['0x30bcb40'], ['0x3314f4e'])
        self.assertEqual(r['direct_callers']['0x3314a40'], ['0x470e80b'])
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
        # tuple element 0 length 0x14 -> 0x15
        self._rejects(self._patch(self.data, 0x3314c2e, b'\x15'), why='0x3314c26')

    def test_user_states_name_rejected(self):
        # user_states -> user_stbtes in the 0x445d0d0 arm (not pinned)
        self._rejects(self._patch(self.data, 0x445da7b, b'b'),
                      why="matches 'user_stbtes', not 'user_states'")

    def test_user_to_state_name_rejected(self):
        self._rejects(self._patch(self.data, 0x445884b, b"z"), why="matches 'uzer_to_state'")

    def test_key_index_rejected(self):
        # users_with_positions: mov cl,1 -> mov cl,2 (not pinned)
        self._rejects(self._patch(self.data, 0x445866b, b'\x02'),
                      why='arm 0x44585ad gives index 2, not 1')

    def test_length_table_rejected(self):
        entry = 0x7ce814 + 4 * (len('user_states') - 3)
        rel = struct.unpack('<i', packet.read_va(self.data, entry, 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', rel + 1)),
                      why='length table 0x7ce814')

    def test_field_table_rejected(self):
        entry = 0x723d40
        rel = struct.unpack('<i', packet.read_va(self.data, entry, 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', rel + 1)),
                      why='table 0x723d40 entry 0')

    def test_sequenced_map_text_rejected(self):
        self._rejects(self._patch(self.data, 0x7de6ee, b'X'), why='0x7de6ec')

    def test_tuple_text_rejected(self):
        self._rejects(self._patch(self.data, 0x7a03a0, b"3"), why='0x7a0390')

    def test_relocation_rejected(self):
        # point the expected-text vtable at the wrong formatter
        rela = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        body = self.data[rela['offset']:rela['offset'] + rela['size']]
        for i, (off, info, addend) in enumerate(struct.iter_unpack('<QQq', body)):
            if off == 0x6490708:
                at = rela['offset'] + 24 * i + 16
                break
        broken = bytearray(self.data)
        broken[at:at + 8] = struct.pack('<q', 0x46dd931)
        self._rejects(bytes(broken), why='relocation at 0x6490708')

    def test_visitor_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x3314f4f), 0x3314f26, why='0x3314f4e')

    def test_caller_census_rejected(self):
        # move the only call to 0x3314a40; its branch entry is removed, so the census must catch it
        self._rejects(self._bump_rel32(self.data, 0x470e80c), 0x470e7f0, jumps=(0x470e80b,),
                      why='direct callers of 0x3314a40')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x389a09e: packet.CLEARINGHOUSE}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
