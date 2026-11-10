"""Node #115 MessagePack path above the user_states reader. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import user_states_msgpack_root_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-user-states-msgpack-root-115/evidence.json'


class UserStatesMsgpackRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_chain_is_cls_then_user_states(self):
        r = self.result
        self.assertEqual(r['struct_field_names'][:2], ['ctx', 'cls'])
        self.assertEqual(len(r['struct_field_names']), 16)
        self.assertEqual(r['tables'], {'0x73da1c[1]': '0x332d10f', '0x73da1c[16]': '0x332ca10'})
        self.assertEqual(r['leas']['0x332fd06']['text'], 'cls')
        self.assertEqual(r['leas']['0x332d12d']['text'], 'Clearinghouses')
        self.assertEqual(r['direct_callers']['0x3274e70'], ['0x389a09e'])
        self.assertEqual(r['direct_callers']['0x3899fe0'], ['0x2f4d668'])
        self.assertEqual(r['direct_callers']['0x2f4d3e0'], ['0x332d134', '0x332dbbb'])
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
        # sequence cap 0x329 -> 0x32a
        self._rejects(self._patch(self.data, 0x3899ffb, b'\x2a'), why='0x3899ff6')

    def test_type_name_rejected(self):
        # Clearinghouses -> Clearinghousez (string is not pinned)
        self._rejects(self._patch(self.data, 0x7d23bf + 13, b'z'), why="is not 'Clearinghouses'")

    def test_field_name_block_rejected(self):
        # cls -> cly; with the block check told to expect it, the duplicate-name lea still rejects
        saved = packet.NAME_BLOCK
        packet.NAME_BLOCK = saved.replace('cls', 'cly', 1)
        try:
            self._rejects(self._patch(self.data, 0x794e8f, b'y'), why="is not 'cls'")
        finally:
            packet.NAME_BLOCK = saved

    def test_other_field_name_rejected(self):
        # msc -> msk: only the name block check sees it
        self._rejects(self._patch(self.data, 0x794eb9, b'k'), why='name block at 0x794e8a')

    def test_field_table_rejected(self):
        entry = packet.FIELD_TABLE + 4
        rel = struct.unpack('<i', packet.read_va(self.data, entry, 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', rel + 1)),
                      why='table 0x73da1c entry 1')

    def test_skip_entry_rejected(self):
        entry = packet.FIELD_TABLE + 4 * 16
        rel = struct.unpack('<i', packet.read_va(self.data, entry, 4))[0]
        self._rejects(self._patch(self.data, entry, struct.pack('<i', rel - 4)),
                      why='table 0x73da1c entry 16')

    def test_relocation_rejected(self):
        rela = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        body = self.data[rela['offset']:rela['offset'] + rela['size']]
        for i, (off, info, addend) in enumerate(struct.iter_unpack('<QQq', body)):
            if off == 0x64e3db8:
                at = rela['offset'] + 24 * i + 16
                break
        broken = bytearray(self.data)
        broken[at:at + 8] = struct.pack('<q', 0x33de701)
        self._rejects(bytes(broken), why='relocation at 0x64e3db8')

    def test_element_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x389a09f), 0x389a091, why='0x389a09e')

    def test_caller_census_rejected(self):
        # move the only call to 0x3899fe0; its pin and branch entry are removed
        self._rejects(self._bump_rel32(self.data, 0x2f4d669), 0x2f4d630, jumps=(0x2f4d668,),
                      why='direct callers of 0x3899fe0')

    def test_holder_rejected(self):
        saved = packet.HOLDERS
        packet.HOLDERS = {**saved, 0x2f4d668: packet.STRUCT}
        try:
            with self.assertRaisesRegex(ValueError, 'not in function'):
                packet.bind(self.data)
        finally:
            packet.HOLDERS = saved


if __name__ == '__main__':
    unittest.main()
