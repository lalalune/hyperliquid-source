"""Node #115 bucket_guard constants: getter writes, constructor store, record readers. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import check, manifest_item
from fde_extents import fde_extents
import bucket_guard_constants_115 as packet

EVIDENCE = packet.PACKET / 'evidence.json'


class BucketGuardConstantsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(packet.ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_result(self):
        r = self.result
        self.assertEqual(r['sha256'], packet.SHA256)
        self.assertEqual(r['record_calls']['total'], 50)
        self.assertEqual(r['record_calls']['by_getter'],
                         {'0x26d4660': 11, '0x3704070': 8, '0x4770930': 1, '0x51eaff0': 30})
        self.assertEqual(r['record_calls']['count_argument'], [1])
        self.assertEqual(r['record']['rbx_operand_modrm_bytes'], {'0x8': [], '0x218': [], '0x238': ['0x15486f0']})
        for g in r['getters']:
            self.assertEqual(g['writes'], {'+0x0': 1, '+0x8': 'b', '+0x238': 10})
        self.assertFalse(r['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), EVIDENCE.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off, old = packet.read_va(self.data, va, len(new))
        self.assertEqual(len(old), len(new))
        self.assertNotEqual(old, new)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_constructor_store_offset_rejected(self):
        # movsd [r14+0x218], xmm0 -> [r14+0x210]
        self._rejects(self._patch(0x1548dd2 + 5, b'\x10'))

    def test_getter_limit_rejected(self):
        # 0x51eaff0 stores 10 at +0x238 -> 11
        self._rejects(self._patch(0x51eb0e2 + 8, b'\x0b'))

    def test_getter_tag_rejected(self):
        # 0x4770930 writes 1 at +0x0 -> 0
        self._rejects(self._patch(0x47709e1 + 5, b'\x00'))

    def test_count_gate_rejected(self):
        # cmp r12, 10 -> cmp r12, 11
        self._rejects(self._patch(0x1547f4b + 3, b'\x0b'))

    def test_record_reads_a_rejected(self):
        # unpinned cmp [rbx+0x240], edi -> cmp [rbx+0x218], edi: only the operand scan sees it
        self._rejects(self._patch(0x1547562 + 2, b'\x18'))

    def test_rollover_result_read_rejected(self):
        # movapd xmm0, [rsp+0x220] -> [rsp+0xd8] between the call and the overwrite
        self._rejects(self._patch(0x1548727 + 5, b'\xd8\x00'))

    def test_count_argument_rejected(self):
        # first 0x51eaff0 record call passes esi = 2
        self._rejects(self._patch(0x5483deb + 1, b'\x02'))

    def test_seconds_constant_rejected(self):
        broken = bytearray(self.data)
        off, _ = packet.read_va(self.data, packet.SECONDS, 8)
        broken[off:off + 8] = struct.pack('<d', 601.0)
        self._rejects(bytes(broken))

    def test_slot_relocation_rejected(self):
        broken = bytearray(self.data)
        for sec in packet.sections(self.data):
            if sec['type'] != 4:
                continue
            for i in range(0, sec['size'], 24):
                va, info, addend = struct.unpack_from('<QQq', self.data, sec['offset'] + i)
                if va == 0x64e1018 and info & 0xffffffff == 8:
                    struct.pack_into('<q', broken, sec['offset'] + i + 16, addend + 16)
        self._rejects(bytes(broken))

    def test_getter_call_removed_rejected(self):
        # the only 0x4770930 call becomes a 5-byte nop
        (site,) = packet.direct_calls(self.data, {0x4770930})[0x4770930]
        self._rejects(self._patch(site, b'\x0f\x1f\x44\x00\x00'))

    def test_wrong_digest_rejected(self):
        broken = bytearray(self.data)
        broken[-1] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'hl-node'
            path.write_bytes(bytes(broken))
            with self.assertRaises(Exception):
                packet.generate(binary=path, output=Path(tmp) / 'out')


if __name__ == '__main__':
    unittest.main()
