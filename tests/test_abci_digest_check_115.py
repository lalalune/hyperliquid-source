"""Node #115 abci digest check in the step wrappers. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import abci_digest_check_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-digest-check-115/evidence.json'


class AbciDigestCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_censuses(self):
        self.assertEqual(self.result['compare']['sites'], ['0x5a05d07', '0x5a07527'])
        self.assertEqual(self.result['compare']['wrappers'], ['0x5a04e40', '0x5a06600'])
        self.assertEqual(self.result['map_fill']['insert_calls'], ['0x5a07fe5', '0x5a08845'])
        self.assertEqual(self.result['panic_template_refs']['functions'], ['0x2d23610', '0x5a04e40', '0x5a06600'])
        self.assertFalse(self.result['gates_changed'])

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

    def test_entry_offset_rejected(self):
        # movdqu xmm2, [r13+0x48] -> [r13+0x40]
        self._rejects(self._patch(0x5a05d07 + 5, b'\x40'))

    def test_entry_stride_rejected(self):
        # add r13, 0x68 -> 0x60
        self._rejects(self._patch(0x5a05d2e + 3, b'\x60'))

    def test_map_offset_rejected(self):
        # lea rbp, [r12+0x400] -> [r12+0x408]
        self._rejects(self._patch(0x5a05cc8 + 4, b'\x08'))

    def test_full_match_mask_rejected(self):
        # cmp eax, 0xffff -> 0xfffe
        self._rejects(self._patch(0x5a05d23 + 1, b'\xfe'))

    def test_trim_length_rejected(self):
        # cmp rdx, 0x33 -> 0x34
        self._rejects(self._patch(0x5a03fc1 + 3, b'\x34'))

    def test_divisor_offset_rejected(self):
        # mov rcx, [rsi+0x39c8] -> [rsi+0x39d0]
        self._rejects(self._patch(0x5a07f85 + 3, b'\xd0'))

    def test_panic_string_rejected(self):
        # computed -> Computed
        self._rejects(self._patch(0x44c994, b'C'))

    def test_wrapper_b_compare_rejected(self):
        # B movdqu xmm0, [r13+0x58] -> [r13+0x50]
        self._rejects(self._patch(0x5a07531 + 5, b'\x50'))


if __name__ == '__main__':
    unittest.main()
