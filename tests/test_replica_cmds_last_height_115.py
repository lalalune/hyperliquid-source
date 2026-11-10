"""Node #115 last applied height from replica_cmds. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import replica_cmds_last_height_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-replica-cmds-last-height-115/evidence.json'


class ReplicaCmdsLastHeightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_entry_and_census(self):
        census = self.result['census']
        self.assertEqual(census['slot_0x64e7720_calls'], ['0x2b41d3c'])
        self.assertEqual(census['mapper_direct_calls'], ['0x543db64'])
        self.assertEqual(census['next_back_direct_calls'], ['0x543db40', '0x595b726'])
        self.assertEqual(self.result['locations'], {
            '0x64b6838': 'node/src/startup.rs:364:19',
            '0x64b6850': 'node/src/startup.rs:376:21',
            '0x64b6868': 'node/src/startup.rs:384:19'})
        self.assertEqual(self.result['sha256'], packet.SHA256)
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

    def test_take_limit_rejected(self):
        # take(5) -> take(6)
        self._rejects(self._patch(0x595b2b9 + 8, b'\x06'))

    def test_maximum_rejected(self):
        # cmovbe r14, r9 -> cmovae r14, r9 (minimum)
        self._rejects(self._patch(0x595b3a7 + 2, b'\x43'))

    def test_back_handle_rejected(self):
        # cmp dword [rsi+0x20], 1 -> [rsi+0x00] (front handle)
        self._rejects(self._patch(0x5152d1e + 2, b'\x00'))

    def test_decimal_base_rejected(self):
        # mov edi, 10 -> mov edi, 16
        self._rejects(self._patch(0x595bb29 + 1, b'\x10'))

    def test_saturation_rejected(self):
        # cmovae r15, r12 -> cmovb r15, r12
        self._rejects(self._patch(0x595bbb3 + 2, b'\x42'))

    def test_lz4_suffix_rejected(self):
        # '.lz4' -> '.lz5'
        self._rejects(self._patch(0x1500e71 + 7, b'\x35'))

    def test_replica_cmds_name_rejected(self):
        self._rejects(self._patch(0x9383d2, b'R'))

    def test_error_text_rejected(self):
        # "no end heights found" -> "no end heights fonnd"
        self._rejects(self._patch(0x439f32 + 18, b'n'))


if __name__ == '__main__':
    unittest.main()
