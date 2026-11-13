"""Node #115 l1 hash inside the abci steps. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import step_l1_hash_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-step-l1-hash-115/evidence.json'


class StepL1HashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_result(self):
        r = self.result
        self.assertEqual(r['after']['direct_calls'],
                         {'0x5a046f0': ['0x5a08267', '0x5a08ac7'], '0x5a03fa0': ['0x5a07fe5', '0x5a08845']})
        self.assertEqual([s['evidence'] for s in r['other_sites']], ['gossip', 'gossip', 'freeze', 'gossip'])
        self.assertEqual(r['sha256'], packet.SHA256)
        self.assertFalse(r['gates_changed'])

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

    def test_l1_gate_rejected(self):
        # je (skip l1 when bpl clear) -> jne
        self._rejects(self._patch(0x5a07fed + 1, b'\x85'))

    def test_label_rejected(self):
        # 'periodic' -> 'periodiC'
        self._rejects(self._patch(0x458f30 + 7, b'C'))

    def test_blocking_flag_rejected(self):
        # mov edx, 1 -> 0 before the l1 helper
        self._rejects(self._patch(0x5a080b4 + 1, b'\x00'))

    def test_record_digest_slot_rejected(self):
        # lea rbp, [rsp+0x80] -> [rsp+0x88]
        self._rejects(self._patch(0x5a08092 + 4, b'\x88'))

    def test_l1_map_offset_rejected(self):
        # lea rdi, [r14+0x3e0] -> [r14+0x3e8]
        self._rejects(self._patch(0x5a08255 + 3, b'\xe8'))

    def test_serialiser_config_rejected(self):
        # 0x01000400 -> 0x01000401
        self._rejects(self._patch(0x4e4aff1 + 4, b'\x01'))

    def test_trim_bound_rejected(self):
        # cmp rdx, 0x33 -> 0x34 in the l1 map insert
        self._rejects(self._patch(0x5a04711 + 3, b'\x34'))

    def test_name_relocation_rejected(self):
        # 'abci_state' -> 'abci_statE'
        self._rejects(self._patch(0x929ae3 + 9, b'E'))


if __name__ == '__main__':
    unittest.main()
