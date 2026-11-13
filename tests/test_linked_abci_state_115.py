"""Node #115 linked abci state step after the snapshot label. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import linked_abci_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-linked-abci-state-115/evidence.json'


class LinkedAbciStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_result(self):
        fn = self.result['linked_state_fn']
        self.assertEqual(fn['direct_callers'], ['0x5a0887e'])
        self.assertEqual(fn['warn_args']['desc'], 'label (rsp+0x160)')
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

    def test_label_choice_rejected(self):
        # cmovne -> cmove (freeze and periodic swap)
        self._rejects(self._patch(0x5a08874 + 2, b'\x44'))

    def test_height_offset_rejected(self):
        # [rax+0x28] -> [rax+0x30]
        self._rejects(self._patch(0x5485faa + 3, b'\x30'))

    def test_unwrap_branch_rejected(self):
        # jne -> je
        self._rejects(self._patch(0x54860a9 + 1, b'\x84'))

    def test_error_drop_rejected(self):
        # je over the drop -> jne
        self._rejects(self._patch(0x54860d2, b'\x75'))

    def test_desc_arg_rejected(self):
        # desc arg slot rsp+0xf0 -> rsp+0xf8
        self._rejects(self._patch(0x548618f + 4, b'\xf8'))

    def test_hard_link_template_rejected(self):
        # utils_hard_link_and_replace -> utils_hard_lINk...
        self._rejects(self._patch(0x439e43 + 12, b'I'))

    def test_periodic_dir_name_rejected(self):
        # periodic_abci_state_statuses -> periodiC_...
        self._rejects(self._patch(0x7a1586 + 7, b'C'))

    def test_state_location_rejected(self):
        # state.rs:201:32 -> 202:32
        self._rejects(self._patch(0x64aa248 + 16, b'\xca'))


if __name__ == '__main__':
    unittest.main()
