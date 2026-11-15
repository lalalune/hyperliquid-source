"""Node #115 abci hash input slots. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import abci_hash_slots_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-hash-slots-115/evidence.json'


class AbciHashSlotsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_table(self):
        slots = self.result['slots']
        self.assertEqual(len(slots), 59)
        self.assertEqual(slots[0]['box_field'], 'group: base + 15 fields')
        self.assertEqual(slots[0]['type_size'], 128)
        self.assertEqual([s['box_field'] for s in slots[23:24]], ['0x42ac'])
        self.assertEqual(slots[23]['type_size'], 1)
        self.assertEqual(slots[13]['box_field'], '0x10e8')
        self.assertEqual(self.result['entry_table']['distinct_vtables'], 45)
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
            packet.bind(data)

    def test_group_field_rejected(self):
        # lea rax, [r15+0x7c0] -> [r15+0x7c8]
        self._rejects(self._patch(0x4e34d06 + 3, b'\xc8'))

    def test_slot_field_rejected(self):
        # lea rax, [r15+0x3ac0] (slot 1) -> [r15+0x3ac8]
        self._rejects(self._patch(0x4e34def + 3, b'\xc8'))

    def test_builder_form_rejected(self):
        # an instruction outside the three allowed forms in the pointer table
        self._rejects(self._patch(0x4e34d06, b'\x90'))

    def test_entry_pointer_rejected(self):
        # mov rax, [rdi+0x80] (entry 1) -> [rdi+0x88]
        self._rejects(self._patch(0x54423d8 + 3, b'\x88'))

    def test_entry_vtable_rejected(self):
        # lea rax, [rip+...] for entry 0's vtable moves by 8
        self._rejects(self._patch(0x54423cc + 3, b'\x95'))

    def test_slot_count_rejected(self):
        # cmp qword [rsi+0x10], 59 -> 60
        self._rejects(self._patch(0x5442a2d + 4, b'\x3c'))

    def test_leaf_tag_rejected(self):
        # dec rcx -> inc rcx (leaf test no longer 0x8000000000000000)
        self._rejects(self._patch(0x141a275 + 2, b'\xc1'))

    def test_skip_constant_rejected(self):
        # movabs rcx, 0x8000000000000001 -> 0x8000000000000002 at the child skip
        self._rejects(self._patch(0x141a3c5 + 2, b'\x02'))


if __name__ == '__main__':
    unittest.main()
