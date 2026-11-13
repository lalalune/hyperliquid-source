"""Node #115 visor_abci_state value and its writers. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import visor_abci_state_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-visor-abci-state-115/evidence.json'


class VisorAbciStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_fields(self):
        self.assertEqual([(f['name'], f['offset']) for f in self.result['fields_in_order']],
                         [('hardfork_version', '0x10'), ('initial_height', '0x18'), ('height', '0x20'),
                          ('scheduled_freeze_height', '0x0'), ('consensus_time', '0x28'),
                          ('wall_clock_time', '0x34')])
        self.assertFalse(self.result['gates_changed'])

    def test_callers(self):
        callers = self.result['callers']
        self.assertEqual(sorted(callers), ['0x5443930', '0x59ec200', '0x5a07ec0', '0x5a08720'])
        self.assertEqual(callers['0x5a08720']['scheduled_freeze_height_from'], 'box +0x1c58')
        self.assertEqual(callers['0x5a07ec0']['location'], 'l1/src/abci/engine.rs:316:46')
        self.assertEqual(callers['0x5443930']['location'], 'node/src/node.rs:659:50')
        self.assertEqual(self.result['freeze_and_byte_shift'], {'freeze': '0xb70', 'slot_0x64e1220_byte': '0xb70'})

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

    def test_field_name_rejected(self):
        # height -> heighT
        self._rejects(self._patch(0x91f97d + 5, b'T'))

    def test_field_offset_rejected(self):
        # lea rcx, [rbx+0x20] -> [rbx+0x28]
        self._rejects(self._patch(0x51ae00c + 3, b'\x28'))

    def test_field_length_rejected(self):
        # mov edx, 0x17 -> 0x16
        self._rejects(self._patch(0x51ae042 + 1, b'\x16'))

    def test_freeze_source_rejected(self):
        # 0x5a08720 [rax+0x1c58] -> [rax+0x10e8]
        self._rejects(self._patch(0x5a08a54 + 3, b'\xe8\x10'))

    def test_swap_rejected(self):
        # pshufd imm 0x4e -> 0x44 (no swap)
        self._rejects(self._patch(0x5443a1e + 9, b'\x44'))

    def test_height_source_rejected(self):
        # mov rbx, [rax+0x28] -> [rax+0x30]
        self._rejects(self._patch(0x54439c0 + 3, b'\x30'))

    def test_wrapper_call_rejected(self):
        # call rel32 to the wrapper shifted by one
        raw = packet.read_va(self.data, 0x5a08ab0 + 1, 1)
        self._rejects(self._patch(0x5a08ab0 + 1, bytes([(raw[0] + 1) & 0xff])))

    def test_name_rejected(self):
        # visor_abci_state -> visor_abci_statE
        self._rejects(self._patch(0x4564d0 + 15, b'E'))


if __name__ == '__main__':
    unittest.main()
