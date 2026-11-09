"""Node #115 liner flush interval and flush gate. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_flush_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-flush-115/evidence.json'


class AbciStepObserverFlushTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_interval_source(self):
        init = self.result['initializer']
        self.assertEqual(init['env_name'], 'LINER_FLUSH_PERIOD')
        self.assertIn('-> 60.0', init['lookup'])
        self.assertIn('liner.rs:17:74', init['parse'])
        self.assertIn('liner.rs:17:84', init['check'])
        cell = self.result['interval_global']
        self.assertEqual(cell['relocations_into_cell'], ['0x64e0030'])
        self.assertEqual(cell['rip_relative_refs_to_cell'], 0)
        self.assertEqual(cell['slot_loads'], ['0x14c3b6f'])
        self.assertEqual(cell['open_slot_calls'], 104)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_check_predicate(self):
        self.assertEqual(self.result['initializer']['check_samples'],
                         {'0.0': True, '-0.0': True, '5e-324': True, '60.0': True, '1e300': True,
                          '-1.0': False, '-5e-324': False, 'inf': False, 'nan': False})

    def test_writer_states_start_none(self):
        states = self.result['observer_writer_states']
        self.assertEqual(states['object_0xb0_copies_into_plus_0x98'], ['0x1548da1'])
        self.assertEqual(states['constructor_slot_calls'], 35)

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _patch(self, va, new):
        broken = bytearray(self.data)
        off, old = packet.read_va(self.data, va, len(new))
        self.assertEqual(len(old), len(new))
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _rejects(self, data):
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_env_name_rejected(self):
        # LINER_FLUSH_PERIOD -> LINER_FLUSH_PERIOE
        self._rejects(self._patch(packet.ENV_NAME[0] + 17, b'E'))

    def test_default_rejected(self):
        # 60.0 -> 61.0
        self._rejects(self._patch(packet.DEFAULT, struct.pack('<d', 61.0)))

    def test_state_at_rest_rejected(self):
        # state dword 3 -> 0 (would read as complete)
        self._rejects(self._patch(packet.GLOBAL + 8, b'\x00'))

    def test_location_line_rejected(self):
        # liner.rs:17:74 -> 18:74
        self._rejects(self._patch(packet.LOC_PARSE + 16, b'\x12'))

    def test_check_sign_rejected(self):
        # setns al -> sets al
        self._rejects(self._patch(0x14c483d, b'\x0f\x98'))

    def test_gate_date_compare_rejected(self):
        # setl dl -> setg dl
        self._rejects(self._patch(0x154cf77, b'\x0f\x9f'))

    def test_gate_fraction_compare_rejected(self):
        # jb -> jbe (flush on equal time)
        self._rejects(self._patch(0x154cfb4, b'\x76'))

    def test_gate_divisor_rejected(self):
        # 0x112e0be826d694b3 -> 0x112e0be826d694b4
        self._rejects(self._patch(0x154cebe, b'\xb4'))

    def test_constructor_none_rejected(self):
        # movabs rax, 0x8000000000000000 -> 0
        self._rejects(self._patch(0x1548bdd + 9, b'\x00'))

    def test_observer_skip_rejected(self):
        # jo 0x1548657 -> jno
        self._rejects(self._patch(0x1548884, b'\x0f\x81'))

    def test_second_state_offset_rejected(self):
        # 0x1548db5 lea rdi, [r14+0x148] -> [r14+0x98]
        self._rejects(self._patch(0x1548db5 + 3, b'\x98\x00'))


if __name__ == '__main__':
    unittest.main()
