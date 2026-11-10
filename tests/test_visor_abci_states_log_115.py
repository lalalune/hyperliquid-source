"""Node #115 'node save visor_abci_state' periodic task. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import visor_abci_states_log_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-visor-abci-states-log-115/evidence.json'


class VisorAbciStatesLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_spawn_and_loop(self):
        spawn = self.result['spawn']
        self.assertEqual(spawn['vtable_lea_sites'], ['0x2aed339', '0x2cb8959'])
        self.assertEqual(spawn['name'], 'node save visor_abci_state')
        self.assertEqual(self.result['loop']['interval_seconds'], 5)
        self.assertEqual(self.result['loop']['direct_calls_to_loop'], 0)
        self.assertEqual(self.result['read_wrapper']['direct_calls'], 1)
        self.assertEqual(self.result['visor_state_fields'],
                         ['hardfork_version', 'initial_height', 'height',
                          'scheduled_freeze_height', 'consensus_time', 'wall_clock_time'])
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _offset(self, va):
        sec = next(s for s in sections(self.data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _rejects(self, va, new):
        broken = bytearray(self.data)
        off = self._offset(va)
        broken[off:off + len(new)] = new
        with self.assertRaises(ValueError):
            packet.bind(bytes(broken), self.fdes)

    def test_interval_rejected(self):
        # mov r14d, 5 -> 6
        self._rejects(0x5a39720 + 2, b'\x06')

    def test_clock_rejected(self):
        # CLOCK_MONOTONIC (1) -> CLOCK_REALTIME (0)
        self._rejects(0x5a3975d + 1, b'\x00')

    def test_task_name_rejected(self):
        self._rejects(0x93b0b6 + 5, b'S')

    def test_vtable_call_rejected(self):
        # relocation addend of the vtable call slot
        rel = next(s for s in sections(self.data) if s['type'] == 4 and s['name'] == '.rela.dyn')
        import struct
        blob = self.data[rel['offset']:rel['offset'] + rel['size']]
        for i in range(0, len(blob), 24):
            va, info, add = struct.unpack_from('<QQq', blob, i)
            if va == 0x64b8b30:
                broken = bytearray(self.data)
                struct.pack_into('<q', broken, rel['offset'] + i + 16, add + 1)
                with self.assertRaises(ValueError):
                    packet.bind(bytes(broken), self.fdes)
                return
        self.fail('vtable relocation not found')

    def test_field_name_rejected(self):
        # scheduled_freeze_height -> Scheduled_freeze_height
        self._rejects(0x91f983, b'S')

    def test_counter_block_rejected(self):
        # lea rbx, [r13+0xb50] -> [r13+0xb58]
        self._rejects(0x564844c + 3, b'\x58')

    def test_read_name_rejected(self):
        # get_visor_state -> gEt_visor_state
        self._rejects(0x93b0e1 + 1, b'E')

    def test_eintr_retry_rejected(self):
        # cmp eax, 4 -> cmp eax, 5
        self._rejects(0x5a39774 + 2, b'\x05')


if __name__ == '__main__':
    unittest.main()
