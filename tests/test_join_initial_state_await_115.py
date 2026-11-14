"""Node #115 await side of initial_slow_state_for_join. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import join_initial_state_await_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-join-initial-state-await-115/evidence.json'


class JoinInitialStateAwaitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_bound_facts(self):
        r = self.result
        self.assertEqual(r['spawn']['location'], 'base/src/lu.rs:116:5')
        self.assertIn('startup.rs:337:49', r['await']['error'])
        self.assertIn('startup.rs:206:37', r['invalid_starting_height']['panic'])
        self.assertEqual(r['function']['direct_callers'],
                         [['0x2af0a5f', '0x2af0660'], ['0x2cbc06b', '0x2cbbbe0']])
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

    def test_spawn_name_rejected(self):
        # initial_slow_state_for_join -> Initial_...
        self._rejects(self._patch(0x60601e, b'I'))

    def test_handle_slot_rejected(self):
        # mov [rbx+0x3f0], rax -> [rbx+0x3f8]
        self._rejects(self._patch(0x2b42621 + 3, b'\xf8'))

    def test_pending_state_rejected(self):
        # mov byte [rax], 3 -> 4
        self._rejects(self._patch(0x2b42655 + 2, b'\x04'))

    def test_error_branch_rejected(self):
        # jne -> je on the result word
        self._rejects(self._patch(0x2b4269d + 1, b'\x84'))

    def test_height_compare_rejected(self):
        # cmp rdx, [rbx+0x48] -> [rbx+0x50]
        self._rejects(self._patch(0x2b42764 + 3, b'\x50'))

    def test_location_line_rejected(self):
        # startup.rs:337 -> 338
        self._rejects(self._patch(0x64480b8 + 16, b'\x52'))

    def test_unwrap_message_rejected(self):
        # mov esi, 0x2b -> 0x2c
        self._rejects(self._patch(0x2b42c2b + 1, b'\x2c'))

    def test_warn_message_rejected(self):
        # running non-validator -> Running
        self._rejects(self._patch(0x605fe1, b'R'))


if __name__ == '__main__':
    unittest.main()
