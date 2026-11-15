"""Node #115 startup last-applied-height check and box handoff. Mutations stay in a copied image."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import startup_initial_box_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-startup-initial-box-115/evidence.json'


class StartupInitialBoxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_callers_and_handoff(self):
        callers = self.result['callers']
        self.assertEqual(callers['startup_calls'], ['0x2af0a5f', '0x2cbc06b'])
        self.assertEqual(callers['0x2af0660']['called_from'], ['0x2aec151'])
        self.assertEqual(callers['0x2cbbbe0']['called_from'], ['0x2cb7771'])
        self.assertIn('0x5a6bfb0', self.result['poller_handoff']['0x2aeaef0'])
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

    def test_panic_branch_rejected(self):
        # jb -> jae at 0x2b41ebb
        self._rejects(self._patch(0x2b41ebb + 1, b'\x83'))

    def test_starting_height_source_rejected(self):
        # mov rsi, [rbx+0x8] -> [rbx+0x10]
        self._rejects(self._patch(0x2b41bb3 + 3, b'\x10'))

    def test_err_tag_rejected(self):
        # cmp rax, 1 -> cmp rax, 2
        self._rejects(self._patch(0x2b41d42 + 3, b'\x02'))

    def test_replica_cmds_name_rejected(self):
        self._rejects(self._patch(0x9383d2, b'R'))

    def test_box_store_rejected(self):
        # mov [rbx+0x60], r15 -> [rbx+0x68]
        self._rejects(self._patch(0x2af0ae1 + 3, b'\x68'))

    def test_handoff_offset_rejected(self):
        # mov rbp, [rsp+0x760] -> [rsp+0x768]
        self._rejects(self._patch(0x2aec184 + 4, b'\x68'))

    def test_builder_slot_rejected(self):
        # call [rip+disp] at 0x2aec3ef: retarget slot
        self._rejects(self._patch(0x2aec3ef + 2, b'\x53'))

    def test_last_applied_slot_rejected(self):
        # call [rip+disp] at 0x2b41d3c: retarget slot
        self._rejects(self._patch(0x2b41d3c + 2, b'\xe6'))


if __name__ == '__main__':
    unittest.main()
