"""Node #115 info_server sleep flag and inner sleep future. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import info_user_ip_future_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-info-user-ip-future-115/evidence.json'


class InfoUserIpFutureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_flag_chain(self):
        flag = self.result['flag']
        self.assertEqual(len(flag['flag_byte_stores']), 5)
        self.assertEqual(flag['flag_byte_stores'][0], 'mov word [rbx+0x6da], 0')
        self.assertEqual(flag['rsp10_operands'], 13)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_sleep_future(self):
        inner = self.result['inner_future']
        self.assertIn('0.014', inner['argument'])
        self.assertEqual(inner['outer']['location'], 'base/src/lu.rs:63:46')
        self.assertEqual(inner['inner']['location'], 'base/src/lu.rs:74:57')
        self.assertIn('base/src/lu.rs:75:5', inner['inner']['timer'])
        self.assertTrue(inner['poll_fn_location'].endswith('tokio/src/time/sleep.rs:467:23'))

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

    def test_zero_store_rejected(self):
        # mov word [rbx+0x6da], 0 -> 1
        self._rejects(self._patch(0x2e3f7e2 + 7, b'\x01'))

    def test_xor_ebp_rejected(self):
        # xor ebp, ebp -> xor ebp, eax
        self._rejects(self._patch(0x2e3f805 + 1, b'\xe8'))

    def test_flag_test_rejected(self):
        # je 0x2e3ff0e -> jne
        self._rejects(self._patch(0x2e3fd54 + 1, b'\x85'))

    def test_argument_rejected(self):
        # 0.014 -> another f64
        self._rejects(self._patch(0x2e3fd71, struct.pack('<d', 0.015)))

    def test_zero_shortcut_rejected(self):
        # jne -> je after the 0.0 compare
        self._rejects(self._patch(0x2d4f7c2, b'\x74'))

    def test_timer_location_rejected(self):
        # lu.rs:75:5 -> line 76
        self._rejects(self._patch(packet.LOC_TIMER + 16, b'\x4c'))

    def test_poll_slot_rejected(self):
        # call [rip+slot] retargeted by one qword
        self._rejects(self._patch(0x2d4fad0 + 2, struct.pack('<i', 0x3790d82 + 8)))

    def test_jump_table_into_span_rejected(self):
        # first entry of the 0x616454 table retargeted into the ebp span (0x2e3f810)
        self._rejects(self._patch(0x616454, struct.pack('<i', 0x2e3f810 - 0x616454)))


if __name__ == '__main__':
    unittest.main()
