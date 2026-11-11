"""Node #115 info_server handler timing and user_ip.rs:28:48 future. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import info_request_timing_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-info-request-timing-115/evidence.json'


class InfoRequestTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_timing(self):
        clock = self.result['clock']
        self.assertTrue(clock['symbol'].startswith('clock_gettime'))
        self.assertEqual(clock['clock_id'], 1)
        self.assertEqual(self.result['recorded_value']['err_tag'], 0.0)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_user_ip_future(self):
        future = self.result['user_ip_future']
        self.assertEqual(future['location'], 'info_server/src/user_ip.rs:28:48')
        self.assertEqual(future['location_refs'], ['0x2e3fe69', '0x2e40f43'])
        self.assertIn('0.014', future['arms']['0'])

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

    def test_clock_id_rejected(self):
        # mov edi, 1 -> mov edi, 0 (CLOCK_REALTIME) at the first read
        self._rejects(self._patch(0x2e3fb20 + 1, b'\x00'))

    def test_start_register_rejected(self):
        # mov [rsp+0xbd8], r14 -> r15
        self._rejects(self._patch(0x2e3fc77 + 2, b'\xbc'))

    def test_dispatch_slot_rejected(self):
        # call [rip+...] retargeted by one qword
        self._rejects(self._patch(0x2e3fb42 + 2, b'\xd8'))

    def test_inf_branch_rejected(self):
        # je -> jne
        self._rejects(self._patch(0x2e3fd29, b'\x75'))

    def test_billion_rejected(self):
        # 1e9 -> 1e9 with a changed low byte
        self._rejects(self._patch(packet.BILLION, b'\x01'))

    def test_location_line_rejected(self):
        # user_ip.rs:28:48 -> 29:48
        self._rejects(self._patch(packet.LOC_USER_IP + 16, struct.pack('<I', 29)))

    def test_initial_value_rejected(self):
        # 0.014 -> another f64
        self._rejects(self._patch(0x2e3fd6f + 2, b'\x7a'))

    def test_state_table_rejected(self):
        # arm 1 offset changed
        self._rejects(self._patch(packet.STATE_TABLE + 4, b'\x00'))


if __name__ == '__main__':
    unittest.main()
