"""Node #115 lu.rs sleep helper callers and the info handler's packed fields. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import lu_sleep_callers_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-lu-sleep-callers-115/evidence.json'


class LuSleepCallersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        self.assertEqual([c['fn'] for c in self.result['outer_calls']],
                         ['0x2cf08b0', '0x2e071c0', '0x2e075f0', '0x2e3ed10'])
        self.assertEqual(self.result['inner_calls'], [['0x2cf0986', '0x2cf08b0'], ['0x2d4f7de', '0x2d4f790']])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_seconds_model(self):
        self.assertEqual(self.result['seconds_model_samples'],
                         {'(1, 500000000)': 1.5, '(0, 0)': 0.0, '(-1, 0)': 0.0, '(2**62, 0)': float(2 ** 62)})

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

    def test_extra_call_rejected(self):
        # turn the handler's call into a call one byte later: census changes
        self._rejects(self._patch(0x2e3fd8f + 1, struct.pack('<i', struct.unpack('<i', bytes.fromhex('fcf9f0ff'))[0] + 1)))

    def test_toggle_rejected(self):
        # xor al, 1 -> xor al, 0
        self._rejects(self._patch(0x2cf095d + 1, b'\x00'))

    def test_zero_check_branch_rejected(self):
        # je -> jne on byte [rbx+0x30]
        self._rejects(self._patch(0x2cf0976, b'\x75'))

    def test_clamp_rejected(self):
        # maxsd -> minsd
        self._rejects(self._patch(0x2e074ba + 2, b'\x5d'))

    def test_nanos_constant_rejected(self):
        self._rejects(self._patch(packet.NANOS, struct.pack('<d', 1e6)))

    def test_constant_seconds_rejected(self):
        # 0.014 -> another f64
        self._rejects(self._patch(0x2e3fd6f + 2, b'\x00'))

    def test_record_tag_rejected(self):
        # mov byte [rbx+0x6c9], 2 -> 3
        self._rejects(self._patch(0x2e3f7db + 6, b'\x03'))

    def test_location_rejected(self):
        # channel.rs:16:9 -> 17:9
        self._rejects(self._patch(0x6451af8 + 16, b'\x11'))


if __name__ == '__main__':
    unittest.main()
