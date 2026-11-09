"""Node #115 hourly mempool_txs writer consumer. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
import line_writer_consumer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-line-writer-consumer-115/evidence.json'


class LineWriterConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_census(self):
        c = self.result['census']
        self.assertEqual(c['spawner_callers'], [['0x2af5b03', '0x2af45f0'], ['0x2cc281f', '0x2cc1120']])
        self.assertEqual(c['write_callers'], ['0x5a88864'])
        self.assertEqual(c['poll_writer_reads'], ['0x5a887cc', '0x5a887fc'])
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_record_fields(self):
        self.assertEqual([f[0] for f in self.result['record']['fields']], ['tx_hash', 'signed_actions'])

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

    def test_task_name_rejected(self):
        # nv_stream_forward_client_blocks -> ...blockS
        self._rejects(self._patch(0x93b982 + 30, b'S'))

    def test_future_size_rejected(self):
        # vtable B size 0x2d80 -> 0x2d88
        self._rejects(self._patch(0x64b91a8 + 8, struct.pack('<Q', 0x2d88)))

    def test_struct_copy_length_rejected(self):
        # mov edx, 0x118 -> 0x110
        self._rejects(self._patch(0x5a81fb8 + 1, b'\x10'))

    def test_writer_offset_rejected(self):
        # cmp [rbx+0x18], rax -> [rbx+0x20]
        self._rejects(self._patch(0x5a887cc + 3, b'\x20'))

    def test_line_separator_rejected(self):
        # ',' -> ';'
        self._rejects(self._patch(0x50e67e5 + 3, b'\x3b'))

    def test_field_name_rejected(self):
        # tx_hash -> tx_hasH
        self._rejects(self._patch(0x93b509 + 6, b'H'))

    def test_flush_byte_rejected(self):
        # cmp byte [r14+0xaa], 0 -> [r14+0xab]
        self._rejects(self._patch(0x4e3ec2c + 3, b'\xab'))

    def test_location_line_rejected(self):
        # base/src/lu.rs:148 -> 149
        self._rejects(self._patch(packet.LOCATION[0] + 16, struct.pack('<I', 149)))


if __name__ == '__main__':
    unittest.main()
