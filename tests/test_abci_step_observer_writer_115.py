"""Node #115 observer line writer 0x14c3370. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_writer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-writer-115/evidence.json'


class AbciStepObserverWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_field_order(self):
        names = [f['name'] for f in self.result['serializer']['fields']]
        self.assertEqual(names, ['time', 'total_n', 'total_mean', 'n_buffer', 'work_frac', 'mean', 'med',
                                 'p90', 'p95', 'max', 'std_dev', 'bucket_mean', 'bucket_work_frac',
                                 'bucket_n', 'bucket_n_orig', 'is_subsampled'])
        self.assertEqual(self.result['serializer']['fields'][-1]['record_offset'], '0xa4')
        self.assertEqual(self.result['observer']['flag_record_offset'], '0xa4')
        self.assertEqual(self.result['serializer']['direct_callers'], 1)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

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

    def test_flag_store_rejected(self):
        # mov byte [rsp+0x17c], r15b -> [rsp+0x17d]
        self._rejects(self._patch(packet.FLAG_STORE + 4, b'\x7d'))

    def test_flag_field_offset_rejected(self):
        # add rbx, 0xa4 -> 0xa5
        self._rejects(self._patch(0x1549221 + 3, b'\xa5'))

    def test_flag_name_rejected(self):
        # is_subsampled -> is_subsampleD
        self._rejects(self._patch(0x466e2a + 12, b'D'))

    def test_field_name_rejected(self):
        # bucket_n_orig -> bucket_n_orih
        self._rejects(self._patch(0x466e1d + 12, b'h'))

    def test_field_offset_rejected(self):
        # lea rcx, [rbx+0x58] (total_mean) -> [rbx+0x60]
        self._rejects(self._patch(0x1548fd6 + 3, b'\x60'))

    def test_field_helper_rejected(self):
        # total_n: call u64 helper -> call f64 helper
        disp = packet.F64[0] - (0x1548fbd + 5)
        self._rejects(self._patch(0x1548fbd, b'\xe8' + struct.pack('<i', disp)))

    def test_newline_rejected(self):
        # mov byte [rbx+rax], 0x0a -> 0x0d
        self._rejects(self._patch(0x14c345a + 3, b'\x0d'))

    def test_null_literal_rejected(self):
        # f64 helper writes 'null' -> 'nulL'
        self._rejects(self._patch(0x159c1d9 + 6, b'L'))

    def test_true_literal_rejected(self):
        # 'true' -> 'truE'
        self._rejects(self._patch(0x159b96a + 6, b'E'))

    def test_open_mode_rejected(self):
        # mode 0o666 -> 0o667
        self._rejects(self._patch(0x14c3976 + 6, b'\xb7'))

    def test_flush_gate_offset_rejected(self):
        # lea rdi, [rbx+0x38] -> [rbx+0x40]
        self._rejects(self._patch(0x14c3838 + 3, b'\x40'))


if __name__ == '__main__':
    unittest.main()
