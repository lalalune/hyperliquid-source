"""Node #115 block-step timer specialization and its five call sites. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_timer_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-timer-115/evidence.json'


class AbciStepTimer115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_five_sites_pass_tags_zero_to_four(self):
        self.assertEqual([row['tag'] for row in self.result['sites']], [0, 1, 2, 3, 4])
        self.assertEqual([row['site_va'] for row in self.result['sites']],
                         ['0x5486544', '0x5a067ec', '0x5a06b29', '0x5a06e11', '0x5a0784c'])
        self.assertFalse(self.result['census']['tag_5_passed'])
        self.assertEqual(self.result['census']['host_direct_calls'], 1)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_recorder_clock_conversion_and_sink(self):
        rec = self.result['recorder']
        self.assertEqual(rec['fde'], {'start_va': '0x5b2a130', 'end_va': '0x5b2aa61'})
        self.assertEqual(rec['clock']['import'], 'clock_gettime')
        self.assertEqual(rec['clock']['edi'], 1)
        self.assertEqual(rec['difference']['nanos_divisor'], 1e9)
        self.assertEqual(rec['sink_call']['target_va'], '0x1547530')
        self.assertEqual((rec['location']['path'], rec['location']['line'], rec['location']['column']),
                         ('node/src/group_and_seq_sampler.rs', 169, 10))

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

    def test_site_tag_immediate_rejected(self):
        # DeliverSignedActions site: mov esi, 2 -> mov esi, 5.
        self._rejects(self._patch(0x5a06b24 + 1, b'\x05'))

    def test_second_clock_id_rejected(self):
        self._rejects(self._patch(0x5b2a1ec + 1, b'\x00'))

    def test_nanos_divisor_operand_rejected(self):
        self._rejects(self._patch(0x5b2a1cc + 4, b'\x7d'))

    def test_checkpoint_reset_store_rejected(self):
        self._rejects(self._patch(0x5b2a1f6, b'\x49\x89\x07'))

    def test_location_line_rejected(self):
        self._rejects(self._patch(packet.LOCATION + 16, struct.pack('<I', 170)))

    def test_host_tag_load_rejected(self):
        self._rejects(self._patch(0x4da7e67 + 2, b'\x07'))

    def test_block_guard_rejected(self):
        # EndBlock site guard: cmp [rdi+0x12a0] -> cmp [rdi+0x12a8].
        self._rejects(self._patch(0x5a06df4 + 3, b'\xa8'))

    def test_extra_recorder_call_rejected(self):
        pad = packet.RECORDER_END
        _, run = packet.read_va(self.data, pad, 5)
        self.assertEqual(run, b'\xcc' * 5)
        self._rejects(self._patch(pad, b'\xe8' + struct.pack('<i', packet.RECORDER - (pad + 5))))


if __name__ == '__main__':
    unittest.main()
