"""Node #115 block-step name bytes and their one host. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_names_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-names-115/evidence.json'


class AbciStepNames115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_six_names_one_load_one_host(self):
        self.assertEqual([row['name'] for row in self.result['tags']], [
            'RecoveredSignerToUser', 'BeginBlock', 'DeliverSignedActions',
            'EndBlock', 'Commit', 'RespHashCheck'])
        self.assertEqual([row['length'] for row in self.result['tags']], [21, 10, 20, 8, 6, 13])
        self.assertEqual(self.result['packed_names'],
                         'RecoveredSignerToUserBeginBlockDeliverSignedActionsCommitRespHashCheck')
        self.assertEqual(self.result['pointer_load_site_va'], '0x4da7fd1')
        self.assertEqual(self.result['host']['fde'], {'start_va': '0x4da7e20', 'end_va': '0x4da81a5'})
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_host_constants_and_format(self):
        host = self.result['host']
        self.assertEqual({k: v['value'] for k, v in host['tag_constants'].items()},
                         {'1': 0.03, '2': 0.32, '3': 0.05, '4': 0.01, '5': 0.01})
        self.assertEqual(host['tag0']['table'].count(0.15), 10)
        self.assertEqual(host['tag0']['table'].count(0.08), 13)
        self.assertEqual(host['tag0']['fallback'], 0.08)
        self.assertEqual([a.get('bytes') for a in host['format']['arguments']], ['seq_task', 'l1', None])
        self.assertEqual(host['format']['template_bytes'], 'c0012fc0012fc000')

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

    def test_name_byte_rejected(self):
        self._rejects(self._patch(0x7c6fce, b'S'))

    def test_endblock_terminator_rejected(self):
        self._rejects(self._patch(0x4599d8 + 8, b'X'))

    def test_length_immediate_rejected(self):
        # Commit is the second arm in the body; its length byte is at start+0x2b+8.
        self._rejects(self._patch(packet.START + 0x2b + 8, b'\x05'))

    def test_writer_table_target_rejected(self):
        _, raw = packet.read_va(self.data, packet.TABLE, 4)
        self._rejects(self._patch(packet.TABLE, struct.pack('<i', struct.unpack('<i', raw)[0] + 1)))

    def test_host_table_target_rejected(self):
        _, raw = packet.read_va(self.data, packet.HOST_TABLE + 8, 4)
        rel = struct.unpack('<i', raw)[0]
        self._rejects(self._patch(packet.HOST_TABLE + 8, struct.pack('<i', rel + 13)))

    def test_host_constant_instruction_rejected(self):
        # DeliverSignedActions arm: change the low displacement byte.
        self._rejects(self._patch(0x4da7ec3 + 4, b'\xd6'))

    def test_format_template_operand_rejected(self):
        self._rejects(self._patch(packet.FORMAT_SITE + 80, b'\x64'))

    def test_extra_pointer_load_rejected(self):
        # Copy the real load instruction into a padding run inside .text.
        pad = packet.END
        _, run = packet.read_va(self.data, pad, 7)
        self.assertEqual(run, b'\xcc' * 7)
        disp = packet.POINTER_SLOT - (pad + 7)
        self._rejects(self._patch(pad, b'\x48\x8b\x05' + struct.pack('<i', disp)))


if __name__ == '__main__':
    unittest.main()
