"""Node #94 block-step name bytes. Mutations stay in a copied image."""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_names as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-names-94/evidence.json'


class AbciStepNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        identity = manifest_item(ROOT, 'artifacts/node/94/hl-node')
        check(packet.TARGET, identity)
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_six_names_and_one_load(self):
        self.assertEqual([row['name'] for row in self.result['tags']], [
            'RecoverUsers', 'BeginBlock', 'DeliverSignedActions', 'EndBlock', 'Commit', 'RespHashCheck'])
        self.assertEqual([row['length'] for row in self.result['tags']], [12, 10, 20, 8, 6, 13])
        self.assertEqual(self.result['pointer_reloc_count'], 1)
        self.assertEqual(self.result['pointer_load_count'], 1)
        self.assertEqual(self.result['pointer_load_site_va'], '0x492619f')
        self.assertFalse(self.result['seventh_table_target_inside_fde'])
        self.assertTrue(self.result['endblock_has_no_following_nul'])
        self.assertEqual(self.result['endblock_neighbor'], 'fee_rate')
        self.assertEqual(self.result['packed_names'],
                         'RecoverUsersBeginBlockDeliverSignedActionsCommitRespHashCheck')
        self.assertFalse(self.result['gates_changed'])
        self.assertEqual(self.result['sha256'], packet.SHA256)

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

    def test_name_byte_rejected(self):
        data = self._patch(0x5b6973, b'S')
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_length_immediate_rejected(self):
        # Commit arm is the second arm in the body. Its length byte sits at start+0x2b+8.
        data = self._patch(packet.START + 0x2b + 8, b'\x05')
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_table_target_rejected(self):
        off, raw = packet.read_va(self.data, packet.TABLE, 4)
        rel = struct.unpack('<i', raw)[0]
        data = self._patch(packet.TABLE, struct.pack('<i', rel + 1))
        with self.assertRaises(ValueError):
            packet.bind(data, self.fdes)

    def test_writer_reloc_rejected(self):
        broken = bytearray(self.data)
        slot = struct.pack('<Q', packet.WRITER_SLOT)
        index = 0
        found = 0
        while True:
            index = broken.find(slot, index)
            if index < 0:
                break
            if index + 24 <= len(broken) and struct.unpack_from('<Q', broken, index + 8)[0] == 8:
                struct.pack_into('<q', broken, index + 16, packet.WRITER + 1)
                found += 1
            index += 1
        self.assertEqual(found, 1)
        with self.assertRaises(ValueError):
            packet.bind(bytes(broken), self.fdes)
        self.assertNotEqual(hashlib.sha256(broken).hexdigest(), packet.SHA256)
