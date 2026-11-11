"""Node #115 shared value observer catalogue: constructor names and record callers. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
import abci_step_observer_catalogue_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-catalogue-115/evidence.json'


class AbciStepObserverCatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        _, cls.fdes, _ = fde_extents(cls.data)
        cls.result = packet.bind(cls.data, cls.fdes)

    def test_constructor_catalogue(self):
        ctor = self.result['constructor']
        self.assertEqual(ctor['calls'], 35)
        self.assertEqual(ctor['by_kind'], {'formatted': 24, 'passed': 2, 'static': 9})
        self.assertEqual(ctor['names']['profiled_mutex/{}/acquire_all'], 8)
        self.assertEqual(ctor['names']['profiled_mutex/{}/compute/{}'], 4)
        self.assertEqual(ctor['names']['bucket_guard/{}'], 4)
        self.assertEqual(ctor['names']['vote_abci_digest'], 1)
        self.assertEqual(self.result['sha256'], packet.SHA256)
        self.assertFalse(self.result['gates_changed'])

    def test_record_catalogue(self):
        rec = self.result['record']
        self.assertEqual(rec['calls'], 68)
        self.assertEqual(rec['with_getter'], 52)
        self.assertEqual(rec['getters']['0x51eaff0'], 30)
        self.assertEqual(rec['location_files']['base/src/bucket_guard.rs'], 50)
        lines = {(s['location']['line'], s['location']['column'])
                 for s in rec['sites'] if s.get('location', {}).get('file') == 'base/src/bucket_guard.rs'}
        self.assertEqual(lines, {(118, 21)})

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

    def test_static_name_byte_rejected(self):
        # "vote_abci_digest" -> "wote_abci_digest"
        self._rejects(self._patch(0x456200, b'w'))

    def test_static_name_length_rejected(self):
        # mov ecx, 29 -> mov ecx, 28 at the tokio_spawn_forever_scheduled site
        self._rejects(self._patch(0x15d86d1 + 1, b'\x1c'))

    def test_template_byte_rejected(self):
        # bucket_guard/{} template: first literal byte changes
        self._rejects(self._patch(0x43bb25 + 1, b'B'))

    def test_format_call_rejected(self):
        # format call at 0x26d46e1 points one slot later
        disp = struct.unpack('<i', packet.read_va(self.data, 0x26d46e1 + 2, 4)[1])[0]
        self._rejects(self._patch(0x26d46e1 + 2, struct.pack('<i', disp + 8)))

    def test_constructor_call_removed_rejected(self):
        # the vote_abci_digest constructor call becomes a 6-byte nop: census shrinks
        self._rejects(self._patch(0x5a6c496, b'\x66\x0f\x1f\x44\x00\x00'))

    def test_esi_value_rejected(self):
        # mov esi, 1 -> mov esi, 2 at the tokio_spawn_forever_scheduled site
        self._rejects(self._patch(0x15d86d9 + 1, b'\x02'))

    def test_getter_target_rejected(self):
        # first bucket_guard getter call moves by 16 bytes
        disp = struct.unpack('<i', packet.read_va(self.data, 0x2bdf7e9 + 1, 4)[1])[0]
        self._rejects(self._patch(0x2bdf7e9 + 1, struct.pack('<i', disp + 16)))

    def test_location_line_rejected(self):
        # the shared bucket_guard Location line 118 -> 119
        target = packet.rip_target(self.data, 0x2bdf7ee, b'\x48\x8d\x15', 7)
        self._rejects(self._patch(target + 16, struct.pack('<I', 119)))

    def test_rdi_source_rejected(self):
        # mov rdi, rax -> mov rdi, rcx at a getter site
        self._rejects(self._patch(0x2bdf7fa, bytes.fromhex('4889cf')))

    def test_constructor_slot_relocation_rejected(self):
        for sec in packet.sections(self.data):
            if sec['type'] != 4:
                continue
            for i in range(sec['size'] // 24):
                off = sec['offset'] + i * 24
                va, info, addend = struct.unpack_from('<QQq', self.data, off)
                if va == packet.CTOR_SLOT:
                    broken = bytearray(self.data)
                    struct.pack_into('<q', broken, off + 16, addend + 1)
                    self._rejects(bytes(broken))
                    return
        self.fail('constructor slot relocation not found')

    def test_wrong_digest_rejected(self):
        broken = bytearray(self.data)
        broken[-1] ^= 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'hl-node'
            path.write_bytes(bytes(broken))
            with self.assertRaises(Exception):
                packet.generate(binary=path, output=Path(tmp) / 'out')


if __name__ == '__main__':
    unittest.main()
