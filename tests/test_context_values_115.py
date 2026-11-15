"""Node #115 Context value decoders. Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import context_values_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-context-values-115/evidence.json'


class ContextValuesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_value_kinds(self):
        names = {v['name'] for v in self.result['stubs'].values()}
        self.assertEqual(names, {'Round', 'SystemNonce', 'Time'})
        self.assertEqual(self.result['newtype_readers']['0x2f4f140']['relocated_to'], '0x348e980')
        self.assertEqual(self.result['newtype_readers']['0x2f43af0']['relocated_to'], '0x348e980')
        self.assertEqual(self.result['newtype_readers']['0x2f6fa30']['relocated_to'], '0x14b93c0')
        self.assertTrue(self.result['tx_index']['nil'].startswith('None'))
        self.assertFalse(self.result['gates_changed'])

    def test_committed_packet_matches(self):
        self.assertEqual(packet.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(packet.main(['--out', tmp, '--check']), 0)

    def _off(self, data, va):
        sec = next(s for s in sections(data)
                   if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def _patch(self, data, va, new):
        off = self._off(data, va)
        broken = bytearray(data)
        broken[off:off + len(new)] = new
        return bytes(broken)

    def _bump_rel32(self, data, va, by=1):
        rel = struct.unpack('<i', packet.read_va(data, va, 4))[0]
        return self._patch(data, va, struct.pack('<i', rel + by))

    def _rejects(self, data, why):
        with self.assertRaisesRegex(ValueError, why):
            packet.bind(data)

    def test_context_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30d22c6), 'branch at 0x30d22c5')

    def test_stub_name_rejected(self):
        self._rejects(self._patch(self.data, 0x7d3b21, b'P'), "not b'Round'")

    def test_stub_length_rejected(self):
        self._rejects(self._patch(self.data, 0x421db68, b'\x0a'), 'length 11')

    def test_ext_name_rejected(self):
        # 'S' of "_ExtStru" inside the movabs immediate of the Round reader
        self._rejects(self._patch(self.data, 0x2f4f152, b'T'), 'no _ExtStruct name check at 0x2f4f148')

    def test_round_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x2f4f258, -0x10), 'not through slot 0x64e2580')

    def test_time_slot_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x2f6fb82, -0x10), 'not through slot 0x64dfec0')

    def test_time_store_rejected(self):
        self._rejects(self._patch(self.data, 0x2f6fbac, b'\x08'), 'dword at \\+0xc')

    def test_tx_nil_rejected(self):
        self._rejects(self._patch(self.data, 0x451c5c7, b'\xc2'), 'nil 0xc0')

    def test_tx_some_rejected(self):
        self._rejects(self._patch(self.data, 0x451c5f9, b'\x00'), 'Some: 1 at \\+8')

    def test_relocation_rejected(self):
        rela = next(s for s in sections(self.data) if s['name'] == '.rela.dyn')
        for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
            if struct.unpack_from('<Q', self.data, off)[0] == packet.TIME_SLOT:
                broken = bytearray(self.data)
                struct.pack_into('<q', broken, off + 16, packet.TIME_READER + 0x10)
                self._rejects(bytes(broken), 'slot 0x64dfec0 is not relocated')
                return
        self.fail('no relocation for the Time slot')


if __name__ == '__main__':
    unittest.main()
