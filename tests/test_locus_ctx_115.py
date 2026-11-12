"""Node #115 Locus field ctx (struct Context). Mutations stay in a copied image."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
import locus_ctx_115 as packet

PACKET = ROOT / 'research/work-items/RE-008-locus-ctx-115/evidence.json'


class LocusCtxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check(packet.TARGET, manifest_item(ROOT, packet.RELATIVE))
        cls.data = packet.TARGET.read_bytes()
        cls.result = packet.bind(cls.data)

    def test_context_fields(self):
        self.assertEqual(self.result['struct_name']['text'], 'struct Context with 13 elements')
        keys = [self.result['fields'][str(i)]['key'] for i in range(13)]
        self.assertEqual(keys, ['hardfork_height', 'hardfork', 'height', 'tx_index', 'round',
                                'time', 'prev_time', 'next_oid', 'next_lid', 'next_twap_id',
                                'system_nonce', 'use_system_nonce', 'mac'])
        self.assertEqual(self.result['required'],
                         ['hardfork_height', 'height', 'time', 'prev_time', 'next_oid', 'next_lid'])
        self.assertEqual(sorted(self.result['sequence_length_errors'].values()), [0, 2, 5, 6, 7, 8])
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

    def test_locus_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x332c806), 'branch at 0x332c805')

    def test_struct_text_rejected(self):
        self._rejects(self._patch(self.data, 0x793562 + 7, b'K'), 'struct Context')

    def test_key_clamp_rejected(self):
        self._rejects(self._patch(self.data, 0x348ed02, b'\x0c'), 'clamped to 13')

    def test_table_entry_rejected(self):
        self._rejects(self._bump_rel32(self.data, packet.FIELD_TABLE + 4 * 5), 'field table entry 5')

    def test_name_length_rejected(self):
        # shared length store for the 8-byte names hardfork / tx_index / next_lid / next_oid
        self._rejects(self._patch(self.data, 0x30d3afe, b'\x07'), 'stores length 7')

    def test_flag_store_rejected(self):
        self._rejects(self._patch(self.data, 0x30d2cba, b'\x30'), 'flag store at 0x30d2cb6')

    def test_slot_call_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30d2b43, 8), 'not through slot 0x64dfeb0')

    def test_missing_template_rejected(self):
        self._rejects(self._bump_rel32(self.data, 0x30d3685, 1), 'lea at 0x30d3682')

    def test_sequence_index_rejected(self):
        self._rejects(self._patch(self.data, 0x30d39fc, b'\x04'), 'element index at 0x30d39fb')

    def test_error_tag_rejected(self):
        self._rejects(self._patch(self.data, packet.ERROR_FMT_TAG + 2, b'\x09'), 'result tag 6')


if __name__ == '__main__':
    unittest.main()
