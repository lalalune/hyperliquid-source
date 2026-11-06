import hashlib
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dex_kind_state_codec_115', ROOT / 'tools/dex_kind_state_codec_115.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

PACKET = ROOT / 'research/work-items/dex-registry-main-hip3-state-codec-115'


def patched(data, va, raw):
    image = tool.Image(data)
    s = image.section_of(va)
    off = s['offset'] + va - s['address']
    out = bytearray(data)
    out[off:off + len(raw)] = raw
    return bytes(out)


class DexKindStateCodecTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.TARGET.read_bytes()
        cls.result = tool.build(cls.data)
        cls.files = tool.render(cls.result)

    def test_capture_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual(s['serializer_matches'], s['serializer_cases'])
        self.assertEqual(s['visitor_matches'], s['visitor_cases'])
        self.assertGreater(s['serializer_cases'], 5000)
        self.assertGreater(s['visitor_cases'], 6000)
        self.assertGreater(s['failure_cases'], 600)
        verdicts = {r[-1] for r in self.result['serializer'] + self.result['failures'] + self.result['visitor']}
        self.assertEqual(verdicts, {'match'})

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        for family, name, mismatches, cases in self.result['negatives']:
            self.assertGreater(mismatches, 0, '%s/%s not caught' % (family, name))
            self.assertLess(mismatches, cases + 1)

    def test_packet_files_are_reproduced_byte_for_byte(self):
        on_disk = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
        self.assertEqual(on_disk, sorted(self.files))
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_bytes(), text.encode('ascii'), name)

    def test_manifest_covers_packet(self):
        rows = [l.split('  ', 1) for l in (PACKET / 'MANIFEST.sha256').read_text().splitlines()]
        names = sorted(n for _, n in rows)
        self.assertEqual(names, sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_variant_pools_decode_to_names(self):
        texts = [(r[0], r[6]) for r in self.result['variant_tables']]
        for pool in tool.VARIANT_POOLS:
            self.assertEqual([t for p, t in texts if p == '0x%x' % pool], ['Main', 'Hip3'])

    def test_reconstruction_examples(self):
        copy = tool.SERIALIZERS[0]
        main = {0: tool.NICHE_MAIN, 0x30: 0, 0x78: 0, 0x90: tool.NONE_90}
        data, log, end, result = tool.recon_serialize(copy, 0, main, 64, 0, None)
        self.assertEqual(data, b'\x81\xa4Main\x94')
        self.assertEqual(result[0], tool.OK_WORD)
        hip3 = {0: 0, 0x30: 0, 0x78: 1, 0x90: tool.NONE_90}
        data, log, end, result = tool.recon_serialize(copy, 1, hip3, 64, 0, None)
        self.assertIn(('map_header', 4), log)
        self.assertEqual(data, b'\x81\xa4Hip3\xa6limits\xa6schema\xa5state')
        self.assertEqual(tool.recon_visitor(b'Hip3'), ('ok', 0x109))
        self.assertEqual(tool.recon_visitor(b'hip3'), ('err', None))

    def test_rejects_other_capture(self):
        with self.assertRaises(tool.Reject):
            tool.build(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_rejects_unmapped_address(self):
        image = tool.Image(self.data)
        with self.assertRaises(tool.Reject):
            image.read(0x10, 4)

    def _visitor(self, data, text):
        image = tool.Image(data)
        stubs = {0x17fbba0: tool.error_stub}
        return tool.run_visitor(image, 0x2b94d80, stubs, text, 0x644cbb0)[0]

    def test_visitor_name_mutation_is_detected(self):
        self.assertEqual(self._visitor(self.data, b'Hip3'), ('ok', 0x109))
        # cmpl $imm32,(%rsi) at 0x2b94d8e: immediate starts 2 bytes in
        bad = patched(self.data, 0x2b94d90, b'Hip4')
        self.assertEqual(self._visitor(bad, b'Hip3'), ('err', None))
        self.assertNotEqual(self._visitor(bad, b'Hip3'), tool.recon_visitor(b'Hip3'))

    def _serialize(self, data, flag, value, cap):
        image = tool.Image(data)
        copy = tool.SERIALIZERS[0]
        stubs = tool.make_stubs(image, copy, tool.Script(copy, None), 0x231e050)
        return tool.run_serializer(image, copy, stubs, flag, value, cap, 0)[:4]

    def test_serializer_byte_mutations_are_detected(self):
        main = {0: tool.NICHE_MAIN, 0x30: 0, 0x78: 0, 0x90: tool.NONE_90}
        want = tool.recon_serialize(tool.SERIALIZERS[0], 0, main, 6, 0, None)
        self.assertEqual(self._serialize(self.data, 0, main, 6), want)
        # or $0x84,%bpl at 0x2bc2791 (41 80 cd 84): header byte immediate
        self.assertEqual(self.data[self._off(0x2bc2791):self._off(0x2bc2791) + 4], bytes.fromhex('4080cd84'))
        bad = patched(self.data, 0x2bc2794, b'\x80')
        self.assertNotEqual(self._serialize(bad, 0, main, 6), want)
        # cmp $0x3,%rax at 0x2bc276b (48 83 f8 03): reserve bound of the name
        self.assertEqual(self.data[self._off(0x2bc276b):self._off(0x2bc276b) + 4], bytes.fromhex('4883f803'))
        bad = patched(self.data, 0x2bc276e, b'\x02')
        self.assertNotEqual(self._serialize(bad, 0, main, 5), tool.recon_serialize(tool.SERIALIZERS[0], 0, main, 5, 0, None))

    def _off(self, va):
        s = tool.Image(self.data).section_of(va)
        return s['offset'] + va - s['address']

    def test_flag_byte_two_is_mixed_encoding(self):
        hip3 = {0: 0, 0x30: 0, 0x78: 0, 0x90: tool.NONE_90}
        data, log, _, _ = tool.recon_serialize(tool.SERIALIZERS[0], 2, hip3, 64, 0, None)
        self.assertIn(('map_header', 3), log)
        self.assertNotIn(b'limits', data)
        rows = [r for r in self.result['serializer'] if r[1] == 2 and r[2] == 'Main']
        self.assertTrue(rows)
        self.assertTrue(all(r[6].startswith('81a44d61696eb4') or r[6].startswith('a36d6f6881a44d61696eb4') for r in rows))

    def test_entries_are_fde_starts(self):
        for row in self.result['functions']:
            self.assertGreater(row['decoded_bytes'], 0)
            self.assertLessEqual(row['decoded_bytes'], row['fde_bytes'])
        self.assertEqual(struct.calcsize('<Q'), 8)


if __name__ == '__main__':
    unittest.main()
