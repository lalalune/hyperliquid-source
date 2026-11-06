import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re015_spot_mark_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-015-spot-mark-codec-115'
DATA = codec.TARGET.read_bytes()
IMAGE = codec.Image(DATA)


def file_offset(va):
    s = IMAGE.section_of(va)
    return s['offset'] + va - s['address']


class SpotMarkCodec115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = codec.build(DATA)
        cls.files = codec.render(cls.result)
        cls.image = IMAGE
        cls.stubs = {t: codec.grow_stub for t in (0x231e050, 0x43bd910, 0x5963a10)}
        cls.stubs.update({t: codec.error_stub for t in (0x17fbba0, 0x2f7fef0, 0x47d2d80)})

    def mutated_image(self, va, data, expect=None):
        off = file_offset(va)
        if expect is not None:
            self.assertEqual(DATA[off:off + len(expect)], expect)
        raw = bytearray(DATA)
        raw[off:off + len(data)] = data
        return codec.Image(bytes(raw))

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (1335, 1335))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (15486, 15486))
        self.assertEqual(s['visitor_inputs'], 5162)
        self.assertEqual(s['accepted_inputs'], 3)
        self.assertEqual(s['functions'], 6)
        self.assertEqual(s['decoded_instructions'], 486)
        self.assertEqual(s['grow_callees'], ['0x231e050', '0x43bd910', '0x5963a10'])
        self.assertEqual(s['error_callees'], ['0x17fbba0', '0x2f7fef0', '0x47d2d80'])

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 9)
        for family, name, mismatches, cases in self.result['negatives']:
            self.assertGreater(mismatches, 0, name)
            self.assertLessEqual(mismatches, cases)

    def test_packet_files_are_byte_identical(self):
        on_disk = sorted(p.name for p in PACKET.iterdir() if p.name not in ('README.md', 'MANIFEST.sha256'))
        self.assertEqual(on_disk, sorted(self.files))
        for name, text in self.files.items():
            self.assertEqual((PACKET / name).read_bytes(), text.encode('ascii'), name)

    def test_manifest(self):
        rows = [line.split('  ', 1) for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines()]
        names = sorted(n for _, n in rows)
        self.assertEqual(names, sorted(p.name for p in PACKET.iterdir() if p.name != 'MANIFEST.sha256'))
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_main_writes_reproducible_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(codec.main(['--out', tmp]), 0)
            for name, text in self.files.items():
                self.assertEqual((Path(tmp) / name).read_text(encoding='ascii'), text)

    def test_wrong_digest_rejected(self):
        raw = bytearray(DATA)
        raw[-1] ^= 1
        with self.assertRaises(codec.Reject):
            codec.build(bytes(raw))

    def test_known_outputs(self):
        for va, pool in zip(codec.VISITORS_TAGGED, codec.VARIANT_POOLS):
            for tag, name in enumerate(codec.NAMES):
                (status, value), _ = codec.run_visitor(self.image, va, self.stubs, name, pool)
                self.assertEqual((status, value), ('ok', 9 | tag << 8))
            for bad in (b'spot', b'Spots', b'ExternalPerq', b'Mar', b''):
                (status, _), _ = codec.run_visitor(self.image, va, self.stubs, bad, pool)
                self.assertEqual(status, 'err')
        for va in codec.SERIALIZERS:
            got = codec.run_serializer(self.image, va, self.stubs, 2, 64, 0)
            self.assertEqual(got[0], b'\xacExternalPerp')
            self.assertEqual(got[1], [])
            self.assertEqual(got[3], codec.OK_WORD)
            # out-of-range tag bytes take the ExternalPerp fall-through
            self.assertEqual(codec.run_serializer(self.image, va, self.stubs, 0xff, 64, 0)[0], b'\xacExternalPerp')
            # empty vector: grow for the marker, then grow again for the 12 name bytes
            self.assertEqual(codec.run_serializer(self.image, va, self.stubs, 2, 0, 0)[1], [(0, 1), (1, 12)])

    def test_mutated_name_immediate_is_detected(self):
        # 0x22e20d6: cmp dword [rsi], 0x746f7053 ('Spot'); change 'S' to 's'.
        img = self.mutated_image(0x22e20d8, b's', expect=b'Spot')
        (status, _), _ = codec.run_visitor(img, 0x22e20d0, self.stubs, b'Spot', 0x642d150)
        self.assertEqual(status, 'err')
        self.assertNotEqual(codec.recon_visitor_tagged(b'Spot')[0], status)

    def test_mutated_tag_compare_is_detected(self):
        # 0x22e381e: cmp ecx, 1 (the Mark arm); make it cmp ecx, 2.
        img = self.mutated_image(0x22e3820, b'\x02', expect=bytes.fromhex('01'))
        got = codec.run_serializer(img, 0x22e3810, self.stubs, 1, 64, 0)
        self.assertNotEqual(got[0], codec.recon_serialize(1, 64, 0)[0])

    def test_mutated_reserve_bound_is_detected(self):
        # 0x22e3845: cmp rcx, 3 / jbe on the Mark arm; make the bound 2.
        img = self.mutated_image(0x22e3848, b'\x02', expect=b'\x03')
        self.assertEqual(DATA[file_offset(0x22e3845):file_offset(0x22e3845) + 4], bytes.fromhex('4883f903'))
        got = codec.run_serializer(img, 0x22e3810, self.stubs, 1, 4, 0)
        self.assertNotEqual(got[1], codec.recon_serialize(1, 4, 0)[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(0x22e20d0, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            codec.run_visitor(img, 0x22e20d0, self.stubs, b'Spot', 0x642d150)

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            codec.run_visitor(self.image, 0x22e20d0, {}, b'Spox', 0x642d150)

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            codec.run_visitor(self.image, 0x22e20d0, self.stubs, b'Spox', 0x6479be0)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(self.image, {})
        with self.assertRaises(codec.Reject):
            m.store(0x642d150, 0, 1)

    def test_variant_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 9)
        self.assertEqual([r[6] for r in rows], ['Spot', 'Mark', 'ExternalPerp'] * 3)
        for pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(IMAGE.read(int(va, 16), length).decode(), text)

    def test_wrong_reconstructions_disagree(self):
        self.assertEqual(codec.wrong_prefix(b'Spotx'), 0)
        self.assertIsNone(codec.recon_classify(b'Spotx'))
        self.assertEqual(codec.wrong_casefold(b'MARK'), 1)
        self.assertIsNone(codec.recon_classify(b'MARK'))
        self.assertNotEqual(codec.wrong_swap(b'Spot'), codec.recon_classify(b'Spot'))
        self.assertEqual(codec.wrong_first8(b'ExternalXXXX'), 2)
        self.assertIsNone(codec.recon_classify(b'ExternalXXXX'))
        self.assertNotEqual(codec.wrong_serialize_range(7, 64, 0), codec.recon_serialize(7, 64, 0))


if __name__ == '__main__':
    unittest.main()
