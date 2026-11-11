import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re015_chain_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-015-chain-codec-115'
DATA = codec.TARGET.read_bytes()


def text_offset(va):
    return va - 0x1000


class ChainCodec115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = codec.build(DATA)
        cls.files = codec.render(cls.result)
        cls.image = codec.Image(DATA)
        cls.stubs = {t: codec.grow_stub for t in (0x231e050, 0x43bd910, 0x5963a10)}
        cls.stubs.update({t: codec.error_stub for t in (0x14a1970, 0x17fbba0, 0x2cf1360, 0x2f7fef0, 0x45a8fe0)})

    def mutated_image(self, va, data):
        raw = bytearray(DATA)
        off = text_offset(va) if va >= 0x1419300 else va
        raw[off:off + len(data)] = data
        return codec.Image(bytes(raw))

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['serializer_matches'], s['serializer_cases']), (360, 360))
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (33375, 33375))
        self.assertEqual(s['visitor_inputs'], 6675)
        self.assertEqual(s['functions'], 8)
        self.assertEqual(s['decoded_instructions'], 771)

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
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
        img, stubs = self.image, self.stubs
        for va in codec.VISITORS_TAGGED:
            for tag, name in enumerate(codec.NAMES):
                (status, value), _ = codec.run_visitor(img, va, stubs, 'visitor_tagged', name)
                self.assertEqual((status, value), ('ok', 9 | tag << 8))
        for va in codec.VISITORS_RESULT:
            (status, value), _ = codec.run_visitor(img, va, stubs, 'visitor_result', b'Mainnet')
            self.assertEqual((status, value), ('ok', 3))
            (status, _), _ = codec.run_visitor(img, va, stubs, 'visitor_result', b'mainnet')
            self.assertEqual(status, 'err')
        for va in codec.SERIALIZERS:
            got = codec.run_serializer(img, va, stubs, 1, 64, 0)
            self.assertEqual(got[0], b'\xa7Sandbox')
            self.assertEqual(got[1], [])
            self.assertEqual(got[3], 0x8000000000000004)

    def test_mutated_name_immediate_is_detected(self):
        # 0x2690cdc: mov eax, 0x61636f4c ('Loca'); change 'L' to 'l'.
        img = self.mutated_image(0x2690cdd, b'l')
        (status, _), _ = codec.run_visitor(img, 0x2690cd0, self.stubs, 'visitor_tagged', b'Local')
        self.assertEqual(status, 'err')
        self.assertNotEqual(codec.recon_visitor_tagged(b'Local')[0], status)

    def test_mutated_jump_table_is_detected(self):
        # Swap serializer table entries for tags 1 and 2 (rodata VA == file offset).
        e1 = DATA[0x5f2964:0x5f2968]
        e2 = DATA[0x5f2968:0x5f296c]
        raw = bytearray(DATA)
        raw[0x5f2964:0x5f2968] = e2
        raw[0x5f2968:0x5f296c] = e1
        img = codec.Image(bytes(raw))
        got = codec.run_serializer(img, 0x2674b80, self.stubs, 1, 64, 0)
        self.assertNotEqual(got[0], codec.recon_serialize(1, 64, 0)[0])

    def test_mutated_reserve_bound_is_detected(self):
        # 0x2674c7b: cmp rcx,0x6 / jbe at the Sandbox arm; make the bound 0x5.
        site = 0x2674c77
        self.assertEqual(DATA[text_offset(site):text_offset(site) + 4], bytes.fromhex('4883f906'))
        img = self.mutated_image(site + 3, b'\x05')
        got = codec.run_serializer(img, 0x2674b80, self.stubs, 1, 7, 0)
        want = codec.recon_serialize(1, 7, 0)
        self.assertNotEqual(got[1], want[1])

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(0x2690cd0, b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            codec.run_visitor(img, 0x2690cd0, self.stubs, 'visitor_tagged', b'Local')

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            codec.run_visitor(self.image, 0x2690cd0, {}, 'visitor_tagged', b'Locax')

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(self.image, {})
        with self.assertRaises(codec.Reject):
            m.store(0x5f2960, 0, 1)

    def test_variant_tables_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 12)
        self.assertEqual([r[6] for r in rows[:4]], ['Local', 'Sandbox', 'Testnet', 'Mainnet'])
        for table, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(DATA[int(va, 16):int(va, 16) + length].decode(), text)

    def test_wrong_reconstructions_disagree(self):
        self.assertEqual(codec.wrong_prefix(b'Localx'), 0)
        self.assertIsNone(codec.recon_classify(b'Localx'))
        self.assertEqual(codec.wrong_casefold(b'LOCAL'), 0)
        self.assertIsNone(codec.recon_classify(b'LOCAL'))
        self.assertNotEqual(codec.wrong_swap(b'Sandbox'), codec.recon_classify(b'Sandbox'))


if __name__ == '__main__':
    unittest.main()
