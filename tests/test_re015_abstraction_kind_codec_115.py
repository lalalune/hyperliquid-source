import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re015_abstraction_kind_codec_115 as codec  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-015-abstraction-kind-codec-115'
DATA = codec.TARGET.read_bytes()
TAGGED = 0x23c65f0
RESULT = 0x23c6720
POOL = 0x642f400


def text_offset(va):
    return va - 0x1000


class AbstractionKindCodec115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = codec.build(DATA)
        cls.files = codec.render(cls.result)
        cls.image = codec.Image(DATA)
        cls.stubs = {t: codec.error_stub for t in (0x17fbba0, 0x2cf1360, 0x2f7fef0, 0x45a8fe0, 0x47d2d80)}

    def mutated_image(self, off, data):
        raw = bytearray(DATA)
        raw[off:off + len(data)] = data
        return codec.Image(bytes(raw))

    def tagged(self, img, text):
        return codec.run_visitor(img, TAGGED, self.stubs, 'visitor_tagged', text, POOL)[0]

    def test_digest(self):
        self.assertEqual(hashlib.sha256(DATA).hexdigest(), codec.SHA115)

    def test_reconstruction_matches_every_case(self):
        s = self.result['summary']
        self.assertTrue(s['reconstruction_matches_all'])
        self.assertEqual((s['visitor_matches'], s['visitor_cases']), (37640, 37640))
        self.assertEqual(s['visitor_inputs'], 7528)
        self.assertEqual(s['accepted_inputs'], 7)
        self.assertEqual(s['functions'], 5)
        self.assertEqual(s['decoded_instructions'], 400)

    def test_every_negative_control_is_caught(self):
        self.assertTrue(self.result['summary']['all_negative_controls_caught'])
        self.assertEqual(len(self.result['negatives']), 6)
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
            pool = {0x23c65f0: 0x642f400, 0x3bdd720: 0x6476120, 0x4d6b5d0: 0x649c2f8}[va]
            for tag, name in enumerate(codec.NAMES):
                (status, value), _ = codec.run_visitor(img, va, stubs, 'visitor_tagged', name, pool)
                self.assertEqual((status, value), ('ok', 9 | tag << 8))
        for va in codec.VISITORS_RESULT:
            pool = {0x23c6720: 0x642f400, 0x3bdd5e0: 0x6476120}[va]
            (status, value), _ = codec.run_visitor(img, va, stubs, 'visitor_result', b'AllBoleTokens', pool)
            self.assertEqual((status, value), ('ok', 6))
            (status, _), _ = codec.run_visitor(img, va, stubs, 'visitor_result', b'allBoleTokens', pool)
            self.assertEqual(status, 'err')

    def test_mutated_name_immediate_is_detected(self):
        # 0x23c66a7: cmp dword [rsi], 0x70726550 ('Perp'); change 'P' to 'p'.
        site = 0x23c66a7
        self.assertEqual(DATA[text_offset(site):text_offset(site) + 6], bytes.fromhex('813e50657270'))
        img = self.mutated_image(text_offset(site) + 2, b'p')
        self.assertEqual(self.tagged(img, b'Perp')[0], 'err')
        self.assertEqual(codec.recon_visitor_tagged(b'Perp')[0], 'ok')

    def test_mutated_sse_constant_is_detected(self):
        # Last byte of the +6 window constant 'teDexAbstraction' (rodata VA == file offset).
        self.assertEqual(DATA[0x450bb0:0x450bc0], b'teDexAbstraction')
        img = self.mutated_image(0x450bbf, b'N')
        self.assertEqual(self.tagged(img, b'ActivateDexAbstraction')[0], 'err')

    def test_mutated_jump_table_is_detected(self):
        # Swap the length-4 and length-5 arms of the tagged copy's table at 0x5ec280.
        e4, e5 = DATA[0x5ec284:0x5ec288], DATA[0x5ec288:0x5ec28c]
        raw = bytearray(DATA)
        raw[0x5ec284:0x5ec288] = e5
        raw[0x5ec288:0x5ec28c] = e4
        img = codec.Image(bytes(raw))
        self.assertEqual(self.tagged(img, b'Spot')[0], 'err')
        self.assertEqual(self.tagged(img, b'Token')[0], 'err')

    def test_mutated_length_bound_is_detected(self):
        # 0x23c65f4: cmp rax, 0x13 bounds lengths 3..22; make it 0x12.
        site = 0x23c65f4
        self.assertEqual(DATA[text_offset(site):text_offset(site) + 4], bytes.fromhex('4883f813'))
        img = self.mutated_image(text_offset(site) + 3, b'\x12')
        self.assertEqual(self.tagged(img, b'ActivateUnifiedAccount')[0], 'err')

    def test_unsupported_bytes_rejected(self):
        img = self.mutated_image(text_offset(TAGGED), b'\x0f\x0b')  # ud2
        with self.assertRaises(codec.Reject):
            self.tagged(img, b'Perp')

    def test_unmodelled_call_rejected(self):
        with self.assertRaises(codec.Reject):
            codec.run_visitor(self.image, TAGGED, {}, 'visitor_tagged', b'Perq', POOL)

    def test_wrong_pool_argument_rejected(self):
        with self.assertRaises(codec.Reject):
            codec.run_visitor(self.image, TAGGED, self.stubs, 'visitor_tagged', b'Perq', 0x6476120)

    def test_store_outside_scratch_rejected(self):
        m = codec.Machine(self.image, {})
        with self.assertRaises(codec.Reject):
            m.store(0x5ec280, 0, 1)

    def test_variant_pools_read_from_relocations(self):
        rows = self.result['variant_tables']
        self.assertEqual(len(rows), 21)
        self.assertEqual([r[6].encode() for r in rows[:7]], list(codec.NAMES))
        for pool, index, slot, pos, va, length, text in rows:
            r_off, r_info, r_add = struct.unpack_from('<QQq', DATA, int(pos, 16))
            self.assertEqual((r_off, r_info & 0xffffffff, r_add), (int(slot, 16), 8, int(va, 16)))
            self.assertEqual(DATA[int(va, 16):int(va, 16) + length].decode(), text)

    def test_jump_tables_cover_exactly_the_name_lengths(self):
        lengths = sorted(set(len(n) for n in codec.NAMES))
        for va in codec.VISITORS_TAGGED + codec.VISITORS_RESULT:
            rows = [r for r in self.result['jump'] if r[0] == '0x%x' % va]
            self.assertEqual(len(rows), 20)
            self.assertEqual(sorted(r[2] for r in rows if r[6] == 'compare'), lengths)

    def test_wrong_reconstructions_disagree(self):
        self.assertEqual(codec.wrong_prefix(b'Perps'), 0)
        self.assertIsNone(codec.recon_classify(b'Perps'))
        self.assertEqual(codec.wrong_casefold(b'SPOT'), 1)
        self.assertIsNone(codec.recon_classify(b'SPOT'))
        self.assertNotEqual(codec.wrong_swap(b'ActivateDexAbstraction'), codec.recon_classify(b'ActivateDexAbstraction'))
        self.assertEqual(codec.wrong_low16(b'ActivateDexAbstraXXXXX'), 4)
        self.assertIsNone(codec.recon_classify(b'ActivateDexAbstraXXXXX'))


if __name__ == '__main__':
    unittest.main()
