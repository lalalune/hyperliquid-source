import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pxpriv_admission as pa

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-pxpriv-admission-94'
GENERATED = ['call-sites.tsv', 'evidence.json', 'guard-bytes.txt', 'MANIFEST.sha256']


class DecoderTests(unittest.TestCase):
    def test_digest_verification_against_artifacts_json(self):
        item = pa.load_expected_artifact(ROOT, pa.BINARY_REL)
        self.assertEqual(item['sha256'], pa.EXPECTED_SHA256)
        self.assertEqual(item['size'], pa.EXPECTED_SIZE)

        # Mismatch in sha256 or size must fail-closed
        with self.assertRaises(pa.EvidenceError):
            pa.check_digest(b'tampered binary payload', root=ROOT)

        with self.assertRaises(pa.EvidenceError):
            pa.load_expected_artifact(ROOT, 'artifacts/nonexistent/hl-node')

    def test_admission_models(self):
        # u64 admission: value != 0
        self.assertFalse(pa.admitted_u64_model(0))
        self.assertTrue(pa.admitted_u64_model(1))
        self.assertTrue(pa.admitted_u64_model((1 << 63) - 1))
        self.assertTrue(pa.admitted_u64_model(1 << 63))
        self.assertTrue(pa.admitted_u64_model((1 << 64) - 1))

        # intermediate u64 conversion from i64: non-negative (bit 63 == 0)
        self.assertTrue(pa.intermediate_admitted_i64_model(0))
        self.assertTrue(pa.intermediate_admitted_i64_model(1))
        self.assertTrue(pa.intermediate_admitted_i64_model((1 << 63) - 1))
        self.assertFalse(pa.intermediate_admitted_i64_model(1 << 63))       # -2^63 (i64::MIN)
        self.assertFalse(pa.intermediate_admitted_i64_model((1 << 64) - 1)) # -1

        # full i64 admission: non-negative AND non-zero (value > 0)
        adm_0, reason_0 = pa.admitted_i64_model(0)
        self.assertFalse(adm_0)
        self.assertEqual(reason_0, 'rejected_zero')

        adm_neg1, reason_neg1 = pa.admitted_i64_model((1 << 64) - 1)
        self.assertFalse(adm_neg1)
        self.assertEqual(reason_neg1, 'rejected_intermediate_negative')

        adm_min, reason_min = pa.admitted_i64_model(1 << 63)
        self.assertFalse(adm_min)
        self.assertEqual(reason_min, 'rejected_intermediate_negative')

        adm_pos, reason_pos = pa.admitted_i64_model(1)
        self.assertTrue(adm_pos)
        self.assertEqual(reason_pos, 'admitted')

        adm_max, reason_max = pa.admitted_i64_model((1 << 63) - 1)
        self.assertTrue(adm_max)
        self.assertEqual(reason_max, 'admitted')

    def test_direct_calls_scanner(self):
        # E8 disp32
        text = b'\x90\xe8\x10\x00\x00\x00\x90'
        # call instruction at offset 1 (VA 0x1001), next insn at VA 0x1006, target 0x1016
        calls = pa.direct_calls(0x1000, text, {0x1016})
        self.assertEqual(calls, [(0x1001, 0x1016)])
        self.assertEqual(pa.direct_calls(0x1000, text, {0x9999}), [])


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / pa.BINARY_REL).read_bytes()
        cls.result, cls.callers = pa.analyse(cls.data, root=ROOT)

    def test_summary_metrics(self):
        summary = self.result['summary']
        expected = {
            'all_callers_hold_all_three_visitors': True,
            'caller_functions': 9,
            'constructors': 12,
            'diagnostic_pieces': 4,
            'direct_calls': 27,
            'direct_calls_i64': 9,
            'direct_calls_intermediate_u64': 9,
            'direct_calls_u64': 9,
            'lea_refs': 12,
            'samples_checked': 190,
        }
        self.assertEqual(summary, expected)

    def test_pieces_layout_and_addresses(self):
        pieces = self.result['pieces']
        self.assertEqual(set(pieces.keys()), {'u64', 'i64', 'intermediate_u64', 'NonZeroU64'})

        self.assertEqual(pieces['u64']['va'], '0x1e66a6')
        self.assertEqual(pieces['i64']['va'], '0x1f7a73')
        self.assertEqual(pieces['intermediate_u64']['va'], '0x1ff8fb')
        self.assertEqual(pieces['NonZeroU64']['va'], '0x1ebe57')

        # Each piece must have exactly 3 LEA references and 3 constructors
        for role, p in pieces.items():
            self.assertEqual(len(p['leas']), 3, f'{role} LEAs')
            self.assertEqual(len(p['constructors']), 3, f'{role} constructors')

    def test_call_sites_and_caller_extents(self):
        pieces = self.result['pieces']
        for role in ('u64', 'i64', 'intermediate_u64'):
            self.assertEqual(len(pieces[role]['call_sites']), 9, f'{role} call sites')

        # Check the 9 caller functions and their sizes (3 of 896 bytes, 6 of 1733 bytes)
        callers = self.result['callers']
        self.assertEqual(len(callers), 9)
        sizes = [c['caller_size'] for c in callers]
        self.assertEqual(sorted(sizes), [896, 896, 896, 1733, 1733, 1733, 1733, 1733, 1733])

    def test_negative_controls(self):
        # 1. Corrupted binary digest
        bad_digest_data = bytearray(self.data)
        bad_digest_data[0x1000] ^= 0x01
        with self.assertRaises(pa.EvidenceError):
            pa.analyse(bytes(bad_digest_data), root=ROOT)

        # 2. Corrupted rodata diagnostic literal
        img = pa.Image(self.data)
        pdef = dict(pa.PIECE_DEFS[0])
        pdef['expected_va'] = 0x999999  # wrong expected VA
        with self.assertRaises(pa.EvidenceError):
            pa.find_diagnostic_piece(img, pdef)

        # 3. FDE range lookup out of bounds
        fdes = pa.Fdes(img)
        with self.assertRaises(pa.EvidenceError):
            fdes.range_of(0x10)  # precedes every FDE

        # 4. Image offset out of bounds
        with self.assertRaises(pa.EvidenceError):
            img.off(0x10, 4)

    def test_packet_files_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(pa.main(['--out', str(tmp_path)]), 0)
            for fname in GENERATED:
                self.assertTrue((tmp_path / fname).is_file(), f'missing {fname}')
                # Byte-for-byte exactness against research packet
                if PACKET.exists() and (PACKET / fname).exists():
                    self.assertEqual(
                        (tmp_path / fname).read_bytes(),
                        (PACKET / fname).read_bytes(),
                        f'content mismatch for {fname}'
                    )

            # Check that MANIFEST.sha256 matches all generated files
            manifest_lines = (tmp_path / 'MANIFEST.sha256').read_text().splitlines()
            for line in manifest_lines:
                expected_sha, fname = line.split('  ', 1)
                actual_sha = hashlib.sha256((tmp_path / fname).read_bytes()).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f'manifest hash mismatch for {fname}')


if __name__ == '__main__':
    unittest.main()
