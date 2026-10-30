"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_vip_classifier as classifier
from elf_index import sections


class VipClassifierEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not classifier.TARGET.is_file() or classifier.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = classifier.inspect(classifier.TARGET)
        cls.data = classifier.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = (classifier.ROOT /
                      'research/work-items/foundation-vip-classifier-94')

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_evidence_matches_tool(self):
        record = json.loads((self.packet / 'evidence.json').read_text())
        self.assertEqual(record['target_sha256'], classifier.SHA256)
        self.assertEqual(record['function']['start_va'], hex(classifier.START))
        self.assertEqual(record['function']['end_va_exclusive'], hex(classifier.END))
        self.assertEqual(record['function']['bytes'], classifier.END - classifier.START)
        self.assertEqual(record['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(record['incoming_pattern_scan']['e8_candidates'],
                         [hex(classifier.CALL_SITE)])

    def test_tag_edges_from_decoded_formula(self):
        self.assertEqual(classifier.classify(b'vip'), 0)
        self.assertEqual(classifier.classify(b'mm'), 1)
        self.assertEqual(classifier.classify(b''), 2)
        self.assertEqual(classifier.classify(b'm'), 2)
        self.assertEqual(classifier.classify(b'vi'), 2)
        self.assertEqual(classifier.classify(b'mmx'), 2)
        self.assertEqual(classifier.classify(b'vix'), 2)
        self.assertEqual(classifier.classify(b'vipx'), 2)
        self.assertEqual(classifier.classify(b'MM'), 2)
        self.assertEqual(classifier.classify(b'mM'), 2)

    def test_output_shape_bytes_locked(self):
        # All three tag stores write byte 0 = 9 and byte 1 = tag, then ret.
        self.assertIn(b'\x88\x48\x01\xc6\x00\x09\xc3', classifier.BODY)
        self.assertEqual(classifier.BODY.count(b'\xc6\x00\x09\xc3'), 3)

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'Target size changed'):
                classifier.inspect(path)
            path.write_bytes(self.mutated(classifier.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'Target digest changed'):
                classifier.inspect(path)

    def test_instruction_mutations_rejected(self):
        cases = [
            (classifier.START + 0, 'instruction window'),
            (classifier.START + 3, 'instruction window'),
            (classifier.START + 15, 'instruction window'),
            (classifier.START + 18, 'instruction window'),
            (classifier.START + 45, 'instruction window'),
            (classifier.START + 52, 'instruction window'),
            (classifier.START + 61, 'instruction window'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        va = classifier.END
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'FDE padding changed'):
            classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_fde_record_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        va = eh['address'] + 0x3cdc0 + 8
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'FDE record changed'):
            classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_caller_fde_record_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        va = eh['address'] + 0x325444 + 8
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'FDE record changed'):
            classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_caller_call_mutation_rejected(self):
        va = classifier.CALL_SITE
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'Caller call bytes changed'):
            classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_caller_call_target_computation(self):
        # The displacement check is unreachable by mutation (the bytes check
        # fires first), so assert the target computation directly instead.
        call = self.data[self.offset(classifier.CALL_SITE):
                         self.offset(classifier.CALL_SITE) + 5]
        self.assertEqual(call, bytes.fromhex('e8c40e7500'))
        self.assertEqual(
            classifier.CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0],
            classifier.START)

    def test_caller_argument_setup_mutation_rejected(self):
        cases = [
            (0x171c688, 'Caller string-pointer setup changed'),
            (0x171c68d, 'Caller length setup changed'),
            (0x171c692, 'Caller output-pointer setup changed'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    classifier.analyze(self.mutated(va, bytes([old ^ 1])))


if __name__ == '__main__':
    unittest.main()
