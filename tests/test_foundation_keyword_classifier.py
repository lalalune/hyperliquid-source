"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_keyword_classifier as classifier
from elf_index import sections


class KeywordClassifierEvidenceTests(unittest.TestCase):
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
                      'research/work-items/foundation-keyword-classifier-94')

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
        self.assertEqual(record['constant']['bytes'], 'required_matches')
        self.assertEqual(record['incoming_pattern_scan']['e8_candidates'],
                         [hex(classifier.CALL_SITE)])

    def test_tag_edges_from_decoded_formula(self):
        self.assertEqual(classifier.classify(b'until'), 0)
        self.assertEqual(classifier.classify(b'required_matches'), 1)
        self.assertEqual(classifier.classify(b''), 2)
        self.assertEqual(classifier.classify(b'untilx'), 2)
        self.assertEqual(classifier.classify(b'untix'), 2)
        self.assertEqual(classifier.classify(b'required_matchex'), 2)
        self.assertEqual(classifier.classify(b'REQUIRED_MATCHES'), 2)
        self.assertEqual(classifier.classify(b'required_match'), 2)

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
            (classifier.START + 42, 'instruction window'),
            (classifier.START + 64, 'instruction window'),
            (classifier.START + 75, 'instruction window'),
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

    def test_constant_mutation_rejected(self):
        va = classifier.CONSTANT_VA + 3
        old = self.data[self.offset(va)]
        with self.assertRaisesRegex(ValueError, 'Keyword constant changed'):
            classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_fde_record_mutation_rejected(self):
        # .eh_frame address equals its file offset for this target.
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        off = eh['offset'] + 0x95ac
        old = self.data[off]
        mutated = bytearray(self.data)
        mutated[off] = old ^ 1
        with self.assertRaisesRegex(ValueError, 'FDE record changed'):
            classifier.analyze(bytes(mutated))

    def test_caller_mutations_rejected(self):
        cases = [
            (classifier.CALL_SITE, 'Caller call bytes changed'),
            (0x13ba4b1, 'Caller string-pointer setup changed'),
            (0x13ba4b9, 'Caller length setup changed'),
            (0x13ba4c1, 'Caller output-pointer setup changed'),
        ]
        for va, pattern in cases:
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, pattern):
                    classifier.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_no_slot_maps_to_window(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        off = self.offset(relsec['address'])
        raw = self.data[off:off + relsec['size']]
        slots = []
        for i in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, i)
            if info == 8 and addend == classifier.START:
                slots.append(address)
        self.assertEqual(slots, [])

    def test_retained_disassembly(self):
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('1437b90:', window)
        self.assertIn('1437be3:', window)
        self.assertNotIn('\tcall', window)
        caller = (self.packet / 'caller.objdump.txt').read_text()
        self.assertIn('13ba4c6:', caller)
        self.assertIn('call   1437b90', caller)
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=0000000001437b90..0000000001437be4', frames)
        self.assertIn('pc=00000000013b9560..00000000013baf1a', frames)


if __name__ == '__main__':
    unittest.main()
