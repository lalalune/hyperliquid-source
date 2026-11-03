'''Focused test: the RE-012 node #115 CLI info packet checker runs on the saved packet.

The test imports the committed checker tools/cli_info_dispatch.py and runs its
real main() against the pinned capture and the saved evidence. It also checks
that the comparator and the digest guard reject altered records, so a corrupted
packet cannot pass silently. Nothing executes the captured binary.
'''
import contextlib
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import cli_info_dispatch as subject


class CliInfoDispatchPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != 105896032:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.TARGET_SHA256:
            raise ValueError('wrong node115 capture')
        if not subject.EVIDENCE.is_file():
            raise AssertionError('missing saved packet evidence: %s' % subject.EVIDENCE)
        cls.recorded = json.loads(subject.EVIDENCE.read_text(encoding='utf-8'))

    def test_saved_packet_records_the_pinned_identity_and_claims(self):
        self.assertEqual(self.recorded['target_sha256'], subject.TARGET_SHA256)
        self.assertEqual(self.recorded['target_size_bytes'], len(self.data))
        self.assertEqual(self.recorded['token'], 'info')
        self.assertEqual(self.recorded['token_va'], '0x4312f2')
        self.assertEqual(self.recorded['token_section'], '.rodata')
        self.assertTrue(self.recorded['token_nul_terminated'])
        self.assertEqual(self.recorded['token_occurrences_in_rodata'], 1)
        self.assertEqual(self.recorded['reference_va'], '0x63d4d18')
        self.assertEqual(self.recorded['reference_bytes_hex'], '488d35d3c505fa4889dfc78424')
        self.assertEqual(self.recorded['reference_target_va'], '0x4312f2')
        self.assertEqual(self.recorded['direct_reference_count'], 1)
        self.assertEqual(self.recorded['fde_start'], '0x63d4bbe')
        self.assertEqual(self.recorded['fde_end'], '0x63d5428')
        self.assertEqual(self.recorded['fde_size_bytes'], 0x63D5428 - 0x63D4BBE)
        self.assertEqual(self.recorded['reference_offset_in_fde'], 0x63D4D18 - 0x63D4BBE)
        self.assertEqual(self.recorded['fde_containing_count'], 1)
        self.assertFalse(self.recorded['captured_code_executed'])
        self.assertTrue((subject.PACKET / 'README.md').is_file())

    def test_pinned_literal_and_reference_bytes_come_from_the_capture(self):
        sections = subject.parse_sections(self.data)
        token_offset = subject.section_offset(sections, subject.TOKEN_VA)
        self.assertEqual(self.data[token_offset:token_offset + len(subject.TOKEN)], subject.TOKEN)
        self.assertEqual(self.data[token_offset + len(subject.TOKEN)], 0)
        self.assertEqual(subject.count_literals(self.data, sections['.rodata'], subject.TOKEN), 1)
        text = sections['.text']
        reference_offset = text['offset'] + (subject.REFERENCE_VA - text['addr'])
        observed = self.data[reference_offset:reference_offset + len(subject.REFERENCE_BYTES)]
        self.assertEqual(observed, subject.REFERENCE_BYTES)

    def test_checker_main_passes_on_the_saved_packet(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = subject.main()
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn('OK: node #115 CLI literal info', output)
        self.assertIn('reference 0x63d4d18', output)
        self.assertIn('FDE [0x63d4bbe, 0x63d5428)', output)
        document, separator, _ = output.partition('\nOK:')
        self.assertTrue(separator)
        derived = json.loads(document)['derived']
        self.assertEqual(derived, {key: self.recorded[key] for key in derived})

    def test_comparator_and_digest_guard_reject_corruption(self):
        subject.compare(dict(self.recorded), self.recorded)
        mutations = [
            ('token', 'infp'),
            ('token_va', '0x4312f3'),
            ('reference_bytes_hex', '488d35d3c505fa4889dfc78425'),
            ('reference_va', '0x63d4d19'),
            ('reference_target_va', '0x4312f3'),
            ('fde_start', '0x63d4bbd'),
            ('fde_end', '0x63d5429'),
            ('fde_size_bytes', 0x63D5428 - 0x63D4BBE + 2),
            ('reference_offset_in_fde', 347),
            ('direct_reference_count', 2),
            ('fde_containing_count', 0),
            ('captured_code_executed', True),
            ('target_sha256', '0' * 64),
        ]
        for key, value in mutations:
            mutated = dict(self.recorded)
            mutated[key] = value
            with self.subTest(key=key):
                with self.assertRaises(AssertionError):
                    subject.compare(mutated, self.recorded)
        extra = dict(self.recorded)
        extra['unrecorded'] = 1
        with self.assertRaises(AssertionError):
            subject.compare(extra, self.recorded)
        with self.assertRaises(AssertionError):
            subject.require_digest('0' * 64, 'control')
