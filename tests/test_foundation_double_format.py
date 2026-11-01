#!/usr/bin/env python3
"""Tests for node #94 double formatter at 0x514c050 (RE-001).

Covers the model in tools/foundation_double_format.py, the packet
verifier, and corruption controls that must make the verifier fail.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKET = REPO_ROOT / 'research' / 'work-items' / 'RE-001-double-format-94'

sys.path.insert(0, str(REPO_ROOT))

from tools.foundation_double_format import build_string, format_double  # noqa: E402


class TestDoubleFormat(unittest.TestCase):
    def test_format_values(self):
        self.assertEqual(format_double(0.0), '0.000000')
        self.assertEqual(format_double(1.5), '1.500000')
        self.assertEqual(format_double(-2.25), '-2.250000')
        self.assertEqual(format_double(123456789.0), '123456789.000000')

    def test_sso_arm_and_boundary(self):
        small = build_string(1.0)
        self.assertEqual(small['storage'], 'sso')
        self.assertEqual(small['length'], 8)
        self.assertEqual(small['pointer'], 'own+0x10')
        # 15 bytes exactly stays SSO: "12345678.000000" is 15 chars.
        edge = build_string(12345678.0)
        self.assertEqual(edge['text'], '12345678.000000')
        self.assertEqual(edge['storage'], 'sso')

    def test_heap_arm_exact_fit(self):
        big = build_string(123456789.0)
        self.assertEqual(big['storage'], 'heap')
        self.assertEqual(big['length'], 16)
        self.assertEqual(big['union_slot'], 16)  # capacity recorded as length
        self.assertEqual(big['terminator_at'], 'pointer+length')

    def test_records_shape(self):
        records = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(records['format']['bytes'], '%f\\x00')
        self.assertEqual(records['function']['sha256'],
                         'de35d4d1ea71805561f47405245dbb89e6834a3b4bb7dc645355639481612c4e')
        self.assertEqual(len(records['callers']), 5)
        self.assertEqual(records['callers'][0]['site'], '0x514cc9f')
        self.assertEqual(records['got_slot']['address'], '0x5778378')
        # No per-instruction mnemonic list: semantic records only.
        self.assertNotIn('instructions', records)
        self.assertNotIn('mnemonics', records)

    def test_packet_verification(self):
        r = subprocess.run([sys.executable, str(PACKET / 'verify.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('ALL CHECKS PASSED', r.stdout)

    def test_excerpt_regeneration(self):
        r = subprocess.run([sys.executable, str(PACKET / 'export_excerpts.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, str(PACKET / 'verify.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('ALL CHECKS PASSED', r.stdout)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'packet'
            shutil.copytree(PACKET, copy)
            records = json.loads((copy / 'records.json').read_text())
            records['function']['sha256'] = '0' * 64
            (copy / 'records.json').write_text(json.dumps(records, indent=2))
            r = subprocess.run([sys.executable, str(copy / 'verify.py'),
                                '--packet-dir', str(copy)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            # A corrupted manifest entry must also fail verification.
            p2 = Path(tmp) / 'packet2'
            shutil.copytree(PACKET, p2)
            (p2 / 'MANIFEST.sha256').write_text('0' * 64 + '  window.objdump.txt\n')
            r = subprocess.run([sys.executable, str(p2 / 'verify.py'),
                                '--packet-dir', str(p2)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)


if __name__ == '__main__':
    unittest.main()
