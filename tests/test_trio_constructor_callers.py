import csv
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import trio_constructor_callers as tcc

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-trio-constructor-callers-94'
GENERATED = ['call-sites.tsv', 'constructor-differences.tsv',
             'constructors.tsv', 'evidence.json', 'helper-sites.tsv']
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'


def read_tsv(name):
    with (PACKET / name).open(newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


class PacketTests(unittest.TestCase):
    def test_evidence_counts(self):
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(evidence['call_sites'], 12)
        self.assertEqual(evidence['helper_sites'], 9)
        self.assertEqual(len(evidence['constructors']), 3)
        self.assertEqual(evidence['pairwise_differing_bytes'],
                         {'AB': 32, 'AC': 22, 'BC': 32})
        self.assertEqual(evidence['pairwise_agreement'],
                         {'AB': '469/501', 'AC': '479/501', 'BC': '469/501'})

    def test_tsv_row_counts(self):
        self.assertEqual(len(read_tsv('constructors.tsv')), 3)
        self.assertEqual(len(read_tsv('call-sites.tsv')), 12)
        self.assertEqual(len(read_tsv('helper-sites.tsv')), 9)
        # 32 + 22 + 32 differing bytes, one row each
        self.assertEqual(len(read_tsv('constructor-differences.tsv')), 86)

    def test_tsv_counts_match_evidence(self):
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        for row in read_tsv('constructors.tsv'):
            rec = evidence['constructors'][row['id']]
            self.assertEqual(row['sha256'], rec['sha256'])
            self.assertEqual(int(row['size']), 501)
            self.assertEqual(row['thunk_sha256'], rec['thunk_sha256'])

    def test_call_sites_cover_six_functions_twice(self):
        rows = read_tsv('call-sites.tsv')
        from collections import Counter
        counts = Counter(r['caller_fde_start'] for r in rows)
        self.assertEqual(len(counts), 6)
        self.assertTrue(all(v == 2 for v in counts.values()))
        self.assertEqual(len({r['callee'] for r in rows}), 3)

    def test_diff_offsets_inside_address_instructions(self):
        rows = read_tsv('constructor-differences.tsv')
        spans = [(o, o + 7) for o, _, _ in tcc.DIFF_SITES]
        for row in rows:
            off = int(row['body_offset'])
            self.assertTrue(any(s <= off < e for s, e in spans),
                            f'diff offset {off} outside any address instruction')

    def test_recorded_digests_detect_one_byte_flip(self):
        data = bytearray(BINARY.read_bytes())
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        # flip a body byte that is neither a template pattern nor a diff site
        flip_at = tcc.va_to_off(0x4e6c8b0) + 10
        data[flip_at] ^= 0x01
        body = bytes(data[tcc.va_to_off(0x4e6c8b0):tcc.va_to_off(0x4e6caa5)])
        self.assertNotEqual(hashlib.sha256(body).hexdigest(),
                            evidence['constructors']['A']['sha256'])

    def test_flipped_diff_site_breaks_build(self):
        data = bytearray(BINARY.read_bytes())
        data[tcc.va_to_off(0x4e6c8b0) + 368 + 3] ^= 0x01
        with self.assertRaises(tcc.EvidenceError):
            tcc.build(bytes(data))

    def test_retargeted_call_breaks_build(self):
        data = bytearray(BINARY.read_bytes())
        off = tcc.va_to_off(0x4e6fdb7)
        data[off + 1:off + 5] = struct.pack('<i', 0)
        with self.assertRaises(tcc.EvidenceError):
            tcc.build(bytes(data))

    def test_digest_mismatch_rejected(self):
        with self.assertRaises(tcc.EvidenceError):
            tcc.check_digest(b'not the node binary')

    def test_regeneration_deterministic_and_matches_packet(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            tcc.main(['--out', d1])
            tcc.main(['--out', d2])
            for name in GENERATED:
                first = (Path(d1) / name).read_bytes()
                second = (Path(d2) / name).read_bytes()
                self.assertEqual(first, second, f'{name} not deterministic')
                self.assertEqual(first, (PACKET / name).read_bytes(),
                                 f'{name} differs from the packet')


if __name__ == '__main__':
    unittest.main()
