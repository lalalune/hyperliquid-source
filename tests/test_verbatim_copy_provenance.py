import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import verbatim_copy_provenance as vcp

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-verbatim-copy-provenance-94'
GENERATED = ['evidence.json', 'verbatim-paths.tsv', 'vtable-routes.tsv',
             'slot-verdicts.tsv', 'segments.txt']
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
NODE_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REGION_DELTA = {'code': -0x1000, 'rodata': 0, 'got': -0x2000, 'data': -0x3000}


def read_tsv(name):
    with (PACKET / name).open(newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


def run_generator(out, seed, tz):
    env = {'PYTHONHASHSEED': seed, 'TZ': tz, 'PATH': '/usr/bin:/bin'}
    subprocess.run([sys.executable,
                    str(ROOT / 'tools' / 'verbatim_copy_provenance.py'),
                    '--out', str(out)], check=True, env=env, timeout=300)


def parse_segments():
    rows = []
    for line in (PACKET / 'segments.txt').read_text().splitlines():
        if line.startswith('#') or not line.strip():
            continue
        m = re.match(r'(\S+) 0x([0-9a-f]+)\.\.0x([0-9a-f]+) length=(\d+) '
                     r'sha256=([0-9a-f]{64}) kind=(\w+) region=(\w+)$', line)
        assert m, line
        rows.append(m.groups())
    return rows


class PacketTests(unittest.TestCase):
    def test_evidence_counts(self):
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(evidence['node'], 94)
        self.assertEqual(evidence['node_sha256'], NODE_SHA256)
        self.assertEqual(evidence['node_size'], 91774280)
        self.assertEqual(len(evidence['functions']), 6)
        self.assertEqual(len(evidence['decoders']), 2)
        self.assertEqual(len(evidence['jump_table']['entries']), 5)
        self.assertEqual(len(evidence['relocations']), 2)
        self.assertEqual(len(evidence['vtable_objects']), 2)
        counts = evidence['counts']
        self.assertEqual(counts['paths'], 6)
        self.assertEqual(counts['vtable_routes'], 5)
        self.assertEqual(counts['slot_rows'], 51)
        self.assertEqual(counts['segment_rows'], 17)
        self.assertEqual(counts['claim_segments'], 15)
        self.assertEqual(counts['anchor_segments'], 2)
        self.assertEqual(counts['claim_bytes'], 719)
        self.assertEqual(counts['anchor_bytes'], 20)
        self.assertEqual(counts['direct_unwritten_paths'], 4)
        self.assertEqual(counts['stale_bytes_per_direct_path'], 22)

    def test_tsv_row_counts(self):
        self.assertEqual(len(read_tsv('verbatim-paths.tsv')), 6)
        self.assertEqual(len(read_tsv('vtable-routes.tsv')), 5)
        self.assertEqual(len(read_tsv('slot-verdicts.tsv')), 51)

    def test_verdict_tally(self):
        rows = read_tsv('slot-verdicts.tsv')
        tally = Counter(r['verdict'] for r in rows)
        self.assertEqual(tally['decoder-written'], 15)
        self.assertEqual(tally['stale'], 8)
        self.assertEqual(tally['path-dependent'], 2)
        self.assertEqual(tally['callee-extent-unverified'], 18)
        self.assertEqual(tally['produced'], 7)
        self.assertEqual(tally['unresolved-indirect'], 1)

    def test_segments_format(self):
        rows = parse_segments()
        self.assertEqual(len(rows), 17)
        for name, s, e, length, digest, kind, region in rows:
            self.assertEqual(int(e, 16) - int(s, 16), int(length), name)
            self.assertIn(kind, ('claim', 'anchor'))
            self.assertIn(region, REGION_DELTA)

    def test_segment_digests(self):
        data = BINARY.read_bytes()
        for name, s, e, length, digest, kind, region in parse_segments():
            off = int(s, 16) + REGION_DELTA[region]
            raw = data[off:off + int(length)]
            self.assertEqual(len(raw), int(length), name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest, name)
        # Concrete anchor: trioA verbatim block opens with
        # mov ecx,[rsp+0x1] (8b 4c 24 01).
        off = 0x4E6FE04 - 0x1000
        self.assertEqual(data[off:off + 4], bytes.fromhex('8b4c2401'))

    def test_regeneration_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_a = Path(tmp) / 'a'
            out_b = Path(tmp) / 'b'
            run_generator(out_a, '1', 'UTC')
            run_generator(out_b, '42', 'Asia/Seoul')
            for name in GENERATED:
                a = (out_a / name).read_bytes()
                b = (out_b / name).read_bytes()
                self.assertEqual(a, b, name)
                self.assertEqual(a, (PACKET / name).read_bytes(), name)

    def test_tamper_digest_fails(self):
        rows = parse_segments()
        name, s, e, length, digest, kind, region = rows[0]
        data = BINARY.read_bytes()
        off = int(s, 16) + REGION_DELTA[region]
        raw = data[off:off + int(length)]
        bad = ('0' if digest[0] != '0' else '1') + digest[1:]
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), bad)

    def test_tamper_slot_fails(self):
        rows = read_tsv('slot-verdicts.tsv')
        rows[0]['verdict'] = 'produced'
        fresh = vcp.slot_rows()
        self.assertNotEqual(
            [tuple(r.values()) for r in rows],
            [(r[0], r[1], r[2], r[3], r[4]) for r in fresh])

    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                         NODE_SHA256)
        self.assertEqual(BINARY.stat().st_size, 91774280)


if __name__ == '__main__':
    unittest.main()
