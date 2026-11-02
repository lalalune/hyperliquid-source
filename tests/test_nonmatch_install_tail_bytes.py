import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import nonmatch_install_tail_bytes as nmtb

PACKET = ROOT / 'research' / 'work-items' / 'RE-004-nonmatch-install-tail-bytes-94'
GENERATED = ['evidence.json', 'installs.tsv', 'tail-writers.tsv',
             'segments.txt']
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'


def read_tsv(name):
    with (PACKET / name).open(newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


def run_generator(out):
    env = {'PYTHONHASHSEED': '1', 'TZ': 'UTC', 'PATH': '/usr/bin:/bin'}
    subprocess.run([sys.executable, str(ROOT / 'tools' / 'nonmatch_install_tail_bytes.py'),
                    '--out', str(out)], check=True, env=env, timeout=300)


class PacketTests(unittest.TestCase):
    def test_evidence_counts(self):
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(evidence['callers'], 5)
        self.assertEqual(evidence['tails_unwritten'], 4)
        self.assertEqual(evidence['tails_path_dependent'], 1)
        self.assertEqual(evidence['installs'], 5)
        self.assertEqual(evidence['writer_rows'], 16)
        self.assertEqual(evidence['segment_rows'], 10)
        self.assertEqual(len(evidence['decoders']), 2)
        self.assertEqual(len(evidence['constructors']), 3)
        self.assertEqual(len(evidence['destructors']), 3)
        self.assertEqual(evidence['nonmatch_len'], 64)
        self.assertEqual(evidence['match_len'], 56)
        self.assertEqual(evidence['node_sha256'],
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')

    def test_tsv_row_counts(self):
        self.assertEqual(len(read_tsv('installs.tsv')), 5)
        self.assertEqual(len(read_tsv('tail-writers.tsv')), 16)

    def test_installs_consistency(self):
        for row in read_tsv('installs.tsv'):
            self.assertEqual(int(row['nonmatch_len']), 64)
            self.assertEqual(int(row['match_len']), 56)
            self.assertEqual(int(row['tail_end_rsp'], 16)
                             - int(row['tail_start_rsp'], 16), 8)
            self.assertEqual(int(row['nonmatch_src_end_rsp'], 16)
                             - int(row['nonmatch_src_start_rsp'], 16), 64)
            self.assertEqual(int(row['caller_end'], 16)
                             - int(row['caller_start'], 16),
                             int(row['caller_len']))
        verdicts = [r['tail_verdict'] for r in read_tsv('installs.tsv')]
        self.assertEqual(verdicts.count('unwritten'), 4)
        self.assertEqual(verdicts.count('path-dependent'), 1)

    def test_segments_format(self):
        lines = (PACKET / 'segments.txt').read_text().splitlines()
        rows = [ln.split() for ln in lines if not ln.startswith('#')]
        self.assertEqual(len(rows), 10)
        for caller, va, hx, start, end, length in rows:
            self.assertEqual(int(end, 16) - int(start, 16), int(length))
            self.assertEqual(int(length), 8)
            self.assertIn(len(hx) // 2, (5, 8))

    def test_writer_rows_cover_callers(self):
        callers = {r['caller'] for r in read_tsv('tail-writers.tsv')}
        self.assertEqual(callers, {'trioA', 'double-gate', 'trioB',
                                   'gate-like', 'trioC'})
        reaches = [r for r in read_tsv('tail-writers.tsv')
                   if r['reaches_tail'] not in ('no',)]
        self.assertEqual(len(reaches), 1)
        self.assertEqual(reaches[0]['caller'], 'trioC')

    def test_regeneration_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a', Path(tmp) / 'b'
            run_generator(a)
            run_generator(b)
            for name in GENERATED:
                self.assertEqual((a / name).read_bytes(),
                                 (b / name).read_bytes())
                self.assertEqual((PACKET / name).read_bytes(),
                                 (a / name).read_bytes())

    def test_tamper_tail_read_fails(self):
        data = bytearray(BINARY.read_bytes())
        off = 0x1342c80 + (0x4e6fde7 - 0x1343c80)
        data[off] ^= 0xFF
        with self.assertRaises(SystemExit):
            nmtb.verify(bytes(data))

    def test_tamper_ctor_tag_fails(self):
        data = bytearray(BINARY.read_bytes())
        off = 0x1342c80 + (0x4e6ca20 - 0x1343c80)
        data[off + 3] ^= 0xFF
        with self.assertRaises(SystemExit):
            nmtb.verify(bytes(data))

    def test_tamper_digest_fails(self):
        data = bytearray(BINARY.read_bytes())
        data[0] ^= 0xFF
        with self.assertRaises(SystemExit):
            nmtb.verify(bytes(data))

    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                         '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')


if __name__ == '__main__':
    unittest.main()
