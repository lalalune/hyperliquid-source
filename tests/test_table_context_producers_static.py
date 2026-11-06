import hashlib
import tempfile
import unittest
from pathlib import Path

from tools import table_context_producers_static as packet


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'
PACKET_DIR = (ROOT / 'research/work-items/'
              'RE-006-node115-table-context-producers')


class TableContextProducersPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()

    def test_generates_committed_packet_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet.generate(self.data, tmp)
            generated = {p.name: p.read_bytes()
                         for p in Path(tmp).iterdir()}
        committed = {p.name: p.read_bytes()
                     for p in PACKET_DIR.iterdir()
                     if p.name != 'README.md' and p.name != 'MANIFEST.sha256'}
        self.assertEqual(set(generated), set(committed))
        for name in generated:
            self.assertEqual(generated[name], committed[name], name)

    def test_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = packet.generate(self.data, tmp)
        counts = records['counts']
        self.assertEqual(counts['level0'], 6)
        self.assertEqual(counts['level1_sites'], 9)
        self.assertEqual(counts['intra_family_edges'], 3)
        self.assertEqual(counts['frontier_bodies'], 9)
        self.assertEqual(counts['level2_sites'], 23)
        self.assertEqual(counts['ctx_pointer_stores_0x450'], 14)
        self.assertEqual(counts['table_header_bulk_copy_touches'], 3)

    def test_frontier_forms_and_funnel(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = packet.generate(self.data, tmp)
        forms = records['frontier_forms']
        self.assertEqual(len(forms), 9)
        self.assertEqual(
            sorted(forms.values()),
            ['mem_rsi', 'mem_rsi', 'rdi', 'rdi', 'rdi', 'rdi',
             'rsi', 'rsi', 'rsi'])
        funnel = records['pq_funnel']
        # each P-body has exactly one caller: a 224-byte once-getter
        self.assertEqual(len(funnel['p_body_callers']), 3)
        for rec in funnel['p_body_callers'].values():
            self.assertIn(rec['caller'], (0x2774590, 0x56186c0, 0x56185e0))
        once_counts = {k: len(v) for k, v in funnel['once_callers'].items()}
        self.assertEqual(sorted(once_counts.values()), [1, 1, 2])
        self.assertEqual(len(funnel['p_installs']), 4)

    def test_no_scalar_header_store_and_store_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = packet.generate(self.data, tmp)
        self.assertEqual(records['table_header_store_offenders'], [])
        kinds = sorted(s['kind']
                       for s in records['ctx_pointer_stores_0x450'])
        self.assertEqual(
            kinds,
            ['call-return', 'call-return', 'field-load', 'field-load',
             'field-load', 'field-load', 'field-load', 'field-load',
             'field-load', 'immediate', 'register-forward',
             'register-forward', 'register-forward', 'register-forward'])

    def test_manifest(self):
        lines = (PACKET_DIR / 'MANIFEST.sha256').read_text().splitlines()
        seen = set()
        for line in lines:
            digest, name = line.split('  ', 1)
            seen.add(name)
            actual = hashlib.sha256(
                (PACKET_DIR / name).read_bytes()).hexdigest()
            self.assertEqual(digest, actual, name)
        on_disk = {p.name for p in PACKET_DIR.iterdir()}
        self.assertEqual(seen, on_disk - {'MANIFEST.sha256'})


if __name__ == '__main__':
    unittest.main()
