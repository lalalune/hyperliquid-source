import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / 'research/work-items/RE-001-node115-branch-call-edges-3aa8840/verify.py'
SPEC = importlib.util.spec_from_file_location('branch_call_edges_3aa8840', VERIFY)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class BranchCallEdgesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = CHECK.verify()

    def test_calls_land_on_target_fde_entries(self):
        source = self.evidence['source_fde']
        self.assertEqual((source['start'], source['end']), ('0x3aa8840', '0x3aa887f'))
        calls = self.evidence['observed_dispatch']['direct_calls']
        self.assertEqual([(row['site'], row['target']) for row in calls],
                         [('0x3aa885d', '0x3b62630'), ('0x3aa8875', '0x3b676e0')])
        for row in calls:
            self.assertEqual(row['target'], row['target_fde']['start'])
            self.assertGreater(row['target_fde']['length'], 0)

    def test_conditional_branches_rederive_from_relative_bytes(self):
        for site, encoding, target in (
                (0x3aa8846, '7503', 0x3aa884b),
                (0x3aa884f, '740c', 0x3aa885d),
                (0x3aa8854, '7513', 0x3aa8869),
                (0x3aa885b, '750c', 0x3aa8869)):
            self.assertEqual(CHECK.relative_target(site, bytes.fromhex(encoding),
                                                   int(encoding[:2], 16)), target)

    def test_error_context_reference_is_in_data_rel_ro(self):
        args = self.evidence['observed_dispatch']['error_helper_arguments']
        self.assertEqual(args['rsi']['addressing'], 'current RSP + 7')
        self.assertEqual(args['rdx']['target'], '0x646fb38')
        self.assertEqual(len(bytes.fromhex(args['rdx']['window_hex'])), 32)
        self.assertEqual(len(args['rdx']['window_sha256']), 64)

    def test_packet_rejects_changed_edge(self):
        with tempfile.TemporaryDirectory() as temp:
            packet = Path(temp)
            for name in ('README.md', 'edges.json', 'window.txt', 'tools.json', 'MANIFEST.sha256'):
                (packet / name).write_bytes((CHECK.PACKET / name).read_bytes())
            evidence = json.loads((packet / 'edges.json').read_text(encoding='utf-8'))
            evidence['observed_dispatch']['direct_calls'][0]['target'] = '0x3b62631'
            (packet / 'edges.json').write_text(json.dumps(evidence), encoding='utf-8')
            with self.assertRaisesRegex(AssertionError, 'saved edge evidence'):
                CHECK.verify(packet)


if __name__ == '__main__':
    unittest.main()
