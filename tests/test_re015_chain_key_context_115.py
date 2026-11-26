import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'chain_key_context', ROOT / 'tools/re015_chain_key_context_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestChainKeyContexts(unittest.TestCase):
    def test_all_direct_callers_have_both_literal_loads(self):
        report = module.extract(module.TARGET.read_bytes())
        self.assertEqual(report['total_direct_calls'], 52)
        self.assertEqual(report['counts_by_serializer'], {
            '0x2674b80': 17, '0x467f2d0': 17, '0x57c1de0': 18})
        for row in report['direct_callers']:
            self.assertEqual(set(row['literals']), {'signatureChainId', 'hyperliquidChain'})
            path = row['hyperliquid_chain_write_path']
            self.assertEqual(path['literal_load_site'], row['call_site'] - 25)
            self.assertEqual(path['marker_site'] + 49, row['call_site'])
            self.assertEqual(len(bytes.fromhex(path['bytes'])), 49)
            self.assertLessEqual(row['fde']['start'], path['capacity_branch_target'])
            self.assertLess(path['capacity_branch_target'], row['fde']['end'])
            for literal in row['literals'].values():
                self.assertEqual(len(bytes.fromhex(literal['load_store_opcode_bytes'])), 9)
                self.assertEqual(len(bytes.fromhex(literal['bytes'])), 16)
                self.assertLessEqual(row['fde']['start'], literal['load_and_store_site'])
                self.assertLess(literal['load_and_store_site'], row['fde']['end'])

    def test_rejects_wrong_target_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the pinned artifact')


if __name__ == '__main__':
    unittest.main()
