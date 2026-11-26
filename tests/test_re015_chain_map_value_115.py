import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'chain_map_value', ROOT / 'tools/re015_chain_map_value_115.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestChainMapValue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = module.TARGET.read_bytes()
        cls.report = module.extract(cls.data)

    def test_key_gate_input_and_tag_mapping(self):
        r = self.report
        self.assertEqual(r['map_entry']['key'], 'hyperliquidChain')
        self.assertEqual(r['map_entry']['value_source']['byte_offset'], 0x30)
        self.assertEqual([x['wire_name'] for x in r['map_entry']['tag_values']],
                         ['Local', 'Sandbox', 'Testnet', 'Mainnet'])
        self.assertEqual(r['key_prefix_gate']['writes_key_prefix_if_byte_equals'], 1)
        self.assertTrue(r['key_prefix_gate']['both_paths_reach_serializer_call'])
        self.assertEqual(r['key_prefix_gate']['unequal_target'], 0x24062c1)
        self.assertEqual([e['target'] for e in r['key_path_edges']],
                         [0x24062c1, 0x2406440, 0x240646d])
        paths = r['capacity_fallback_paths']
        self.assertEqual(len(paths), 2)
        self.assertEqual([p['call_target'] for p in paths], [0x231e050, 0x231e050])
        self.assertEqual([p['rejoin_target'] for p in paths], [0x2406292, 0x24062ae])
        self.assertTrue(all(p['save_rsi_bytes'] == '4989f5' and
                            p['restore_rsi_bytes'] == '4c89ee' for p in paths))
        self.assertEqual(r['caller']['fde'], {'start': 0x2406120, 'end': 0x24064e4})

    def test_rejects_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, 'target digest mismatch'):
            module.extract(b'not the target')

    def test_rejects_changed_source_pointer_instruction(self):
        changed = bytearray(self.data)
        changed_va = 0x2406277
        changed[changed_va - 0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction bytes changed'):
            module.extract(bytes(changed), authenticate=False)


if __name__ == '__main__':
    unittest.main()
