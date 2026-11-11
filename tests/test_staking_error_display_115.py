"""Digest-bound controls for the node #115 staking error display arms."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-staking-error-display'
CRATE = ROOT / 'src/node115-staking-error-text'
spec = importlib.util.spec_from_file_location('staking_error_display', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class StakingErrorDisplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()

    def test_pinned_interval_and_static_texts(self):
        with tempfile.TemporaryDirectory() as directory:
            record = collector.collect(self.data, Path(directory))
        self.assertEqual(record['dispatch']['arm_count'], 418)
        self.assertFalse(record['dispatch']['bounds_check_in_prologue'])
        self.assertEqual(record['dispatch']['direct_calls'], 0)
        self.assertEqual(len(record['callers']), 19)
        by_index = {arm['index']: arm for arm in record['selection']['arms']}
        self.assertEqual(set(by_index), {51, 159, 160, 184, 267, 268, 269, 270, 273, 278, 282, 306, 324, 325, 358})
        self.assertEqual(by_index[159]['immediate_f64'], 300.0)
        self.assertEqual(by_index[159]['literals'][1], ' seconds')
        self.assertEqual(by_index[160]['literals'], ['Jailed until '])
        self.assertNotIn('immediate', by_index[160])
        self.assertEqual(by_index[267]['text'], 'Insufficient balance to delegate')
        self.assertEqual(by_index[282]['text'], 'Insufficient stake')
        self.assertEqual(record['fde']['bytes'], 14879)

    def test_anchor_and_identity_corruption_rejected(self):
        mutated = bytearray(self.data)
        mutated[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                collector.collect(mutated, Path(directory) / 'absent')
        for address, message in ((collector.ENTRY, 'changed native anchor'),
                                 (collector.TABLE + 3, 'jump table length'),
                                 (collector.FLOAT_FMT, 'changed native anchor'),
                                 (0x457740, 'staking arm text mismatch')):
            mutated = bytearray(self.data)
            offset, _ = collector.read_va(mutated, collector.sections(mutated), address, 1)
            mutated[offset] ^= 1
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, message):
                    collector.collect(bytes(mutated), Path(directory), identity=False)

    def test_exports_regenerate(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.assertEqual(collector.collect(self.data, out), json.loads((PACKET / 'records.json').read_text()))
            for name in ('display.objdump.txt', 'records.json'):
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)
            versions = {name: subprocess.check_output([name, '--version'], text=True).splitlines()[0]
                        for name in ('objdump', 'readelf')}
            self.assertEqual(json.loads((out / 'tool-versions.json').read_text()), versions)

    def test_rust_crate_matches_static_contract(self):
        completed = subprocess.run(
            ['cargo', 'test', '--locked', '--offline', '--manifest-path',
             str(CRATE / 'Cargo.toml')],
            cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn('test result: ok', completed.stdout)


if __name__ == '__main__':
    unittest.main()
