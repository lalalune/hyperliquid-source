"""Static evidence and Rust model for the node #115 clearinghouse notional ratio."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-007-node115-clearinghouse-ntl-ratio'
spec = importlib.util.spec_from_file_location('node115_ntl_ratio_packet', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class StaticPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()

    def test_original_operand_and_branch_anchors(self):
        expected = json.loads((PACKET / 'records.json').read_text())['facts']
        self.assertEqual(collector.anchors(self.data), expected)

    def test_divisor_identity_holds_for_every_u64(self):
        collector.prove_divisor()
        self.assertEqual(collector.MAGIC, 0x346dc5d63886594b)

    def test_every_claim_anchor_rejects_private_byte_corruption(self):
        mutated = bytearray(self.data)
        for address, raw in collector.CONFIG['anchors'].items():
            with self.subTest(anchor=address):
                offset, _ = collector.read(self.data, int(address, 16), len(bytes.fromhex(raw)))
                mutated[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'changed arithmetic anchor'):
                    collector.anchors(mutated)
                mutated[offset] ^= 1

    def test_wrong_identity_fails_before_native_tools_and_output(self):
        mutated = bytearray(self.data)
        mutated[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                collector.collect(mutated, output)
            self.assertFalse(output.exists())

    def test_complete_native_exports_regenerate_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            actual = collector.collect(self.data, output)
            self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
            names = ['frames.txt', 'relocations.txt', 'records.json',
                     *[path.name for path in PACKET.glob('*.objdump.txt')]]
            for name in names:
                with self.subTest(file=name):
                    self.assertEqual((output / name).read_bytes(), (PACKET / name).read_bytes())

    def test_rust_model_matches_its_locked_cases(self):
        cargo = subprocess.run(
            ['cargo', 'test', '--locked', '--offline', '--manifest-path',
             'src/node115-clearinghouse-ntl-ratio/Cargo.toml'],
            cwd=ROOT, check=False, text=True, capture_output=True)
        if cargo.returncode != 0:
            self.fail(cargo.stdout + cargo.stderr)


if __name__ == '__main__':
    unittest.main()
