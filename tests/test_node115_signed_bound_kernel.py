"""Target-grounded controls for the explicitly bounded interior arithmetic."""
import importlib.util
import hashlib
import json
import mmap
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-signed-bound-kernel-115'
sys.path.insert(0, str(PACKET))
spec = importlib.util.spec_from_file_location('signed_bound_native115', PACKET / 'native.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)

class SignedBoundKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im = n.Image()
        if hashlib.sha256(cls.im.data).hexdigest() != n.SHA:
            cls.im.close()
            raise ValueError('wrong115target')
        cls.record = json.loads((PACKET / 'FREEZE.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.im.close()

    def test_frozen_original_streams(self):
        inputs, expected, seen = n.corpus(self.im)
        self.assertEqual(hashlib.sha256(inputs).hexdigest(), self.record['input_sha256'])
        self.assertEqual(hashlib.sha256(expected).hexdigest(), self.record['expected_sha256'])
        self.assertEqual(len(set(inputs.splitlines())), self.record['rows'])
        self.assertEqual(expected.splitlines().count(b'N'), self.record['diagnostic_rows'])
        self.assertEqual(sorted(seen), self.record['visited_addresses'])

    def test_original_cow_controls(self):
        for c in json.loads((PACKET / 'native-controls.json').read_text()):
            with self.subTest(name=c['name']):
                changed = n.Image()
                changed.data = mmap.mmap(changed.view.file.fileno(), 0, access=mmap.ACCESS_COPY)
                try:
                    offset = changed.view.offset(int(c['va'], 16))
                    self.assertEqual(bytes([changed.data[offset]]).hex(), c['original_byte'])
                    changed.data[offset] = int(c['changed_byte'], 16)
                    self.assertEqual(n.evaluate(self.im, c['input'])[0], c['original'])
                    self.assertEqual(n.evaluate(changed, c['input'])[0], c['changed'])
                    self.assertNotEqual(c['original'], c['changed'])
                finally:
                    changed.close()

    def test_decoder_lengths_and_full_selected_visitation(self):
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        selected = set()
        for start, end in n.RANGES:
            rows = list(cs.disasm(self.im.view.read(start, end-start), start))
            self.assertEqual(sum(x.size for x in rows), end-start)
            for instruction in rows:
                actual = self.im.fetch(instruction.address)
                self.assertEqual(actual.size, instruction.size)
                selected.add(instruction.address)
        self.assertEqual(selected, set(self.record['visited_addresses']))
        self.assertEqual(len(selected), 59)
        self.assertEqual(self.im.view.fde(n.START), (0x4483920, 0x4483baa))

    def test_immutable_footprint_and_frontiers(self):
        machine = n.Machine(self.im)
        for address, length in [(n.ROW-1, 1), (n.ROW+48, 1), (n.ROW+47, 2)]:
            with self.assertRaisesRegex(ValueError, 'footprint'):
                machine.load(address, length)
        for method in [machine.store, machine.spill]:
            with self.assertRaisesRegex(ValueError, 'write forbidden'):
                method()
        with self.assertRaisesRegex(ValueError, 'unclosed'):
            machine.call()
        for address in [n.END, n.DIAGNOSTIC, 0x4483a7a]:
            with self.assertRaisesRegex(ValueError, 'CFG escape'):
                self.im.fetch(address)
        for row in [[], [0]*5, [0]*7, [0]*5+[-1], [0]*5+[True]]:
            with self.assertRaisesRegex(ValueError, 'rawu64'):
                n.evaluate(self.im, row)

    def test_digest_guard_without_assertions(self):
        code = "import native; native.SHA='0'*64; native.verify()"
        result = subprocess.run([sys.executable, '-O', '-c', code], cwd=PACKET, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'wrong115target', result.stderr)

    def test_minimum_signed_guard_order(self):
        # Native-observed values; N is a boundary, not a native return status.
        self.assertEqual(n.evaluate(self.im, (0, 100, 200, 100, 100, 1 << 63))[0], 'N')
        self.assertEqual(n.evaluate(self.im, (1, 100, 200, 100, 100, 1 << 63))[0], 'C:200')
        self.assertEqual(n.evaluate(self.im, (0, 100, 200, 0, 0, 1 << 63))[0], 'C:200')

if __name__ == '__main__':
    unittest.main()
