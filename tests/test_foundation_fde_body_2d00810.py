'''Tests for the RE-001 node #115 FDE body checker at 0x2d00810..0x2d009ef.'''
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER = os.path.join(ROOT, 'tools', 'foundation_fde_body_2d00810.py')
PACKET = os.path.join(ROOT, 'research', 'work-items', 'RE-001-node115-fde-body-2d00810')
EVIDENCE = os.path.join(PACKET, 'evidence.json')


class FdeBodyCheckerTest(unittest.TestCase):
    def run_checker(self, env=None):
        return subprocess.run(
            [sys.executable, '-B', CHECKER],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
        )

    def corrupt_and_run(self, mutate):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(EVIDENCE, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
            mutate(data)
            target = os.path.join(temp_dir, 'evidence.json')
            with open(target, 'w', encoding='utf-8') as handle:
                json.dump(data, handle)
            env = dict(os.environ)
            env['FDE_BODY_PACKET_DIR'] = temp_dir
            proc = self.run_checker(env=env)
        return proc

    def test_checker_passes_when_packet_present(self):
        if not os.path.isfile(EVIDENCE):
            self.skipTest('packet evidence not yet written')
        proc = self.run_checker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('ok: window 0x2d00810..0x2d009ef', proc.stdout)
        self.assertIn('ok: call edge 0x2d00849 -> 0x2a21c70', proc.stdout)

    def test_checker_rejects_corrupted_start_with_specific_diagnostic(self):
        if not os.path.isfile(EVIDENCE):
            self.skipTest('packet evidence not yet written')

        def mutate(data):
            data['window']['start'] = '0x2d00811'

        proc = self.corrupt_and_run(mutate)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('FAIL: evidence window start mismatch', proc.stderr)

    def test_checker_rejects_corrupted_call_displacement_decimal(self):
        if not os.path.isfile(EVIDENCE):
            self.skipTest('packet evidence not yet written')

        def mutate(data):
            data['call_edge']['displacement_decimal'] = -3009503

        proc = self.corrupt_and_run(mutate)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('FAIL: evidence call_edge displacement_decimal mismatch', proc.stderr)

    def test_checker_rejects_corrupted_call_target_va(self):
        if not os.path.isfile(EVIDENCE):
            self.skipTest('packet evidence not yet written')

        def mutate(data):
            data['call_edge']['target_va'] = '0x2cd2990'

        proc = self.corrupt_and_run(mutate)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('FAIL: evidence call_edge target_va mismatch', proc.stderr)

    def test_checker_rejects_corrupted_call_instruction_bytes(self):
        if not os.path.isfile(EVIDENCE):
            self.skipTest('packet evidence not yet written')

        def mutate(data):
            data['call_edge']['instruction_bytes'] = 'e8 22 14 d2 fe'

        proc = self.corrupt_and_run(mutate)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('FAIL: evidence call_edge instruction_bytes mismatch', proc.stderr)


if __name__ == '__main__':
    unittest.main()
