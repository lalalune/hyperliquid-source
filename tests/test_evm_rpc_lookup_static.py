"""RE-011 static evidence regeneration and operative corruption controls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-011-evm-rpc-lookup-94'


class EvmRpcLookupStatic(unittest.TestCase):
    def test_regeneration_and_proof_binding_controls(self):
        with tempfile.TemporaryDirectory(prefix='re011-static-check-') as tmp:
            output = Path(tmp) / 'result.json'
            command = [sys.executable, '-B']
            if sys.flags.optimize:
                command.append('-O')
            command += [str(PACKET / 'verify.py'), '--target',
                        str(ROOT / 'artifacts/node/94/hl-node'), '--output', str(output)]
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            result = json.loads(output.read_text())
            self.assertEqual(result['regenerated_files'], 8)
            self.assertEqual(result['control_count'], 27)
            self.assertEqual(result['fresh_native_control_count'], 16)
            self.assertEqual(len(result['layout_cases']), 6)
            self.assertFalse(result['captured_execution'])
            self.assertFalse(result['instruction_evaluation'])


if __name__ == '__main__':
    unittest.main()
