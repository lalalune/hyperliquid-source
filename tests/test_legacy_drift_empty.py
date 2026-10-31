import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIFT = ROOT / "tools" / "legacy" / "drift.py"


class LegacyDriftEmptyTests(unittest.TestCase):
    def test_zero_qualifying_literals_still_writes_report(self):
        # The tree's only literal is "short" (len 5 < default MIN_LEN 8), so no
        # literal qualifies: the summary percentages used to divide by n == 0
        # and the run died with ZeroDivisionError before writing OUT_JSON.
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "src"
            src.mkdir()
            (src / "a.rs").write_text('fn main() { let x = "short"; }\n', encoding="utf-8")
            bin_a, bin_b = td / "binA", td / "binB"
            bin_a.write_bytes(b"\x7fELF placeholder a")
            bin_b.write_bytes(b"\x7fELF placeholder b")
            out_json = td / "out.json"
            r = subprocess.run(
                [sys.executable, "-I", str(DRIFT), str(src), str(bin_a), str(bin_b), str(out_json)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("0 distinct literals", r.stdout)
            report = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(report, {"counts": {}, "per_crate": {}, "items": []})


if __name__ == "__main__":
    unittest.main()
