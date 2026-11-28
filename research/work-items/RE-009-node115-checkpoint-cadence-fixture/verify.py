"""Reproduce the landed selected checkpoint cadence witnesses."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
for packet in ("RE-009-node115-checkpoint-root-cadence", "RE-009-node115-json-root-cadence"):
    subprocess.run(
        [sys.executable, "-B", str(ROOT / "research/work-items" / packet / "verify.py")],
        cwd=ROOT,
        check=True,
    )
