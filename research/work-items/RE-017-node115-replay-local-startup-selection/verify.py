"""Re-run the two native #115 contracts joined by local replay selection."""
from pathlib import Path
import subprocess
import sys

work_items = Path(__file__).resolve().parent.parent
for item in ("RE-017-node115-local-replay-hardfork-rewrite",
             "RE-017-node115-completed-replay-block-gate"):
    subprocess.run([sys.executable, "-B", str(work_items / item / "verify.py")], check=True)
