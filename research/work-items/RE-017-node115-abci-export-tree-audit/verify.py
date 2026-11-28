"""Verify the native #115 JSON tree shape and MessagePack preimage witnesses."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
for script in ("abci_hashes_log_115.py", "abci_hashes_tree_json_115.py", "abci_hash_tree_encoding_115.py"):
    subprocess.run(
        [sys.executable, "-B", str(ROOT / "tools" / script), "--check"],
        cwd=ROOT,
        check=True,
    )
print("PASS: authenticated #115 image a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
