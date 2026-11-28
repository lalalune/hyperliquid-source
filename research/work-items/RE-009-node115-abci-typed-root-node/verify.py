"""Recheck #115 root selection and hash preimage witnesses."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
subprocess.run(
    [sys.executable, "-B", "tools/abci_hash_tree_encoding_115.py", "--check"],
    cwd=ROOT,
    check=True,
)
print("PASS: #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
