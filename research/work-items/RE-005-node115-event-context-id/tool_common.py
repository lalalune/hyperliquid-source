"""Shared output-directory guard for the three tools in this packet.

Every tool writes only into a directory that it creates itself. An existing
path, or any path inside this packet or inside the crate, is refused so a
tool can never overwrite committed evidence or the inputs it reads.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CRATE = ROOT / "src" / "node115-event-context-id"
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def fresh_outdir(text):
    """Create and return a new output directory, or exit 2 with a reason."""
    path = Path(text).absolute()
    resolved = path.resolve()
    for protected in (HERE, CRATE):
        if resolved == protected or protected in resolved.parents:
            sys.exit(f"refusing --outdir inside {protected.name}: {path}")
    if path.exists() or path.is_symlink():
        sys.exit(f"refusing --outdir that already exists: {path}")
    if not path.parent.is_dir():
        sys.exit(f"--outdir parent does not exist: {path.parent}")
    path.mkdir()
    return path
