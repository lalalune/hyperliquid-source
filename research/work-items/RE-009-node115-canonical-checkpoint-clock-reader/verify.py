"""Check native witnesses for the canonical checkpoint clock projection."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


def main():
    packets = ROOT / "research/work-items"
    for family in (
        "RE-009-node115-json-time-format-items",
        "RE-009-node115-msgpack-clock-text-path",
        "RE-009-node115-clock-calendar-pack",
    ):
        subprocess.run(
            [sys.executable, "-B", str(packets / family / "verify.py")],
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    main()
