"""Re-run the pinned static contracts used by the completed replay gate."""
from pathlib import Path
import subprocess
import sys

WORK_ITEMS = Path(__file__).resolve().parent.parent


def main():
    for name in (
        "RE-017-node115-replay-completed-payload",
        "RE-017-node115-replay-block-identity-gate",
        "RE-017-node115-replay-parent-projection",
    ):
        subprocess.run([sys.executable, "-B", str(WORK_ITEMS / name / "verify.py")], check=True)


if __name__ == "__main__":
    main()
