"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root:
  python3 research/work-items/RE-001-wal-record-scan-94/export_excerpts.py
The binary path is repo-relative, as in earlier work items: objdump
spells the header from the path it is given, so running from anywhere
else changes the excerpt text.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-record-scan-94"
EXCERPTS = [
    ("window.txt", "0x51628f0", "0x5162ec2"),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        (PACKET / name).write_text(out)
        print(f"wrote {name} ({len(out.splitlines())} lines)")


if __name__ == "__main__":
    main()
