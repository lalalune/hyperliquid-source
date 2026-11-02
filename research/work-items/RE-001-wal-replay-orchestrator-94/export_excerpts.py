"""Regenerate the verbatim disassembly excerpts for this work item.

Run from the repository root:
  python3 research/work-items/RE-001-wal-replay-orchestrator-94/export_excerpts.py

The binary path must stay relative (an absolute path changes objdump's
header line and breaks the byte-identical regeneration check).
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-orchestrator-94"
BIN = "work/hl-node-94.bin"

RANGES = {
    "window.txt": (0x520E1B0, 0x520E7E3),
    "cleanup.txt": (0x520E12E, 0x520E1A1),
    "known-18.txt": (0x5208E00, 0x5208E09),
}

# (call site, context bytes before, bytes after) for caller-site samples.
CALLER_SITES = [
    (0x502DFC9, 48, 16),
    (0x520E8DC, 48, 16),
]


def dump(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout


def main():
    for name, (start, end) in RANGES.items():
        (PACKET / name).write_text(dump(start, end))
    parts = []
    for site, before, after in CALLER_SITES:
        parts.append(f"# call site {hex(site)}\n")
        parts.append(dump(site - before, site + after))
    (PACKET / "caller-sites.txt").write_text("".join(parts))
    print("excerpts regenerated")


if __name__ == "__main__":
    main()
