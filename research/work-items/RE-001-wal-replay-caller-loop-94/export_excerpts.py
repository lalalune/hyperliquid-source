"""Regenerate the verbatim disassembly excerpts for the RE-001 WAL replay
caller-loop work item from the digest-verified binary.

Run from the repository root so objdump prints the repo-relative binary
path (an absolute path changes the header line and breaks regeneration
checks, as caught in earlier cycles).
"""
import subprocess
import sys
from pathlib import Path

BIN = "work/hl-node-94.bin"
OUT = Path("research/work-items/RE-001-wal-replay-caller-loop-94")


def dump(start, stop, dest):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={start}",
         f"--stop-address={stop}", BIN],
        check=True, capture_output=True, text=True).stdout
    (OUT / dest).write_text(text)
    return text


def frames():
    text = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        check=True, capture_output=True, text=True).stdout
    lines = text.splitlines()
    block = []
    for i, line in enumerate(lines):
        if "pc=000000000520d3a0..000000000520e12e" in line:
            block.append(line)
            j = i + 1
            while j < len(lines) and lines[j].strip() and \
                    "FDE " not in lines[j] and "CIE " not in lines[j]:
                block.append(lines[j])
                j += 1
            break
    import re
    targets = {"0x520d3a0", "0x520a830", "0x520a990", "0x529f350",
               "0x520c120", "0x529ca20", "0x529d060", "0x542efe0",
               "0x5209430", "0x52092a0", "0x52091d0"}
    block.append("")
    block.append("# Direct-callee FDE headers (pc ranges only, census):")
    for line in lines:
        m = re.search(r"FDE .* pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)", line)
        if m and ("0x" + m.group(1)) in targets:
            block.append(line.strip())
    (OUT / "frames.txt").write_text("\n".join(block) + "\n")


def main():
    dump("0x520d3a0", "0x520e12e", "window.txt")
    dump("0x520d31e", "0x520d3a0", "cleanup.txt")
    parts = []
    for start, stop in [("0x520e1f0", "0x520e260"),
                        ("0x520e4c0", "0x520e520"),
                        ("0x520f5e0", "0x520f640")]:
        parts.append(subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", BIN],
            check=True, capture_output=True, text=True).stdout)
    (OUT / "caller-site.txt").write_text("".join(parts))
    frames()
    print("excerpts regenerated")


if __name__ == "__main__":
    sys.exit(main())
