#!/usr/bin/env python3
"""Export whole-function verbatim objdump excerpts for the
InternalIterator vtable tail windows.

Reads the window list (windows.txt, produced by census.py) and the FDE
table (frames.txt, the `objdump --dwarf=frames` output for the binary),
then emits one file per window under excerpts/, named
`0x<start>.objdump.txt`, containing the raw GNU objdump 2.42 output for
exactly the FDE range [start, end). No instruction is edited, reordered
or summarised: the excerpts are the verbatim disassembly the semantic
records in records.json are derived from.

Usage (from the repository root):
    python3 research/work-items/RE-001-iterator-vtable-tail-115/export_excerpts.py

The binary must be present at work/hl-node-115.bin.
"""
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
OBJDUMP = "objdump"

# Extra supporting windows that are not vtable slots but are referenced
# by the tail implementations: the shared NextAndGetResult default
# (slot [8]) and the ForwardIterator SetPinnedItersMgr fan-out helper
# that slot [17] tail-jumps to.
SUPPORTING = {
    0x5DF7CE0: "slot [8] NextAndGetResult default (base class)",
    0x5EDA1E0: "ForwardIterator::UpdateChildrenPinnedItersMgr (slot [17] target)",
}


def load_fdes(frames_path):
    fdes = {}
    pat = re.compile(
        r"^[0-9a-f]{8} [0-9a-f]{16} [0-9a-f]{8} FDE cie=[0-9a-f]+ "
        r"pc=([0-9a-f]+)\.\.([0-9a-f]+)")
    with open(frames_path) as f:
        for line in f:
            m = pat.match(line)
            if m:
                fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    return fdes


def main():
    windows = {}
    for line in open(HERE / "windows.txt"):
        addr = int(line.split("\t")[0], 16)
        uses = line.split("\t", 1)[1].strip()
        windows[addr] = uses
    for addr, note in SUPPORTING.items():
        windows.setdefault(addr, note)
    fdes = load_fdes(HERE / "frames.txt")
    missing = [a for a in windows if a not in fdes]
    if missing:
        raise SystemExit(
            "no FDE for: " + ", ".join(hex(a) for a in missing))
    out_dir = HERE / "excerpts"
    out_dir.mkdir(exist_ok=True)
    for addr in sorted(windows):
        end = fdes[addr]
        out = subprocess.run(
            [OBJDUMP, "-d", f"--start-address={addr:#x}",
             f"--stop-address={end:#x}", str(BIN)],
            capture_output=True, text=True, check=True).stdout
        # Keep only the instruction lines (drop the objdump header and
        # the symbol line); the file stays verbatim otherwise.
        lines = [l for l in out.splitlines()
                 if re.match(r"^\s*[0-9a-f]+:\t", l)]
        path = out_dir / f"0x{addr:x}.objdump.txt"
        path.write_text(
            f"# objdump -d --start-address=0x{addr:x} "
            f"--stop-address=0x{end:x} work/hl-node-115.bin\n"
            f"# window: {windows[addr]}\n"
            f"# FDE range: 0x{addr:x}..0x{end:x} ({end - addr} bytes)\n"
            + "\n".join(lines) + "\n")
        print(f"0x{addr:x}..0x{end:x} -> {path.name}")
    print(f"exported {len(windows)} excerpts")


if __name__ == "__main__":
    main()
