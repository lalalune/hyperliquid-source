#!/usr/bin/env python3
"""Regenerate main.txt, cold.txt, decode.txt and frames.txt for the
node #115 table-footer magic packet.

  main.txt   -- FooterBuilder::Build  0x6168620..0x61686e4
  cold.txt   -- Footer::DecodeFrom cold part 0x61686e4..0x6168780
  decode.txt -- Footer::DecodeFrom    0x6168780..0x6169f65

Commands (run from the repository root with the pinned binary
materialized at work/hl-node-115.bin):
  objdump -d --start-address=0x6168620 --stop-address=0x61686e4 work/hl-node-115.bin
  objdump -d --start-address=0x61686e4 --stop-address=0x6168780 work/hl-node-115.bin
  objdump -d --start-address=0x6168780 --stop-address=0x6169f65 work/hl-node-115.bin
  readelf --debug-dump=frames-interp work/hl-node-115.bin
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent

BUILD_START, BUILD_END = 0x6168620, 0x61686E4
COLD_START, COLD_END = 0x61686E4, 0x6168780
DECODE_START, DECODE_END = 0x6168780, 0x6169F65
# Pinned routine FDEs plus every distinct caller FDE named by the
# census (refs.tsv, callers.tsv, decode_callers.tsv).
FDE_STARTS = (0x60E80A0, 0x611FB10, 0x6161440, 0x6168620, 0x61686E4,
              0x6168780, 0x616A070, 0x616D2B0, 0x618DCB0, 0x61A0DC0,
              0x61A4140)


def excerpt(start, end):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    # Normalize the objdump header to the bare binary name so the
    # committed excerpt carries no machine-specific path; verify.py
    # applies the same normalization before comparing.
    return text.replace(str(BIN), BIN.name)


def main():
    for name, start, end in (("main.txt", BUILD_START, BUILD_END),
                             ("cold.txt", COLD_START, COLD_END),
                             ("decode.txt", DECODE_START, DECODE_END)):
        text = excerpt(start, end)
        (HERE / name).write_text(text)
        print(f"wrote {name} ({len(text.splitlines())} lines)")
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for line in frames.splitlines():
        m = re.search(r"pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)", line)
        if m and "FDE cie=" in line and int(m.group(1), 16) in FDE_STARTS:
            lines.append(line)
    (HERE / "frames.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote frames.txt ({len(lines)} lines)")


if __name__ == "__main__":
    main()
