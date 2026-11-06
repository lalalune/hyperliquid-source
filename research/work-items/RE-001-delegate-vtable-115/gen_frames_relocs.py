#!/usr/bin/env python3
"""Generate frames.txt and relocations.txt for RE-001-delegate-vtable-115.

frames.txt: the raw `readelf --debug-dump=frames-interp` FDE lines
for every excerpt window in export_excerpts.py (plus the FDE lines
for the five new windows' neighbours are NOT included; only the
windows' own FDEs).

relocations.txt: the `readelf -r -W` rows for every relocation that
pins the delegate vtable family:
  * for each of the 19 family tables: the typeinfo-pointer reloc at
    base-0x8, the offset-to-top reloc absence is implicit (no row
    at base-0x10), and every slot reloc at base..base+nslots*8;
  * the typeinfo-object relocs (type 1 at T, type 8 at T+0x08 and
    T+0x10) for each family's typeinfo;
  * the five GOT landmark rows (0x64eceb8, 0x64eceb0, 0x64ecf50,
    0x64ecf80, 0x64ed8b0).

Run from the repository root:
    python3 research/work-items/RE-001-delegate-vtable-115/gen_frames_relocs.py
"""

import json
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

sys.dont_write_bytecode = True
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402

GOT_LANDMARKS = [0x64ECEB8, 0x64ECEB0, 0x64ECF50, 0x64ECF80, 0x64ED8B0]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout


def main():
    records = json.load(open(PACKET / "records.json"))

    # --- frames.txt -----------------------------------------------------
    frames = run(["readelf", "--debug-dump=frames-interp", str(BINARY)])
    wanted = set()
    for _name, start, stop in WINDOWS:
        wanted.add("pc=%016x..%016x" % (start, stop))
    lines = [ln for ln in frames.splitlines()
             if ln.strip().endswith(tuple(wanted)) or
             any(w in ln for w in wanted)]
    # Keep only genuine FDE lines (the pc= marker is unique to them).
    lines = [ln for ln in lines if " FDE " in ln and "pc=" in ln]
    missing = [w for w in wanted if not any(w in ln for ln in lines)]
    if missing:
        print("missing FDEs: %s" % missing, file=sys.stderr)
        return 1
    (PACKET / "frames.txt").write_text("\n".join(lines) + "\n")
    print("wrote frames.txt (%d FDE lines)" % len(lines))

    # --- relocations.txt -------------------------------------------------
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    wanted_offsets = set(GOT_LANDMARKS)
    for v in records["vtables"]:
        base = int(v["vtable"], 16)
        wanted_offsets.add(base - 0x8)
        for off in v["slots"]:
            wanted_offsets.add(base + int(off, 16))
        # typeinfo-object rows for this table's typeinfo: find the
        # typeinfo address from the base-0x8 reloc's addend.
        for ln in dyn.splitlines():
            m = re.match(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+"
                         r"(\S+)\s+([0-9a-f]+)\s*(.*)$", ln)
            if m and int(m.group(1), 16) == base - 0x8:
                tinfo = int(m.group(4), 16)
                wanted_offsets.update(
                    (tinfo, tinfo + 0x08, tinfo + 0x10))
                break
    rows = []
    for ln in dyn.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+"
                     r"(\S+)\s+([0-9a-f]+)\s*(.*)$", ln)
        if m and int(m.group(1), 16) in wanted_offsets:
            rows.append(ln)
    (PACKET / "relocations.txt").write_text("\n".join(rows) + "\n")
    print("wrote relocations.txt (%d rows)" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
