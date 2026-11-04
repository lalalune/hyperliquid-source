"""Reproduce the reference census for RE-001-per-group-materialize-115.

Scans the digest-verified node #115 work binary and reports, for each
window, every direct call site, every direct tail-jump site, every
whole-file stored qword equal to the window address, and every
R_X86_64_RELATIVE relocation carrying the window address as addend.

Usage (from the repository root):
    python3 research/work-items/RE-001-per-group-materialize-115/census.py

Writes callers.tsv next to this script (one row per direct call site)
and prints a JSON summary. The full disassembly pass takes on the
order of two minutes on this VM; that is expected.
"""

import json
import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    "main": 0x5F6A630,
    "factory": 0x5F54680,
}

CALL_RE = re.compile(r"^\s*([0-9a-f]+):\t.*\t(call|jmp)\s+([0-9a-f]+)")
RELA_RE = re.compile(
    r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)")


def main():
    data = BINARY.read_bytes()
    dis = subprocess.run(["objdump", "-d", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    calls = {name: [] for name in TARGETS}
    jmps = {name: [] for name in TARGETS}
    for line in dis.splitlines():
        match = CALL_RE.match(line)
        if not match:
            continue
        site = int(match.group(1), 16)
        target = int(match.group(3), 16)
        for name, want in TARGETS.items():
            if target == want:
                if match.group(2) == "call":
                    calls[name].append(site)
                else:
                    jmps[name].append(site)
    qwords = {}
    for name, want in TARGETS.items():
        needle = struct.pack("<Q", want)
        hits = []
        offset = 0
        while True:
            index = data.find(needle, offset)
            if index < 0:
                break
            hits.append(index)
            offset = index + 1
        qwords[name] = hits
    rela_out = subprocess.run(["readelf", "-r", str(BINARY)],
                              capture_output=True, text=True,
                              check=True).stdout
    relas = {name: [] for name in TARGETS}
    for line in rela_out.splitlines():
        match = RELA_RE.match(line)
        if match:
            addend = int(match.group(2), 16)
            for name, want in TARGETS.items():
                if addend == want:
                    relas[name].append(int(match.group(1), 16))
    rows = []
    for name in TARGETS:
        for site in sorted(calls[name]):
            rows.append((name, hex(site), "call"))
    (PACKET / "callers.tsv").write_text(
        "window\tsite\tkind\n"
        + "".join("%s\t%s\t%s\n" % row for row in rows))
    summary = {
        name: {
            "direct_calls": [hex(s) for s in sorted(calls[name])],
            "tail_jumps": [hex(s) for s in sorted(jmps[name])],
            "stored_qwords": [hex(o) for o in qwords[name]],
            "relative_addends": [hex(o) for o in relas[name]],
        }
        for name in TARGETS
    }
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    main()
