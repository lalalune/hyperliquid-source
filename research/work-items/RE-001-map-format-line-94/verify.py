"""Verify the RE-001 map-format-line packet against the target binary.

Checks, all re-derived from target bytes (no claim is taken on trust):
  * the work binary digest matches provenance/artifacts.json node #94
  * the window, helper and caller-enclosing function SHAs match
    records.json
  * every excerpt regenerates byte-for-byte from a fresh objdump run
  * frames.txt holds all four FDE lines
  * relocations.txt holds all four PLT GOT entries
  * every recorded map::at call site, inline-search key block and
    caller site appears in the excerpts, and the format string and
    the 2^63 constant are present in the target bytes

Usage: python3 verify.py [--binary PATH]
Exit 0 with ALL CHECKS PASSED, else 1 with the failing checks listed.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
# parents: [0] work-items, [1] research, [2] repository root.
REPO = PACKET.parents[2]
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def file_offset(vaddr):
    # .text file offset is vaddr - 0x1000 in this binary (verified
    # against the section headers); low sections map vaddr == offset.
    return vaddr - 0x1000 if vaddr >= 0x1343C80 else vaddr


def excerpt(start, stop, binary):
    result = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(stop), str(binary)],
        capture_output=True, text=True, check=True,
    )
    lines = [line for line in result.stdout.splitlines()
             if line.strip() and (line.startswith(" ") or line[0].isdigit())]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
    args = parser.parse_args()
    binary = Path(args.binary) if args.binary else Path(
        os.environ.get("HL_NODE94_BIN", REPO / "work" / "hl-node-94.bin"))
    failures = []

    def check(name, ok, detail=""):
        if not ok:
            failures.append("%s %s" % (name, detail))
        return ok

    if not binary.exists():
        print("missing binary: %s" % binary, file=sys.stderr)
        return 1
    data = binary.read_bytes()
    check("target digest", hashlib.sha256(data).hexdigest() == TARGET_SHA)

    records = json.loads((PACKET / "records.json").read_text())
    check("records target", records["target"]["sha256"] == TARGET_SHA)
    for fn in records["functions"]:
        start = int(fn["start"], 16)
        blob = data[file_offset(start):file_offset(start) + fn["size"]]
        check("function sha %s" % fn["name"],
              hashlib.sha256(blob).hexdigest() == fn["sha256"],
              fn["start"])

    ranges = {
        "window.objdump.txt": [(0x514D0C0, 0x514D770)],
        "helper_int.objdump.txt": [(0x5430310, 0x5430561)],
        "helper_size.objdump.txt": [(0x5430570, 0x5430766)],
        "callers.objdump.txt": [(0x51560B0, 0x5157A19)],
        "plt.objdump.txt": [(0x56605F0, 0x5660600), (0x5660710, 0x5660720),
                            (0x5660470, 0x5660480), (0x5660430, 0x5660440)],
    }
    for name, parts in ranges.items():
        regenerated = "".join(excerpt(s, e, binary) for s, e in parts)
        check("excerpt %s" % name,
              (PACKET / name).read_text() == regenerated)

    frames = (PACKET / "frames.txt").read_text()
    for fn in records["functions"]:
        check("frame %s" % fn["start"],
              fn["fde_record"].removeprefix("0x") in frames)
    relocations = (PACKET / "relocations.txt").read_text()
    for plt in records["plt"]:
        check("relocation %s" % plt["name"],
              plt["got"].removeprefix("0x") in relocations
              and plt["name"] in relocations)

    window = (PACKET / "window.objdump.txt").read_text()
    callers = (PACKET / "callers.objdump.txt").read_text()
    for call in records["direct_map_at_calls"]:
        check("map_at site %s" % call["site"],
              ("%s:" % call["site"].removeprefix("0x")) in window
              and "call   514b490" in window)
    for search in records["inline_searches"]:
        check("inline search key %s" % search["key"],
              ("%s:" % search["loop"].removeprefix("0x")) in window)
    for caller in records["callers"]:
        check("caller site %s" % caller["site"],
              ("%s:" % caller["site"].removeprefix("0x")) in callers
              and "call   514d0c0" in callers)
    check("snprintf call", "call   56605f0" in window)
    check("throw call", "call   5660710" in window)
    check("dispose call", "call   5660470" in window)
    check("format string in bytes",
          records["format"]["string"].encode() in data)
    const = struct.pack("<d", records["key3_uint_conversion"]["constant"])
    check("2^63 constant in bytes",
          data[0x20A7F0:0x20A7F8] == const)
    check("map::at string in bytes", b"map::at\x00" in data)

    if failures:
        print("FAILURES:")
        for failure in failures:
            print(" - %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
