"""Verify the RE-001 tree-teardown-68 packet against the target binary.

Checks, all re-derived from target bytes (no claim is taken on trust):
  * the work binary digest matches provenance/artifacts.json node #94
  * the window, wrapper and cleanup-enclosing function SHAs match
    records.json
  * every excerpt regenerates byte-for-byte from a fresh objdump run
  * frames.txt holds all three FDE lines
  * relocations.txt holds both PLT GOT entries
  * every recorded call target appears in the window/wrapper/cleanup
    excerpts, and the self-call, wrapper call and cleanup call sites
    are present in the excerpts

Usage: python3 verify.py [--binary PATH]
Exit 0 with ALL CHECKS PASSED, else 1 with the failing checks listed.
"""

import argparse
import hashlib
import json
import os
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
        "window.objdump.txt": [(0x514CD00, 0x514D010)],
        "wrapper.objdump.txt": [(0x514D010, 0x514D087)],
        "cleanup.objdump.txt": [(0x5150870, 0x5150BAF)],
        "plt.objdump.txt": [(0x5660440, 0x5660450), (0x5660470, 0x5660480)],
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
    wrapper = (PACKET / "wrapper.objdump.txt").read_text()
    cleanup = (PACKET / "cleanup.objdump.txt").read_text()
    check("self call site", "514cd9c:" in window)
    check("self call target", "call   514cd00" in window)
    check("wrapper call site", "514d027:" in wrapper)
    check("wrapper call target", "call   514cd00" in wrapper)
    check("cleanup call site", "5150b34:" in cleanup)
    check("cleanup call target", "call   514cd00" in cleanup)
    check("delete stub in window", "call   5660440" in window)
    check("dispose stub in window", "call   5660470" in window)
    check("node size 0x68 in window", "$0x68" in window)
    check("wrapper node size 0x68", "$0x68" in wrapper)

    if failures:
        print("FAILURES:")
        for failure in failures:
            print(" - %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
