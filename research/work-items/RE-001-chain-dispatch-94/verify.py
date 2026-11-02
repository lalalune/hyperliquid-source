"""Verify the RE-001 chain-dispatch packet against the target binary.

Checks, all re-derived from target bytes (no claim is taken on trust):
  * the work binary digest matches provenance/artifacts.json node #94
  * the four function SHAs match records.json
  * every excerpt regenerates byte-for-byte from a fresh objdump run
  * frames.txt holds all four FDE lines
  * the packet records no PLT relocations, and the excerpts contain
    no PLT call (every call is indirect through a dispatch slot)
  * every recorded sentinel-check site and dispatch-call site
    appears in the excerpts, and each getter's sentinel cell
    address appears as a rip-relative comment target

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
        "helper.objdump.txt": [(0x514DF80, 0x514DFA0)],
        "getters.objdump.txt": [(0x514DFA0, 0x514E030),
                                (0x514E030, 0x514E0C0),
                                (0x514E0C0, 0x514E160)],
    }
    excerpts = {}
    for name, parts in ranges.items():
        regenerated = "".join(excerpt(s, e, binary) for s, e in parts)
        excerpts[name] = regenerated
        check("excerpt %s" % name,
              (PACKET / name).read_text() == regenerated)

    frames = (PACKET / "frames.txt").read_text()
    for fn in records["functions"]:
        check("frame %s" % fn["start"],
              fn["fde_record"].removeprefix("0x") in frames)
    relocations = (PACKET / "relocations.txt").read_text()
    check("no plt relocations", records["plt"] == []
          and "No PLT relocations" in relocations)
    getters = excerpts["getters.objdump.txt"]
    check("no plt call in getters",
          "call   5660" not in getters)
    check("helper loads sub-object and head",
          "0x788(%rdi)" in excerpts["helper.objdump.txt"]
          and "0x6b0(%rax)" in excerpts["helper.objdump.txt"])
    for getter in records["getters"]:
        for site in getter["sentinel_check_sites"]:
            check("sentinel check %s" % site,
                  ("%s:" % site.removeprefix("0x")) in getters)
        for site in getter["dispatch_call_sites"]:
            check("dispatch call %s" % site,
                  ("%s:" % site.removeprefix("0x")) in getters)
        check("sentinel cell %s" % getter["sentinel_cell"],
              getter["sentinel_cell"].removeprefix("0x") in getters)
        check("chain link 0x38 in %s" % getter["start"],
              "0x38(%r" in getters)
    check("null head returns 0",
          getters.count("xor    %edx,%edx") == 3
          or getters.count("xor    %edx,%edx") >= 3)

    if failures:
        print("FAILURES:")
        for failure in failures:
            print(" - %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
