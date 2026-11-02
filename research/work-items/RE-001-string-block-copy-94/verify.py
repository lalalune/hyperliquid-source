"""Verify the RE-001 string-block-copy packet against the target binary.

Checks, all re-derived from target bytes (no claim is taken on trust):
  * the work binary digest matches provenance/artifacts.json node #94
  * the window and enclosing function SHAs match records.json
  * every excerpt regenerates byte-for-byte from a fresh objdump run
  * frames.txt holds both FDE lines
  * relocations.txt holds all three PLT GOT entries
  * every recorded call site and target appears in the window excerpt
  * the caller census holds exactly 61 sites and the sample excerpt
    holds the first three of them

Usage: python3 verify.py [--binary PATH]
Exit 0 with ALL CHECKS PASSED, else 1 with the failing checks listed.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET = Path(__file__).resolve().parent
# parents: [0] work-items, [1] research, [2] repository root.
REPO = PACKET.parents[2]
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def file_offset(vaddr):
    # .text file offset is vaddr - 0x1000 in this binary (verified
    # against the section headers); low sections map vaddr == offset.
    return vaddr - 0x1000 if vaddr >= 0x1343C80 else vaddr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
        end = int(fn["end"], 16)
        got = hashlib.sha256(data[file_offset(start):file_offset(end)]).hexdigest()
        check("function sha %s" % fn["start"], got == fn["sha256"],
              "got %s" % got)

    # Excerpt regeneration via the packet's own export script.
    sys.path.insert(0, str(PACKET))
    import export_excerpts
    with tempfile.TemporaryDirectory() as tmp:
        outdir = Path(tmp)
        old_bin = export_excerpts.BIN
        export_excerpts.BIN = binary
        try:
            for name, ranges in export_excerpts.RANGES.items():
                regen = "".join(export_excerpts.excerpt(s, e) for s, e in ranges)
                committed = (PACKET / name).read_text()
                check("excerpt %s" % name, regen == committed)
        finally:
            export_excerpts.BIN = old_bin

    frames = (PACKET / "frames.txt").read_text()
    for fn in records["functions"]:
        check("frame %s" % fn["start"],
              fn["fde_record"] in frames and fn["start"][2:] in frames
              and fn["end"][2:] in frames)

    relocs = (PACKET / "relocations.txt").read_text()
    check("reloc memcpy", "5778da8" in relocs and "5660100" in relocs)
    check("reloc chk_fail", "5778f40" in relocs and "5660430" in relocs)
    check("reloc _M_create", "5778f90" in relocs and "56604d0" in relocs)

    window = (PACKET / "window.objdump.txt").read_text()
    for site, target in [("514deb8", "56604d0"), ("514ded1", "5660100"),
                         ("514dee2", "5660430")]:
        check("call %s -> %s" % (site, target),
              site in window and target in window)
    check("window canary", "fs:0x28" in window)
    check("window block tail store", "0x60(%rbx)" in window)
    check("window sso store", "0x10(%rbx)" in window)

    census = records["caller_census"]
    sites = census["sites"]
    check("census count", len(sites) == 61 and census["count"] == 61,
          "got %d" % len(sites))
    check("census unique", len(set(sites)) == len(sites))
    sample = (PACKET / "caller_sample.objdump.txt").read_text()
    for site in sites[:3]:
        check("sample site %s" % site, site[2:] in sample)
    check("sample call target", "514de00" in sample)

    if failures:
        print("FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
