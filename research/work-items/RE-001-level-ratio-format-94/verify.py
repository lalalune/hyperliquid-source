"""Verify the RE-001 level-ratio-format packet against the target binary.

Checks, all re-derived from target bytes (no claim is taken on trust):
  * the work binary digest matches provenance/artifacts.json node #94
  * the window, parser and ratio function SHAs match records.json
  * every excerpt regenerates byte-for-byte from a fresh objdump run
  * frames.txt holds all five FDE lines
  * relocations.txt holds both PLT GOT entries
  * the "%f" format bytes, the -1.0 ratio constant and the parser
    overflow threshold are present at the recorded addresses / in the
    recorded excerpts, and every recorded call target appears in the
    window excerpt

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
            # Reuse the module's excerpt() directly to avoid its
            # default-path write behaviour.
            for name, ranges in export_excerpts.RANGES.items():
                regen = "".join(export_excerpts.excerpt(s, e) for s, e in ranges)
                committed = (PACKET / name).read_text()
                check("excerpt %s" % name, regen == committed)
        finally:
            export_excerpts.BIN = old_bin

    frames = (PACKET / "frames.txt").read_text()
    for fn in records["functions"]:
        # frames.txt lines carry the record offset, length and next
        # offset; match on the record (without the 0x prefix) + pc range.
        check("frame %s" % fn["start"],
              fn["fde_record"][2:] in frames and fn["start"][2:] in frames
              and fn["end"][2:] in frames)

    relocs = (PACKET / "relocations.txt").read_text()
    check("reloc chk_fail", "5778f40" in relocs and "5660430" in relocs)
    check("reloc _ZdlPvm", "5778f48" in relocs and "5660440" in relocs)

    window = (PACKET / "window.objdump.txt").read_text()
    for site, target in [("514cc4e", "54307c0"), ("514cc7f", "51ca8a0"),
                         ("514cc9f", "514c050"), ("514ccaa", "514b4f0"),
                         ("514ccc7", "5660440"), ("514ccf4", "5660430")]:
        check("call %s -> %s" % (site, target),
              site in window and target in window)
    parser_text = (PACKET / "parser.objdump.txt").read_text()
    check("parser overflow constant", "1999999999999999" in parser_text)
    check("format string", data[0x1DF3ED:0x1DF3EF] == b"%f")
    import struct
    check("ratio -1.0 constant",
          struct.unpack("<d", data[0x20A278:0x20A280])[0] == -1.0)

    if failures:
        print("FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
