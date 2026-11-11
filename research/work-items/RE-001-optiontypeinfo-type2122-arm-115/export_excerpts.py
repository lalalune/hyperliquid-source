#!/usr/bin/env python3
"""Regenerate every whole-function objdump excerpt in this packet from
artifacts/node/115/hl-node, using the FDE ranges recorded in records.json.
The archived input filename label is retained for byte-identical excerpts.

Usage: python3 export_excerpts.py [out_dir]  (default: this script's dir)
Each file is the verbatim output of:
  objdump -d --start-address=<fde_start> --stop-address=<fde_end> work/hl-node-115.bin
run from the repository root, so the header line names the relative path.
Two excerpts (apply 0x60bedc0, serializer 0x60bb9a0) are re-shipped
byte-identical from PR #4311's packet (RE-001-verification-gate-115);
regenerating them here produces the identical bytes.
"""
import hashlib
import os
import subprocess
import sys

BIN = "artifacts/node/115/hl-node"
ARCHIVED_LABEL = "work/hl-node-115.bin"

# (file, fde_start, fde_end)
WINDOWS = [
    ("fn-60bedc0-apply.objdump.txt", 0x60BEDC0, 0x60BF5BC),
    ("fn-60bb9a0-serialize.objdump.txt", 0x60BB9A0, 0x60BBDEB),
    ("fn-60b9d70-config-copy.objdump.txt", 0x60B9D70, 0x60B9DFC),
    ("fn-6099e70-set-equals.objdump.txt", 0x6099E70, 0x609A1A9),
    ("fn-609ba30-set-no-equals-fwd.objdump.txt", 0x609BA30, 0x609BA76),
    ("fn-609b8a0-create-by-name.objdump.txt", 0x609B8A0, 0x609BA2A),
    ("fn-6096f40-scan-options.objdump.txt", 0x6096F40, 0x609710F),
    ("fn-609b700-apply-created.objdump.txt", 0x609B700, 0x609B869),
    ("fn-6097110-configure-slot9.objdump.txt", 0x6097110, 0x609714E),
    ("fn-5e33fb0-config-dtor.objdump.txt", 0x5E33FB0, 0x5E33FEA),
    ("fn-6083a90-type22-helper.objdump.txt", 0x6083A90, 0x6083C83),
    ("fn-60809e0-custom-parse.objdump.txt", 0x60809E0, 0x6080A71),
    ("fn-607d190-parse-manager.objdump.txt", 0x607D190, 0x607D1BD),
    ("fn-60956f0-empty-status.objdump.txt", 0x60956F0, 0x609570C),
    ("fn-609d980-get-option-name.objdump.txt", 0x609D980, 0x609DC18),
    ("fn-60c1190-map-parse.objdump.txt", 0x60C1190, 0x60C1887),
    ("fn-607ea10-factory-builder.objdump.txt", 0x607EA10, 0x607EB17),
]


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    # The repo root is fixed by this script's own location, not the output
    # directory (verify.py regenerates into a temp dir).
    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "..", ".."))
    for name, start, end in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start, "--stop-address=%#x" % end, BIN],
            cwd=repo, capture_output=True, text=True, check=True).stdout
        out = out.replace("\n" + BIN + ":     file format",
                          "\n" + ARCHIVED_LABEL + ":     file format", 1)
        path = os.path.join(out_dir, name)
        with open(path, "w") as f:
            f.write(out)
        digest = hashlib.sha256(out.encode()).hexdigest()
        print("%s  %s  %d bytes" % (digest[:12], name, len(out)))
    print("wrote %d excerpts" % len(WINDOWS))


if __name__ == "__main__":
    main()
