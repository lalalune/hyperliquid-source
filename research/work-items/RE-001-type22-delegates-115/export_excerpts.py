#!/usr/bin/env python3
"""Export whole-function objdump excerpts for RE-001 type22-delegates-115.

Reads the pinned node #115 binary and emits one verbatim objdump file per
pinned function. Re-run to regenerate; verify.py diffs the output
byte-for-byte against a fresh objdump run.
"""
import subprocess
import sys
from pathlib import Path

BIN = Path(__file__).resolve().parents[3] / "artifacts" / "node" / "115" / "hl-node"
OUT = Path(__file__).resolve().parent

# name -> (start, end) vaddrs; end is exclusive (FDE end)
FUNCTIONS = {
    "fn-609a740-type22-delegate.objdump.txt": (0x609A740, 0x609B6F3),
    "fn-60971c0-serializer-helper.objdump.txt": (0x60971C0, 0x609755B),
    "fn-609de80-slot12-nested-serializer.objdump.txt": (0x609DE80, 0x609E29E),
    "fn-5d32a30-getid.objdump.txt": (0x5D32A30, 0x5D32A51),
    "fn-61d1390-ends-with.objdump.txt": (0x61D1390, 0x61D13DB),
    "fn-61d13e0-string-compare.objdump.txt": (0x61D13E0, 0x61D1437),
    "fn-60986b0-slot10-configure-core.objdump.txt": (0x60986B0, 0x6098A9C),
}


def excerpt(name, start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(BIN)],
        capture_output=True, text=True, check=True,
    ).stdout
    # Preserve the imported display-path header; every instruction stays exact.
    retained = OUT / name
    if retained.exists():
        old_lines = retained.read_text().splitlines(keepends=True)
        new_lines = out.splitlines(keepends=True)
        for i, line in enumerate(new_lines):
            if line.endswith(":     file format elf64-x86-64\n"):
                headers = [old for old in old_lines
                           if old.endswith(":     file format elf64-x86-64\n")]
                if len(headers) != 1:
                    raise ValueError("expected one retained ELF display header")
                new_lines[i] = headers[0]
                break
        out = "".join(new_lines)
    return out


def main() -> int:
    for name, (start, end) in FUNCTIONS.items():
        out = excerpt(name, start, end)
        (OUT / name).write_text(out)
        print(f"{name}: {start:#x}..{end:#x} ({len(out.stdout.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
