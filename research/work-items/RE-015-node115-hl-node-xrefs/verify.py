#!/usr/bin/env python3
"""Verify direct .text references to the five pinned `hl-node` occurrences."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
OUT = Path(__file__).resolve().parent / "records.json"
TOKEN = b"hl-node"
OCCURRENCES = (0x434A3E, 0x440F36, 0x605CCD, 0x60F0B2, 0x92A890)

# Direct resolved data targets and the exact instruction VAs that form/read them.
REFERENCES = {
    0x434A2D: (
        (0x2AE624E, 7), (0x2AE62E3, 7),
        (0x2CE02D6, 7), (0x2CE037B, 7),
    ),
    0x440F30: ((0x15A230B, 7),),
    0x605CCD: ((0x2AE4574, 7), (0x2AEB181, 7)),
    0x60F0B2: ((0x2CB6791, 7), (0x2CDE639, 7)),
    0x92A890: ((0x2AE42A4, 6), (0x2B7B66C, 6)),
    0x92A893: ((0x2AE429B, 6), (0x2B7B663, 6)),
}
DISASM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):.*?#\s*(?:0x)?([0-9a-fA-F]+)\s+<"
)


def vaddr_to_offset(va: int) -> int:
    # The executable PT_LOAD starts at file 0x1418300 and VA 0x1419300.
    return va - 0x1000


def analyze() -> dict:
    blob = TARGET.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise ValueError(f"wrong node115 target digest: {digest}")

    found = []
    pos = 0
    while True:
        pos = blob.find(TOKEN, pos)
        if pos < 0:
            break
        found.append(pos)
        pos += 1
    if tuple(found) != OCCURRENCES:
        raise ValueError(f"unexpected occurrence set: {[hex(x) for x in found]}")

    objdump = shutil.which("objdump")
    if not objdump:
        raise ValueError("GNU objdump is required on PATH")
    proc = subprocess.Popen(
        [objdump, "-d", "-w", "-j", ".text", str(TARGET)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    actual: dict[int, list[int]] = {target: [] for target in REFERENCES}
    assert proc.stdout is not None
    for line in proc.stdout:
        match = DISASM_LINE.match(line)
        if match:
            source, target = (int(value, 16) for value in match.groups())
            if target in actual:
                actual[target].append(source)
    proc.stdout.close()
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.stderr:
        proc.stderr.close()
    status = proc.wait()
    if status:
        raise RuntimeError(f"objdump failed ({status}): {stderr.strip()}")

    rows = []
    for target, sites in REFERENCES.items():
        wanted = [site for site, _ in sites]
        if actual[target] != wanted:
            raise ValueError(
                f"references to {target:#x}: got {[hex(x) for x in actual[target]]}, "
                f"expected {[hex(x) for x in wanted]}"
            )
        for site, size in sites:
            offset = vaddr_to_offset(site)
            rows.append({
                "site_va": f"{site:#x}",
                "target_va": f"{target:#x}",
                "instruction_file_offset": f"{offset:#x}",
                "instruction_bytes": blob[offset:offset + size].hex(),
            })

    return {
        "target": {"path": "artifacts/node/115/hl-node", "sha256": digest},
        "section_coordinates": {
            "rodata_va": "0x430400", "rodata_file_offset": "0x430400",
            "rodata_size": "0x76e640", "text_va": "0x1419300",
            "text_file_offset": "0x1418300", "text_size": "0x4fd7700",
        },
        "token_hex": TOKEN.hex(),
        "occurrences": [
            {"va": f"{va:#x}", "file_offset": f"{va:#x}"}
            for va in found
        ],
        "direct_references": rows,
        "scope": "objdump-resolved direct .text references to listed data anchors; indirect/data-only references not assessed",
    }


def main() -> int:
    try:
        record = analyze()
        encoded = json.dumps(record, indent=2) + "\n"
        if len(sys.argv) == 2 and sys.argv[1] == "--write":
            OUT.write_text(encoded)
        elif OUT.exists() and OUT.read_text() != encoded:
            raise ValueError("records.json differs; run verify.py --write after reviewing the change")
        print(f"verified occurrences={len(record['occurrences'])} direct_references={len(record['direct_references'])}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"verify: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
