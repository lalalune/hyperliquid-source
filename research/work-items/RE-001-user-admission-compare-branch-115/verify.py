#!/usr/bin/env python3
"""Recheck only the frozen node #115 user-key comparison branch."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone


def need(ok, what):
    if not ok:
        raise ValueError(what)


def sha(data):
    return hashlib.sha256(data).hexdigest()


spec = json.loads((PACKET / "scope.json").read_text())
data = TARGET.read_bytes()
need(sha(data) == spec["target_sha256"], "wrong target digest")
ss = sections(data)
start, end = int(spec["owner"]["start"], 16), int(spec["owner"]["end"], 16)
fdes = [f for f in eh_frame_records(data, ss)[1] if f["start"] == start]
need(len(fdes) == 1 and fdes[0]["end"] == end, "owner FDE boundary")
owners = [s for s in ss if s["type"] != 8 and s["address"] <= start and end <= s["address"] + s["size"]]
need(len(owners) == 1, "owner VA mapping")
s = owners[0]
off = s["offset"] + start - s["address"]
body = data[off : off + end - start]
need(len(body) == spec["owner"]["bytes"] and sha(body) == spec["owner"]["sha256"], "owner body digest")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
ins = list(md.disasm(body, start))
need(b"".join(bytes(i.bytes) for i in ins) == body, "incomplete instruction partition")
by_addr = {i.address: i for i in ins}
need(len(by_addr) == len(ins), "duplicate instruction addresses")
need(capstone.__version__ == "5.0.7", "Capstone version must be 5.0.7")

for a in spec["anchors"]:
    va, expected = int(a["va"], 16), bytes.fromhex(a["raw"])
    need(data[off + va - start : off + va - start + len(expected)] == expected, "anchor " + a["va"])

# The comparison result is signed: cdqe/test/sets/setg/sub produce 0, 1 or
# 0xff, then the branches select equal, positive, or negative paths.
need(by_addr[0x2C77831].mnemonic == "call", "comparison call")
need(by_addr[0x2C77834].mnemonic == "cdqe", "signed return extension")
need(by_addr[0x2C77839].mnemonic == "sets" and by_addr[0x2C7783C].mnemonic == "setg", "signed ordering flags")
need(by_addr[0x2C7784D].mnemonic == "je" and by_addr[0x2C7784D].operands[0].imm == 0x2C77820, "positive sibling loop")
need(by_addr[0x2C7785E].mnemonic == "je" and by_addr[0x2C7785E].operands[0].imm == 0x2C776AC, "equal root route")
need(by_addr[0x2C77864].mnemonic == "jmp" and by_addr[0x2C77864].operands[0].imm == 0x2C7786E, "negative/exhausted depth path")
need(by_addr[0x2C7787C].mnemonic == "jb" and by_addr[0x2C7787C].operands[0].imm == 0x2C778DE, "depth-zero result")

print(json.dumps({
    "target_sha256": sha(data),
    "owner": spec["owner"],
    "capstone": capstone.__version__,
    "instructions": len(ins),
    "anchors": len(spec["anchors"]),
    "branch_map": {
        "equal": "0x2c776ac root route",
        "positive_with_sibling": "0x2c77820 next sibling",
        "negative_or_exhausted": "0x2c7786e depth decrement; zero depth reaches 0x2c778de",
    },
    "captured_execution": False,
}, indent=2, sort_keys=True))
