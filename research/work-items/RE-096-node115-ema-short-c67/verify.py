#!/usr/bin/env python3
import hashlib
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / "artifacts/node/115/hl-node"
START, END, FDE = 0x4D3F290, 0x4D3F39D, 0xF17C10
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
W = {
    0x4D3F290: "4157",
    0x4D3F2A3: "48833f00",
    0x4D3F2E0: "e80ba2ae00",
    0x4D3F312: "488d35679f71fb",
    0x4D3F38D: "ff15a5017a01",
    0x4D3F39C: "c3",
}

if hashlib.sha256(BIN.read_bytes()).hexdigest() != TARGET:
    raise SystemExit("target hash mismatch")
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable, str(ROOT / "tools/fde_extents.py"),
                           "--release", "115", "--output-dir", td],
                          stdout=subprocess.DEVNULL)
    rows = (pathlib.Path(td) / "node-115-fde.tsv").read_text().splitlines()
    expected = f"{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}"
    if not any(row.startswith(expected) for row in rows):
        raise SystemExit("FDE boundary mismatch")

obj = subprocess.check_output([
    "/opt/homebrew/opt/binutils/bin/objdump", "-d",
    f"--start-address={START:#x}", f"--stop-address={END:#x}", str(BIN)
], text=True)
got = {}
for line in obj.splitlines():
    if ":" not in line:
        continue
    address, rest = line.split(":", 1)
    try:
        address = int(address.strip(), 16)
    except ValueError:
        continue
    fields = rest.split("\t")
    got[address] = "".join(fields[1].split()) if len(fields) > 1 else ""

def matches(witnesses):
    return all(got.get(address, "").startswith(raw) for address, raw in witnesses.items())

if not matches(W):
    raise SystemExit("witness mismatch")
mutated = dict(W)
mutated[START] = "4057"
if matches(mutated):
    raise SystemExit("entry identity mutation not rejected")
mutated = dict(W)
mutated[0x4D3F2E0] = "e90ba2ae00"
if matches(mutated):
    raise SystemExit("call-site identity mutation not rejected")
print({"fde_start": hex(START), "fde_end": hex(END), "fde_bytes": END - START,
       "eh_frame_offset": hex(FDE), "witnesses": len(W), "identity_controls": 2})
