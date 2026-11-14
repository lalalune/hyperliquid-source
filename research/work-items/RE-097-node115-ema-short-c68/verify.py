#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / "artifacts/node/115/hl-node"
START, END, FDE = 0x4D3F3A0, 0x4D3F4B0, 0xF17C40
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
W = {
    0x4D3F3A0: "4157", 0x4D3F3B3: "833f01",
    0x4D3F3D8: "4883c708", 0x4D3F3F3: "e848763c00",
    0x4D3F42C: "488d7c2408", 0x4D3F4AF: "c3",
}
if hashlib.sha256(BIN.read_bytes()).hexdigest() != TARGET:
    raise SystemExit("target hash mismatch")
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable, str(ROOT / "tools/fde_extents.py"),
                           "--release", "115", "--output-dir", td],
                          stdout=subprocess.DEVNULL)
    rows = (pathlib.Path(td) / "node-115-fde.tsv").read_text().splitlines()
    prefix = f"{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}"
    if not any(row.startswith(prefix) for row in rows):
        raise SystemExit("FDE boundary mismatch")
obj = subprocess.check_output(["/opt/homebrew/opt/binutils/bin/objdump", "-d",
    f"--start-address={START:#x}", f"--stop-address={END:#x}", str(BIN)], text=True)
got = {}
for line in obj.splitlines():
    if ":" not in line: continue
    address, rest = line.split(":", 1)
    try: address = int(address.strip(), 16)
    except ValueError: continue
    fields = rest.split("\t")
    got[address] = "".join(fields[1].split()) if len(fields) > 1 else ""
def matches(w): return all(got.get(a, "").startswith(b) for a, b in w.items())
if not matches(W): raise SystemExit("witness mismatch")
bad = dict(W); bad[START] = "4057"
if matches(bad): raise SystemExit("entry mutation not rejected")
bad = dict(W); bad[0x4D3F3F3] = "e948763c00"
if matches(bad): raise SystemExit("call-site mutation not rejected")
print({"fde_start": hex(START), "fde_end": hex(END), "fde_bytes": END-START,
       "eh_frame_offset": hex(FDE), "witnesses": len(W), "identity_controls": 2})
