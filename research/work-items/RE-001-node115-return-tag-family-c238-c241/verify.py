#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
PACKET = Path(__file__).resolve().parent
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

def die(msg): raise SystemExit(msg)
def read(va, n):
    # Node #115's executable .text mapping is VA 0x1000 above file offsets.
    b = TARGET.read_bytes()[va - 0x1000:va - 0x1000 + n]
    if len(b) != n: die("short ELF read")
    return b

def main():
    if hashlib.sha256(TARGET.read_bytes()).hexdigest() != SHA: die("target digest mismatch")
    rec = json.loads((PACKET/"records.json").read_text())
    if rec["sha256"] != SHA or len(rec["families"]) != 4: die("record mismatch")
    for f in rec["families"]:
        start, end = int(f["start"],16), int(f["end"],16)
        if end <= start: die("bad extent")
        call = int(f["call"],16); ret = int(f["ret"],16)
        if not (start <= call < end and start <= ret < end): die("boundary mismatch")
        if read(call, len(bytes.fromhex(f["call_bytes"]))).hex() != f["call_bytes"]: die(f["id"]+" call mismatch")
        if read(ret, len(bytes.fromhex(f["ret_bytes"]))).hex() != f["ret_bytes"]: die(f["id"]+" ret mismatch")
        if read(int(f["terminal"],16), len(bytes.fromhex(f["terminal_bytes"]))).hex() != f["terminal_bytes"]: die(f["id"]+" terminal mismatch")
    c = rec["families"][2]
    if read(int(c["terminal"],16), 3).hex() != "488903": die("store mismatch")
    print(json.dumps({"target_sha256":SHA,"families_verified":4,"captured_code_executed_or_emulated":False}, indent=2))
if __name__ == "__main__": main()
