#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
TARGET=ROOT/"artifacts/node/115/hl-node"
SHA="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DATA=json.loads((Path(__file__).parent/"records.json").read_text())
def main():
 data=TARGET.read_bytes(); assert hashlib.sha256(data).hexdigest()==SHA==DATA["sha256"]
 assert len(DATA["windows"])==3
 for row in DATA["windows"]:
  raw=bytes.fromhex(row["bytes"]); va=int(row["va"],16); assert data[va-0x1000:va-0x1000+len(raw)]==raw
 excerpt=(Path(__file__).parent/"excerpts.objdump.txt").read_text()
 for marker in ("5ce0207","5ce023f","5ce06a0"): assert marker in excerpt
 print(json.dumps({"target_sha256":SHA,"windows_verified":3,"captured_code_executed_or_emulated":False},sort_keys=True))
if __name__=="__main__": main()
