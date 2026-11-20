#!/usr/bin/env python3
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DATA = json.loads((Path(__file__).parent / "records.json").read_text())

def sections(data):
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    raw = []
    for i in range(shnum):
        raw.append(struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize))
    string = raw[shstrndx]
    table = data[string[4]:string[4] + string[5]]
    out = {}
    for row in raw:
        name = table[row[0]:].split(b"\0", 1)[0].decode()
        out[name] = row
    return out

def text_bytes(data, va, size):
    return data[int(va, 16) - 0x1000:int(va, 16) - 0x1000 + size]

def main():
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA == DATA["sha256"]
    for row in DATA["windows"]:
        raw = bytes.fromhex(row["bytes"])
        assert text_bytes(data, row["va"], len(raw)) == raw
    rela = sections(data)[".rela.dyn"]
    entries = {}
    for slot, info, addend in struct.iter_unpack("<QQq", data[rela[4]:rela[4] + rela[5]]):
        entries[slot] = (info, addend)
    assert entries[int(DATA["relocation"]["slot"], 16)] == (DATA["relocation"]["type"], int(DATA["relocation"]["addend"], 16))
    excerpt = (Path(__file__).parent / "excerpts.objdump.txt").read_text()
    for marker in ("15d7026", "15d70c2", "5cf9600", "5cf9664", "5cde590"):
        assert marker in excerpt
    print(json.dumps({"target_sha256": SHA, "windows_verified": 5,
                      "relocation_verified": True,
                      "captured_code_executed_or_emulated": False}, sort_keys=True))

if __name__ == "__main__":
    main()
