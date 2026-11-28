"""Follow the callback registration, format descriptor and four chain display arms."""
from pathlib import Path
import hashlib
import json
import struct
import sys

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "tools"))
from elf_index import sections

data = (root / "artifacts/node/115/hl-node").read_bytes()
target = hashlib.sha256(data).hexdigest()
assert target == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
layout = sections(data)


def read(va, n):
    s = next(s for s in layout if s["name"] in (".text", ".rodata") and s["address"] <= va and va + n <= s["address"] + s["size"])
    i = s["offset"] + va - s["address"]
    return data[i:i + n]


def rel(va, prefix):
    op = bytes.fromhex(prefix)
    assert read(va, len(op)) == op
    after = va + len(op) + 4
    return after + struct.unpack("<i", read(after - 4, 4))[0]


section = next(s for s in layout if s["name"] == ".rela.dyn")
relocs = {a: val for a, kind, val in struct.iter_unpack("<QQq", data[section["offset"]:section["offset"] + section["size"]]) if kind == 8}
assert rel(0x2e37b17, "e8") == 0x2d0e8b0
assert read(0x2d0e8df, 4) == bytes.fromhex("40886810")
assert read(rel(0x2e37b1c, "488d15"),18) == b"web3_clientVersion"
assert read(0x2e37b2e,5) == bytes.fromhex("b912000000")
assert rel(0x2e37b33, "e8") == 0x2cff5c0
descriptor = rel(0x2cff628, "488d05")
assert relocs[descriptor + 32] == relocs[descriptor + 40] == 0x2d01520
assert read(0x2d01540,4) == bytes.fromhex("4883c010")
prefix = read(rel(0x2d0155b, "488d35"),19)
assert prefix == b"\x10hyperliquid evm \xc0\x00"
assert relocs[rel(0x2d0154f, "488b05")] == 0x1778c60
table = rel(0x1778c66, "488d15")
results = []
for i in range(4):
    arm = table + struct.unpack("<i", read(table + 4*i,4))[0]
    address = rel(arm, "488d35")
    assert read(arm+7,1) == b"\xba"
    length = struct.unpack("<I",read(arm+8,4))[0]
    results.append((prefix[1:17] + read(address,length)).decode())
assert results == ["hyperliquid evm " + name for name in ("Local", "Sandbox", "Testnet", "Mainnet")]
print(json.dumps({"target_sha256":target,"registration":"0x2e37b1c","callback":hex(relocs[descriptor+32]),"display_table":hex(table),"results":results},indent=2))
