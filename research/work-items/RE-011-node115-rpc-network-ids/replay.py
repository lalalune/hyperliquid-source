"""Read both network-ID registrations and trace their configuration values."""
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
    s = next(s for s in layout if s["name"] in (".text", ".rodata", ".data", ".data.rel.ro") and s["address"] <= va and va + n <= s["address"] + s["size"])
    i = s["offset"] + va - s["address"]
    return data[i:i + n]


def rel(va, prefix):
    op = bytes.fromhex(prefix)
    assert read(va, len(op)) == op
    after = va + len(op) + 4
    return after + struct.unpack("<i", read(after - 4, 4))[0]


section = next(s for s in layout if s["name"] == ".rela.dyn")
relocs = {a: val for a, kind, val in struct.iter_unpack("<QQq", data[section["offset"]:section["offset"] + section["size"]]) if kind == 8}
members = []
for name, key, registration, wrapper, descriptor, callback, accessor, field in [
    (b"net_version", 0x2e377fe, 0x2e37815, 0x2cff400, 0x2cff468, 0x2cffb40, 0x2cffb72, 0x2cffb7b),
    (b"eth_chainId", 0x2a05fe1, 0x2a05ff5, 0x2cff240, 0x2cff2a8, 0x2d01390, 0x2d013bf, 0x2d013c8),
]:
    assert read(rel(key,"488d15"), len(name)) == name
    assert rel(registration,"e8") == wrapper
    vtable = rel(descriptor,"488d05")
    assert relocs[vtable+32] == relocs[vtable+40] == callback
    assert relocs[rel(accessor,"ff15")] == 0x46f3eb0
    assert read(field,3) in (bytes.fromhex("488bb8"),bytes.fromhex("488b98"))
    assert struct.unpack("<I",read(field+3,4))[0] == 0x388
    members.append(name.decode())

table = rel(0x46f3eb9, "488d0d")
ids = []
for index, load in enumerate([0x46f3ed7, 0x46f3f1c, 0x46f3eee, 0x46f3f05]):
    arm = table + struct.unpack("<i",read(table+4*index,4))[0]
    assert 0 <= load-arm < 16
    cell = rel(load, "488d05")
    initializer = relocs[cell]
    assert read(initializer,1) == b"\xbf"
    argument = struct.unpack("<I",read(initializer+1,4))[0]
    assert rel(initializer+5, "e9") == 0x4345010
    assert read(0x4345037,4) == bytes.fromhex("400fb6df")
    assert read(0x434503b,3) == bytes.fromhex("4881c3")
    offset = struct.unpack("<I",read(0x434503e,4))[0]
    ids.append(offset+argument)
assert ids == [996,997,998,999]
assert read(0x4345050,7) == bytes.fromhex("0f94c1480f45d8")
assert read(0x43452ff,8) == bytes.fromhex("48899c24f8030000")
assert read(0x5bcd146,8) == bytes.fromhex("660f6f8370030000")
assert read(0x5bcd763,7) == bytes.fromhex("0f298370030000")
print(json.dumps({"target_sha256":target,"methods":members,"payload_offset":"0x388","selector":"0x46f3eb0","local_sandbox_testnet_mainnet":ids},indent=2))
