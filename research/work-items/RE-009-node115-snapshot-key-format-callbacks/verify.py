import hashlib
import struct
import subprocess
from pathlib import Path

target = Path("artifacts/node/115/hl-node")
binary = target.read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
phoff = struct.unpack_from("<Q", binary, 32)[0]
stride, count = struct.unpack_from("<HH", binary, 54)
headers = [struct.unpack_from("<IIQQQQQQ", binary, phoff + i * stride) for i in range(count)]

def locate(address):
    return next(offset + address - va for kind, _, offset, va, _, size, _, _
                in headers if kind == 1 and va <= address < va + size)

def valid(data, relocations):
    for address, length, slot, callback in (
        (0x46AA497, 7, 0x64DFEE8, 0x168A370),
        (0x46AA503, 7, 0x64DFEE8, 0x168A370),
        (0x46AA519, 7, 0x64DF6C8, 0x1689420),
        (0x46AA536, 6, 0x64DF6E8, 0x141E3A0),
    ):
        delta = struct.unpack_from("<i", data, locate(address) + length - 4)[0]
        if address + length + delta != slot or relocations.get(slot) != callback:
            return False
    table = locate(0x46EA12)
    return (
        data[table:table + 200] == "".join(f"{i:02}" for i in range(100)).encode()
        and data[locate(0x168A374):locate(0x168A376)] == bytes.fromhex("8b07")
        and data[locate(0x1689429):locate(0x168942C)] == bytes.fromhex("4c8b07")
        and data[locate(0x1689466):locate(0x1689473)] == bytes.fromhex("49f7e148c1ea0b69c210270000")
    )

rows = subprocess.check_output(["llvm-readelf", "-r", str(target)], text=True)
slots = {0x64DFEE8, 0x64DF6C8, 0x64DF6E8}
relocations = {}
for row in rows.splitlines():
    fields = row.split()
    if len(fields) == 4 and fields[2] == "R_X86_64_RELATIVE":
        slot = int(fields[0], 16)
        if slot in slots:
            assert slot not in relocations
            relocations[slot] = int(fields[-1], 16)
assert valid(binary, relocations)
for slot in slots:
    assert not valid(binary, dict(relocations) | {slot: 0})
changed = bytearray(binary)
changed[locate(0x46EA12)] ^= 1
assert not valid(changed, relocations)
print("PASS: digest, four instruction references, three relative relocations, 100 decimal pairs and four negative controls")
