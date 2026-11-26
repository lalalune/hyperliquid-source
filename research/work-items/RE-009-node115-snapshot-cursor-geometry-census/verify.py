import hashlib
from pathlib import Path
import re
import struct
import subprocess

target = Path("artifacts/node/115/hl-node")
binary = target.read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
frames = subprocess.check_output(["llvm-dwarfdump", "--eh-frame", str(target)], text=True)
extents = {int(a, 16): int(z, 16) for a, z in re.findall(
    r"pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", frames
)}
origin = 0x2442070
prefix = binary[origin - 0x1000:origin - 0x1000 + 27]
operands = [
    (0x24420B0, "0fb78f"), (0x24420D3, "4881c1"), (0x2442280, "440fb7b7"),
    (0x244225B, "bd"), (0x244228B, "be"),
]

def geometry(body):
    result = []
    for address, opcode_hex in operands:
        offset = address - origin
        opcode = bytes.fromhex(opcode_hex)
        if body[offset:offset + len(opcode)] != opcode:
            return None
        result.append(struct.unpack_from("<I", body, offset + len(opcode))[0])
    return tuple(result)

matches = [match.start() + 0x1000 for match in re.finditer(re.escape(prefix), binary)]
assert len(matches) == 211
assert all(extents.get(address) == address + 938 for address in matches)
rows = {}
for address in matches:
    start = address - 0x1000
    row = geometry(binary[start:start + 938])
    if row is not None:
        rows[address] = row
assert len(rows) == 83 and len(set(rows.values())) == 34
assert rows[origin] == (0x42A, 0x438, 0x428, 0x430, 0x490)
assert rows[0x2442420] == (0x4AE, 0x4B8, 0x4AC, 0x4B0, 0x510)

for address, _ in operands:
    sample = bytearray(binary[origin - 0x1000:origin - 0x1000 + 938])
    sample[address - origin] ^= 1
    assert geometry(sample) is None

print("entry\tcount_offset\tsuccessor_offset\tparent_index_offset\tleaf_size\tinternal_size")
for address, row in rows.items():
    print("\t".join(hex(x) for x in (address, *row)))
