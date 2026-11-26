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
forms = {
    "original": [(0x40, "0fb78f", 4), (0x63, "4881c1", 4),
                 (0x210, "440fb7b7", 4), (0x1eb, "bd", 4), (0x21b, "be", 4)],
    "shifted": [(0x40, "0fb78f", 4), (0x63, "4881c1", 4),
                (0x214, "440fb7b7", 4), (0x1eb, "bd", 4), (0x21f, "be", 4)],
    "short": [(0x40, "0fb74f", 1), (0x60, "4881c1", 4),
              (0x210, "440fb777", 1), (0x1e8, "bd", 4), (0x218, "be", 4)],
}

def decode(body, fields):
    values = []
    for start, prefix, width in fields:
        opcode = bytes.fromhex(prefix)
        if body[start:start + len(opcode)] != opcode:
            return None
        pos = start + len(opcode)
        values.append(int.from_bytes(body[pos:pos + width], "little"))
    return tuple(values)

from collections import Counter
matches = [m.start() + 4096 for m in re.finditer(re.escape(prefix), binary)]
assert len(matches) == 211
assert all(extents.get(a) == a + 938 for a in matches)
counts = Counter()
rows = []
for address in matches:
    start = address - 4096
    body = binary[start:start + 938]
    found = [(name, decode(body, form)) for name, form in forms.items()]
    found = [(name, value) for name, value in found if value is not None]
    assert len(found) == 1, hex(address)
    name, value = found[0]
    counts[name] += 1
    if name != "original":
        rows.append((address, name, value))
assert counts == {"original": 83, "shifted": 123, "short": 5}
for address, name, expected in [
    (0x166CFE0, "shifted", (0x1a82, 0x1a90, 0x1a80, 0x1a88, 0x1ae8)),
    (0x244DBC0, "short", (0x62, 0x158, 0x60, 0x150, 0x1b0)),
]:
    assert (address, name, expected) in rows
    for offset, _, _ in forms[name]:
        start = address - 4096
        body = bytearray(binary[start:start + 938])
        body[offset] ^= 1
        assert decode(body, forms[name]) is None

print("entry\tencoding\tcount_offset\tsuccessor_offset\tparent_index_offset\tleaf_size\tinternal_size")
for address, name, values in rows:
    print("\t".join([hex(address), name, *(hex(x) for x in values)]))
