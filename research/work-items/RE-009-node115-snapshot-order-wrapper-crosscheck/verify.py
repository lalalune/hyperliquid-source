import hashlib
import struct
from pathlib import Path

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
first, second = 0x22B89C0, 0x22B8E00
operands = [
    (0x22B89E9, 0x25DD560, 0x23F6EC0),
    (0x22B8A78, 0x64DF508, 0x64DF508),
    (0x22B8AC0, 0x231E050, 0x231E050),
    (0x22B8AFA, 0x2630FD0, 0x2630FD0),
    (0x22B8B66, 0x64DF508, 0x64DF508),
    (0x22B8BAD, 0x231E050, 0x231E050),
    (0x22B8BC5, 0x25DD560, 0x23F6EC0),
    (0x22B8BE4, 0x2331920, 0x2331920),
    (0x22B8C16, 0x231E050, 0x231E050),
    (0x22B8C44, 0x231E050, 0x231E050),
    (0x22B8C6C, 0x231E050, 0x231E050),
    (0x22B8C7C, 0x642DC00, 0x642DC00),
    (0x22B8C82, 0x64DF520, 0x64DF520),
]

def verify(blob):
    bodies = [bytearray(blob[va - 0x1000:va - 0x1000 + 710]) for va in (first, second)]
    for address, left, right in operands:
        offset = address - first
        for base, body, expected in zip((first, second), bodies, (left, right)):
            displacement = struct.unpack_from("<i", body, offset)[0]
            if base + offset + 4 + displacement != expected:
                return False
            body[offset:offset + 4] = bytes(4)
    return bodies[0] == bodies[1]

assert verify(data)
for va in [first] + [address for address, _, _ in operands]:
    changed = bytearray(data)
    changed[va - 0x1000] ^= 1
    assert not verify(changed)
print("PASS: 658 unmasked bytes per body, 13 operand pairs and 14 rejected corruptions")
