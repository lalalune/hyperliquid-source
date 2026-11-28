import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(38216480, 6, 38216656), (38216662, 6, 38217072), (38216705, 2, 38216656), (38216710, 6, 38216448), (38216749, 2, 38216736), (38216807, 2, 38216768), (38216823, 6, 38216468), (38216829, 2, 38216950)]
anchors = [(38216672, '440fb76f60'), (38216700, '66443b6b62'), (38216716, '4a8d04eb4883c070'), (38216736, '488b18488d4368'), (38216809, '4531ed4889dfb80000000049ffce')]

def valid(data):
    for address, width, target in edges:
        size = 1 if width == 2 else 4
        offset = address + width - size - 0x1000
        displacement = struct.unpack_from("<b" if size == 1 else "<i", data, offset)[0]
        if address + width + displacement != target:
            return False
    for address, encoded in anchors:
        expected = bytes.fromhex(encoded)
        offset = address - 0x1000
        if data[offset:offset + len(expected)] != expected:
            return False
    return True

assert valid(binary)
for address in [a + w - 1 for a, w, _ in edges] + [a for a, _ in anchors]:
    damaged = bytearray(binary)
    damaged[address - 0x1000] ^= 1
    assert not valid(damaged)
print(f"PASS: pinned digest, {len(edges)} edges, {len(anchors)} instruction anchors, and {len(edges)+len(anchors)} rejected mutations")
