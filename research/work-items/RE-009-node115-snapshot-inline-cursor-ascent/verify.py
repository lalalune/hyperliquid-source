import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(38019258, 6, 38019668), (38019702, 6, 38020067), (38019750, 2, 38019696), (38019762, 6, 38019279)]
anchors = [(38019696, '4c8b3f4d85ff'), (38019712, '440fb7b728040000'), (38019723, 'be90040000480f44f531d2ffd3'), (38019742, '66453bb72a040000')]

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
