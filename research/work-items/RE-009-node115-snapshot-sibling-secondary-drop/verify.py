import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(37937114, 2, 37937178), (37937181, 5, 38782880), (37937222, 6, 105772192), (37937257, 5, 38057696), (37937318, 5, 38057696), (37937379, 2, 37937395), (37937403, 2, 37937312), (37937408, 2, 37937312)]
anchors = [(37937199, '4969f7e0000000'), (37937333, '48694c2418d8000000'), (37937356, '837c086002400f94c5c1e503'), (37937368, '488bb41590000000'), (37937381, '498b7c2d3848c1e603'), (37937395, '498b742d584c39fe'), (37937410, '498b7c2d6048c1e605')]

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
