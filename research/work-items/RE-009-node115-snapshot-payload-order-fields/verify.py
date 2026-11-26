import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(36409569, 2, 36409595), (36409590, 5, 36284304), (36409677, 5, 39876544), (36409744, 5, 36284304), (36409752, 2, 36409880), (36409774, 5, 39876544), (36409841, 5, 39180816), (36409849, 2, 36409880)]
anchors = [(36409640, 'c604017b'), (36409662, '488d359d1733fe'), (36409672, 'ba0b000000'), (36409759, '488d35471733fe'), (36409769, 'ba12000000'), (36409785, '4883c330'), (6203618, '626f6f6b5f6f7264657273756e7472696767657265645f6f7264657273')]

def valid(data):
    for address, width, target in edges:
        size = 1 if width == 2 else 4
        offset = address + width - size - 0x1000
        displacement = struct.unpack_from("<b" if size == 1 else "<i", data, offset)[0]
        if address + width + displacement != target:
            return False
    for address, encoded in anchors:
        expected = bytes.fromhex(encoded)
        offset = address if address == 0x5ea8e2 else address - 0x1000
        if data[offset:offset + len(expected)] != expected:
            return False
    return True

assert valid(binary)
for address in [a + w - 1 for a, w, _ in edges] + [a for a, _ in anchors]:
    damaged = bytearray(binary)
    damaged[address if address == 0x5ea8e2 else address - 0x1000] ^= 1
    assert not valid(damaged)
print(f"PASS: pinned digest, {len(edges)} edges, {len(anchors)} instruction anchors, and {len(edges)+len(anchors)} rejected mutations")
