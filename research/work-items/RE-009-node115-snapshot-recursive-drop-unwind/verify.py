import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(36745116, 2, 36745144), (36745138, 6, 105772192), (36745171, 2, 36745194), (36745184, 5, 36744976), (36745232, 6, 105772192), (36745253, 6, 105772192), (36745262, 5, 104794704)]
anchors = [(36745109, '488b73484885f6'), (36745118, '488b7b5031d2'), (36745159, '4989c7'), (36745173, '498dac24a8000000'), (36745259, '4c89ff')]

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
