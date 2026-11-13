import hashlib
from pathlib import Path
b=Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(b).hexdigest()=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ANCHORS = {94201120: '4156534883ec184889fb488b064c8d4608488b0a488d7c24084889c64c89c2e89cdbf8ff', 93733102: '4889f5488b06488b70184c8b60204c2365084939f40f83e40300004c8b40104f8d3c6449c1e7044b8d1c3840b60131c0f0430fb034380f8559020000488b43', 93733162: '488b4328483b4508747f', 93733299: '48ff450848895f0848c70703000000'}
def valid(data):
    return all(data[a-0x1000:a-0x1000+len(bytes.fromhex(h))] == bytes.fromhex(h) for a,h in ANCHORS.items())
assert valid(b)
for a in ANCHORS:
    changed=bytearray(b); changed[a-0x1000] ^= 1
    assert not valid(changed)
print("OK: four anchored instruction spans, four corruption controls")
