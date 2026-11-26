import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

def inspect(data):
    call = 0x2C6F14F
    if data[call - 0x1000] != 0xE8:
        return False
    target = call + 5 + struct.unpack_from("<i", data, call + 1 - 0x1000)[0]
    start = 0x46AA47D - 0x1000
    store = 0x46AA4BE - 0x1000
    return (
        target == 0x46AA470
        and data[start:start + 5] == bytes.fromhex("4885f67428")
        and data[store:store + 36] == bytes.fromhex(
            "48b9505552522f555344488908c640084348c70309000000"
            "4889430848c7431009000000"
        )
    )

assert inspect(binary)
for address in (0x2C6F14F, 0x46AA480, 0x46AA4C0):
    modified = bytearray(binary)
    modified[address - 0x1000] ^= 1
    assert not inspect(modified)
print("PASS: pinned digest, direct edge, zero branch, literal stores, 3 mutation controls")
