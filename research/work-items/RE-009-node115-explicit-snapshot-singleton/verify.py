import hashlib
import struct
from pathlib import Path

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

def valid(blob):
    def read(address, length):
        offset = address - 0x1000
        return blob[offset:offset + length]

    def edge(address, width, target):
        displacement = struct.unpack("<i", read(address + width - 4, 4))[0]
        return address + width + displacement == target

    return (
        edge(0x22B7532, 6, 0x22B7984)
        and read(0x22B7984, 8) == bytes.fromhex("488b46104883f865")
        and edge(0x22B798C, 6, 0x22B7AEA)
        and edge(0x22B79C2, 5, 0x2C6FA00)
        and read(0x22B79C7, 10) == bytes.fromhex("6681bc2410010000a201")
        and read(0x22B79E7, 5) == bytes.fromhex("bf10000000")
        and read(0x22B7A06, 3) == bytes.fromhex("0f1100")
        and read(0x22B7A21, 26) == bytes.fromhex(
            "4c897c240841bc01000000b8010000004889442430448b6c2404"
        )
        and edge(0x22B7A3B, 5, 0x22B75E9)
    )

assert valid(data)
for address in (0x22B7534, 0x22B798B, 0x22B79C3, 0x22B79CF, 0x22B7A28, 0x22B7A3C):
    altered = bytearray(data)
    altered[address - 0x1000] ^= 1
    assert not valid(altered)
print("PASS: target digest, 9 static observations and 6 rejected mutations")
