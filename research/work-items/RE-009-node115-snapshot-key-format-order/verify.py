import hashlib
import struct
import subprocess
from pathlib import Path

target = Path("artifacts/node/115/hl-node")
data = target.read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

def valid(blob, rows):
    instruction = blob[0x46AA525 - 0x1000:0x46AA52C - 0x1000]
    descriptor = 0x46AA52C + struct.unpack_from("<i", instruction, 3)[0]
    call = blob[0x141E4BE - 0x1000:0x141E4C4 - 0x1000]
    slot = 0x141E4C4 + struct.unpack_from("<i", call, 2)[0]
    return (
        descriptor == 0x433517 and blob[descriptor:descriptor + 3] == b"\xc0\xc0\x00"
        and slot == 0x64DF6F0 and any(
            row.split() == ["00000000064df6f0", "0000000000000008", "R_X86_64_RELATIVE", "1680500"]
            for row in rows.splitlines()
        )
        and blob[0x1680594 - 0x1000:0x16805A8 - 0x1000]
        == bytes.fromhex("4181ffc0000000753f4c8b7dd04c89f848c1e004")
        and blob[0x168065E - 0x1000:0x168067A - 0x1000]
        == bytes.fromhex("488b3c03488d75b8ff54030884c0754149ffc74c897dd0e9d6feffff")
    )

rows = subprocess.check_output(["llvm-readelf", "-r", str(target)], text=True)
assert valid(data, rows)
assert not valid(data, rows.replace("1680500", "0"))
for offset in (0x433517, 0x1680666 - 0x1000):
    changed = bytearray(data)
    changed[offset] ^= 1
    assert not valid(changed, rows)
print("PASS: target digest, two-token descriptor, dispatch relocation and callback loop; three corruptions rejected")
