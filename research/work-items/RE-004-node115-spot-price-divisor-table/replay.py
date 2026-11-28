"""Recover the divisors referenced by the single and dual spot price conversions."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "tools"))
from elf_index import sections

data = (root / "artifacts/node/115/hl-node").read_bytes()
target = sha256(data).hexdigest()
assert target == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
layout = {section["name"]: section for section in sections(data)}


def read(name, address, length):
    section = layout[name]
    offset = address - section["address"]
    assert 0 <= offset and offset + length <= section["size"]
    start = section["offset"] + offset
    return data[start:start + length]


sites = []
for load, load_bytes, subtract, sub_bytes, index, lea, division in [
    (0x50bea14, "0fb6440249", 0x50bea20, "2a440a487252", 0x50bea47, "488d0d", "f20f5e04c1"),
    (0x22f5e3f, "410fb6440349", 0x22f5e4c, "412a4433480f82e4000000", 0x22f5e78, "488d35", "f20f5e0cc6"),
    (0x22f5ece, "0fb6440149", 0x22f5eda, "2a441148725b", 0x22f5f01, "488d0d", "f20f5e04c1"),
]:
    for address, sequence in [
        (load, load_bytes), (subtract, sub_bytes), (index, "0fb6c0" + lea), (index + 10, division)
    ]:
        expected = bytes.fromhex(sequence)
        assert read(".text", address, len(expected)) == expected
    table = index + 10 + struct.unpack("<i", read(".text", index + 6, 4))[0]
    values = read(".rodata", table, 256 * 8)
    recurrent = bytearray()
    power = 1.0
    for exponent in range(256):
        recurrent.extend(struct.pack("<d", power))
        power *= 10.0
    assert recurrent == values
    direct_matches = sum(
        struct.pack("<d", float(10**i)) == values[8*i:8*i+8] for i in range(256)
    )
    sites.append(dict(index=hex(index), table=hex(table), sha256=sha256(values).hexdigest(),
                      recurrent_matches=256, direct_rounding_matches=direct_matches))

assert {row["table"] for row in sites} == {"0x5ed748", "0x91b7c0"}
assert len({row["sha256"] for row in sites}) == 1
print(json.dumps({"target_sha256": target, "consumers": sites}, indent=2))
