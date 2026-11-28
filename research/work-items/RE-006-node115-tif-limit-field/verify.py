"""Check selected named Tif field emissions for node #115."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
for bounds in ((0x25DAD80, 0x25DB0C3), (0x44983A0, 0x44986E3), (0x520C170, 0x520C57D)):
    assert any((entry["start"], entry["end"]) == bounds for entry in entries)

by_name = {section["name"]: section for section in sections}


def read(va, size):
    for name in (".text", ".rodata"):
        section = by_name[name]
        delta = va - section["address"]
        if 0 <= delta <= section["size"] - size:
            start = section["offset"] + delta
            return data[start:start + size]
    raise AssertionError(hex(va))


row_pattern = re.compile(r"^\s*([a-f0-9]+):\t([a-f0-9 ]+)\s+\t")
rows = {}
for line in Path(__file__).with_name("windows.txt").read_text().splitlines():
    match = row_pattern.match(line)
    if match:
        rows[int(match[1], 16)] = bytes.fromhex(match[2])

targets = {
    0x25DAE5D: 0x25DA5C0, 0x449847D: 0x4497590, 0x520C29A: 0x5192420,
}
literal_sites = (
    (0x25DADDC, 0x25DADD7, 0x25DAE42, 0x25DAE3D),
    (0x44983FC, 0x44983F7, 0x4498462, 0x449845D),
    (0x520C20E, 0x520C208, 0x520C27C, 0x520C277),
)


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
    for limit_first, limit_last, tif_first, tif_last in literal_sites:
        def immediate(site, size):
            raw = reader(site, len(rows[site]))
            return raw[-size:]

        assert immediate(limit_first, 4) + immediate(limit_last, 1) == b"limit"
        assert immediate(tif_first, 2) + immediate(tif_last, 1) == b"tif"


check(read)
controls = (0x25DAD90, 0x25DAE26, 0x4498466, 0x449847E, 0x520C24C, 0x520C27B)
for bad in controls:
    def corrupt(va, size):
        raw = bytearray(read(va, size))
        if va <= bad < va + size:
            raw[bad - va] ^= 1
        return raw

    try:
        check(corrupt)
    except AssertionError:
        continue
    raise AssertionError(f"mutation at {bad:#x} was accepted")


print(f"{len(rows)} instructions, {len(targets)} call targets, three FDEs")
print(f"{len(literal_sites)} matching limit/tif literal pairs, {len(controls)} corruption controls passed")
