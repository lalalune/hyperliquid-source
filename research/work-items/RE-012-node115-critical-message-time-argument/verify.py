"""Check node #115 critical-message time argument."""
from hashlib import sha256
from pathlib import Path
import re
from struct import iter_unpack

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x1509B70, 0x156D7F0, 0x141E3A0)
assert all(any(entry["start"] == owner for entry in entries) for owner in owners)

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
    0x1509E17: (0x4399BA, 4), 0x1509E1E: (0x64DF6E8, 4),
    0x1509E67: (0x64E0998, 4), 0x1509E7D: (0x431560, 4),
    0x1509F76: (0x64E0AF8, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    assert reader(0x431560, 6) == bytes.fromhex("c0c00120c000")


reloc = by_name[".rela.dyn"]
data_slice = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
expected = {0x64E0998: (8, 0x156D7F0), 0x64DF6E8: (8, 0x141E3A0)}
actual = [(slot, (kind, target)) for slot, kind, target in iter_unpack("<QQq", data_slice)
          if slot in expected]
assert sorted(actual) == sorted(expected.items())

check(read)
controls = (0x1509E20, 0x1509E36, 0x1509E65, 0x1509E72, 0x1509F70, 0x431560)
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


print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
