"""Check node #115 ENV79 decoder callers."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x14BE160, 0x14BE630, 0x14CEAE0)
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
    0x14BE170: (0x14B3080, 4), 0x14BE647: (0x14B3080, 4),
    0x14BE188: (0x463F48, 4), 0x14BE660: (0x464084, 4),
    0x14BE181: (0x14BE1A6, 1), 0x14BE659: (0x14BE692, 1),
}
tables = ((0x463F48, 0x14BE198, 0x14BE627), (0x464084, 0x14BE670, 0x14BF104))


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    for base, start, end in tables:
        for variant in range(79):
            relative = int.from_bytes(reader(base + 4 * variant, 4), "little", signed=True)
            arm = base + relative
            assert start <= arm < end
            store = bytes((0x66, 0xC7, 0x03, 9, variant))
            if base == 0x463F48:
                assert reader(arm, 5) == store
                continue
            assert reader(arm, 9) == bytes.fromhex("488d7c24084c89f6e8")
            displacement = int.from_bytes(reader(arm + 9, 4), "little", signed=True)
            assert arm + 13 + displacement == 0x14CEAE0
            assert reader(arm + 13, 5) == bytes.fromhex("807c240809")
            branch = reader(arm + 18, 2)
            if branch[0] == 0x75:
                width = 2
            else:
                assert branch == bytes.fromhex("0f85")
                width = 6
            relative = int.from_bytes(reader(arm + 18 + width - (1 if width == 2 else 4),
                                             1 if width == 2 else 4), "little", signed=True)
            assert arm + 18 + width + relative == 0x14BF104
            assert reader(arm + 18 + width, 5) == store


check(read)
controls = (0x14BE180, 0x14BE658, 0x463F48, 0x464084, 0x14BE60F, 0x14BF0D7)
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


print(f"{len(rows)} instructions, {len(targets)} relative targets, {2 * 79} dispatch rows")
print(f"{len(controls)} corruption controls passed")
