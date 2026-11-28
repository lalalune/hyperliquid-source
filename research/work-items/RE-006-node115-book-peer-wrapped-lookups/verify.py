from bisect import bisect_left
from hashlib import sha256
from itertools import combinations
from pathlib import Path
import re
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(data).hexdigest() == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
for lo, hi in [(0x57f7bd0, 0x57f7d97), (0x57fbf50, 0x57fc084)]:
    assert any((entry['start'], entry['end']) == (lo, hi) for entry in entries)
section = next(item for item in sections if item['name'] == '.text')
def read(va, size):
    offset = va - section['address']
    assert 0 <= offset <= section['size'] - size
    pos = section['offset'] + offset
    return data[pos:pos+size]

pattern = re.compile(r'^\s*([a-f0-9]+):\t([a-f0-9 ]+)\s+\t')
rows = {}
for line in Path(__file__).with_name('windows.txt').read_text().splitlines():
    match = pattern.match(line)
    if match:
        rows[int(match[1], 16)] = bytes.fromhex(match[2])
def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, dst in [(0x58e44b6, 0x57f7bd0), (0x58e458f, 0x57fbf50),
                      (0x57f7c12, 0x64dfb50), (0x57f7d66, 0x64dfb50)]:
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], 'little', signed=True) == dst
check(read)
controls = (0x57f7c12, 0x57f7d82, 0x57fbf96, 0x57fbfed, 0x58e44bd, 0x58e4596)
for bad in controls:
    def corrupt(va, size):
        raw = bytearray(read(va, size))
        if va <= bad < va + size:
            raw[bad-va] ^= 1
        return raw
    try:
        check(corrupt)
    except AssertionError:
        continue
    raise AssertionError(hex(bad))

def search(keys, key):
    index, remaining = 0, len(keys)
    while remaining > 1:
        half = remaining // 2
        if keys[index + half] <= key:
            index += half
        remaining -= half
    return int(keys[index] != key), index + int(keys[index] < key)

cases = 0
for size in range(2, 7):
    for keys in combinations(range(0, 14, 2), size):
        for cut in range(1, size):
            for key in range(15):
                if key == keys[cut]:
                    actual = 0, cut
                elif key < keys[cut]:
                    actual = search(keys[:cut], key)
                else:
                    miss, index = search(keys[cut:], key)
                    actual = miss, index + cut
                assert actual == (int(key not in keys), bisect_left(keys, key))
                cases += 1
print(f'{len(rows)} instruction windows, {len(controls)} corruption controls, {cases} wrapped cases passed')
