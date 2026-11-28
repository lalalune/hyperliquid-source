from bisect import bisect_left
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

binary = Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(binary).hexdigest() == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sections, _ = unwind_index(binary)
_, entries = eh_frame_records(binary, sections)
assert any(e['start'] == 0x57f4ac0 and e['end'] == 0x57f4c87 for e in entries)

def read(address, length):
    section = next(s for s in sections if s['name'] == '.text' and
                   s['address'] <= address <= s['address'] + s['size'] - length)
    offset = section['offset'] + address - section['address']
    return binary[offset:offset+length]

pins = {
    0x57f4ad5: '746c', 0x57f4af3: '7655', 0x57f4b50: '486bcd38',
    0x57f4b58: '4929ee', 0x57f4b63: '0f840c010000',
    0x57f4b69: '4531ed', 0x57f4b86: '48d1eb4901dd',
    0x57f4b93: 'ba14000000', 0x57f4b9e: 'ff15acafce00',
    0x57f4bac: '4d0f4fec4929de', 0x57f4bc8: 'ff1582afce00',
    0x57f4bd0: '7413c1e81f4901c5', 0x57f4bdb: 'b801000000',
    0x57f4be5: '31c0', 0x57f4c75: '4c89f2',
    0x4dc5bc4: 'e8f7eea2004885c07459',
}

def verify(reader):
    for address, expected_hex in pins.items():
        expected = bytes.fromhex(expected_hex)
        assert reader(address, len(expected)) == expected, hex(address)
    for call in (0x57f4b9e, 0x57f4bc8):
        assert call+6+int.from_bytes(reader(call+2, 4), 'little', signed=True) == 0x64dfb50
    call = 0x4dc5bc4
    assert call+5+int.from_bytes(reader(call+1, 4), 'little', signed=True) == 0x57f4ac0

verify(read)
controls = (0x57f4ad5, 0x57f4b53, 0x57f4bae, 0x57f4bd4, 0x4dc5bc5)
for changed in controls:
    def alter(address, length):
        data = bytearray(read(address, length))
        if address <= changed < address+length:
            data[changed-address] ^= 1
        return data
    try:
        verify(alter)
    except AssertionError:
        continue
    raise AssertionError(f'undetected mutation at {changed:#x}')

def selected_search(rows, key):
    if not rows:
        return 1, 0
    current, remaining = 0, len(rows)
    while remaining > 1:
        half = remaining // 2
        probe = current + half
        if rows[probe] <= key:
            current = probe
        remaining -= half
    row = rows[current]
    return int(row != key), current + int(row < key)

values = tuple(i.to_bytes(20, 'big') for i in range(0, 16, 2))
cases = 0
for size in range(len(values)+1):
    for rows in combinations(values, size):
        for i in range(16):
            key = i.to_bytes(20, 'big')
            assert selected_search(rows, key) == (int(key not in rows), bisect_left(rows, key))
            cases += 1
print(f'1 FDE, {len(pins)} windows, {len(controls)} corruption controls, {cases} ordered-key cases passed')
