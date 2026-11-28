from hashlib import sha256
from pathlib import Path
from struct import unpack
from elf_index import unwind_index
from fde_extents import eh_frame_records

binary = Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(binary).hexdigest() == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sections, _ = unwind_index(binary)
_, entries = eh_frame_records(binary, sections)
assert any(e['start'] == 0x5181da0 and e['end'] == 0x51821a5 for e in entries)

def read(address, length):
    section = next(s for s in sections if s['name'] in ('.text', '.rodata') and
                   s['address'] <= address <= s['address'] + s['size'] - length)
    offset = section['offset'] + address - section['address']
    return binary[offset:offset+length]

pins = {
    0x5181fd3: '4d3b7d10', 0x5181fe7: '0f8468010000',
    0x5181ff1: '49c1e705', 0x5181ff5: '420fb644381d',
    0x5181ffb: '4883f807', 0x5181fff: '0f835f010000',
    0x5182005: 'b90600000029c1c1e103', 0x518200f: '488d05aa9779fb',
    0x5182016: 'f20f101401', 0x518201d: '488b4424484885c00f95c1',
    0x5182035: '660f62dc', 0x5182041: '660f5cdd', 0x5182051: 'f20f5ec2',
    0x5182055: 'f30f7e742450660f62f4660f5cf5', 0x51820b3: 'f20f5eda',
    0x5182128: 'f20f115b28', 0x5182131: '48890bf20f114308',
}

def verify(reader):
    for address, encoded in pins.items():
        expected = bytes.fromhex(encoded)
        assert reader(address, len(expected)) == expected, hex(address)
    address = 0x518200f
    target = address + 7 + int.from_bytes(reader(address+3, 4), 'little', signed=True)
    assert target == 0x91b7c0
    assert unpack('<7d', reader(target, 56)) == tuple(10.0**i for i in range(7))

verify(read)
controls = (0x5181ff8, 0x5182006, 0x5182053, 0x51820b5, 0x518212c, 0x91b7c0)
for bad in controls:
    def mutate(address, length):
        data = bytearray(read(address, length))
        if address <= bad < address + length:
            data[bad-address] ^= 1
        return data
    try:
        verify(mutate)
    except AssertionError:
        continue
    raise AssertionError(f'undetected corruption at {bad:#x}')
print(f'1 FDE, {len(pins)} instruction windows, seven table entries, {len(controls)} corruption controls passed')
