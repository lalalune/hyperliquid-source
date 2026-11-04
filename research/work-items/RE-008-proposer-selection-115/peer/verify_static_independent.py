#!/usr/bin/env python3
"""Read only the authenticated ELF and recorded facts; do not execute the target."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

def require(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

ap = argparse.ArgumentParser()
ap.add_argument('--root', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
args = ap.parse_args()
root, out = args.root.resolve(), args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
packet = root / 'research/work-items/RE-008-proposer-selection-115'
target = root / 'artifacts/node/115/hl-node'
data = target.read_bytes()
require(sha(data) == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', 'target digest')
require(data[:6] == b'\x7fELF\x02\x01', 'not little-endian ELF64')
offset = struct.unpack_from('<Q', data, 40)[0]
stride, count, strings_index = struct.unpack_from('<HHH', data, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * stride) for i in range(count)]

def read(va, size):
    matches = [s for s in sections if s[3] <= va and va + size <= s[3] + s[5]]
    require(len(matches) == 1, 'ambiguous VA span')
    s = matches[0]
    require(s[1] != 8, 'no file bytes in NOBITS')
    begin = s[4] + va - s[3]
    return data[begin:begin + size]

relas = []
for sec in sections:
    if sec[1] != 4:
        continue
    require(sec[9] == 24 and sec[5] % 24 == 0, 'RELA stride')
    symtab = sections[sec[6]]
    names = sections[symtab[6]]
    for pos in range(sec[4], sec[4] + sec[5], 24):
        va, info, addend = struct.unpack_from('<QQq', data, pos)
        symbol_index = info >> 32
        symbol = None
        if symbol_index:
            name = struct.unpack_from('<I', data, symtab[4] + symbol_index * symtab[9])[0]
            begin = names[4] + name
            symbol = data[begin:data.index(0, begin)].decode('ascii')
        relas.append({'address': va, 'kind': info & 0xffffffff, 'addend': addend,
                      'symbol': symbol, 'file_offset': pos})

record = json.loads(gzip.decompress((packet / 'bindings.json.gz').read_bytes()))
bodies = record['bodies'] + [r['body'] for r in record['incoming']]
require(len({b['start'] for b in bodies}) == 34, 'body inventory')
allowed_cies = {
    bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'),
    bytes.fromhex('1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'),
}
commands, instruction_total, starts_by_body = [], 0, {}
for b in bodies:
    raw = read(b['start'], b['end'] - b['start'])
    require(raw.hex() == b['hex'] and sha(raw) == b['sha256'], 'complete body bytes')
    f = b['fde']; length = struct.unpack('<I', read(f, 4))[0]
    fde = read(f, length + 4)
    require(fde.hex() == b['fde_hex'], 'FDE raw record')
    cie = f + 4 - struct.unpack_from('<I', fde, 4)[0]
    c_length = struct.unpack('<I', read(cie, 4))[0]
    c_raw = read(cie, c_length + 4)
    require(cie == b['cie'] and c_raw in allowed_cies and c_raw.hex() == b['cie_hex'], 'CIE encoding')
    # Both independently inspected CIEs above declare FDE encoding0x1b:
    # PC-relative signed32 start and unsigned size using the same low format.
    start = f + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require((start, start + extent) == (b['start'], b['end']), 'actual FDE start/extent')
    argv = ['/opt/homebrew/opt/binutils/bin/objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start}', f'--stop-address={start+extent}', str(target)]
    result = subprocess.run(argv, capture_output=True)
    label = f'{start:x}'
    (out / (label + '.gnu.txt')).write_bytes(result.stdout)
    (out / (label + '.stderr')).write_bytes(result.stderr)
    require(result.returncode == 0 and not result.stderr, 'GNU decode failed')
    parsed = []
    for line in result.stdout.decode().splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
        if m:
            parsed.append((int(m[1], 16), bytes.fromhex(m[2])))
    cursor = start
    for address, bs in parsed:
        require(address == cursor and bool(bs), 'GNU gap/duplicate row')
        cursor += len(bs)
    require(cursor == start + extent, 'GNU full coverage')
    require(parsed == [(r[0], bytes.fromhex(r[1])) for r in b['instructions']], 'fresh instruction starts/bytes')
    starts_by_body[start] = {a: bs for a, bs in parsed}
    instruction_total += len(parsed)
    commands.append({'start': hex(start), 'end': hex(start + extent), 'argv': argv,
                     'exit_code': result.returncode, 'stdout_sha256': sha(result.stdout),
                     'stderr_sha256': sha(result.stderr), 'instructions': len(parsed)})

slot = 0x64e86f0
writers = [r for r in relas if r['address'] < slot + 8 and slot < r['address'] + 8]
require(len(writers) == 1 and writers[0]['address'] == slot and writers[0]['kind'] == 8
        and writers[0]['addend'] == 0x595cb30, 'unique complete naming-slot writer')
require(read(slot, 8) == bytes(8), 'file naming-slot word')
incoming = []
for row in record['incoming']:
    starts = starts_by_body[row['body']['start']]
    for edge in row['sites']:
        bs = starts[edge['site']]
        require(bs[:2] == b'\xff\x15' and len(bs) == 6, 'not actual FF15 instruction')
        resolved = edge['site'] + 6 + int.from_bytes(bs[2:], 'little', signed=True)
        require(resolved == slot, 'wrong incoming slot')
        incoming.append(hex(edge['site']))
require(len(incoming) == 8, 'incoming count')
for span in record['data_spans']:
    require(read(span['address'], span['length']).hex() == span['hex'], 'data span')
for table in record['history_jump_tables']:
    raw = read(table['address'], 16)
    require(raw.hex() == table['hex'], 'jump table raw')
    require([table['address'] + x for x in struct.unpack('<4i', raw)] == table['targets'], 'table targets')
names = [r for r in relas if r['kind'] == 8 and r['addend'] in {b['start'] for b in record['bodies']}]
require(names == record['naming_relocations'], 'all selected naming RELAs')
summary = {'status': 'PASS', 'target_sha256': sha(data), 'full_bodies': len(bodies),
           'bytes': sum(b['length'] for b in bodies), 'instructions': instruction_total,
           'all_rela_records': len(relas), 'unique_entry_slot_writer': writers,
           'incoming_instruction_sites': incoming, 'source_sha256': sha((packet/'rust/lib.rs').read_bytes()),
           'limits': 'Independent ELF/FDE/GNU byte authentication of selected extents and named calls, not a new exhaustive call census or captured execution.'}
(out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
(out/'static-review.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
