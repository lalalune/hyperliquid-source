"""Bind the complete container pop/retreat transition, ordered loads/stores and caller."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import capstone

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, SITE = 0x5178be0, 0x5178c37, 0x508f33e
RANGES = [('window', START, END, '75452a99cb5494b32fa60fdadf25261f69374120431a4dbeaed1a02534c2d620'),
          ('caller', 0x508f300, 0x508f7ed, 'ad60ed412e260c470158986e6fa162569e2e851f713a03c96e7820d6eaca5c85')]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def listing(path, image, begin, end):
    rows, cursor = [], begin
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= end, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == end, 'complete listing')
    return rows


def inspect(data):
    image = Elf(data, 3); cies, frames = eh_frame_records(data)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    def frame_record(begin, end):
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (begin, end),
                'complete unique FDE')
        frame, records = overlapping[0], {}
        for kind in ['fde', 'cie']:
            address = frame[kind]; size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, mapping = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': mapping['file_offset'], 'hex': raw.hex()}
        return {'frame': frame, 'cie': cies[frame['cie']], 'records': records}
    bodies = {}
    for name, begin, end, digest in RANGES:
        raw, mapping = image.va_bytes(begin, end - begin, executable=True)
        require(sha(raw) == digest, name + ' complete body')
        rows = listing(PACKET / (name + '.gnu.txt'), image, begin, end)
        llvm = listing(PACKET / (name + '.llvm.txt'), image, begin, end)
        joined, prefixes, index = [], [], 0
        while index < len(llvm):
            address, value = llvm[index]
            if value == b'\xf0':
                require(index + 1 < len(llvm) and llvm[index + 1][0] == address + 1, 'LOCK prefix adjacency')
                prefixes.append(address); value += llvm[index + 1][1]; index += 1
            joined.append((address, value)); index += 1
        require(rows == joined, 'GNU/LLVM boundaries')
        decoded = list(decoder.disasm(raw, begin))
        require(rows == [(i.address, bytes(i.bytes)) for i in decoded], 'Capstone boundaries')
        if name == 'window':
            require([(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')] ==
                    [(0x5178bec, 'je', '0x5178c00')], 'branch closure')
            require(not any(i.mnemonic == 'call' for i in decoded), 'helper call')
            require([i.address for i in decoded if i.mnemonic == 'ret'] == [0x5178bfb, 0x5178c36], 'return closure')
        else:
            require([i.address for i in decoded if i.mnemonic == 'call' and i.op_str == hex(START)] == [SITE],
                    'caller boundary/target')
        bodies[name] = {**frame_record(begin, end), 'begin': begin, 'end': end, 'bytes': len(raw),
            'hex': raw.hex(), 'sha256': sha(raw), 'file_offset': mapping['file_offset'],
            'instruction_starts': [i.address for i in decoded], 'llvm_raw_rows': len(llvm),
            'llvm_joined_lock_prefix_rows': prefixes}
    require(bodies['window']['frame']['lsda'] is None, 'leaf LSDA')
    require(bodies['window']['records']['cie']['hex'] == '1400000000000000017a5200017810011b0c070890010000', 'leaf CIE')
    neighbors = [frame_record(0x5178b50, START - 7), frame_record(END + 9, 0x5178e43)]
    require(image.va_bytes(START - 7, 7)[0] == b'\xcc' * 7, 'leading padding')
    require(image.va_bytes(END, 9)[0] == b'\xcc' * 9, 'following padding')
    require(image.va_bytes(SITE - 7, 12)[0].hex() == '488dbf28020000e89d980e00', 'caller argument LEA and call')
    naming, count, kinds = [], 0, {}
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, offset); kind = info & 0xffffffff
            require(kind in [1, 6, 7, 8, 18], 'unreviewed relocation width')
            require(not any(destination < hi and lo < destination + 8 for lo, hi in
                            [(START - 7, END + 9), (RANGES[1][1], RANGES[1][2])]), 'protected code relocation')
            if addend == START:
                naming.append({'slot': destination, 'kind': kind, 'symbol': info >> 32})
            count += 1; kinds[str(kind)] = kinds.get(str(kind), 0) + 1
    require(not naming, 'entry naming relocation')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    edges = {}
    for opcode in [b'\xe8', b'\xe9']:
        hits, position = [], 0
        while (position := code.find(opcode, position)) >= 0:
            if position + 5 <= len(code) and text['address'] + position + 5 + struct.unpack_from('<i', code, position + 1)[0] == START:
                hits.append(text['address'] + position)
            position += 1
        edges[opcode.hex()] = hits
    require(edges == {'e8': [SITE], 'e9': []}, 'direct call/jump census')
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'bodies': bodies,
        'neighbors': neighbors, 'padding_before_hex': 'cc' * 7, 'padding_after_hex': 'cc' * 9,
        'direct_encoding_candidates': edges, 'naming_relocations': naming, 'rela_records_checked': count,
        'rela_kinds': kinds, 'callees': [], 'external_constant_data': [], 'complete_xref_census': False,
        'capstone_version': capstone.__version__, 'full_rax': 'new object+8 qword: old cursor-32 or post-top-store popped value+480, modulo 2^64',
        'captured_execution': False, 'instruction_emulation': False}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data); leaf = record['bodies']['window']; base = leaf['file_offset']
    changes = {'current load': base + 7, 'compare displacement': base + 11, 'equality branch': base + 12,
        'retreat distance': base + 17, 'retreat counter decrement': base + 22,
        'top load': base + 35, 'pop distance': base + 39, 'top store': base + 43,
        'post-store popped load': base + 47, 'pop counter decrement': base + 52,
        'pair increment': base + 57, 'first SIMD move': base + 64, 'pair pack': base + 77,
        'adjusted return': base + 73, 'pair store': base + 85,
        'leading padding': base - 1, 'following padding': base + 87,
        'leaf FDE': leaf['records']['fde']['file_offset'] + 12,
        'leaf CIE': leaf['records']['cie']['file_offset'] + 15,
        'caller target': record['bodies']['caller']['file_offset'] + SITE - RANGES[1][1] + 1,
        'caller FDE': record['bodies']['caller']['records']['fde']['file_offset'] + 12}
    rejected = {}
    for name, offset in changes.items():
        changed = bytearray(data); changed[offset] ^= 1
        try:
            inspect(bytes(changed))
        except ValueError as error:
            rejected[name] = str(error)
        else:
            raise ValueError('accepted corruption: ' + name)
    record['corruption_controls'] = rejected
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args(); record = validate(); raw = encoded(record)
    if args.freeze:
        with (PACKET / 'static.json').open('xb') as stream:
            stream.write(raw)
    else:
        require((PACKET / 'static.json').read_bytes() == raw, 'static record drift')
    print(json.dumps({'instructions': {k: len(v['instruction_starts']) for k, v in record['bodies'].items()},
                     'controls': len(record['corruption_controls']),
                     'llvm_prefixes': {k: v['llvm_joined_lock_prefix_rows'] for k, v in record['bodies'].items()}}))


if __name__ == '__main__':
    main()
