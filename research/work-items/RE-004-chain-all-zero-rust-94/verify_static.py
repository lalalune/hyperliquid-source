"""Bind the complete flag-gated chain predicate, CFG and sole direct caller."""
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
START, END, SITE = 0x51a5d60, 0x51a5da8, 0x51fd9e5
RANGES = [('window', START, END, '80708970d69bcb62f58f3ae6811f4f5b13f4834362ff3c4308100775c8ff80c4'),
          ('caller', 0x51fd4c0, 0x51fe69d, 'ed7cf74c69dd8c7e8571c108aa942006c57e8a91688f7c50cc16cf5912fc84da')]


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
                    [(0x51a5d6d, 'jne', '0x51a5d98'), (0x51a5d76, 'jne', '0x51a5d88'),
                     (0x51a5d78, 'jmp', '0x51a5da0'), (0x51a5d86, 'je', '0x51a5da0'),
                     (0x51a5d8d, 'je', '0x51a5d80')], 'branch closure')
            require(not any(i.mnemonic == 'call' for i in decoded), 'helper call')
            require([i.address for i in decoded if i.mnemonic == 'ret'] ==
                    [0x51a5d91, 0x51a5d9c, 0x51a5da7], 'return closure')
        else:
            require([i.address for i in decoded if i.mnemonic == 'call' and i.op_str == hex(START)] == [SITE],
                    'caller boundary/target')
        bodies[name] = {**frame_record(begin, end), 'begin': begin, 'end': end, 'bytes': len(raw),
            'hex': raw.hex(), 'sha256': sha(raw), 'file_offset': mapping['file_offset'],
            'instruction_starts': [i.address for i in decoded], 'llvm_raw_rows': len(llvm),
            'llvm_joined_lock_prefix_rows': prefixes}
    require(bodies['window']['frame']['lsda'] is None, 'leaf LSDA')
    require(bodies['window']['records']['cie']['hex'] == '1400000000000000017a5200017810011b0c070890010000', 'leaf CIE')
    neighbors = [frame_record(0x51a5b20, START - 14), frame_record(END + 8, 0x51a5f09)]
    require(image.va_bytes(START - 14, 14)[0] == b'\xcc' * 14, 'leading padding')
    require(image.va_bytes(END, 8)[0] == b'\xcc' * 8, 'following padding')
    require(image.va_bytes(SITE, 7)[0].hex() == 'e87683faff84c0', 'caller call and AL test')
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
                            [(START - 14, END + 8), (RANGES[1][1], RANGES[1][2])]), 'protected code relocation')
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
        'neighbors': neighbors, 'padding_before_hex': 'cc' * 14, 'padding_after_hex': 'cc' * 8,
        'direct_encoding_candidates': edges, 'naming_relocations': naming, 'rela_records_checked': count,
        'rela_kinds': kinds, 'callees': [], 'external_constant_data': [], 'complete_xref_census': False,
        'capstone_version': capstone.__version__, 'full_rax': '0 or 1 on every normal return',
        'captured_execution': False, 'instruction_emulation': False}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data); leaf = record['bodies']['window']; base = leaf['file_offset']
    changes = {'root load': base + 6, 'flag displacement': base + 10, 'flag branch': base + 13,
        'head displacement': base + 18, 'head null gate': base + 22, 'link load': base + 34,
        'node null gate': base + 38, 'field displacement': base + 43, 'field branch': base + 45,
        'zero full-register return': base + 49, 'flag-set clear': base + 57,
        'terminal one': base + 65, 'leading padding': base - 1, 'following padding': base + 72,
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
