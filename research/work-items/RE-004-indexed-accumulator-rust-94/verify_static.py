"""Bind the complete indexed accumulator and its exact full-RAX return."""
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
START, END = 0x514ac60, 0x514ac8c
BODY = '4aec06b08170d83e53cc0c7ffd81f0f74635ccdffa3ac1f23e993186096ccae9'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def listing(path, image):
    rows, cursor = [], START
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= END, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == END, 'complete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    cies, frames = eh_frame_records(data)
    raw, mapping = image.va_bytes(START, END - START, executable=True)
    require(sha(raw) == BODY, 'complete 44-byte body')
    rows = listing(PACKET / 'gnu.txt', image)
    require(rows == listing(PACKET / 'llvm.txt', image), 'GNU/LLVM boundaries')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = list(decoder.disasm(raw, START))
    require([(i.address, bytes(i.bytes)) for i in instructions] == rows, 'Capstone boundaries')
    require([(i.address, i.mnemonic, i.op_str) for i in instructions if i.mnemonic.startswith('j')]
            == [(0x514ac72, 'je', '0x514ac78')], 'branch closure')
    require(not any(i.mnemonic == 'call' for i in instructions), 'helper call')
    require([i.address for i in instructions if i.mnemonic == 'ret'] == [END - 1], 'return closure')

    def frame_record(begin, end):
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (begin, end),
                'complete unique FDE')
        frame, records = overlapping[0], {}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            value, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': value.hex()}
        require(records['cie']['hex'] == '1400000000000000017a5200017810011b0c070890010000',
                'CIE encoding/augmentation')
        return {'frame': frame, 'cie': cies[frame['cie']], 'records': records}

    frame = frame_record(START, END)
    require(frame['frame']['lsda'] is None, 'unexpected LSDA')
    neighbors = [frame_record(0x514ac40, START - 1), frame_record(END + 4, 0x514ac95)]
    require(image.va_bytes(START - 1, 1)[0] == b'\xcc', 'leading padding')
    require(image.va_bytes(END, 4)[0] == b'\xcc' * 4, 'following padding')
    naming, count, kinds = [], 0, {}
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, offset)
            kind = info & 0xffffffff
            require(kind in [1, 6, 7, 8, 18], 'unreviewed relocation width')
            require(not (destination < END + 4 and START - 1 < destination + 8), 'protected code relocation')
            if addend == START:
                naming.append({'slot': destination, 'kind': kind, 'symbol': info >> 32})
            count += 1; kinds[str(kind)] = kinds.get(str(kind), 0) + 1
    require(not naming, 'unexpected naming relocation')
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
    require(edges == {'e8': [], 'e9': []}, 'direct call/jump candidate census')
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'begin': START, 'end': END,
            'body_sha256': sha(raw), 'body_hex': raw.hex(), 'file_offset': mapping['file_offset'],
            'frame': frame, 'neighbors': neighbors, 'padding_before_hex': 'cc', 'padding_after_hex': 'cccccccc',
            'instructions': [{'va': i.address, 'hex': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic,
                              'operands': i.op_str} for i in instructions],
            'direct_encoding_candidates': edges, 'naming_relocations': naming,
            'rela_records_checked': count, 'rela_kinds': kinds, 'external_constant_data': [], 'callees': [],
            'complete_xref_census': False, 'capstone_version': capstone.__version__,
            'rax': 'loaded base + 8*sign_extended_index modulo 2^64, not the index',
            'captured_execution': False, 'instruction_emulation': False}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data); base = record['file_offset']
    changes = {'selector pointer load': base + 6, 'addend load': base + 9,
               'default index': base + 11, 'null branch': base + 19,
               'signed index load': base + 21, 'index displacement': base + 23,
               'base load': base + 26, 'RAX entry scale': base + 30,
               'counter displacement': base + 34, 'counter increment': base + 38,
               'sum displacement': base + 42, 'return': base + 43,
               'leading padding': base - 1, 'following padding': base + 44,
               'FDE range': record['frame']['records']['fde']['file_offset'] + 12,
               'CIE encoding': record['frame']['records']['cie']['file_offset'] + 15}
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
    print(json.dumps({'instructions': len(record['instructions']), 'controls': len(record['corruption_controls']),
                      'incoming_candidates': record['direct_encoding_candidates'], 'naming_slots': len(record['naming_relocations'])}))


if __name__ == '__main__':
    main()
