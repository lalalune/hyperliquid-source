"""Bind the complete three-path pair leaf and actual relocated entry slot."""
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
START, END, SLOT = 0x50fa260, 0x50fa2b2, 0x575ad00
BODY = 'fcf7a2d87a78a0f531aa367f3ed4af90ae5959f7dd62a7856a7b07906e341d98'


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
            rows.append((address, raw))
            cursor += len(raw)
    require(cursor == END, 'complete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    cies, frames = eh_frame_records(data)
    def frame_record(begin, end):
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (begin, end), 'unique complete FDE')
        frame, records = overlapping[0], {}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': raw.hex()}
        return {'frame': frame, 'cie': cies[frame['cie']], 'records': records}
    raw, where = image.va_bytes(START, END - START, executable=True)
    require(sha(raw) == BODY, 'complete body')
    rows = listing(PACKET / 'window.gnu.txt', image)
    require(rows == listing(PACKET / 'window.llvm.txt', image), 'GNU/LLVM boundaries')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoded = list(decoder.disasm(raw, START))
    require(rows == [(i.address, bytes(i.bytes)) for i in decoded], 'Capstone boundaries')
    require(not any(i.mnemonic == 'call' for i in decoded), 'leaf calls')
    branches = [(i.address, i.mnemonic, int(i.op_str, 16)) for i in decoded if i.mnemonic.startswith('j')]
    require(branches == [(START+11, 'je', START+64), (START+34, 'je', START+56), (START+60, 'jmp', START+36)], 'exact branch closure')
    require([i.address for i in decoded if i.mnemonic == 'ret'] == [START+52, END-1], 'two return sites')
    body = {**frame_record(START, END), 'begin': START, 'end': END, 'hex': raw.hex(),
            'bytes': len(raw), 'sha256': sha(raw), 'file_offset': where['file_offset'],
            'instructions': [{'address': i.address, 'bytes': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in decoded]}
    neighbors = [frame_record(0x50fa170, 0x50fa251), frame_record(0x50fa2c0, 0x50fa45d)]
    require(image.va_bytes(START-15, 15)[0] == b'\xcc'*15, 'leading padding')
    require(image.va_bytes(END, 14)[0] == b'\xcc'*14, 'following padding')
    slot_bytes, slot_mapping = image.va_bytes(SLOT, 8)
    require(slot_bytes == bytes(8) and slot_mapping['section']['name'] == '.data.rel.ro', 'entry slot initial storage')
    relocations, count = [], 0
    protected = [(START-15, END+14)]
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for at in range(section['offset'], section['offset']+section['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', data, at)
            kind, symbol = info & 0xffffffff, info >> 32
            count += 1
            require(kind in [1, 6, 7, 8, 18], 'unreviewed relocation width')
            require(not any(dest < end and begin < dest+8 for begin, end in protected), 'code relocation')
            if addend == START or (dest < SLOT+8 and SLOT < dest+8):
                require(addend == START and dest == SLOT and kind == 8 and symbol == 0 and section['name'] == '.rela.dyn', 'exact RELATIVE entry slot')
                relocations.append({'file_offset': at, 'hex': data[at:at+24].hex(), 'destination': dest,
                                    'type': kind, 'symbol': symbol, 'addend': addend})
    require(len(relocations) == 1, 'unique entry naming relocation')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    edges = {}
    for opcode in [b'\xe8', b'\xe9']:
        hits, position = [], 0
        while (position := code.find(opcode, position)) >= 0:
            if position+5 <= len(code) and text['address']+position+5+struct.unpack_from('<i', code, position+1)[0] == START:
                hits.append(text['address']+position)
            position += 1
        require(not hits, 'unexpected direct edge candidate')
        edges[opcode.hex()] = hits
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'body': body, 'neighbors': neighbors,
            'leading_padding_hex': 'cc'*15, 'following_padding_hex': 'cc'*14, 'branches': branches,
            'slot': {'va': SLOT, 'file_hex': slot_bytes.hex(), 'mapping': slot_mapping, 'relocation': relocations[0]},
            'rela_records_checked': count, 'direct_encoding_candidates': edges,
            'complete_xref_census': False, 'capstone_version': capstone.__version__,
            'captured_execution': False, 'instruction_emulation': False}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data)
    body, slot = record['body'], record['slot']
    changes = {f'body operand+{n}': body['file_offset']+n for n in [6, 10, 12, 15, 19, 23, 30, 35, 39, 45, 48, 51, 59, 61, 67, 74, 80]}
    changes.update({'FDE extent': body['records']['fde']['file_offset']+12,
                    'CIE encoding': body['records']['cie']['file_offset']+15,
                    'leading padding': body['file_offset']-1,
                    'following padding': body['file_offset']+82,
                    'previous FDE': record['neighbors'][0]['records']['fde']['file_offset']+12,
                    'next FDE': record['neighbors'][1]['records']['fde']['file_offset']+12,
                    'entry slot bytes': slot['mapping']['file_offset'],
                    'relocation destination': slot['relocation']['file_offset'],
                    'relocation kind': slot['relocation']['file_offset']+8,
                    'relocation symbol': slot['relocation']['file_offset']+12,
                    'relocation addend': slot['relocation']['file_offset']+16})
    rejected = {}
    for label, at in changes.items():
        changed = bytearray(data)
        changed[at] ^= 1
        try:
            other = inspect(bytes(changed))
            require({k: v for k, v in other.items() if k != 'target_sha256'} == {k: v for k, v in record.items() if k != 'target_sha256'}, 'structural drift')
        except ValueError as error:
            rejected[label] = str(error)
        else:
            raise ValueError('accepted corruption '+label)
    record['corruption_controls'] = rejected
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    record = validate()
    if args.freeze:
        with (PACKET / 'static.json').open('xb') as file:
            file.write(encoded(record))
    else:
        require((PACKET / 'static.json').read_bytes() == encoded(record), 'static drift')
    print(json.dumps({'instructions': len(record['body']['instructions']), 'controls': len(record['corruption_controls']), 'slot': hex(SLOT)}))


if __name__ == '__main__':
    main()
