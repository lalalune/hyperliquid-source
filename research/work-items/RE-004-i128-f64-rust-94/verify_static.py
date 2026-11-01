"""Bind the complete signed conversion, its relocation and observed callers."""
import argparse
import json
import re
import struct
import sys

from oracle import ROOT, PACKET, require, sha
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
import capstone

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN, END, SLOT = 0x565f4f0, 0x565f598, 0x576f7c0
BODY = '9ad0f5b92a2985f8e1bf622bc4bf0a395637cb73463db282a38913ac51ee9362'
CALLS = [0x145f655, 0x1f98de5, 0x3cf7485, 0x4b00b0e, 0x4ead6d7, 0x4f6798c, 0x4f67efd]


def listing(path, image):
    rows, cursor = [], BEGIN
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= END, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == END, 'incomplete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, END - BEGIN, executable=True)
    require(sha(body) == BODY, 'complete conversion body')
    _, frames = eh_frame_records(data)
    def frame_at(start, end):
        overlaps = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlaps) == 1 and (overlaps[0]['start'], overlaps[0]['end']) == (start, end),
                'unique complete FDE')
        frame, records = overlaps[0], {}
        for kind in ('fde', 'cie'):
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, location = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': location['file_offset'], 'hex': raw.hex()}
        return frame, records
    frame, records = frame_at(BEGIN, END)
    rows = listing(PACKET / 'conversion.gnu.txt', image)
    require(rows == listing(PACKET / 'conversion.llvm.txt', image), 'decoder boundaries disagree')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(body, BEGIN))
    require([(x.address, bytes(x.bytes)) for x in instructions] == rows, 'Capstone body boundaries')
    require(not any(x.mnemonic.startswith(('j', 'call')) for x in instructions), 'unexpected control edge')
    require([x.address for x in instructions if x.mnemonic == 'ret'] == [END - 1], 'single terminal return')
    require(not any(o.type == capstone.x86.X86_OP_MEM for x in instructions for o in x.operands),
            'unexpected explicit data-memory operand')
    require(image.va_bytes(END, 8)[0] == b'\xcc' * 8, 'following padding')
    relocation = image.relative(SLOT)
    require(relocation['addend'] == BEGIN, 'slot target')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    direct, through_slot = [], []
    for prefix in (b'\xe8', b'\xff\x15', b'\xff\x25'):
        position = 0
        while (position := code.find(prefix, position)) >= 0:
            size = len(prefix) + 4
            if position + size <= len(code):
                destination = text['address'] + position + size + struct.unpack_from('<i', code, position + len(prefix))[0]
                if prefix == b'\xe8' and destination == BEGIN:
                    direct.append(text['address'] + position)
                elif prefix != b'\xe8' and destination == SLOT:
                    require(prefix == b'\xff\x15', 'unexpected RIP tail-jump candidate')
                    through_slot.append(text['address'] + position)
            position += 1
    require(direct == [] and sorted(through_slot) == CALLS, 'bounded xref candidates')
    callers = []
    for caller in frames:
        sites = [site for site in CALLS if caller['start'] <= site < caller['end']]
        if not sites:
            continue
        start, end = caller['start'], caller['end']
        cf, cr = frame_at(start, end)
        raw, where = image.va_bytes(start, end - start, executable=True)
        decoded = list(decoder.disasm(raw, start))
        require(sum(i.size for i in decoded) == len(raw), 'incomplete caller decode')
        selected = [i for i in decoded if i.address in sites]
        require([i.address for i in selected] == sites, 'call is not instruction aligned')
        for i in selected:
            require(i.mnemonic == 'call' and bytes(i.bytes[:2]) == b'\xff\x15' and
                    i.address + 6 + struct.unpack('<i', bytes(i.bytes[2:]))[0] == SLOT, 'caller slot edge')
        callers.append({'frame': cf, 'frame_records': cr, 'bytes': len(raw),
                        'file_offset': where['file_offset'], 'sha256': sha(raw),
                        'instructions': len(decoded),
                        'sites': [{'va': i.address, 'hex': i.bytes.hex(),
                                   'file_offset': where['file_offset'] + i.address - start} for i in selected]})
    require(sum(len(c['sites']) for c in callers) == len(CALLS), 'caller admission coverage')
    protected = [(BEGIN, END + 8), (SLOT, SLOT + 8)]
    count, writes, naming = 0, [], []
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            dest, info, addend = struct.unpack_from('<QQq', data, offset); count += 1
            if addend == BEGIN:
                naming.append(dest)
            if any(dest < hi and lo < dest + 8 for lo, hi in protected):
                require(dest == SLOT and info == 8 and addend == BEGIN, 'protected relocation')
                writes.append(offset)
    require(writes == [relocation['record_file_offset']] and naming == [SLOT], 'nonunique slot binding')
    return {'target_sha256': sha(data), 'target_bytes': len(data),
            'body': {'begin': BEGIN, 'end': END, 'bytes': len(body), 'hex': body.hex(), 'sha256': sha(body),
                     'file_offset': mapping['file_offset'], 'instructions': len(rows)},
            'frame': frame, 'frame_records': records, 'relocation': relocation,
            'callers': callers, 'direct_e8_candidates': direct, 'rip_slot_candidates': CALLS,
            'complete_xref_census': False, 'rela_records_checked': count,
            'explicit_external_leaf_data': [], 'capstone_version': capstone.__version__,
            'captured_code_executed': False, 'instruction_emulation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(sha(data) == TARGET, 'target identity')
    record = inspect(data)
    locations = {'body rounding': record['body']['file_offset'] + 0x77,
                 'body signed magnitude': record['body']['file_offset'] + 0x20,
                 'FDE extent': record['frame_records']['fde']['file_offset'] + 12,
                 'CIE encoding': record['frame_records']['cie']['file_offset'] + 15,
                 'slot addend': record['relocation']['record_file_offset'] + 16,
                 'padding': record['body']['file_offset'] + END - BEGIN,
                 'caller slot': record['callers'][0]['sites'][0]['file_offset'] + 2}
    rejected = {}
    for name, offset in locations.items():
        changed = bytearray(data); changed[offset] ^= 1
        try:
            modified = inspect(bytes(changed))
            require(modified == record, 'structural record drift')
        except ValueError as error:
            rejected[name] = str(error)
        else:
            raise ValueError('accepted corrupted ' + name)
    record['corruption_controls'] = rejected
    text = json.dumps(record, indent=2, sort_keys=True) + '\n'
    if args.write:
        with (PACKET / 'static.json').open('x') as file:
            file.write(text)
    else:
        require((PACKET / 'static.json').read_text() == text, 'retained static record drift')
    print(json.dumps({'instructions': record['body']['instructions'], 'callers': len(record['callers']),
                      'corruption_controls': rejected}, indent=2))


if __name__ == '__main__':
    main()
