"""Bind all three keyword classifiers, their constants and complete direct callers."""
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
LEAVES = {
    'until': (0x1437b90, 0x1437be4, 0x13ba4c6, 0x14374a0, 0x1437b86, 0x1437bf0, 0x1437c00),
    'vip': (0x1e6d560, 0x1e6d5a6, 0x171c697, 0x1e6d4c0, 0x1e6d551, 0x1e6d5b0, 0x1e6db8a),
    'gas': (0x25903d0, 0x2590426, 0x18fa9ee, 0x25901e0, 0x25903c3, 0x2590430, 0x2590604),
}
RANGES = [
 ('until',0x1437b90,0x1437be4,'fb5d6795cd23e87c8f99d19d3e7e8ba5914b539e4eff8e40d5ad27802a8e7dad'),
 ('vip',0x1e6d560,0x1e6d5a6,'4a4b36a2203f581fa60aae1443c9c1fc047fb3c326d7ba5538eee3e904c6212b'),
 ('gas',0x25903d0,0x2590426,'ff09c1b1b3cec55658a533695cd1715b03df0788ebeed1dff6ca0e4dd4ffadf3'),
 ('until-caller',0x13b9560,0x13baf1a,'0fd77fe7e373ce9afba912915c9565ebecc9d517ab7e55f75ce1d3e0537be5d7'),
 ('vip-caller',0x171b780,0x171d0fd,'2ec71cc95d8c4f977f6799c80ec91c0125a939b58f1041f145a3705e65397009'),
 ('gas-caller',0x18f9940,0x18fb1d2,'f746497451e70d5305fb23c1f700a624df476fbd0730727e8ef55805c1241f44'),
]


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
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); decoder.detail = True
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
        if name in LEAVES:
            require(not any(i.mnemonic == 'call' for i in decoded), 'helper call')
            starts = {i.address for i in decoded}
            require(all(int(i.op_str,16) in starts for i in decoded if i.mnemonic.startswith('j')), 'branch closure')
            require(sum(i.mnemonic == 'ret' for i in decoded) == 3, 'three returns')
        else:
            leaf = name.removesuffix('-caller')
            require([i.address for i in decoded if i.mnemonic == 'call' and i.op_str == hex(LEAVES[leaf][0])] == [LEAVES[leaf][2]],
                    'caller boundary/target')
        bodies[name] = {**frame_record(begin, end), 'begin': begin, 'end': end, 'bytes': len(raw),
            'hex': raw.hex(), 'sha256': sha(raw), 'file_offset': mapping['file_offset'],
            'instruction_starts': [i.address for i in decoded], 'llvm_raw_rows': len(llvm),
            'llvm_joined_lock_prefix_rows': prefixes}
    neighbors, padding = {}, {}
    for name,(begin,end,site,prev_begin,prev_end,next_begin,next_end) in LEAVES.items():
        require(bodies[name]['frame']['lsda'] is None, 'leaf LSDA')
        require(bodies[name]['records']['cie']['hex'] == '1400000000000000017a5200017810011b0c070890010000', 'leaf CIE')
        neighbors[name] = [frame_record(prev_begin,prev_end),frame_record(next_begin,next_end)]
        before = image.va_bytes(prev_end,begin-prev_end)[0];after = image.va_bytes(end,next_begin-end)[0]
        require(before == b'\xcc' * len(before) and after == b'\xcc' * len(after), 'padding')
        padding[name] = {'before_hex':before.hex(),'after_hex':after.hex()}
    # PCMPEQB uses one immutable 16-byte comparand; short literals are bound
    # in the complete instruction bytes, not inferred from a string search.
    require(image.va_bytes(0x1437bbe,8)[0].hex() == '660f74054acfdcfe', 'SIMD operand encoding')
    require(0x1437bc6 + struct.unpack('<i',image.va_bytes(0x1437bc2,4)[0])[0] == 0x204b10, 'SIMD constant target')
    constant, mapping = image.va_bytes(0x204b10,16)
    require(constant == b'required_matches', 'SIMD constant bytes')
    require(mapping['section']['name'] == '.rodata' and not mapping['section']['flags'] & 1, 'readonly comparand')
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
                            [(a,b) for _,a,b,_ in RANGES] + [(0x204b10,0x204b20)]), 'protected code relocation')
            if addend in [v[0] for v in LEAVES.values()]:
                naming.append({'slot': destination, 'kind': kind, 'symbol': info >> 32})
            count += 1; kinds[str(kind)] = kinds.get(str(kind), 0) + 1
    require(not naming, 'entry naming relocation')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    edges = {}
    for name,(begin,_,site,*_) in LEAVES.items():
        candidates = {}
        for opcode in [b'\xe8', b'\xe9']:
            hits,position = [],0
            while (position := code.find(opcode,position)) >= 0:
                if position+5 <= len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0] == begin:
                    hits.append(text['address']+position)
                position += 1
            candidates[opcode.hex()] = hits
        require(candidates == {'e8':[site],'e9':[]}, 'direct call/jump census')
        edges[name] = candidates
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'neighbors':neighbors,'padding':padding,
        'constant':{'va':0x204b10,'hex':constant.hex(),'file_offset':mapping['file_offset'],'sha256':sha(constant)},
        'direct_encoding_candidates':edges,'naming_relocations':naming,'rela_records_checked':count,'rela_kinds':kinds,
        'callees':[],'complete_xref_census':False,'capstone_version':capstone.__version__,
        'full_rax':'incoming output pointer on every normal return',
        'captured_execution':False,'instruction_emulation':False}


def validate():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data); changes = {}
    for name, offsets in {'until':[0,6,12,17,23,28,36,49,52,58,76],
                          'vip':[0,6,12,19,28,34,41,48,53,63],
                          'gas':[0,6,12,17,23,28,36,44,57,66,78]}.items():
        leaf = record['bodies'][name]
        for offset in offsets:
            changes[f'{name} body+{offset}'] = leaf['file_offset'] + offset
        changes[name+' following padding'] = leaf['file_offset'] + leaf['bytes']
        changes[name+' FDE'] = leaf['records']['fde']['file_offset']+12
        caller = record['bodies'][name+'-caller']
        changes[name+' caller FDE'] = caller['records']['fde']['file_offset']+12
        changes[name+' caller target'] = caller['file_offset']+LEAVES[name][2]-caller['begin']+1
    changes['shared CIE'] = record['bodies']['until']['records']['cie']['file_offset']+15
    changes['SIMD comparand'] = record['constant']['file_offset']+8
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
