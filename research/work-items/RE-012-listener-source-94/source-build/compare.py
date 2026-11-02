"""Compare complete source-built symbol bytes using only actual relocation fields."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone

TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x3cd6690, 0x3cd67c1
SYMBOL = '_ZN3mio3net3tcp8listener11TcpListener4bind17hff6dea028ce7a111E'
SLOTS = {0x5775210: 'socket', 0x576f0d0: 'setsockopt', 0x576e8d8: '__errno_location',
         0x5775220: 'bind', 0x5776450: 'listen', 0x576e708: 'close'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, why):
    if not ok:
        raise ValueError(why)


class Elf:
    def __init__(self, data, kind):
        self.data = data
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
        need(header[0][:7] == b'\x7fELF\x02\x01\x01' and header[1:3] == (kind, 62), 'ELF type')
        self.sh = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + i * header[11]) for i in range(header[12])]
        table = self.sh[header[13]]
        names = data[table[4]:table[4] + table[5]]
        self.names = [names[s[0]:].split(b'\0', 1)[0].decode() for s in self.sh]
        self.ph = [struct.unpack_from('<IIQQQQQQ', data, header[5] + i * header[9]) for i in range(header[10])]

    def contents(self, index):
        s = self.sh[index]
        return self.data[s[4]:s[4] + s[5]]

    def va(self, address, size):
        candidates = [p for p in self.ph if p[0] == 1 and p[3] <= address and address + size <= p[3] + p[5]]
        need(len(candidates) == 1, 'unique file PT_LOAD')
        p = candidates[0]
        offset = p[2] + address - p[3]
        return self.data[offset:offset + size], offset

    def symbols(self, index):
        section = self.sh[index]
        need(section[9] == 24, 'symbol record size')
        strings = self.contents(section[6])
        result = []
        for off in range(section[4], section[4] + section[5], 24):
            name, info, other, owner, value, size = struct.unpack_from('<IBBHQQ', self.data, off)
            result.append({'name': strings[name:].split(b'\0', 1)[0].decode(), 'info': info,
                           'other': other, 'section': owner, 'value': value, 'size': size})
        return result

    def relas(self):
        result = []
        for index, section in enumerate(self.sh):
            if section[1] != 4:
                continue
            need(section[9] == 24 and section[5] % 24 == 0, 'RELA shape')
            symbols = self.symbols(section[6])
            for offset in range(section[4], section[4] + section[5], 24):
                destination, info, addend = struct.unpack_from('<QQq', self.data, offset)
                symbol = symbols[info >> 32]
                result.append({'relocation_section': self.names[index], 'owner_section': section[7],
                               'file_offset': offset, 'offset': destination, 'kind': info & 0xffffffff,
                               'symbol_index': info >> 32, 'symbol': symbol['name'], 'addend': addend})
        return result


def masked(raw, fields):
    result = bytearray(raw)
    used = set()
    for field in fields:
        at = field['offset']
        need(0 <= at and at + 4 <= len(raw), 'mask bounds')
        need(not used.intersection(range(at, at + 4)), 'overlapping masks')
        used.update(range(at, at + 4))
        result[at:at + 4] = bytes(4)
    return bytes(result)


def compare(a, af, b, bf):
    # Relocation identity/order remains part of equality; only the four-byte
    # actual external GOT displacement fields are cleared.
    identity_a = [(x['offset'], x['symbol']) for x in af]
    identity_b = [(x['offset'], x['symbol']) for x in bf]
    return {'raw_equal': a == b, 'same_length': len(a) == len(b),
            'relocation_field_map_equal': identity_a == identity_b,
            'relocation_only_equal': len(a) == len(b) and identity_a == identity_b and masked(a, af) == masked(b, bf)}


def main(args):
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    target = args.target.read_bytes()
    need(sha(target) == TARGET_SHA and len(target) == 91774280, 'full target identity')
    elf = Elf(target, 3)
    body, target_offset = elf.va(START, END - START)
    (output / 'target-body.bin').write_bytes(body)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    target_ins = list(decoder.disasm(body, START))
    need(sum(i.size for i in target_ins) == len(body) and len(target_ins) == 81, 'target complete decode')
    relocations = elf.relas()
    fields = []
    imports = {}
    for ins in target_ins:
        if ins.mnemonic != 'call':
            continue
        need(bytes(ins.bytes)[:2] == b'\xff\x15' and ins.size == 6, 'target GOT call')
        displacement = struct.unpack_from('<i', ins.bytes, 2)[0]
        slot = ins.address + ins.size + displacement
        need(slot in SLOTS, 'expected named target slot')
        writers = [r for r in relocations if r['offset'] < slot + 8 and slot < r['offset'] + 8]
        need(len(writers) == 1 and writers[0]['offset'] == slot, 'one whole slot writer')
        writer = writers[0]
        need(writer['kind'] == 6 and writer['addend'] == 0 and writer['symbol'] == SLOTS[slot], 'GLOB_DAT named libc import')
        slot_raw, slot_file = elf.va(slot, 8)
        fields.append({'offset': ins.address - START + 2, 'width': 4, 'symbol': writer['symbol'],
                       'call_va': ins.address, 'got_slot_va': slot, 'target_slot_relocation': writer})
        imports[hex(slot)] = {'raw_hex': slot_raw.hex(), 'file_offset': slot_file, 'relocation': writer}
    need(len(fields) == 7 and len(imports) == 6, 'target call/import count')
    frame_index = elf.names.index('.eh_frame')
    frame = elf.sh[frame_index]
    offset, limit = frame[4], frame[4] + frame[5]
    cies, frames = {}, []
    while offset < limit:
        size = struct.unpack_from('<I', target, offset)[0]
        if size == 0:
            break
        need(4 <= size < 0xffffffff and offset + 4 + size <= limit, 'frame record bounds')
        va = frame[3] + offset - frame[4]
        back = struct.unpack_from('<I', target, offset + 4)[0]
        if back == 0:
            cies[va] = target[offset:offset + 4 + size]
        else:
            cie = va + 4 - back
            need(cie in cies and cies[cie][8:11] in (b'\x01zR', b'\x01zP'), 'known target CIE class')
            delta, extent = struct.unpack_from('<ii', target, offset + 8)
            start = va + 8 + delta
            frames.append({'fde': va, 'cie': cie, 'start': start, 'end': start + extent})
        offset += 4 + size
    overlaps = [f for f in frames if f['start'] < END and START < f['end']]
    need(len(frames) == 121299 and len(cies) == 3, 'complete FDE/CIE inventory')
    need({va: raw.hex() for va, raw in cies.items()} == {
        0xce1518: '1400000000000000017a5200017810011b0c070890010000',
        0xfbdc2c: '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000',
        0x1301ae8: '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000',
    }, 'all CIE encodings bound to pcrel sdata4')
    need(len(overlaps) == 1 and overlaps[0]['start'] == START and overlaps[0]['end'] == END, 'unique complete target FDE')
    record = overlaps[0]
    record['cie_hex'] = cies[record['cie']].hex()
    size = struct.unpack('<I', elf.va(record['fde'], 4)[0])[0] + 4
    record['fde_hex'] = elf.va(record['fde'], size)[0].hex()

    object_path = args.object
    object_raw = object_path.read_bytes()
    obj = Elf(object_raw, 1)
    symbols = obj.symbols(obj.names.index('.symtab'))
    matches = [s for s in symbols if s['name'] == SYMBOL]
    need(len(matches) == 1, 'one public TcpListener bind symbol')
    symbol = matches[0]
    source = obj.contents(symbol['section'])[symbol['value']:symbol['value'] + symbol['size']]
    source_relas = [r for r in obj.relas() if r['owner_section'] == symbol['section'] and symbol['value'] <= r['offset'] < symbol['value'] + symbol['size']]
    candidate_fields = []
    for relocation in source_relas:
        need(relocation['kind'] == 9 and relocation['addend'] == -4 and relocation['symbol'] in SLOTS.values(), 'actual candidate external GOTPCREL')
        at = relocation['offset'] - symbol['value']
        need(source[at - 2:at] == b'\xff\x15', 'relocation applies exactly to call displacement')
        candidate_fields.append({'offset': at, 'width': 4, 'symbol': relocation['symbol'], 'relocation': relocation})
    source_ins = list(decoder.disasm(source, 0))
    need(sum(i.size for i in source_ins) == len(source), 'complete candidate decode')
    (output / 'candidate-body.bin').write_bytes(source)
    (output / 'target-relocation-masked.bin').write_bytes(masked(body, fields))
    (output / 'candidate-relocation-masked.bin').write_bytes(masked(source, candidate_fields))
    result = compare(body, fields, source, candidate_fields)
    controls = {}
    controls['identity'] = compare(source, candidate_fields, source, candidate_fields)
    changed = bytearray(source); changed[candidate_fields[0]['offset']] ^= 1
    controls['actual_displacement_change'] = compare(source, candidate_fields, bytes(changed), candidate_fields)
    changed = bytearray(source); changed[0] ^= 1
    controls['nonrelocation_change'] = compare(source, candidate_fields, bytes(changed), candidate_fields)
    altered_fields = [dict(f) for f in candidate_fields]; altered_fields[0]['symbol'] = 'wrong_import'
    controls['import_identity_change'] = compare(source, candidate_fields, source, altered_fields)
    controls['truncation'] = compare(source, candidate_fields, source[:-1], candidate_fields)
    need(controls['identity']['raw_equal'] and controls['identity']['relocation_only_equal'], 'identity control')
    need(not controls['actual_displacement_change']['raw_equal'] and controls['actual_displacement_change']['relocation_only_equal'], 'actual relocation control')
    for name in ('nonrelocation_change', 'import_identity_change', 'truncation'):
        need(not controls[name]['relocation_only_equal'], 'control rejected: ' + name)
    record = {'target_sha256': sha(target), 'target_va': [START, END], 'target_bytes': len(body),
              'target_body_sha256': sha(body), 'target_file_offset': target_offset,
              'target_instruction_count': len(target_ins), 'target_fde': record,
              'target_relocation_count_scanned': len(relocations), 'target_imports': imports,
              'target_mask_fields': fields, 'object_sha256': sha(object_raw), 'symbol': symbol,
              'candidate_body_bytes': len(source), 'candidate_instruction_count': len(source_ins),
              'candidate_body_sha256': sha(source), 'candidate_mask_fields': candidate_fields,
              'comparison': result, 'complete_windows_compared': 1, 'raw_equal_windows': int(result['raw_equal']),
              'relocation_only_equal_windows': int(result['relocation_only_equal']),
              'unmatched_windows': int(not result['relocation_only_equal']), 'normalization_controls': controls,
              'no_arbitrary_immediate_or_opcode_or_branch_masks': True,
              'target_or_listener_execution': False, 'instruction_emulation': False}
    (output / 'comparison.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'target_bytes': len(body), 'candidate_bytes': len(source), 'comparison': result,
                      'target_calls': len(fields), 'candidate_calls': len(candidate_fields), 'controls': len(controls)}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    main(parser.parse_args())
