'''RE-001 node #115: one FDE-bound LSDA header and its call-site table.

Static read-only analysis of the pinned Linux x86-64 node #115 image. The
module authenticates artifacts/node/115/hl-node against its required SHA-256
and size, parses the ELF section table, walks .eh_frame CIEs and FDEs, selects
a concrete FDE whose CIE declares an LSDA pointer encoding, then decodes the
referenced .gcc_except_table LSDA header and the complete call-site table.

The target binary is never executed, copied or emulated.
'''

import hashlib
import json
import os
import struct
import sys

TARGET = os.path.join('artifacts', 'node', '115', 'hl-node')
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
NUL = bytes([0])
ELF_MAGIC = bytes([0x7F, 0x45, 0x4C, 0x46])
PE_OMIT = 0xFF
FORMAT_SIZE = {0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}
SIGNED_FORMATS = (0x0A, 0x0B, 0x0C)
REQUIRED_SECTIONS = ('.text', '.eh_frame', '.gcc_except_table')


def read_uleb(blob, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(blob):
            raise ValueError('truncated uleb128 at offset %d' % pos)
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError('uleb128 wider than 64 bits')


def read_sleb(blob, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(blob):
            raise ValueError('truncated sleb128 at offset %d' % pos)
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos
        if shift > 63:
            raise ValueError('sleb128 wider than 64 bits')


def read_encoded(blob, pos, encoding, field_va, datarel_va=0, func_va=0):
    '''Decode one DW_EH_PE pointer; returns (value, next_pos, indirect).'''
    if encoding == PE_OMIT:
        return None, pos, False
    fmt = encoding & 0x0F
    app = encoding & 0x70
    indirect = bool(encoding & 0x80)
    if fmt == 0x00:
        if pos + 8 > len(blob):
            raise ValueError('truncated absptr at offset %d' % pos)
        raw = int.from_bytes(blob[pos:pos + 8], 'little')
        pos += 8
    elif fmt == 0x01:
        raw, pos = read_uleb(blob, pos)
    elif fmt == 0x09:
        raw, pos = read_sleb(blob, pos)
    elif fmt in FORMAT_SIZE:
        size = FORMAT_SIZE[fmt]
        if pos + size > len(blob):
            raise ValueError('truncated encoded pointer at offset %d' % pos)
        raw = int.from_bytes(blob[pos:pos + size], 'little',
                             signed=fmt in SIGNED_FORMATS)
        pos += size
    else:
        raise ValueError('unsupported pointer encoding 0x%02x' % encoding)
    if app == 0x00:
        value = raw
    elif app == 0x10:
        value = field_va + raw
    elif app == 0x30:
        value = datarel_va + raw
    elif app == 0x40:
        value = func_va + raw
    else:
        raise ValueError('unsupported pointer application 0x%02x' % app)
    return value, pos, indirect


def parse_sections(data):
    if data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        raise ValueError('not a little-endian ELF64 image')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3A)
    if shentsize < 64 or shnum == 0:
        raise ValueError('unusable section header table')
    sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        name_off, sh_type, flags, va, offset, size = struct.unpack_from(
            '<IIQQQQ', data, base)
        sections.append({'index': index, 'name_off': name_off,
                         'type': sh_type, 'flags': flags, 'va': va,
                         'offset': offset, 'size': size})
    strtab = sections[shstrndx]['offset']
    for section in sections:
        start = strtab + section['name_off']
        stop = data.index(NUL, start)
        section['name'] = data[start:stop].decode('utf-8')
    return sections


def parse_cie(blob, pos, base_va):
    cie = {'version': blob[pos]}
    pos += 1
    stop = blob.index(NUL, pos)
    augmentation = blob[pos:stop].decode('ascii')
    pos = stop + 1
    cie['augmentation'] = augmentation
    address_size = 8
    segment_size = 0
    if cie['version'] >= 4:
        address_size = blob[pos]
        segment_size = blob[pos + 1]
        pos += 2
    code_align, pos = read_uleb(blob, pos)
    data_align, pos = read_sleb(blob, pos)
    if cie['version'] == 1:
        return_register = blob[pos]
        pos += 1
    else:
        return_register, pos = read_uleb(blob, pos)
    cie.update({'address_size': address_size, 'segment_size': segment_size,
                'code_alignment': code_align, 'data_alignment': data_align,
                'return_address_register': return_register,
                'fde_encoding': 0x00, 'lsda_encoding': PE_OMIT,
                'personality': None, 'augmentation_data_length': None})
    if augmentation.startswith('z'):
        aug_len, pos = read_uleb(blob, pos)
        aug_end = pos + aug_len
        cie['augmentation_data_length'] = aug_len
        for char in augmentation[1:]:
            if char == 'R':
                cie['fde_encoding'] = blob[pos]
                pos += 1
            elif char == 'L':
                cie['lsda_encoding'] = blob[pos]
                pos += 1
            elif char == 'P':
                encoding = blob[pos]
                pos += 1
                value, pos, indirect = read_encoded(
                    blob, pos, encoding, base_va + pos)
                cie['personality'] = {'encoding': encoding, 'value': value,
                                      'indirect': indirect}
            elif char in ('S', 'B', 'G'):
                continue
            else:
                raise ValueError('unsupported CIE augmentation %r' % char)
        pos = max(pos, aug_end)
    cie['size'] = pos
    return cie


def parse_fde(blob, pos, cie, base_va):
    encoding = cie['fde_encoding']
    entry, pos, entry_indirect = read_encoded(blob, pos, encoding, base_va + pos)
    length, pos, length_indirect = read_encoded(
        blob, pos, encoding & 0x0F, base_va + pos)
    fde = {'entry': entry, 'range': length, 'end': None,
           'initial_location_encoding': encoding,
           'initial_location_indirect': entry_indirect,
           'range_indirect': length_indirect,
           'augmentation_data_length': None, 'lsda': None}
    if entry is not None and length is not None:
        fde['end'] = entry + length
    if cie['augmentation'].startswith('z'):
        aug_len, pos = read_uleb(blob, pos)
        aug_end = pos + aug_len
        fde['augmentation_data_length'] = aug_len
        if 'L' in cie['augmentation'][1:]:
            value, pos, indirect = read_encoded(
                blob, pos, cie['lsda_encoding'], base_va + pos)
            fde['lsda'] = {'encoding': cie['lsda_encoding'], 'value': value,
                           'indirect': indirect}
        pos = max(pos, aug_end)
    return fde, pos


def walk_eh_frame(blob, base_va):
    cies = {}
    fdes = []
    pos = 0
    total = len(blob)
    while pos + 4 <= total:
        start = pos
        length = struct.unpack_from('<I', blob, pos)[0]
        pos += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            length = struct.unpack_from('<Q', blob, pos)[0]
            pos += 8
        record_end = pos + length
        if record_end > total:
            raise ValueError('record at offset %d overruns .eh_frame' % start)
        cie_pointer = struct.unpack_from('<I', blob, pos)[0]
        if cie_pointer == 0:
            cie = parse_cie(blob, pos + 4, base_va)
            cie['record_offset'] = start
            cie['record_bytes_hex'] = blob[start:record_end].hex()
            cies[start] = cie
        else:
            cie_offset = pos - cie_pointer
            cie = cies.get(cie_offset)
            if cie is None:
                raise ValueError('FDE at %d references unknown CIE %d'
                                 % (start, cie_offset))
            fde, _pos = parse_fde(blob, pos + 4, cie, base_va)
            fde['record_offset'] = start
            fde['cie_record_offset'] = cie_offset
            fde['record_bytes_hex'] = blob[start:record_end].hex()
            fdes.append(fde)
        pos = record_end
    return cies, fdes


def decode_lsda(blob, lsda_va, section_va):
    pos = lsda_va - section_va
    if pos < 0 or pos >= len(blob):
        raise ValueError('LSDA pointer outside .gcc_except_table')
    header_start = pos
    lpstart_encoding = blob[pos]
    pos += 1
    lpstart_value = None
    if lpstart_encoding != PE_OMIT:
        lpstart_value, pos, _lp = read_encoded(
            blob, pos, lpstart_encoding, section_va + pos,
            datarel_va=section_va)
    ttype_encoding = blob[pos]
    pos += 1
    ttype_offset = None
    if ttype_encoding != PE_OMIT:
        ttype_offset, pos = read_uleb(blob, pos)
    call_site_encoding = blob[pos]
    pos += 1
    length_offset = pos - header_start
    table_length, pos = read_uleb(blob, pos)
    header_end = pos
    sites = []
    table_start = header_end
    remaining = table_length
    while remaining > 0:
        field_va = section_va + pos
        site_start, pos, _a = read_encoded(
            blob, pos, call_site_encoding, field_va)
        site_length, pos, _b = read_encoded(
            blob, pos, call_site_encoding, section_va + pos)
        landing, pos, _c = read_encoded(
            blob, pos, call_site_encoding, section_va + pos)
        action, pos = read_uleb(blob, pos)
        remaining = table_length - (pos - table_start)
        if remaining < 0:
            raise ValueError('call-site table overruns its declared length')
        sites.append({'index': len(sites),
                      'start_offset': site_start,
                      'byte_length': site_length,
                      'landing_pad': None if landing is None else '0x%x' % landing,
                      'action': action})
    if remaining != 0:
        raise ValueError('call-site table does not consume its length')
    return {'header': {
                'lpstart_encoding': lpstart_encoding,
                'lpstart_value': None if lpstart_value is None else '0x%x' % lpstart_value,
                'ttype_encoding': ttype_encoding,
                'ttype_offset': ttype_offset,
                'call_site_encoding': call_site_encoding,
                'call_site_table_length': table_length,
                'call_site_table_length_offset': length_offset,
                'call_site_table_offset': header_end - header_start,
                'header_bytes_hex': blob[header_start:header_end].hex()},
            'call_site_table_bytes_hex': blob[header_end:header_end + table_length].hex(),
            'call_sites': sites}


def negative_controls(eh_blob, eh_va, gcc_blob, gcc_va, lsda_va, record):
    results = []

    def expect_reject(name, func):
        try:
            func()
        except ValueError:
            results.append({'control': name, 'outcome': 'rejected'})
        else:
            results.append({'control': name, 'outcome': 'ACCEPTED'})

    corrupted = bytearray(eh_blob)
    corrupted[0:4] = (0xFFFFFFF0).to_bytes(4, 'little')
    expect_reject('eh-frame-record-length-overflow',
                  lambda: walk_eh_frame(bytes(corrupted), eh_va))
    expect_reject('lsda-pointer-outside-section',
                  lambda: decode_lsda(gcc_blob, gcc_va + len(gcc_blob), gcc_va))
    offset = lsda_va - gcc_va
    header = record['header']
    table_end = offset + header['call_site_table_offset'] + header['call_site_table_length']
    expect_reject('call-site-table-truncated',
                  lambda: decode_lsda(gcc_blob[:table_end - 1], lsda_va, gcc_va))
    mutated = bytearray(gcc_blob)
    length_pos = offset + header['call_site_table_length_offset']
    mutated[length_pos] = (header['call_site_table_length'] - 1) & 0x7F
    try:
        altered = decode_lsda(bytes(mutated), lsda_va, gcc_va)
    except ValueError:
        results.append({'control': 'declared-table-length-shortened',
                        'outcome': 'rejected'})
    else:
        if altered['header']['call_site_table_length'] != header['call_site_table_length']:
            results.append({'control': 'declared-table-length-shortened',
                            'outcome': 'changed'})
        else:
            results.append({'control': 'declared-table-length-shortened',
                            'outcome': 'UNCHANGED'})
    for entry in results:
        if entry['outcome'] not in ('rejected', 'changed'):
            raise ValueError('negative control %s did not discriminate: %s'
                             % (entry['control'], entry['outcome']))
    return results


def analyse(path=TARGET):
    with open(path, 'rb') as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('target digest %s is not the pinned %s'
                         % (digest, TARGET_SHA256))
    if len(data) != TARGET_SIZE:
        raise ValueError('target size %d is not the pinned %d'
                         % (len(data), TARGET_SIZE))
    sections = parse_sections(data)
    found = {}
    for section in sections:
        if section['name'] in REQUIRED_SECTIONS:
            found[section['name']] = section
    for name in REQUIRED_SECTIONS:
        if name not in found:
            raise ValueError('missing required section %s' % name)
    eh = found['.eh_frame']
    gcc = found['.gcc_except_table']
    eh_blob = data[eh['offset']:eh['offset'] + eh['size']]
    gcc_blob = data[gcc['offset']:gcc['offset'] + gcc['size']]
    cies, fdes = walk_eh_frame(eh_blob, eh['va'])
    eligible = []
    for fde in fdes:
        if fde['lsda'] is None or fde['lsda']['value'] in (None, 0):
            continue
        if fde['lsda']['indirect'] or fde['entry'] in (None, 0):
            continue
        lsda_va = fde['lsda']['value']
        if not (gcc['va'] <= lsda_va < gcc['va'] + gcc['size']):
            continue
        try:
            record = decode_lsda(gcc_blob, lsda_va, gcc['va'])
        except ValueError:
            continue
        declared = record['header']['call_site_table_length']
        if not 12 <= declared <= 127:
            continue
        if len(record['call_sites']) < 2:
            continue
        eligible.append((fde['entry'], fde, record))
    if not eligible:
        raise ValueError('no FDE with a bounded LSDA call-site table found')
    eligible.sort(key=lambda item: item[0])
    _entry, fde, record = eligible[0]
    cie = cies[fde['cie_record_offset']]
    lsda_va = fde['lsda']['value']
    controls = negative_controls(eh_blob, eh['va'], gcc_blob, gcc['va'],
                                 lsda_va, record)
    return {
        'target': {'path': TARGET, 'release': 115, 'sha256': digest,
                   'size': len(data)},
        'sections': {name: {'va': '0x%x' % found[name]['va'],
                            'file_offset': '0x%x' % found[name]['offset'],
                            'size': found[name]['size']}
                     for name in REQUIRED_SECTIONS},
        'eh_frame_census': {'cie_count': len(cies), 'fde_count': len(fdes),
                            'fdes_with_lsda': sum(1 for f in fdes if f['lsda']),
                            'eligible_call_site_fdes': len(eligible)},
        'cie': {'record_offset': '0x%x' % cie['record_offset'],
                'version': cie['version'],
                'augmentation': cie['augmentation'],
                'code_alignment': cie['code_alignment'],
                'data_alignment': cie['data_alignment'],
                'return_address_register': cie['return_address_register'],
                'fde_encoding': '0x%02x' % cie['fde_encoding'],
                'lsda_encoding': '0x%02x' % cie['lsda_encoding'],
                'personality': cie['personality'],
                'record_bytes_hex': cie['record_bytes_hex']},
        'fde': {'record_offset': '0x%x' % fde['record_offset'],
                'entry': '0x%x' % fde['entry'],
                'range': fde['range'], 'end': '0x%x' % fde['end'],
                'initial_location_encoding': '0x%02x' % fde['initial_location_encoding'],
                'augmentation_data_length': fde['augmentation_data_length'],
                'record_bytes_hex': fde['record_bytes_hex']},
        'lsda': {'va': '0x%x' % lsda_va,
                 'file_offset': '0x%x' % (gcc['offset'] + lsda_va - gcc['va']),
                 'encoding': '0x%02x' % fde['lsda']['encoding'],
                 'header': record['header'],
                 'call_site_table_bytes_hex': record['call_site_table_bytes_hex'],
                 'call_sites': record['call_sites']},
        'negative_controls': controls,
    }


def compare_recorded(recorded, derived, path=''):
    problems = []
    if isinstance(recorded, dict) and isinstance(derived, dict):
        for key in sorted(recorded):
            sub = path + '/' + key
            if key not in derived:
                problems.append('%s: recorded but not derived' % sub)
                continue
            problems.extend(compare_recorded(recorded[key], derived[key], sub))
    elif isinstance(recorded, list) and isinstance(derived, list):
        if len(recorded) != len(derived):
            problems.append('%s: recorded %d entries, derived %d'
                            % (path, len(recorded), len(derived)))
        else:
            for index, (left, right) in enumerate(zip(recorded, derived)):
                problems.extend(compare_recorded(left, right,
                                                 '%s[%d]' % (path, index)))
    elif recorded != derived:
        problems.append('%s: recorded %r, derived %r' % (path, recorded, derived))
    return problems


def main(argv):
    path = TARGET
    packet = None
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == '--target':
            path = args.pop(0)
        elif arg == '--packet':
            packet = args.pop(0)
        else:
            raise SystemExit('unexpected argument %r' % arg)
    derived = analyse(path)
    if packet is None:
        print(json.dumps(derived, indent=2, sort_keys=True))
        return 0
    with open(os.path.join(packet, 'evidence.json'), 'r', encoding='utf-8') as handle:
        evidence = json.load(handle)
    recorded = evidence.get('derived')
    problems = ['evidence.json has no derived block'] if recorded is None \
        else compare_recorded(recorded, derived)
    if problems:
        print('packet mismatch: %d field(s)' % len(problems))
        for problem in problems:
            print('  ' + problem)
        return 1
    print('packet matches the derived node #115 LSDA record')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
