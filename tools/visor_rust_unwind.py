#!/usr/bin/env python3
"""One visor Rust-associated cleanup LSDA and its error-wrapper bindings; static only.

Native decode/relocation helpers adapt project-authored MIT code from PR #266,
commit65af927; this collector has no dependency on that unmerged branch.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records, uleb
from short_string_static import read_va

SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
RANGES = {'owner': (0x3c7ef0, 0x3c8056), 'option_error': (0x49ab90, 0x49aba9),
          'formatted_error': (0x49abb0, 0x49ac02),
          'literal_bridge': (0x49ade0, 0x49adf2), 'format_bridge': (0x49ae00, 0x49ae2c)}
LOCATIONS = {0x7af278: (0x3c7ff9, b'\x48\x8d\x3d', 17, 84),
             0x7af260: (0x3c801f, b'\x4c\x8d\x05', 17, 74)}
SOURCE = b'base/src/liner.rs'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256,
            'Not the pinned captured visor')


def decode_lines(text):
    records = {}
    for line in text.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)', line)
        if match:
            va = int(match[1], 16)
            if va in records:
                raise ValueError('Duplicate native instruction address')
            records[va] = (bytes.fromhex(match[2]), match[3].strip())
    return records


def call_target(va, body):
    if len(body) == 5 and body[0] == 0xE8:
        return 'direct', va+5+struct.unpack_from('<i', body, 1)[0]
    if len(body) == 6 and body[:2] == b'\xff\x15':
        return 'rip-slot', va+6+struct.unpack_from('<i', body, 2)[0]
    return 'register-indirect', None


def relocation(data, secs, slot):
    matches = []
    for section in secs:
        if section['type'] == 4:
            for p in range(section['offset'], section['offset']+section['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', data, p)
                if address == slot:
                    matches.append((info, addend))
    if len(matches) != 1:
        raise ValueError('Expected one relocation for selected slot')
    info, addend = matches[0]
    result = {'slot_va': hex(slot), 'type': info & 0xFFFFFFFF, 'addend': hex(addend)}
    symbol = info >> 32
    if symbol:
        names = {s['name']: s for s in secs}
        symtab, strings = names['.dynsym'], names['.dynstr']
        shoff = struct.unpack_from('<Q', data, 40)[0]
        stride = struct.unpack_from('<H', data, 58)[0]
        index_in_sections = next(i for i, s in enumerate(secs) if s['name'] == '.dynsym')
        entry_size = struct.unpack_from('<Q', data, shoff+stride*index_in_sections+56)[0]
        if entry_size != 24 or symbol*24+24 > symtab['size']:
            raise ValueError('Selected dynamic symbol is out of bounds')
        index = struct.unpack_from('<I', data, symtab['offset']+symbol*24)[0]
        if index >= strings['size']:
            raise ValueError('Selected dynamic name is out of bounds')
        start = strings['offset']+index
        end = data.find(b'\0', start, strings['offset']+strings['size'])
        if end < 0:
            raise ValueError('Unterminated selected dynamic name')
        result['symbol'] = data[start:end].decode('ascii')
    return result


def decode(data):
    """Both native tools read one owned, non-executable snapshot, never the target."""
    exports, decoded = {}, {}
    gnu_version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
    require('GNU objdump' in gnu_version, 'GNU objdump is required')
    llvm = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
    llvm_version = subprocess.check_output([llvm, '--version'], text=True).splitlines()[0]
    frame_version = subprocess.check_output(['readelf', '--version'], text=True).splitlines()[0]
    require('GNU readelf' in frame_version, 'GNU readelf is required')
    with tempfile.TemporaryDirectory(prefix='visor-unwind-') as folder:
        binary = Path(folder) / 'visor-static-input'
        binary.write_bytes(data)
        binary.chmod(0o400)
        for name, (begin, end) in RANGES.items():
            arguments = [f'--start-address={begin:#x}', f'--stop-address={end:#x}', str(binary)]
            gnu = subprocess.check_output(['objdump', '-d', '--insn-width=16', *arguments], text=True)
            other = subprocess.check_output([llvm, '-d', *arguments], text=True)
            one, two = decode_lines(gnu), decode_lines(other)
            require({a: b for a, (b, _) in one.items()} == {a: b for a, (b, _) in two.items()},
                    'Native instruction boundaries/bytes disagree')
            cursor = begin
            for address, (body, _) in one.items():
                require(address == cursor and body == read_va(data, address, len(body))[1],
                        'Native decode is incomplete or not from this snapshot')
                cursor += len(body)
            require(cursor == end, 'Native decode misses the declared end')
            decoded[name] = one
            exports[f'{name}.gnu.txt'] = gnu.replace(str(binary), '<authenticated-visor>')
            exports[f'{name}.llvm.txt'] = other.replace(str(binary), '<authenticated-visor>')
        frames = subprocess.check_output(['readelf', '--debug-dump=frames', str(binary)], text=True)
        selected = []
        observed = set()
        for block in frames.split('\n\n'):
            match = re.search(r'\bFDE\b.*\bpc=([0-9a-f]+)\.\.([0-9a-f]+)', block)
            if match and tuple(int(x, 16) for x in match.groups()) in RANGES.values():
                selected.append(block)
                observed.add(tuple(int(x, 16) for x in match.groups()))
        require(observed == set(RANGES.values()) and len(selected) == len(RANGES),
                'Independent readelf FDE extents disagree')
        exports['frames.txt'] = '\n\n'.join(selected) + '\n'
    return decoded, exports, {'gnu': gnu_version, 'llvm': llvm_version,
                             'readelf':frame_version,'python':platform.python_version()}


def cleanup_table(data, fde, upper, instructions):
    """Only the observed omit/omit/ULEB, action-zero cleanup format is supported."""
    begin, end = RANGES['owner']
    offset, raw = read_va(data, fde['lsda'], upper-fde['lsda'])
    require(raw[:3] == b'\xff\xff\x01', 'Unsupported cleanup LSDA header')
    length, p = uleb(raw, 3, len(raw))
    table_end = p + length
    require(table_end <= len(raw), 'Call-site table escapes LSDA upper bound')
    rows, previous = [], begin
    while p < table_end:
        fields, positions = [], []
        for _ in range(4):
            positions.append(p)
            value, p = uleb(raw, p, table_end)
            fields.append(value)
        start, size, pad, action = fields
        first, last = begin + start, begin + start + size
        landing = begin + pad if pad else None
        require(begin <= first < last <= end and first >= previous, 'Invalid call-site interval')
        require(first in instructions and (last == end or last in instructions),
                'Call-site boundary is inside an instruction')
        require(landing is None or landing in instructions, 'Landing pad is inside an instruction')
        require(action == 0, 'Nonzero action is outside this cleanup-only packet')
        rows.append({'start_va': hex(first), 'end_va': hex(last),
                     'landing_pad_va': hex(landing) if landing else None,
                     'action': action, 'field_offsets': positions})
        previous = last
    require(len(rows) == 3 and {r['landing_pad_va'] for r in rows if r['landing_pad_va']} == {'0x3c8038'},
            'Selected cleanup ownership changed')
    return {'va': hex(fde['lsda']), 'file_offset': hex(offset), 'upper_bound_va': hex(upper),
            'upper_bound_is_object_size': False, 'bytes_through_upper_bound': raw.hex(),
            'declared_table_end_va': hex(fde['lsda']+table_end), 'rows': rows}


def analyse(data, decoded):
    """Below-identity analysis is exposed for actual-ELF corruption controls only."""
    secs = sections(data)
    cies, fdes = eh_frame_records(data, secs)
    owned = {}
    for name, (begin, end) in RANGES.items():
        matches = [f for f in fdes if (f['start'], f['end']) == (begin, end)]
        require(len(matches) == 1, 'Expected one exact selected FDE')
        owned[name] = matches[0]
        cursor = begin
        for va, (body, _) in decoded[name].items():
            require(va == cursor and body == read_va(data, va, len(body))[1], 'Instruction snapshot mismatch')
            cursor += len(body)
        require(cursor == end, 'Incomplete selected decode')
    owner = owned['owner']
    exception = next(s for s in secs if s['name'] == '.gcc_except_table')
    require(owner['lsda'] is not None and exception['address'] <= owner['lsda'] < exception['address']+exception['size'],
            'Owner LSDA is outside exception section')
    upper = min([f['lsda'] for f in fdes if f['lsda'] and owner['lsda'] < f['lsda'] < exception['address']+exception['size']]
                + [exception['address']+exception['size']])
    lsda = cleanup_table(data, owner, upper, decoded['owner'])
    bindings = {}
    for slot, expected in {0x7e4de0: 0x49ab90, 0x7e4be0: 0x49abb0,
                           0x7e4c60: 0x49ade0, 0x7e4c00: 0x49ae00}.items():
        binding = relocation(data, secs, slot)
        require(binding == {'slot_va': hex(slot), 'type': 8, 'addend': hex(expected)},
                'Selected error-wrapper relocation changed')
        bindings[hex(slot)] = binding
    personality = relocation(data, secs, cies[owner['cie']]['personality_slot'])
    require(personality == {'slot_va': '0x7e9468', 'type': 8, 'addend': '0x696f30'},
            'Selected personality binding changed')
    require(sum(f['start'] == 0x696f30 for f in fdes) == 1, 'Personality is not one FDE start')

    locations = []
    for slot, (site, opcode, line, column) in LOCATIONS.items():
        body = decoded['owner'][site][0]
        require(body[:3] == opcode and len(body) == 7 and site+7+struct.unpack_from('<i', body, 3)[0] == slot,
                'Owner source-location reference changed')
        binding = relocation(data, secs, slot)
        require(binding['type'] == 8 and 'symbol' not in binding, 'Not a local Rust Location binding')
        source = int(binding['addend'], 16)
        length, actual_line, actual_column = struct.unpack('<QII', read_va(data, slot+8, 16)[1])
        require((length, actual_line, actual_column) == (len(SOURCE), line, column)
                and read_va(data, source, length)[1] == SOURCE, 'Rust Location contents changed')
        locations.append({'reference_va': hex(site), **binding, 'source': SOURCE.decode(),
                          'line': line, 'column': column})
    # An explicit Option::unwrap diagnostic binds the cold error helper without
    # trusting a stripped function name or the unlicensed inferred source tree.
    option = decoded['option_error']
    require(option[0x49ab94][0] == bytes.fromhex('4889fa')
            and option[0x49ab9e][0] == bytes.fromhex('be2b000000'), 'Option error arguments changed')
    literal = option[0x49ab97][0]
    require(literal[:3] == b'\x48\x8d\x3d' and len(literal) == 7, 'Option diagnostic reference changed')
    literal_va = 0x49ab9e + struct.unpack_from('<i', literal, 3)[0]
    diagnostic = read_va(data, literal_va, 43)[1]
    require(diagnostic == b'called `Option::unwrap()` on a `None` value', 'Option diagnostic changed')
    # These are the actual register-preservation, conditional cleanup arguments,
    # and exception handoff instructions; opaque helper behavior is not modeled.
    cleanup = {0x3c8038:'4989c7', 0x3c803b:'4885db', 0x3c803e:'740e',
               0x3c8040:'4c89f7', 0x3c8043:'4889de', 0x3c8046:'31d2', 0x3c804e:'4c89ff'}
    for va, body in cleanup.items():
        require(decoded['owner'][va][0].hex() == body, 'Cleanup/exception handoff instruction changed')

    calls = []
    for name, instructions in decoded.items():
        for va, (body, asm) in instructions.items():
            if not re.match(r'call\w*\s', asm):
                continue
            kind, target = call_target(va, body)
            require(target is not None, 'Unexpected register-indirect call in selected window')
            rows = [i for i, row in enumerate(lsda['rows']) if name == 'owner'
                    and int(row['start_va'], 16) <= va+len(body)-1 < int(row['end_va'], 16)]
            require(len(rows) <= 1, 'Call has overlapping LSDA rows')
            binding = relocation(data, secs, target) if kind == 'rip-slot' else None
            calls.append({'window': name, 'site_va': hex(va), 'bytes': body.hex(),
                          'kind': kind, 'target_or_slot_va': hex(target), 'binding': binding,
                          'return_pc_minus_one': hex(va+len(body)-1), 'lsda_row': rows[0] if rows else None})
    require(len(calls) == 12, 'Selected call denominator changed')
    required_edges = {0x3c8000:0x7e4de0, 0x3c8030:0x7e4be0, 0x3c8048:0x7e4b80,
                      0x49aba3:0x7e4c60, 0x49abfc:0x7e4c00, 0x49adec:0x7e4c00, 0x49ae26:0x7e6b78}
    for site, slot in required_edges.items():
        matches = [c for c in calls if c['site_va'] == hex(site)]
        require(len(matches) == 1 and matches[0]['kind'] == 'rip-slot'
                and matches[0]['target_or_slot_va'] == hex(slot), 'Error/cleanup call edge changed')
    for site in ('0x3c8000', '0x3c8030'):
        row = next(c['lsda_row'] for c in calls if c['site_va'] == site)
        require(row is not None and lsda['rows'][row]['landing_pad_va'] == '0x3c8038',
                'Source-associated error call no longer owns the cleanup pad')
    resume = next(c for c in calls if c['site_va'] == '0x3c8051')
    require(resume['kind'] == 'direct', 'Resume call is not direct')
    plt = int(resume['target_or_slot_va'], 16)
    stub = read_va(data, plt, 6)[1]
    require(stub[:2] == b'\xff\x25', 'Resume PLT is not a RIP jump')
    slot = plt + 6 + struct.unpack_from('<i', stub, 2)[0]
    resume_binding = relocation(data, secs, slot)
    require(resume_binding['type'] == 7 and resume_binding.get('symbol') == '_Unwind_Resume'
            and int(resume_binding['addend'], 16) == 0, 'Resume import binding changed')
    return {'target_sha256': hashlib.sha256(data).hexdigest(), 'target_bytes': len(data),
            'windows': {name: {'fde': {k:hex(v) if v is not None else None for k,v in fde.items()},
                               'file_offset': hex(read_va(data, fde['start'], 1)[0]),
                               'bytes': fde['end']-fde['start'], 'instructions':len(decoded[name]),
                               'sha256':hashlib.sha256(read_va(data,fde['start'],fde['end']-fde['start'])[1]).hexdigest()}
                        for name,fde in owned.items()},
            'owner_cie': cies[owner['cie']], 'opaque_personality_binding': personality,
            'locations': locations, 'option_diagnostic': {'va':hex(literal_va),'text':diagnostic.decode()},
            'wrapper_bindings':bindings, 'lsda':lsda, 'calls':calls,
            'resume':{'plt_va':hex(plt),'plt_bytes':stub.hex(),**resume_binding},
            'denominator':{'fdes':len(owned),'bytes':sum(end-begin for begin,end in RANGES.values()),
                           'instructions':sum(len(x) for x in decoded.values()),'calls':len(calls),
                           'owner_calls':sum(c['window']=='owner' for c in calls),
                           'owner_calls_with_cleanup':sum(c['window']=='owner' and c['lsda_row'] is not None
                                                         and lsda['rows'][c['lsda_row']]['landing_pad_va'] is not None for c in calls),
                           'call_site_intervals':len(lsda['rows']),'cleanup_pads':1},
            'limits':['Static metadata and decoded call/cleanup ownership only, not executed exception behavior.',
                      'No binary-wide panic strategy or compiler flags established.',
                      'Personality, allocator-shaped helper, retrieval/parser and final panic runtime remain opaque.',
                      'No first-party source recovery, Rust implementation, identity or component gate claim.']}


def collect(path):
    data = Path(path).read_bytes()
    authenticate(data)
    decoded, exports, versions = decode(data)
    return analyse(data, decoded), exports, versions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/visor/captured/hl-visor')
    parser.add_argument('--output', type=Path, default=ROOT/'work/visor-rust-unwind')
    args = parser.parse_args()
    facts, exports, versions = collect(args.binary)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, text in exports.items():
        (args.output/name).write_text(text)
    (args.output/'ownership.json').write_text(json.dumps(facts, indent=2)+'\n')
    (args.output/'toolchain.json').write_text(json.dumps(versions, indent=2)+'\n')
    print(json.dumps(facts['denominator'], sort_keys=True))


if __name__ == '__main__':
    main()

