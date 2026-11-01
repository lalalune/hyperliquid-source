#!/usr/bin/env python3
"""Collect bounded static evidence; never execute or interpret captured code."""
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REL = 'artifacts/node/94/hl-node'
RANGES = {'constructor': (74786960, 74792287),
 'wrapper': (78278896, 78279505),
 'result-field': (77336336, 77336822),
 'index-4aa7fc0': (78282688, 78283355),
 'index-4aa7810': (78280720, 78281386),
 'index-4aa6e60': (78278240, 78278886),
 'index-4aa8bf0': (78285808, 78286417),
 'index-4aa89b0': (78285232, 78285795),
 'index-4aa95b0': (78288304, 78288913),
 'index-4aa7ab0': (78281392, 78282059),
 'field-finalizer': (82580464, 82580951),
 'insert-context': (75169744, 75170219),
 'builder-cleanup-context': (74669264, 74669595),
 'allocator': (88868528, 88868722)}
# Fixed scout-selected witnesses; each is checked below the target hash gate.
ANCHORS = {'niche-base': (74786977, '49bc0300000000000080'),
 'select': (74786995, '4831c14885c0b827000000480f48c1'),
 'dispatch': (74787020, '486304814801c8ffe0'),
 'field-result-test': (74791300, '4885c07427'),
 'field-error-store': (74791305, '488943084983c4024c8923'),
 'builder-cleanup-call': (74791321, 'e83223feff'),
 'constructor-return': (74791326, '4889d84881c4d80000005b415c415e415fc3'),
 'finalizer-call': (74791427, 'ff15f7180201'),
 'wrapper-inner-call': (78279098, 'e8d1b6caff'),
 'wrapper-result-tag': (78279103, '49bc05000000000000804c39237536'),
 'wrapper-copy72': (78279172, '488b434048898424f0000000'),
 'wrapper-insert-call': (78279255, 'e8748dd0ff'),
 'field-input-result-test': (77336451, '498d4525493904247521'),
 'field-err-wrapper': (77336516, 'e827610e00'),
 'field-output-error-test': (77336521, '4c396c24287527'),
 'index-overwrite': (78282942, '4c89e1'),
 'case-0x0-entry': (74787029, 'bf08000000'),
 'case-0x1-entry': (74789399, '4983c6084c'),
 'case-0x2-entry': (74788835, 'bf11000000'),
 'case-0x3-entry': (74789107, 'bf0d000000'),
 'case-0x4-entry': (74788397, 'bf0f000000'),
 'case-0x5-entry': (74789716, 'bf0f000000'),
 'case-0x6-entry': (74790049, '4983c6084c'),
 'case-0x7-entry': (74789327, 'bf15000000'),
 'case-0x8-entry': (74790242, 'bf10000000'),
 'case-0x9-entry': (74788686, 'bf0a000000'),
 'case-0xa-entry': (74790175, 'bf0a000000'),
 'case-0xb-entry': (74788352, 'bf0b000000'),
 'case-0xc-entry': (74788483, 'bf10000000'),
 'case-0xd-entry': (74789974, 'bf0f000000'),
 'case-0xe-entry': (74788091, 'bf13000000'),
 'case-0xf-entry': (74788897, 'bf14000000'),
 'case-0x10-entry': (74788040, '4983c6084c'),
 'case-0x11-entry': (74789522, 'bf0b000000'),
 'case-0x12-entry': (74790100, 'bf0d000000'),
 'case-0x13-entry': (74790875, '4983c6084c'),
 'case-0x14-entry': (74789641, 'bf0e000000'),
 'case-0x15-entry': (74789765, 'bf12000000'),
 'case-0x16-entry': (74790423, 'bf11000000'),
 'case-0x17-entry': (74790926, '4983c6084c'),
 'case-0x18-entry': (74788770, 'bf13000000'),
 'case-0x19-entry': (74788721, 'bf0f000000'),
 'case-0x1a-entry': (74791435, 'bf20000000'),
 'case-0x1b-entry': (74787726, 'bf1d000000'),
 'case-0x1c-entry': (74790977, '4983c6084c'),
 'case-0x1d-entry': (74791028, 'bf12000000'),
 'case-0x1e-entry': (74790300, 'bf17000000'),
 'case-0x1f-entry': (74789450, 'bf16000000'),
 'case-0x20-entry': (74790372, '4983c6084c'),
 'case-0x21-entry': (74788301, '4983c6084c'),
 'case-0x22-entry': (74787795, 'bf13000000'),
 'case-0x23-entry': (74787286, 'bf0e000000'),
 'case-0x24-entry': (74787506, 'bf0e000000'),
 'case-0x25-entry': (74787235, '4983c6084c'),
 'case-0x26-entry': (74791092, 'bf17000000'),
 'case-0x27-entry': (74790630, 'bf19000000'),
 'case-0x28-entry': (74788432, '4983c6084c'),
 'case-0x29-entry': (74789590, '4983c6084c')}
TABLES = {7314332: (74787029,
           74789399,
           74788835,
           74789107,
           74788397,
           74789716,
           74790049,
           74789327,
           74790242,
           74788686,
           74790175,
           74788352,
           74788483,
           74789974,
           74788091,
           74788897,
           74788040,
           74789522,
           74790100,
           74790875,
           74789641,
           74789765,
           74790423,
           74790926,
           74788770,
           74788721,
           74791435,
           74787726,
           74790977,
           74791028,
           74790300,
           74789450,
           74790372,
           74788301,
           74787795,
           74787286,
           74787506,
           74787235,
           74791092,
           74790630,
           74788432,
           74789590)}
REQUIRED_RELOCS = {91676600: 20209768, 91676632: 88868528, 91676688: 88902832, 91706112: 82580464}

def demand(condition, message):
    if not condition:
        raise ValueError(message)

def read_va(data, secs, va, size):
    found = [s for s in secs if s['type'] != 8 and s['address'] <= va
             and va + size <= s['address'] + s['size']]
    demand(len(found) == 1, 'ambiguous/unmapped VA')
    sec = found[0]
    off = sec['offset'] + va - sec['address']
    return data[off:off + size]

def relocations(data, secs):
    matches = [s for s in secs if s['name'] == '.rela.dyn']
    demand(len(matches) == 1 and matches[0]['type'] != 8, 'relocation section')
    sec = matches[0]
    demand(sec['size'] % 24 == 0, 'truncated RELA')
    rows = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in REQUIRED_RELOCS:
            demand(slot not in rows, 'duplicate selected relocation')
            demand(info & 0xffffffff == 8 and info >> 32 == 0
                   and addend == REQUIRED_RELOCS[slot], 'selected relocation binding')
            rows[slot] = {'slot': hex(slot), 'type': info & 0xffffffff,
                          'symbol_index': info >> 32,
                          'addend': hex(addend), 'record_file_offset': off,
                          'record_hex': data[off:off + 24].hex()}
    demand(set(rows) == set(REQUIRED_RELOCS), 'missing selected relocation')
    # The name-copy dependency is an imported symbol, not a RELATIVE addend.
    imports = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == 0x576dfe0:
            demand(info == ((6 << 32) | 6) and addend == 0, 'selected relocation binding')
            sym = next(s for s in secs if s['name'] == '.dynsym')
            strings = next(s for s in secs if s['name'] == '.dynstr')
            pos = sym['offset'] + 6 * 24
            name_offset, st_info, _, shndx, _, _ = struct.unpack_from('<IBBHQQ',data,pos)
            begin = strings['offset'] + name_offset
            end = data.index(0, begin, strings['offset'] + strings['size'])
            demand(data[begin:end] == b'memcpy' and st_info & 15 == 2 and shndx == 0,
                   'selected imported symbol')
            imports.append({'slot':hex(slot),'type':6,'symbol_index':6,'symbol':'memcpy',
                            'addend':hex(addend),'record_file_offset':off,
                            'record_hex':data[off:off+24].hex()})
    demand(len(imports) == 1, 'missing/duplicate selected imported relocation')
    return [rows[k] for k in sorted(rows)] + imports

def selected_checks(data):
    """Semantic byte/table/relocation obligations; deliberately no digest gate."""
    secs = sections(data)
    for name, (va, expected) in ANCHORS.items():
        demand(read_va(data, secs, va, len(bytes.fromhex(expected))).hex() == expected,
               'anchor ' + name)
    tables = []
    for va, expected in TABLES.items():
        raw = read_va(data, secs, va, 4 * len(expected))
        targets = tuple(va + n for n in struct.unpack('<' + str(len(expected)) + 'i', raw))
        demand(targets == expected, 'dispatch table')
        tables.append({'va': hex(va), 'hex': raw.hex(), 'targets': [hex(x) for x in targets],
                       'domain': '42 selected enum cases only; nonnegative input selects 0x27. No general validity claim for negative indexes outside 0..41.'})
    contract_checks(data, secs)
    return secs, tables, relocations(data, secs)

def contract_checks(data, secs, contract=None):
    """Decode fixed argument operands; no register/memory/flag execution."""
    if contract is None:
        contract = json.loads((Path(__file__).parent / 'contract.json').read_text())
    cases = contract['cases']
    demand([int(c['selector'], 16) for c in cases] == list(range(42)), 'contract selector domain')
    expected_counts = {'direct-name': 19, 'field-builder': 12, 'explicit-index-helper': 11}
    demand({k:sum(c['construction'] == k for c in cases) for k in expected_counts} == expected_counts,
           'contract construction counts')
    for case, target in zip(cases, TABLES[0x6f9b9c]):
        demand(int(case['entry'],16) == target, 'contract table target')
        if case['construction'] == 'direct-name':
            b = read_va(data, secs, target, 5)
            demand(b[0] == 0xbf and struct.unpack('<I',b[1:])[0] == case['name_length'], 'name allocation length')
            va = int(case['output_stores'],16)
            n = struct.pack('<I',case['name_length'])
            expected = bytes.fromhex('4c892348c74308') + n + bytes.fromhex('4889431048c74318') + n
            demand(read_va(data,secs,va,len(expected)) == expected, 'direct output stores')
        elif case['construction'] == 'explicit-index-helper':
            call = int(case['call'],16); b = read_va(data, secs, call, 5)
            demand(b.hex() == case['call_hex'] and b[0] == 0xe8 and
                   call + 5 + struct.unpack('<i',b[1:])[0] == int(case['callee'],16), 'explicit helper call')
        else:
            for field in case['fields_in_order']:
                for address_key, bytes_key in [('call','call_hex'),('input_setup','input_setup_hex'),
                                               ('key_lea','key_lea_hex'),('key_length_at','key_length_hex'),
                                               ('key_va','key_hex')]:
                    expected = bytes.fromhex(field[bytes_key]); va = int(field[address_key],16)
                    demand(read_va(data,secs,va,len(expected)) == expected, 'field witness ' + address_key)
                b = bytes.fromhex(field['call_hex']); va = int(field['call'],16)
                demand(b[0] == 0xe8 and va + 5 + struct.unpack('<i',b[1:])[0] == int(field['callee'],16), 'field call target')
                b = bytes.fromhex(field['key_lea_hex']); va = int(field['key_lea'],16)
                demand(b[:3] == bytes.fromhex('488d35') and va + 7 + struct.unpack('<i',b[3:])[0] == int(field['key_va'],16), 'field key target')
                b = bytes.fromhex(field['key_length_hex'])
                demand(b[0] == 0xba and struct.unpack('<I',b[1:])[0] == field['key_size'] == len(bytes.fromhex(field['key_hex'])), 'field key length')
                b = bytes.fromhex(field['input_setup_hex'])
                if b[:3] in (bytes.fromhex('498d4e'),bytes.fromhex('4983c6')) and len(b) == 4:
                    operand = struct.unpack('<b',b[3:])[0]
                elif b == bytes.fromhex('4c89f1'):
                    operand = 0
                else:
                    raise ValueError('unsupported fixed input operand')
                demand(operand == int(field['input_offset'],16), 'field input operand')
    for witness in contract['additional_witnesses']:
        b = bytes.fromhex(witness['hex'])
        demand(read_va(data,secs,int(witness['va'],16),len(b)) == b,
               'additional witness ' + witness['role'])
    return contract

def parse_disassembly(text, start, end):
    rows = []
    pattern = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$')
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            va = int(match[1], 16)
            if start <= va < end:
                rows.append({'va': hex(va), 'hex': ''.join(match[2].split()), 'asm': match[3].strip()})
    cursor = start
    for row in rows:
        demand(int(row['va'], 16) == cursor, 'non-contiguous native decode')
        cursor += len(bytes.fromhex(row['hex']))
    demand(cursor == end, 'native decode scope incomplete')
    return rows

def instruction_partition(rows):
    """LLVM prints LOCK on its own row; join that exact prefix without hiding bytes."""
    result = []
    i = 0
    while i < len(rows):
        row = rows[i].copy()
        if row['hex'] == 'f0' and row['asm'] == 'lock':
            demand(i + 1 < len(rows), 'dangling LOCK prefix')
            after = rows[i + 1]
            demand(int(after['va'], 16) == int(row['va'], 16) + 1, 'nonadjacent LOCK')
            row['hex'] += after['hex']; row['asm'] += ' ' + after['asm']; i += 1
        result.append(row); i += 1
    return result

def decode(data, secs, tool, label, bounds, snapshot):
    start, end = bounds
    flags = ['-d', '-M', 'intel', '--insn-width=16'] if label == 'gnu' else ['--disassemble', '--x86-asm-syntax=intel']
    cmd = [tool, *flags, f'--start-address={start:#x}', f'--stop-address={end:#x}', snapshot.name]
    output = subprocess.check_output(cmd, cwd=snapshot.parent, text=True)
    rows = parse_disassembly(output, start, end)
    body = b''.join(bytes.fromhex(x['hex']) for x in rows)
    demand(body == read_va(data, secs, start, end - start), 'native bytes disagree with target')
    return output, rows

def transfer_rows(rows, start, end):
    result = []
    starts = {int(r['va'], 16) for r in rows}
    for row in rows:
        va = int(row['va'], 16); b = bytes.fromhex(row['hex']); kind = None; target = None
        if b[:1] in (b'\xe8', b'\xe9') and len(b) == 5:
            kind = 'call' if b[0] == 0xe8 else 'jump'; target = va + 5 + struct.unpack('<i', b[1:])[0]
        elif len(b) == 2 and (b[0] == 0xeb or 0x70 <= b[0] <= 0x7f):
            kind = 'jump' if b[0] == 0xeb else 'conditional'; target = va + 2 + struct.unpack('<b', b[1:])[0]
        elif len(b) == 6 and b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
            kind = 'conditional'; target = va + 6 + struct.unpack('<i', b[2:])[0]
        elif b[:2] == b'\xff\x15' and len(b) == 6:
            kind = 'indirect-call-slot'; target = va + 6 + struct.unpack('<i', b[2:])[0]
        elif row['asm'].split()[0].startswith(('call', 'jmp', 'ret')) or b == b'\x0f\x0b':
            kind = 'other-control';
        if kind:
            if target is not None and start <= target < end and kind != 'indirect-call-slot':
                demand(target in starts, 'control transfer into instruction interior')
            result.append({'at': row['va'], 'kind': kind, 'target': None if target is None else hex(target), 'asm': row['asm']})
    return result

def lsda_calls(data, secs, fde):
    """Decode call-site table only; type/action chains and unwinder behavior excluded."""
    if fde['lsda'] is None: return None
    va = fde['lsda']; raw = read_va(data, secs, va, 2048)
    demand(raw[0] == 0xff, 'unexpected LPStart encoding')
    pos = 2
    if raw[1] != 0xff:
        _, pos = uleb(raw, pos, len(raw))
    encoding = raw[pos]; pos += 1
    demand(encoding == 1, 'unexpected LSDA call-site encoding')
    length, pos = uleb(raw, pos, len(raw)); end = pos + length
    demand(end <= len(raw), 'truncated LSDA call-site table')
    rows = []
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(raw, pos, end); values.append(value)
        first, size, landing, action = values
        rows.append({'start': hex(fde['start'] + first), 'length': size,
                     'landing': hex(fde['start'] + landing) if landing else None, 'action_offset': action})
    demand(pos == end, 'LSDA table boundary')
    return {'va': hex(va), 'header_and_callsite_hex': raw[:end].hex(), 'rows': rows,
            'limit': 'Action/type tables and actual exceptional reachability are not interpreted.'}

def normal_cfg(rows, start, end):
    """Instruction-level structural edges, not symbolic execution or reachability."""
    transfers = {int(r['at'], 16): r for r in transfer_rows(rows, start, end)}
    computed = {0x47528d3: TABLES[0x6f9b9c]}
    boundaries = {int(row['va'],16) for row in rows}
    for site, targets in computed.items():
        if start <= site < end:
            demand(all(t in boundaries for t in targets), 'dispatch target not an instruction start')
    edges = []
    unresolved = []
    for row in rows:
        va = int(row['va'], 16); after = va + len(bytes.fromhex(row['hex']))
        t = transfers.get(va)
        def add(kind, target):
            edges.append({'from': hex(va), 'kind': kind, 'to': hex(target)})
        if t is None:
            if after < end: add('fallthrough', after)
        elif t['kind'] in ('call', 'indirect-call-slot'):
            add(t['kind'], int(t['target'], 16))
            if after < end: add('if-call-returns-normally', after)
        elif t['kind'] in ('jump', 'conditional'):
            add(t['kind'], int(t['target'], 16))
            if t['kind'] == 'conditional' and after < end: add('otherwise', after)
        elif va in computed:
            for index, target in enumerate(computed[va]): add('table-index-' + str(index), target)
        elif row['asm'].startswith('call'):
            unresolved.append(row)
            if after < end: add('if-call-returns-normally', after)
        elif not (row['asm'].startswith('ret') or row['hex'] == '0f0b'):
            unresolved.append(row)
    # Retain complete structural CFG as basic blocks rather than duplicate every
    # instruction already present in both raw native exports.
    leaders = {start}
    for row in rows:
        va = int(row['va'], 16)
        if va in transfers:
            after = va + len(bytes.fromhex(row['hex']))
            if after < end: leaders.add(after)
    for edge in edges:
        target = int(edge['to'], 16)
        if edge['kind'] != 'fallthrough' and start <= target < end:
            leaders.add(target)
    blocks = []
    for row in rows:
        va = int(row['va'], 16)
        if va in leaders:
            blocks.append({'start': hex(va), 'end': None, 'instruction_count': 0, 'last': None})
        block = blocks[-1]
        block['end'] = hex(va + len(bytes.fromhex(row['hex'])))
        block['instruction_count'] += 1
        block['last'] = row['va']
    outgoing = {}
    for edge in edges:
        outgoing.setdefault(edge['from'], []).append({k:v for k,v in edge.items() if k != 'from'})
    for block in blocks:
        block['successors'] = outgoing.get(block.pop('last'), [])
    return {'blocks': blocks, 'unresolved_indirect_transfers': unresolved,
            'limit': 'Complete decoded-range structural basic blocks, including landing pads. Calls have conditional normal-return edges; no LSDA edges, external effects, or dynamic reachability inferred.'}

def fde_checks(data, secs):
    """Check selected actual FDE extents and index links without a digest gate."""
    _, fdes = eh_frame_records(data, secs)
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    hb = data[hdr['offset']:hdr['offset'] + hdr['size']]
    demand(hb[:4] == bytes.fromhex('011b033b'), 'unsupported unwind index encoding')
    count = struct.unpack_from('<I', hb, 8)[0]
    demand(12 + count * 8 == len(hb), 'unwind index size')
    entries = [(hdr['address'] + a, hdr['address'] + p) for a,p in struct.iter_unpack('<ii', hb[12:])]
    selected = {}
    for name, (start, end) in RANGES.items():
        matches = [f for f in fdes if f['start'] == start]
        demand(len(matches) == 1 and matches[0]['end'] == end, 'FDE extent')
        f = matches[0]
        demand([p for a,p in entries if a == start] == [f['fde']], 'FDE/index disagreement')
        selected[name] = f
    return selected

def collect(binary, out, gnu, llvm):
    data = binary.read_bytes()
    demand(hashlib.sha256(data).hexdigest() == DIGEST, 'wrong target digest')
    demand(binary.resolve() == (ROOT / REL).resolve(), 'native export input must be canonical target')
    secs, tables, relocs = selected_checks(data)
    fdes = fde_checks(data, secs)
    out.mkdir(parents=True, exist_ok=False)
    result = {'target': {'path': REL, 'sha256': DIGEST, 'size': len(data)},
              'native_input': 'One private temporary hl-node copy of authenticated bytes, shared by both disassemblers; full copy digest checked before and after all exports. Copy is never executed.',
              'coordinate_system': 'linked ELF virtual addresses, half-open extents',
              'tables': tables, 'relocations': relocs, 'ranges': {},
              'anchors': {k: {'va': hex(v[0]), 'hex': v[1]} for k,v in ANCHORS.items()},
              'tool_versions': {k: subprocess.check_output([v, '--version'], text=True).splitlines()[0] for k,v in [('gnu',gnu),('llvm',llvm)]},
              'parser_hashes': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ['tools/elf_index.py','tools/fde_extents.py']}}
    cfg_lines = ['range\tstart\tend\tinstructions\tsuccessors(kind:target;...)']
    with tempfile.TemporaryDirectory(prefix='consensus-construction-native-') as private:
        snapshot = Path(private) / 'hl-node'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot digest before exports')
        for name, (start, end) in RANGES.items():
            f = fdes[name]
            exports = {}
            export_files = {}
            for label, tool in [('gnu', gnu), ('llvm', llvm)]:
                text, rows = decode(data, secs, tool, label, (start,end), snapshot)
                raw = text.encode()
                file_name = f'{name}.{label}.txt' + ('.gz' if label == 'llvm' else '')
                stored = gzip.compress(raw,mtime=0) if label == 'llvm' else raw
                (out / file_name).write_bytes(stored)
                export_files[label] = {'file':file_name,'raw_sha256':hashlib.sha256(raw).hexdigest(),
                                       'stored_sha256':hashlib.sha256(stored).hexdigest()}
                exports[label] = rows
            gnu_partition = instruction_partition(exports['gnu'])
            llvm_partition = instruction_partition(exports['llvm'])
            demand([(r['va'],r['hex']) for r in gnu_partition] == [(r['va'],r['hex']) for r in llvm_partition], 'native partition mismatch')
            frlen = struct.unpack('<I', read_va(data,secs,f['fde'],4))[0]+4
            cilen = struct.unpack('<I', read_va(data,secs,f['cie'],4))[0]+4
            cfg = normal_cfg(gnu_partition,start,end)
            for block in cfg['blocks']:
                successors = ';'.join(e['kind'] + ':' + e['to'] for e in block['successors']) or '-'
                cfg_lines.append('\t'.join([name,block['start'],block['end'],str(block['instruction_count']),successors]))
            cfg_summary = {'table':'cfg.tsv','range_key':name,'block_count':len(cfg['blocks']),
                           'unresolved_indirect_transfers':cfg['unresolved_indirect_transfers'],
                           'limit':cfg['limit']}
            result['ranges'][name] = {'start':hex(start),'end':hex(end),'bytes':end-start,
                'sha256':hashlib.sha256(read_va(data,secs,start,end-start)).hexdigest(),
                'fde':{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                'fde_hex':read_va(data,secs,f['fde'],frlen).hex(),
                'cie_hex':read_va(data,secs,f['cie'],cilen).hex(),
                'lsda_call_sites':lsda_calls(data,secs,f),
                'instruction_count':len(gnu_partition),
                'native_raw_rows':{k:len(v) for k,v in exports.items()},
                'native_exports':export_files,
                'comparison_rule':'Identical bytes/boundaries after joining only standalone LLVM f0 LOCK prefix rows; no bytes omitted or masked.',
                'normal_cfg':cfg_summary}
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot digest after exports')
    (out / 'cfg.tsv').write_text('\n'.join(cfg_lines)+'\n')
    (out / 'records.json').write_text(json.dumps(result, indent=2)+'\n')
    return result

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--gnu',default='/opt/homebrew/opt/binutils/bin/objdump')
    p.add_argument('--llvm',default='/usr/bin/objdump')
    a=p.parse_args()
    try:
        r=collect(ROOT/REL,a.out,a.gnu,a.llvm)
        print(json.dumps({'ranges':len(r['ranges']),'bytes':sum(v['bytes'] for v in r['ranges'].values()),'rows':sum(v['instruction_count'] for v in r['ranges'].values())}))
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        p.exit(1,str(e)+'\n')
