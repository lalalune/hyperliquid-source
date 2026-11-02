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

SPEC_PATH = Path(__file__).resolve().with_name('spec.json')
SPEC = json.loads(SPEC_PATH.read_text())
DIGEST = SPEC['target']['sha256']
REL = SPEC['target']['path']
RANGES = {name: tuple(int(x, 16) for x in bounds) for name, bounds in SPEC['ranges'].items()}
ANCHORS = {name: (int(row['va'], 16), row['hex']) for name, row in SPEC['anchors'].items()}
LITERALS = {name: (int(row['va'], 16), row['hex']) for name, row in SPEC['literals'].items()}
REQUIRED_RELOCS = {int(slot, 16): int(target, 16) for slot, target in SPEC['relocations'].items()}

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
    return [rows[k] for k in sorted(rows)]

def selected_checks(data):
    """Check semantic obligations below (independently of) the input digest gate."""
    secs = sections(data)
    for name, (va, expected) in ANCHORS.items():
        demand(read_va(data, secs, va, len(bytes.fromhex(expected))).hex() == expected,
               'anchor ' + name)
    for name, (va, expected) in LITERALS.items():
        demand(read_va(data, secs, va, len(bytes.fromhex(expected))).hex() == expected,
               'literal ' + name)
    return secs, relocations(data, secs)

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
        elif b[:2] in (b'\xff\x15', b'\xff\x25') and len(b) == 6:
            kind = 'indirect-call-slot' if b[1] == 0x15 else 'indirect-tail-slot'
            target = va + 6 + struct.unpack('<i', b[2:])[0]
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
    computed = {}  # These two FDEs have no local computed dispatch.
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
            else: add('fallthrough-outside-FDE', after)
        elif t['kind'] in ('call', 'indirect-call-slot'):
            add(t['kind'], int(t['target'], 16))
            if after < end: add('if-call-returns-normally', after)
            else: add('if-call-returns-outside-FDE', after)
        elif t['kind'] in ('jump', 'conditional'):
            add(t['kind'], int(t['target'], 16))
            if t['kind'] == 'conditional' and after < end: add('otherwise', after)
        elif t['kind'] == 'indirect-tail-slot':
            add('indirect-tail-slot', int(t['target'], 16))
        elif va in computed:
            for index, target in enumerate(computed[va]): add('table-index-' + str(index), target)
        elif row['asm'].startswith('call'):
            unresolved.append(row)
            if after < end: add('if-call-returns-normally', after)
            else: add('if-call-returns-outside-FDE', after)
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


def operand_facts(data, secs):
    """Read named encoded fields; do not evaluate instructions or input cases."""
    return {name: int.from_bytes(read_va(data, secs, int(row['va'], 16), row['size']), 'little')
            for name, row in SPEC['operand_fields'].items()}


def selected_slot_bindings(data, secs, slots):
    """Retain each actual indirect call/tail slot, including opaque imports."""
    sec = next(s for s in secs if s['name'] == '.rela.dyn')
    syms = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in slots:
            continue
        demand(slot not in result, 'duplicate call-slot relocation')
        typ, symbol = info & 0xffffffff, info >> 32
        row = {'type': typ, 'symbol_index': symbol, 'addend': hex(addend),
               'record_file_offset': off, 'record_hex': data[off:off + 24].hex()}
        if typ == 8:
            demand(symbol == 0, 'RELATIVE symbol must be zero')
        else:
            demand(typ == 6 and symbol * 24 + 24 <= syms['size'], 'unsupported call-slot import')
            so = syms['offset'] + symbol * 24
            no = struct.unpack_from('<I', data, so)[0]
            demand(no < strings['size'], 'symbol name offset')
            first = strings['offset'] + no
            last = data.find(b'\0', first, strings['offset'] + strings['size'])
            demand(last >= first, 'unterminated symbol name')
            row['symbol_name'] = data[first:last].decode('ascii')
            row['symbol_hex'] = data[so:so + 24].hex()
        result[slot] = row
    demand(set(result) == slots, 'missing call-slot relocation')
    return {hex(k): result[k] for k in sorted(result)}


def opaque_callee_checks(data, secs):
    """Bind callee identity/extent only; never infer behavior from a digest."""
    _, fdes = eh_frame_records(data, secs)
    for address, expected in SPEC['opaque_callees'].items():
        start, end = int(address, 16), int(expected['end'], 16)
        matches = [f for f in fdes if f['start'] == start]
        demand(len(matches) == 1 and matches[0]['end'] == end, 'opaque callee extent')
        demand(hashlib.sha256(read_va(data, secs, start, end - start)).hexdigest()
               == expected['body_sha256'], 'opaque callee identity')
    return SPEC['opaque_callees']


def collect(binary, out, gnu, llvm):
    demand(not out.exists(), 'existing output refused')
    data = binary.read_bytes()
    demand(len(data) == SPEC['target']['size'] and hashlib.sha256(data).hexdigest() == DIGEST,
           'wrong target digest')
    secs, relocs = selected_checks(data)
    fdes = fde_checks(data, secs)
    opaque = opaque_callee_checks(data, secs)
    out.mkdir(parents=True, exist_ok=False)
    result = {'target': SPEC['target'], 'research_base': SPEC['research_base'],
              'spec_sha256': hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest(),
              'native_input': 'Both decoders read one private authenticated read-only snapshot; full snapshot digest checked before and after. Never executed.',
              'coordinate_system': 'Linked ELF virtual addresses; half-open function extents',
              'operand_facts': operand_facts(data, secs), 'required_relocations': relocs,
              'ranges': {}, 'opaque_callees': opaque,
              'tool_versions': {k: subprocess.check_output([v, '--version'], text=True).splitlines()[0]
                                for k, v in [('gnu', gnu), ('llvm', llvm)]},
              'parser_hashes': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                for p in ['tools/elf_index.py', 'tools/fde_extents.py']}}
    cfg_lines = ['range\tstart\tend\tinstructions\tsuccessors(kind:target;...)']
    transfer_lines = ['range\taddress\tkind\ttarget_or_slot\tinstruction']
    rip_lines = ['range\taddress\treferenced_va\tinstruction']
    slots = set()
    with tempfile.TemporaryDirectory(prefix='impact-native-') as private:
        snapshot = Path(private) / 'hl-node'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot before exports')
        for name, (start, end) in RANGES.items():
            exports, metadata = {}, {}
            for label, tool in [('gnu', gnu), ('llvm', llvm)]:
                text, rows = decode(data, secs, tool, label, (start, end), snapshot)
                raw = text.encode()
                stored = raw if label == 'gnu' else gzip.compress(raw, mtime=0)
                filename = name + '.' + label + '.txt' + ('.gz' if label == 'llvm' else '')
                (out / filename).write_bytes(stored)
                metadata[label] = {'file': filename, 'raw_sha256': hashlib.sha256(raw).hexdigest(),
                                   'stored_sha256': hashlib.sha256(stored).hexdigest()}
                exports[label] = instruction_partition(rows)
            demand([(r['va'], r['hex']) for r in exports['gnu']] ==
                   [(r['va'], r['hex']) for r in exports['llvm']], 'native partition mismatch')
            rows = exports['gnu']
            tx = transfer_rows(rows, start, end)
            for t in tx:
                transfer_lines.append('\t'.join([name, t['at'], t['kind'], t['target'] or '-', t['asm']]))
                if t['kind'] in ('indirect-call-slot', 'indirect-tail-slot'):
                    slots.add(int(t['target'], 16))
            for row in rows:
                if '[rip' in row['asm']:
                    match = re.search(r'#\s+([0-9a-f]+)', row['asm'])
                    demand(match is not None, 'missing RIP reference annotation')
                    rip_lines.append('\t'.join([name, row['va'], hex(int(match[1], 16)), row['asm']]))
            cfg = normal_cfg(rows, start, end)
            for block in cfg['blocks']:
                successors = ';'.join(e['kind'] + ':' + e['to'] for e in block['successors']) or '-'
                cfg_lines.append('\t'.join([name, block['start'], block['end'],
                                             str(block['instruction_count']), successors]))
            f = fdes[name]
            fl = struct.unpack('<I', read_va(data, secs, f['fde'], 4))[0] + 4
            cl = struct.unpack('<I', read_va(data, secs, f['cie'], 4))[0] + 4
            lsda = lsda_calls(data, secs, f)
            boundaries = {int(row['va'], 16) for row in rows} | {end}
            if lsda:
                for site in lsda['rows']:
                    first = int(site['start'], 16)
                    last = first + site['length']
                    demand(start <= first <= last <= end and first in boundaries and last in boundaries,
                           'LSDA call-site boundary')
                    demand(site['landing'] is None or int(site['landing'], 16) in boundaries - {end},
                           'LSDA landing boundary')
            result['ranges'][name] = {
                'start': hex(start), 'end': hex(end), 'bytes': end - start,
                'body_sha256': hashlib.sha256(read_va(data, secs, start, end - start)).hexdigest(),
                'fde': {k: hex(v) if isinstance(v, int) else v for k, v in f.items()},
                'fde_hex': read_va(data, secs, f['fde'], fl).hex(),
                'cie_hex': read_va(data, secs, f['cie'], cl).hex(),
                'lsda_call_sites': lsda,
                'instruction_count': len(rows), 'transfer_count': len(tx),
                'native_exports': metadata,
                'cfg': {'table': 'cfg.tsv', 'block_count': len(cfg['blocks']),
                        'unresolved_indirect_transfers': cfg['unresolved_indirect_transfers']}}
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot after exports')
    result['call_slot_bindings'] = selected_slot_bindings(data, secs, slots)
    result['structure_limit'] = ('CFG includes every decoded instruction and landing-pad block; calls have '
                                 'conditional normal-return edges. LSDA is separate call-site metadata, '
                                 'not actual unwind semantics. RIP and call tables are inventories, '
                                 'not transitive callee/literal meanings.')
    for filename, lines in [('cfg.tsv', cfg_lines), ('transfers.tsv', transfer_lines), ('rip-references.tsv', rip_lines)]:
        (out / filename).write_text('\n'.join(lines) + '\n')
    (out / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    args = parser.parse_args()
    try:
        result = collect(ROOT / REL, args.out, args.gnu, args.llvm)
        print(json.dumps({'ranges': len(result['ranges']),
                          'bytes': sum(x['bytes'] for x in result['ranges'].values()),
                          'rows': sum(x['instruction_count'] for x in result['ranges'].values())}))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
