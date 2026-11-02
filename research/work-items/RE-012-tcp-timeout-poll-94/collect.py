#!/usr/bin/env python3
"""Collect bounded static evidence; never execute or interpret captured code."""
import argparse
import hashlib
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
RANGES = {
    'controller': (0x2036460, 0x20367c3),
    'timer-adapter': (0x4f68f00, 0x4f6903e),
    'write-adapter': (0x4f7d1a0, 0x4f7d34b),
    'error-adapter': (0x288d0d0, 0x288d134),
    'cleanup-context': (0x1fb6110, 0x1fb61f8),
    'writer-context': (0x204b340, 0x204c216),
}
# Hand-selected proof obligations, checked separately below whole-image/body hashes.
ANCHORS = {
    'outer-state-load': (0x20364c1, '0fb683e0000000'),
    'inner-state-load': (0x2036516, '0fb683c0000000'),
    'requested-count-add': (0x203654d, 'f048014a10'),
    'zero-write-token': (0x203656e, '49bc0300000017000000'),
    'write-call': (0x2036596, 'e8056cf402'),
    'pending-before-error': (0x203659b, '4883f802745b'),
    'write-error-lowbit': (0x20365a1, 'a8017563'),
    'remaining-sentinel': (0x20365b3, '48c783d00000000100000048c783d800000000000000'),
    'remaining-subtract': (0x20365c9, '4829d10f8237010000'),
    'pointer-advance': (0x20365d2, '4801d0488983d000000048898bd8000000'),
    'zero-write': (0x20365e3, '4885d27598eb21'),
    'empty-result': (0x20365f8, '31d2eb1a'),
    'inner-pending-store': (0x20365fc, '41c6450003b801000000eb15'),
    'error-call': (0x203660e, 'e8bd6a85004889c2'),
    'inner-completed-store': (0x2036616, '41c645000131c0'),
    'outer-state-store': (0x203661d, '8d0c00fec1888be0000000'),
    'timer-return-map': (0x2036682, '0fb6c048ffc0'),
    'resume-remaining': (0x203669b, '488b8bd8000000e9c7feffff'),
    'timer-normal-zero': (0x4f68fcd, '31c0eb11'),
    'timer-normal-one': (0x4f68fe0, 'b001'),
    'writer-call': (0x204be81, 'e8daa5feff'),
    'writer-pending-test': (0x204be86, '4989c64883f8020f84de010000'),
    'writer-save-cleanup': (0x204be93, '4989d44c89efe872a2f6ff'),
    'writer-post-cleanup-test': (0x204be9e, '41f6c6010f85f5010000'),
    'writer-pending-stores': (0x204c071, 'c683da02000003c683e002000003c683e802000003b801000000'),
    'writer-payload-test': (0x204bf1f, '4d85e40f85f1000000'),
    'writer-diagnostic-call': (0x204c0d7, 'e89470fdff4989c4'),
}
TABLES = {
    0x3c3b38: (0x20364d8, 0x2036731, 0x2036724, 0x203650f),
    0x3c3b48: (0x203652d, 0x203673e, 0x203674d, 0x203669b),
}
REQUIRED_RELOCS = {0x576f088: 0x4f68f00, 0x576f1e0: 0x4edda70,
                   0x576f1e8: 0x4f77880, 0x576e098: 0x157b810,
                   0x576f038: 0x157b560, 0x576f040: 0x157b540}

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
    """Semantic byte/table/relocation obligations; deliberately no digest gate."""
    secs = sections(data)
    for name, (va, expected) in ANCHORS.items():
        demand(read_va(data, secs, va, len(bytes.fromhex(expected))).hex() == expected,
               'anchor ' + name)
    tables = []
    for va, expected in TABLES.items():
        raw = read_va(data, secs, va, 4 * len(expected))
        targets = tuple(va + n for n in struct.unpack('<4i', raw))
        demand(targets == expected, 'dispatch table')
        tables.append({'va': hex(va), 'hex': raw.hex(), 'targets': [hex(x) for x in targets],
                       'domain': 'Four decoded entries only. The ordinary relation assumes outer=0 fresh or outer=3,inner=3 from a prior pending return.'})
    return secs, tables, relocations(data, secs)

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
    computed = {0x20364d6: TABLES[0x3c3b38], 0x203652b: TABLES[0x3c3b48]}
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
    return {'edges': edges, 'unresolved_indirect_transfers': unresolved,
            'limit': 'All decoded instructions, including landing-pad bytes. Calls have conditional normal-return edges; no LSDA edges, external effects, or dynamic reachability inferred.'}

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
    with tempfile.TemporaryDirectory(prefix='tcp-timeout-native-') as private:
        snapshot = Path(private) / 'hl-node'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot digest before exports')
        for name, (start, end) in RANGES.items():
            f = fdes[name]
            exports = {}
            for label, tool in [('gnu', gnu), ('llvm', llvm)]:
                text, rows = decode(data, secs, tool, label, (start,end), snapshot)
                (out / f'{name}.{label}.txt').write_text(text)
                exports[label] = rows
            gnu_partition = instruction_partition(exports['gnu'])
            llvm_partition = instruction_partition(exports['llvm'])
            demand([(r['va'],r['hex']) for r in gnu_partition] == [(r['va'],r['hex']) for r in llvm_partition], 'native partition mismatch')
            frlen = struct.unpack('<I', read_va(data,secs,f['fde'],4))[0]+4
            cilen = struct.unpack('<I', read_va(data,secs,f['cie'],4))[0]+4
            result['ranges'][name] = {'start':hex(start),'end':hex(end),'bytes':end-start,
                'sha256':hashlib.sha256(read_va(data,secs,start,end-start)).hexdigest(),
                'fde':{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                'fde_hex':read_va(data,secs,f['fde'],frlen).hex(),
                'cie_hex':read_va(data,secs,f['cie'],cilen).hex(),
                'lsda_call_sites':lsda_calls(data,secs,f),
                'instruction_count':len(gnu_partition), 'instructions':gnu_partition,
                'native_raw_rows':{k:len(v) for k,v in exports.items()},
                'comparison_rule':'Identical bytes/boundaries after joining only standalone LLVM f0 LOCK prefix rows; no bytes omitted or masked.',
                'control_transfers':transfer_rows(gnu_partition,start,end),
                'normal_cfg':normal_cfg(gnu_partition,start,end)}
        demand(hashlib.sha256(snapshot.read_bytes()).hexdigest() == DIGEST, 'snapshot digest after exports')
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
