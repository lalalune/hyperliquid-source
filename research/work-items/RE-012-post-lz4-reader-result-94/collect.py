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
RANGES = {'reader': (33855824, 33861141),
 'consumer': (33861152, 33861682),
 'reader-cleanup': (33339024, 33339231),
 'decompressor-context': (64072640, 64075307),
 'statistics-context': (64137008, 64138224),
 'difference-context': (82720560, 82720763),
 'clock-context': (82720768, 82720969),
 'cleanup-slot-context': (88902832, 88902997)}
# Fixed scout-selected witnesses; each is checked below the target hash gate.
ANCHORS = {'reader-result-base': (33855846, '4889f348897c243048b800000000000000804889842428010000'),
 'reader-entry-state': (33855872, '0fb64648488d0ddda337fe486304814801c8ffe0'),
 'original-triple-and-flag': (33858065, '4c897360488943684c897370c6434901'),
 'remaining-exit': (33860066, '488b43584829f80f86b6000000'),
 'compression-gate': (33860261, '807b50000f84bf010000'),
 'decompress-arguments': (33860286, '488b4b28488b7368488b5370488dbc2430010000ff15388d7203'),
 'decompress-result-gate': (33860312,
                            '4c8ba424300100004c8bac243801000048b800000000000000804939c40f8458010000'),
 'decoded-length-save': (33860351, '4c8bbc2440010000'),
 'compressed-length-save': (33860363, '488b437048890424'),
 'clock-before-decode': (33860271, 'bf01000000e8478de902'),
 'clock-after-decode': (33860371, 'bf01000000e8e38ce902'),
 'difference-call': (33860409, '488dbc2430010000488db424c0000000488d542448e8dd8be902'),
 'difference-tag-gate': (33860435, '80bc243001000000660f57c0753c'),
 'stats-arguments': (33860509, '4883c5204889ef4c89fe488b1424ff15678c7203'),
 'success-buffer-flag': (33860529, '807b49000f84c3000000'),
 'success-capacity-guard': (33860539, '488b73604885f60f84b6000000'),
 'success-cleanup-request': (33860552, '488b7b6831d2ff153c347203'),
 'error-capacity-guard': (33860691, '488b73604885f6740c'),
 'error-cleanup-request': (33860700, '488b7b6831d2ff15a8337203'),
 'error-flag-clear': (33860712, 'c6434900eb1c'),
 'raw-original-triple': (33860718, 'c64349004c8b63604c8b6b684c8b7b70'),
 'success-capacity-store': (33860734, 'c64349004c89a42428010000'),
 'reader-result-stores': (33860746, '488b442430488b8c24280100004889084c8968084c897810'),
 'reader-complete-state': (33860770, 'b001884348'),
 'pending-result': (33860581, '48b9000000000000008048ffc1488b442430488908b005'),
 'consumer-call': (33861287, '488d7c24104889dee89ceaffff'),
 'consumer-pending-test': (33861300, '49bc00000000000000804c8b7c2410498d4424014939c7750c'),
 'consumer-pending-store': (33861325, '41c6060240b503'),
 'consumer-completed-cleanup': (33861352, '4889dfe8a007f8ff'),
 'consumer-error-test': (33861363, '4d39e7750a41b4014c8b6c2408eb6b'),
 'consumer-decoder-arguments': (33861411, '488d7c2438488b7424084c89eae8fb168700'),
 'consumer-decoder-result-test': (33861429, '807c2438127556'),
 'consumer-capacity-guard': (33861446, '4531e44d85ff741f'),
 'consumer-cleanup-args': (33861454, '488b7c24084c89fe'),
 'consumer-cleanup-call': (33861471, 'ff15ab307203'),
 'consumer-result-stores': (33861485, '4588264188460141884e024d896e08'),
 'consumer-state-store': (33861500, '4088ab81020000'),
 'consumer-error-builder': (33861542, '488d7c2410e8900000004989c5'),
 'consumer-error-cleanup-rejoin': (33861555, '41b4014d85ff7593ebb0'),
 'cleanup-state-gates': (33339032, '0fb6474883f803744783f805756b'),
 'cleanup-return': (33339153, '5b415e415fc3'),
 'cleanup-slot-fallback': (88902992, 'e9fbe7ffff'),
 'decoded-landing-request': (33860939, '4989c74d85e40f84990000004c89ef4c89e6eb1c'),
 'landing-cleanup-call': (33860987, '31d2ff158d327203'),
 'original-landing-request': (33861104, '488b73604885f6740c488b7b6831d2ff150b327203'),
 'exception-state-stores': (33861125, 'c6434900c6434802')}
TABLES = {3947880: (33855892, 33858169, 33858156, 33856014, 33857334, 33856663),
 3947904: (33856709, 33858246, 33858205, 33857518),
 3947920: (33857555, 33858318, 33858282, 33859535),
 3947936: (33856048, 33858223, 33858182, 33857425),
 3947952: (33857484, 33858300, 33858264, 33857128),
 3947968: (33861195, 33861578, 33861565, 33861287)}
REQUIRED_RELOCS = {91676688: 88902832, 91699216: 64072640, 91699224: 64137008}

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
        targets = tuple(va + n for n in struct.unpack('<' + str(len(expected)) + 'i', raw))
        demand(targets == expected, 'dispatch table')
        tables.append({'va': hex(va), 'hex': raw.hex(), 'targets': [hex(x) for x in targets],
                       'domain': 'Selected valid async states only: reader entry 0..5; four reader substate and consumer entry tables 0..3. No local bounds check or malformed-state safety claim.'})
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
    computed = {0x2049992: TABLES[0x3c3d68], 0x2049cc3: TABLES[0x3c3d80],
                0x204a011: TABLES[0x3c3d90], 0x2049a2e: TABLES[0x3c3da0],
                0x2049fca: TABLES[0x3c3db0], 0x204ae49: TABLES[0x3c3dc0]}
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
    with tempfile.TemporaryDirectory(prefix='post-lz4-native-') as private:
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
