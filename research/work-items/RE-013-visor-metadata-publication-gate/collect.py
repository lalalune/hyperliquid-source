#!/usr/bin/env python3
"""Static evidence only: authenticated bytes, native decoders and graph structure."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

SHA = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
TARGET = ROOT / 'artifacts/visor/captured/hl-visor'
FULL = {'metadata': (0x415620, 0x416cce), 'download': (0x4148b0, 0x4155a2),
        'publication': (0x416f30, 0x41718a)}
CONTEXT = {'caller-select': (0x5e5fb2, 0x5e60e7),
           'caller-move': (0x5e6271, 0x5e63d4),
           'caller-cache': (0x5e6474, 0x5e64b9)}
RANGES = FULL | CONTEXT
CALLER = (0x5e44c0, 0x5ea1c1)
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/usr/bin/objdump'
TABLE = (0x7bcf8, [0x41564d, 0x415f00, 0x415a5e, 0x415ce7])


def need(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
        offset = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        self.loads = []
        for i in range(count):
            kind, _, off, va, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', data, offset+i*width)
            if kind == 1:
                self.loads.append((va, off, size))
        self.secs = sections(data)

    def offset(self, va, size):
        matches = [off+va-base for base, off, n in self.loads if base <= va and va+size <= base+n]
        need(len(matches) == 1, 'unique file-backed PT_LOAD mapping')
        return matches[0]

    def at(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off+size]


def bindings(image):
    expected = json.loads((HERE/'bindings.json').read_text())
    for label, item in expected['witnesses'].items():
        raw = bytes.fromhex(item['hex'])
        need(image.at(int(item['va'], 16), len(raw)) == raw, 'witness '+label)
    va, targets = TABLE
    need([va+x for x in struct.unpack('<4i', image.at(va, 16))] == targets, 'mode table')
    selected = {int(k, 16): v for k, v in expected['relocations'].items()}
    found = {}
    for sec in image.secs:
        if sec['name'] != '.rela.dyn':
            continue
        for off in range(sec['offset'], sec['offset']+sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, off)
            if slot in selected:
                need(slot not in found, 'duplicate selected RELA')
                want = selected[slot]
                need(info == int(want['info'], 16) and addend == int(want['addend'], 16), 'selected RELA')
                if 'symbol' in want:
                    syms = next(s for s in image.secs if s['name'] == '.dynsym')
                    strings = next(s for s in image.secs if s['name'] == '.dynstr')
                    symbol_off = syms['offset'] + (info >> 32)*24
                    name_off = strings['offset'] + struct.unpack_from('<I', image.data, symbol_off)[0]
                    actual = image.data[name_off:image.data.index(b'\0', name_off)].decode('ascii')
                    need(actual == want['symbol'], 'selected imported symbol')
                found[slot] = {'slot': hex(slot), 'info': hex(info), 'addend': hex(addend),
                               'file_offset': off, 'hex': image.data[off:off+24].hex()}
    need(set(found) == set(selected), 'missing selected RELA')
    return [found[k] for k in sorted(found)]


def unwind(image):
    _, fdes = eh_frame_records(image.data, image.secs)
    h = next(s for s in image.secs if s['name'] == '.eh_frame_hdr')
    hb = image.data[h['offset']:h['offset']+h['size']]
    need(hb[:4] == bytes.fromhex('011b033b'), 'unwind header encoding')
    count = struct.unpack_from('<I', hb, 8)[0]
    need(12+8*count == len(hb), 'unwind header size')
    entries = [(h['address']+a, h['address']+b) for a,b in struct.iter_unpack('<ii', hb[12:])]
    result = {}
    for name, (start, end) in (FULL | {'caller-container': CALLER}).items():
        matches = [f for f in fdes if f['start'] == start]
        need(len(matches) == 1 and matches[0]['end'] == end, 'FDE range '+name)
        f = matches[0]
        need([b for a,b in entries if a == start] == [f['fde']], 'FDE header link')
        fr = image.at(f['fde'], 4+struct.unpack('<I', image.at(f['fde'], 4))[0])
        cr = image.at(f['cie'], 4+struct.unpack('<I', image.at(f['cie'], 4))[0])
        need(f['fde']+4-struct.unpack_from('<I', fr, 4)[0] == f['cie'], 'CIE backref')
        result[name] = {'fields': {k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                        'fde_hex':fr.hex(), 'cie_hex':cr.hex()}
    return result


def parse(text, start, end):
    pattern = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$')
    rows = []
    for line in text.splitlines():
        m = pattern.match(line)
        if m and start <= int(m[1],16) < end:
            rows.append((int(m[1],16), bytes.fromhex(m[2]), m[3].split('#')[0].strip()))
    cursor = start
    for a,b,_ in rows:
        need(a == cursor, 'native contiguous partition')
        cursor += len(b)
    need(cursor == end, 'native complete range')
    return rows


def graph(rows, bounds):
    """Raw direct branch/table edges; never evaluate captured instructions."""
    start, end = bounds
    starts = {a for a,_,_ in rows}
    edges = {}; calls = []; unresolved = []; returns = []
    for a,b,asm in rows:
        after = a+len(b); successors=[]
        if a == 0x41564b:
            need(b == bytes.fromhex('ffe0'), 'mode dispatch opcode')
            successors = TABLE[1]
        elif b == b'\xc3':
            returns.append(a)
        elif b == b'\x0f\x0b':
            pass
        elif len(b) == 5 and b[0] in (0xe8,0xe9):
            dest = after+struct.unpack('<i',b[1:])[0]
            if b[0] == 0xe8:
                calls.append({'at':hex(a),'kind':'direct','target':hex(dest)})
                successors=[after]
            else:
                successors=[dest]
        elif len(b) == 2 and (b[0] == 0xeb or 0x70 <= b[0] <= 0x7f):
            dest = after+struct.unpack('<b',b[1:])[0]
            successors=[dest] if b[0] == 0xeb else [dest,after]
        elif len(b) == 6 and b[0] == 15 and 0x80 <= b[1] <= 0x8f:
            successors=[after+struct.unpack('<i',b[2:])[0],after]
        elif asm.startswith('call'):
            if len(b) == 6 and b[:2] == b'\xff\x15':
                calls.append({'at':hex(a),'kind':'slot','target':hex(after+struct.unpack('<i',b[2:])[0])})
            else:
                calls.append({'at':hex(a),'kind':'opaque-indirect','operand':asm})
            successors=[after]
        elif asm.startswith(('jmp','ret','j')):
            unresolved.append({'at':hex(a),'asm':asm})
        else:
            successors=[after]
        for target in successors:
            if start <= target < end:
                need(target in starts, 'branch instruction boundary')
        edges[a] = [x for x in successors if start <= x < end]
    need(not unresolved, 'unresolved local transfer')
    return edges, calls, returns


def reachable(edges, start, removed=()):
    removed=set(removed);seen=set();todo=[start]
    while todo:
        a=todo.pop()
        if a in seen or a in removed:
            continue
        seen.add(a);todo.extend(edges.get(a,[]))
    return seen


def certificate(rows):
    """Nonvacuous structural cutsets support, but do not replace, manual dataflow."""
    gm,_,_=graph(rows['metadata'],FULL['metadata'])
    gd,_,_=graph(rows['download'],FULL['download'])
    gp,_,_=graph(rows['publication'],FULL['publication'])
    checks = [
        ('metadata-return-has-flag-or-error',gm,0x415620,0x416767,[0x415a50,0x41655c,0x41674b,0x41682e,0x416149,0x416848]),
        ('mode2-flag-has-bit-definition',gm,0x415a5e,0x41655c,[0x415cd3,0x416392]),
        ('mode3-flag-has-local-definition',gm,0x415ce7,0x41674b,[0x4162a3,0x416342,0x416596]),
        ('download-success-has-xor',gd,0x4148b0,0x41521b,[0x4151ce]),
        ('download-success-has-byte-load',gd,0x4148b0,0x41521b,[0x41492d]),
        ('publication-operations-have-gate',gp,0x416f30,0x416fb4,[0x416f47]),
        ('publication-first-request-has-gate',gp,0x416f30,0x417040,[0x416f47]),
        ('publication-final-request-has-gate',gp,0x416f30,0x417092,[0x416f47]),
    ]
    results=[]
    for name,g,start,end,cut in checks:
        need(end in reachable(g,start), 'vacuous cutset '+name)
        need(end not in reachable(g,start,cut), 'cutset bypass '+name)
        results.append({'name':name,'start':hex(start),'end':hex(end),'cut':[hex(x) for x in cut]})
    denied=reachable(gp,0x41711b)
    need(not {0x416fb4,0x417040,0x417092} & denied, 'rejection calls publication operation')
    need(0x4170da in denied, 'rejection return missing')
    return {'cutsets':results,'rejection_reaches_return_without_publication_calls':True,
            'limit':'Structural paths overapproximate branch feasibility; calls return conditionally. No register, memory, source-type or runtime proof is computed.'}


def field_writes(rows, offset):
    """Explicit first-operand RSP stores only; no alias/call effect conclusion."""
    widths={'BYTE':1,'WORD':2,'DWORD':4,'QWORD':8,'XMMWORD':16}
    found=[]
    for a,_,asm in rows:
        first=asm.split(',',1)[0];op=asm.split()[0]
        m=re.search(r'(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR \[rsp(?:\+0x([0-9a-f]+))?\]',first)
        if m and op not in ('cmp','test','lea'):
            off=int(m[2] or '0',16)
            if off <= offset < off+widths[m[1]]:
                found.append({'at':hex(a),'asm':asm})
    return found


def collect(out, gnu=GNU, llvm=LLVM):
    data=TARGET.read_bytes();need(hashlib.sha256(data).hexdigest()==SHA,'target SHA256')
    image=Image(data);relocs=bindings(image);fdes=unwind(image)
    out.mkdir(parents=True,exist_ok=False)
    result={'target':{'sha256':SHA,'size':len(data)},'ranges':{},'fdes':fdes,'relocations':relocs,
            'mode_table':{'va':hex(TABLE[0]),'hex':image.at(TABLE[0],16).hex(),'targets':[hex(x) for x in TABLE[1]]},
            'tools':{k:subprocess.check_output([v,'--version'],text=True).splitlines()[0] for k,v in [('gnu',gnu),('llvm',llvm)]},
            'shared_MIT_parser_hashes':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['tools/elf_index.py','tools/fde_extents.py']}}
    allrows={};inventory=['range\taddress\tkind\tdetail'];frame=['range\taddress\tinstruction']
    flow=['range\taddress\tinstruction\tlocal structural successors']
    with tempfile.TemporaryDirectory(prefix='visor-metadata-native-') as tmp:
        path=Path(tmp)/'visor.elf';path.write_bytes(data);path.chmod(0o400)
        need(hashlib.sha256(path.read_bytes()).hexdigest()==SHA,'snapshot before native')
        for name,(start,end) in RANGES.items():
            decoded={};export={}
            for label,tool in [('gnu',gnu),('llvm',llvm)]:
                flags=['-d','-M','intel','--insn-width=16'] if label=='gnu' else ['--disassemble','--x86-asm-syntax=intel']
                text=subprocess.check_output([tool,*flags,f'--start-address={start:#x}',f'--stop-address={end:#x}',path.name],cwd=tmp,text=True)
                decoded[label]=parse(text,start,end)
                need(b''.join(b for _,b,_ in decoded[label])==image.at(start,end-start),'native target bytes')
                raw=text.encode();stored=raw if label=='gnu' else gzip.compress(raw,mtime=0)
                filename=name+'.'+label+'.txt'+('' if label=='gnu' else '.gz')
                (out/filename).write_bytes(stored)
                export[label]={'file':filename,'raw_sha256':hashlib.sha256(raw).hexdigest(),'stored_sha256':hashlib.sha256(stored).hexdigest()}
            need([(a,b) for a,b,_ in decoded['gnu']]==[(a,b) for a,b,_ in decoded['llvm']],'independent native partition')
            rows=decoded['gnu'];allrows[name]=rows;g,calls,rets=graph(rows,(start,end))
            for call in calls:
                inventory.append('\t'.join([name,call['at'],call['kind'],call.get('target',call.get('operand',''))]))
            # Retain address-formation sites, not a second copy of all stack rows.
            # The complete native exports remain the write/operand review source.
            for a,_,asm in rows:
                if (asm.startswith('lea') and 'rsp' in asm) or re.search(r',rsp$',asm):
                    frame.append(name+'\t'+hex(a)+'\t'+asm)
                if asm.startswith(('j','call','ret','ud2')):
                    flow.append('\t'.join([name,hex(a),asm,','.join(hex(x) for x in g[a]) or '-']))
            result['ranges'][name]={'start':hex(start),'end':hex(end),'bytes':end-start,'rows':len(rows),
                'scope':'complete FDE' if name in FULL else 'selected lifecycle corridor only',
                'body_sha256':hashlib.sha256(image.at(start,end-start)).hexdigest(),'exports':export,
                'calls':len(calls),'returns':[hex(x) for x in rets]}
        need(hashlib.sha256(path.read_bytes()).hexdigest()==SHA,'snapshot after native')
    result['structural_certificate']=certificate(allrows)
    result['explicit_stack_field_writes']={n:field_writes(allrows[n],off) for n,off in [('metadata',0x2c),('download',0xd)]}
    need([x['at'] for x in result['explicit_stack_field_writes']['metadata']] == ['0x4162a3','0x416342','0x416596'], 'metadata frame field writers')
    need([x['at'] for x in result['explicit_stack_field_writes']['download']] == ['0x414934'], 'download frame field writers')
    (out/'calls.tsv').write_text('\n'.join(inventory)+'\n')
    (out/'frame-review.tsv').write_text('\n'.join(frame)+'\n')
    (out/'flow.tsv').write_text('\n'.join(flow)+'\n')
    (out/'records.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--gnu',default=GNU);p.add_argument('--llvm',default=LLVM);a=p.parse_args()
    result=collect(a.out,a.gnu,a.llvm)
    print(json.dumps({'ranges':len(result['ranges']),'bytes':sum(x['bytes'] for x in result['ranges'].values()),'rows':sum(x['rows'] for x in result['ranges'].values())}))
