#!/usr/bin/env python3
"""Client transaction join static ELF admission and full native exports; no evaluation.

Generic parsing/export method adapted from the MIT author-owned client-batch
packet, with no runtime dependency on that pending contribution. Baseline parser
hashes are the only imported tool dependencies. Pins bind the manual proof; this
is not a machine-code evaluator or automatic semantic-equivalence proof.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280


class EvidenceError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dependencies():
    deps = json.loads((HERE / 'dependencies.json').read_text())
    for name, sha in deps.items():
        need(digest((ROOT / name).read_bytes()) == sha, f'dependency changed: {name}')
    return deps


# Import only the two reviewed static ELF/DWARF parsers, after binding their hashes.
dependencies()
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records


class Elf:
    def __init__(self, data, *, identity=True):
        need(len(data) == SIZE, 'target size')
        if identity:
            need(digest(data) == SHA, 'target SHA-256')
        need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
        need(struct.unpack_from('<H', data, 18)[0] == 62, 'x86-64 machine')
        self.data = data
        self.secs = sections(data)
        need(len({s['name'] for s in self.secs}) == len(self.secs), 'duplicate section names')
        self.byname = {s['name']: s for s in self.secs}
        off = struct.unpack_from('<Q', data, 32)[0]
        stride, count = struct.unpack_from('<HH', data, 54)
        need(stride == 56 and count > 0 and off + stride * count <= len(data), 'program headers')
        self.loads = [struct.unpack_from('<IIQQQQQQ', data, off + i * stride) for i in range(count)]
        self.loads = [x for x in self.loads if x[0] == 1]
        for x in self.loads:
            need(x[5] <= x[6] and x[2] + x[5] <= len(data), 'PT_LOAD bounds')
        self.cies, self.fdes = eh_frame_records(data, self.secs)
        self.relas = {}
        need({s['name'] for s in self.secs if s['type']==4} == {'.rela.dyn','.rela.plt'},
             'complete RELA section census')
        for name in ('.rela.dyn','.rela.plt'):
            s = self.byname[name]
            need(s['size'] % 24 == 0, 'RELA width')
            for at in range(s['offset'], s['offset'] + s['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, at)
                need(slot not in self.relas, 'duplicate RELA slot')
                self.relas[slot] = dict(offset=at, info=info, addend=addend)

    def offset(self, va, count, execute=False):
        need(va >= 0 and count >= 0, 'negative span')
        matches = [x[2] + va - x[3] for x in self.loads
                   if x[3] <= va and va + count <= x[3] + x[5] and (not execute or x[1] & 1)]
        need(len(matches) == 1, f'file-backed PT_LOAD span {va:#x}+{count}')
        return matches[0]

    def read(self, va, count, execute=False):
        off = self.offset(va, count, execute)
        return self.data[off:off + count]

    def record(self, va):
        length = struct.unpack('<I', self.read(va, 4))[0]
        need(4 <= length < 1024 and length != 0xffffffff, 'DWARF record length')
        return self.read(va, length + 4)

    def symbol(self, index):
        s = self.byname['.dynsym']; strings = self.byname['.dynstr']
        need((index + 1) * 24 <= s['size'], 'dynsym index')
        at = s['offset'] + index * 24
        name = struct.unpack_from('<I', self.data, at)[0]
        need(name < strings['size'], 'dynstr offset')
        start = strings['offset'] + name
        end = self.data.find(b'\0', start, strings['offset'] + strings['size'])
        need(end >= start, 'dynstr terminator')
        return self.data[start:end].decode('ascii')


def native_rows(text):
    rows = []
    for line in text.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)', line)
        if not m:
            continue
        row = dict(va=int(m[1], 16), raw=bytes.fromhex(m[2]), asm=m[3].strip())
        if rows and rows[-1]['asm'] == 'lock' and rows[-1]['va'] + len(rows[-1]['raw']) == row['va']:
            rows[-1]['raw'] += row['raw']; rows[-1]['asm'] += ' ' + row['asm']
        else:
            rows.append(row)
    return rows


def partition(elf, rows, start, end):
    pos = start
    for r in rows:
        need(r['va'] == pos and len(r['raw']) > 0, f'contiguous native partition at {pos:#x}')
        need(r['raw'] == elf.read(pos, len(r['raw']), True), f'row raw bytes at {pos:#x}')
        pos += len(r['raw'])
    need(pos == end, f'full FDE partition ending {end:#x}')


EXPECTED_STARTS = [0x439baf0, 0x45315f0, 0x4533940, 0x453ea10, 0x4548050,
                   0x454e3f0, 0x4759970, 0x4760f80, 0x4761900, 0x4b3c880,
                   0x54c06b0, 0x54c8cb0]
CONTEXTS = {0x439baf0, 0x4759970, 0x4b3c880}


def scope_rows(scope=None):
    scope = scope if scope is not None else json.loads((HERE/'scope.json').read_text())
    need(scope['sha256'] == SHA and scope['size'] == SIZE, 'scope target')
    need(scope['base'] == '56c0ec672bd8fdcfaa80f2db700a61e6240b3663', 'scope baseline')
    rows = scope['ranges']
    need([int(x['start'],16) for x in rows] == EXPECTED_STARTS, 'exact full-FDE census/order')
    need(sum(x['size'] for x in rows) == 53725 and sum(x['rows'] for x in rows) == 9361,
         'full export denominator')
    need(sum(x['size'] for x in rows if int(x['start'],16) not in CONTEXTS) == 2580,
         'bounded core/helper byte denominator')
    return rows


def relocation(elf, slot):
    need(slot in elf.relas, 'missing RELA slot')
    rel = elf.relas[slot]; kind, symbol = rel['info'] & 0xffffffff, rel['info'] >> 32
    result = dict(slot=hex(slot),file_offset=rel['offset'],kind=kind,symbol_index=symbol,
                  addend=rel['addend'],raw=elf.data[rel['offset']:rel['offset']+24].hex(),
                  stored_slot=elf.read(slot,8).hex())
    if kind == 8:
        need(symbol == 0, 'RELATIVE symbol index must be zero')
        result['target'] = hex(rel['addend'])
    else:
        need(kind == 6 and rel['addend'] == 0, 'admitted import kind/addend')
        result['symbol'] = elf.symbol(symbol)
    if slot == 0x576e488:
        need(kind == 6 and result.get('symbol') == 'memcmp', 'memcmp symbol binding')
    return result


def references(elf, rows):
    """All native call/tail transfers and RIP references, including loaded callees.

    RIP comments locate candidate addresses; a matching instruction-relative raw
    disp32 is required. Whole-body/pin checks separately bind the instruction.
    This is static export, not register-value execution or arbitrary call closure.
    """
    refs=[]
    for row in rows:
        va,raw,asm = row['va'],row['raw'],row['asm']
        op=asm.split()[0]; r=dict(at=hex(va),asm=asm,raw=raw.hex())
        if op in ('call','jmp'):
            r['transfer']=op
            if raw[0] in (0xe8,0xe9) and len(raw)==5:
                r['target']=hex(va+5+struct.unpack_from('<i',raw,1)[0])
            elif raw[0]==0xeb and len(raw)==2:
                r['target']=hex(va+2+struct.unpack_from('<b',raw,1)[0])
            else:r['indirect']=True
        if '[rip' in asm:
            m=re.search(r'#\s+([0-9a-f]+)\b',asm)
            need(m is not None,'RIP reference comment')
            target=int(m[1],16)
            candidates=[i for i in range(len(raw)-3)
                        if va+len(raw)+struct.unpack_from('<i',raw,i)[0]==target]
            need(len(candidates)==1,'raw RIP disp32 correspondence')
            r.update(rip_target=hex(target),displacement_offset=candidates[0])
            if target in elf.relas:r['relocation']=relocation(elf,target)
        if 'transfer' in r or 'rip_target' in r:refs.append(r)
    return refs


def validate(elf, decoded, *, body_identity=True, scope=None):
    wanted=scope_rows(scope)
    need(sorted(decoded)==EXPECTED_STARTS,'decoded full-FDE census')
    pins=json.loads((HERE/'obligations.json').read_text())
    need(pins['target']==SHA and len(pins['instructions'])==622,'instruction pin target/census')
    need(len({x['va'] for x in pins['instructions']})==622,'unique instruction pins')
    need([(x['va'],len(bytes.fromhex(x['raw']))) for x in pins['data']]==[('0x6f5ac0',156)],
         'complete selected-error table census')
    allrows={}; records=[]; slots={}
    for r in wanted:
        start,end=int(r['start'],16),int(r['end'],16)
        need(end-start==r['size'] and end>start,'range size')
        overlap=[f for f in elf.fdes if f['start']<end and f['end']>start]
        need(len(overlap)==1,'unique overlapping FDE')
        f=overlap[0]
        need((f['start'],f['end'],f['fde'],f['cie'])==
             (start,end,int(r['fde'],16),int(r['cie'],16)),'exact FDE/CIE identity/extent')
        need(elf.record(f['fde']).hex()==r['fde_raw'] and elf.record(f['cie']).hex()==r['cie_raw'],
             'raw FDE/CIE records')
        need((hex(f['lsda']) if f['lsda'] else None)==r['lsda'],'LSDA pointer identity')
        body=elf.read(start,end-start,True)
        if body_identity:need(digest(body)==r['sha256'],'full body identity '+hex(start))
        gr,lr=decoded[start];partition(elf,gr,start,end);partition(elf,lr,start,end)
        need([(x['va'],x['raw']) for x in gr]==[(x['va'],x['raw']) for x in lr],
             'GNU/LLVM full byte partition agreement')
        need(len(gr)==r['rows'],'native grouped instruction denominator')
        for row in gr:
            op=row['asm'].split()[0]
            if op in ('data16','cs','ds','es','ss','fs','gs','rep','repz','repnz','addr32'):
                need(re.fullmatch(r'(?:(?:data16|cs) )*nop(?: .*)?',row['asm']) is not None,
                     'unreviewed non-NOP prefix '+hex(row['va']))
            need(row['va'] not in allrows,'overlapping decoded row');allrows[row['va']]=row
        refs=references(elf,gr)
        calls=[x for x in refs if x.get('transfer')=='call']
        need([x['at'] for x in calls]==[x['at'] for x in r['calls']],'complete call-site census')
        for actual,original in zip(calls,r['calls']):
            if 'slot' in original:
                rel=actual.get('relocation',{})
                need(rel.get('slot')==original['slot'] and rel.get('kind')==original['rela_type']
                     and rel.get('symbol_index')==original['symbol_index']
                     and rel.get('addend')==int(original['addend'],16),'call RELA identity')
            elif 'target' in original:need(actual.get('target')==original['target'],'direct call target')
            else:need(actual['asm']==original['asm'],'dynamic call shape')
        for x in refs:
            if 'relocation' in x:slots[x['relocation']['slot']]=x['relocation']
        records.append(dict(start=hex(start),end=hex(end),size=end-start,rows=len(gr),
                            sha256=digest(body),role=r['role'],fde=hex(f['fde']),cie=hex(f['cie']),
                            fde_raw=elf.record(f['fde']).hex(),cie_raw=elf.record(f['cie']).hex(),
                            lsda=r['lsda'],references=refs))
    for p in pins['instructions']:
        row=allrows.get(int(p['va'],16));need(row is not None,'pin address')
        need(row['raw'].hex()==p['raw'],'instruction obligation bytes '+p['va'])
        need(row['asm']==p['asm'],'instruction obligation decode '+p['va'])
    for p in pins['data']:
        need(elf.read(int(p['va'],16),len(bytes.fromhex(p['raw']))).hex()==p['raw'],'table obligation')
    # Read-only code bytes must not receive any captured dynamic relocation.
    # Node94's full .rela.dyn/.rela.plt census is 1/6/7/8/18, each an eight-byte field
    # under AMD64 psABI. Other kinds fail rather than guessing their width.
    kinds={}
    for slot,rel in elf.relas.items():
        kind=rel['info']&0xffffffff;need(kind in (1,6,7,8,18),'unreviewed RELA width')
        kinds[kind]=kinds.get(kind,0)+1
        need(all(not(slot<int(r['end'],16) and slot+8>int(r['start'],16)) for r in wanted),
             'dynamic relocation overlaps selected code')
    return dict(target=SHA,full_export=dict(functions=12,bytes=53725,rows=9361),
                core_and_bounded_helpers=dict(functions=9,bytes=2580,rows=634),
                caller_context_only=dict(functions=3,bytes=51145,rows=8727),
                instruction_pins=622,data_pins=1,ranges=records,
                relocation_slots=[slots[k] for k in sorted(slots,key=lambda x:int(x,16))],
                all_dynamic_relocation_type_census=kinds)


def flow(rows):
    """Conservative ordinary entry CFG, calls may return; no inferred noreturn."""
    graph={};by={r['va']:r for r in rows}
    for row in rows:
        at=row['va'];asm=row['asm'].split('#',1)[0].strip();op=asm.split()[0]
        if op in ('data16','cs'):
            need(re.fullmatch(r'(?:(?:data16|cs) )*nop(?: .*)?',asm) is not None,'CFG prefixed operation')
        nxt=at+len(row['raw']);edges=[]
        if op.startswith('j'):
            m=re.match(r'j[a-z]+\s+([0-9a-f]+)\b',asm);need(m is not None,'CFG indirect branch')
            target=int(m[1],16);need(target in by,'CFG branch boundary');edges.append(target)
            if op!='jmp' and nxt in by:edges.append(nxt)
        elif op not in ('ret','ud2') and nxt in by:edges.append(nxt)
        graph[at]=edges
    return graph


def reachable(graph,start,blocked=()):
    seen=set();todo=[start];blocked=set(blocked)
    while todo:
        at=todo.pop()
        if at in seen or at in blocked:continue
        need(at in graph,'CFG entry');seen.add(at);todo.extend(graph[at])
    return seen


def local_facts(elf,decoded):
    rows=decoded[0x4548050][0];g=flow(rows);by={r['va']:r for r in rows}
    supplied=reachable(g,0x4548076);empty=reachable(g,0x4548304);miss=reachable(g,0x4548347)
    need(0x45480b0 in supplied and 0x45480b0 in empty and 0x45480b0 in miss,'ordinary return reachability')
    need(not any(by[x]['asm'].startswith('call') for x in supplied),'provided rows cannot call a helper')
    need(not({0x45480b1,0x4548133,0x4548138,0x454815c}&supplied),'provided bypasses hash/map views')
    need(not({0x4548133,0x4548138,0x454815c,0x4548225}&empty),'empty bypasses hash pointer/map')
    checks=[]
    for label,start,dest,gate in [
        ('missing hash fully published before prefix release',0x4548347,0x45483be,0x454838b),
        ('missing hash fully published before row free',0x4548347,0x45483e6,0x454838b),
        ('missing hash fully published before block release',0x4548347,0x45483f1,0x454838b),
        ('row storage cleanup precedes block release',0x45483e6,0x45483f1,0x45483ec),
        ('hit error-drop precedes value clone',0x4548270,0x45482ac,0x454829f),
        ('row identity store precedes length increase',0x4548170,0x4548197,0x454817c),
        ('success Arc allocation precedes output row pointer',0x4548420,0x45484a4,0x4548460)]:
        need(dest in reachable(g,start),'nonvacuous ordering '+label)
        need(dest not in reachable(g,start,{gate}),'dominance '+label)
        checks.append(dict(name=label,start=hex(start),destination=hex(dest),gate=hex(gate)))
    table=elf.read(0x6f5ac0,156);targets=[0x6f5ac0+x for x in struct.unpack('<39i',table)]
    drop={x['va']:x for x in decoded[0x453ea10][0]}
    need(all(x in drop for x in targets),'all drop table destinations are decoded boundaries')
    need(targets[27]==0x453ea99 and drop[0x453ea99]['raw']==b'\x5b' and
         drop[0x453ea9a]['raw']==b'\xc3','raw 1c selected error drop is pop/ret')
    writes=[];implicit=[]
    for row in rows:
        asm=row['asm'];core=asm[5:] if asm.startswith('lock ') else asm;op=core.split()[0]
        need(not op.startswith(('stos','movs','ins','outs')),'unreviewed implicit string memory effect')
        if op in ('call','push','pop','ret'):implicit.append(dict(at=hex(row['va']),kind=op))
        first=core.split(None,1)[1].split(',',1)[0] if ' ' in core else ''
        if '[' in first and op not in ('cmp','test','nop','lea','call','jmp','push','pop','ret','data16','cs') and not op.startswith('j'):
            writes.append(dict(at=hex(row['va']),asm=asm,on_miss_path=row['va'] in miss))
    need(0x333333333333333==((1<<63)-1)//40,'40-byte signed-span bound')
    return dict(ordering=checks,provided_path=[hex(x) for x in sorted(supplied)],
                empty_path=[hex(x) for x in sorted(empty)],missing_path=[hex(x) for x in sorted(miss)],
                drop_table_destinations=[hex(x) for x in targets],selected_drop_index=27,
                explicit_first_operand_memory_writes=writes,implicit_stack_effects=implicit,
                scope='Ordinary CFG plus raw selected-table check; manual proof supplies values, stable count, ownership and helper frames.')


def decode_snapshot(elf, *, gnu=GNU, llvm=LLVM, subset=None):
    outputs={};decoded={};commands=[]
    with tempfile.TemporaryDirectory(prefix='txjoin-static-') as directory:
        path=Path(directory)/'hl-node';path.write_bytes(elf.data);path.chmod(0o400)
        for r in scope_rows():
            start,end=int(r['start'],16),int(r['end'],16)
            if subset is not None and start not in subset:continue
            texts=[]
            for provider,cmd in [('gnu',[gnu,'-d','-w','-Mintel']),('llvm',[llvm,'-d','--x86-asm-syntax=intel'])]:
                cmd += [f'--start-address={start}',f'--stop-address={end}',str(path)]
                run=subprocess.run(cmd,capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'})
                need(run.returncode==0 and not run.stderr,'native provider failed: '+run.stderr)
                texts.append(run.stdout.replace(str(path),'hl-node'))
                commands.append(dict(argv=['<'+provider.upper()+'>']+cmd[1:-1]+['<PRIVATE_TARGET_SNAPSHOT>'],
                                     exit_code=run.returncode,stderr=run.stderr,
                                     stdout_file=f'native/{start:x}.{provider}.txt.gz',
                                     normalized_stdout_sha256=digest(texts[-1].encode()),
                                     normalization='Only input filename replaced by hl-node; command executable/snapshot paths represented by logical identities.'))
            for name,txt in zip(('gnu','llvm'),texts):
                outputs[f'native/{start:x}.{name}.txt.gz']=gzip.compress(txt.encode(),mtime=0)
            decoded[start]=(native_rows(texts[0]),native_rows(texts[1]))
        need(path.read_bytes()==elf.data,'private snapshot modified during export')
    outputs['native/commands.json']=(json.dumps(commands,separators=(',',':'))+'\n').encode()
    return outputs,decoded


def collect(binary=None, *, gnu=GNU, llvm=LLVM):
    dependencies();elf=Elf((binary or ROOT/'artifacts/node/94/hl-node').read_bytes())
    outputs,decoded=decode_snapshot(elf,gnu=gnu,llvm=llvm)
    record=validate(elf,decoded);record['local_facts']=local_facts(elf,decoded)
    outputs['records.json']=(json.dumps(record,separators=(',',':'))+'\n').encode()
    return outputs


def write_new(out,outputs):
    need(not out.exists(),'output must be new')
    for name,raw in outputs.items():
        path=out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--gnu',default=GNU);ap.add_argument('--llvm',default=LLVM);a=ap.parse_args()
    outputs=collect(a.binary,gnu=a.gnu,llvm=a.llvm);write_new(a.out,outputs)
    print(json.dumps(dict(files=len(outputs),full_fdes=12,core_fdes=9,core_bytes=2580,caller_context_bytes=51145)))


if __name__=='__main__':main()
