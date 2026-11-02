#!/usr/bin/env python3
"""ABCI stream greeting static ELF admission and full native exports; no evaluation.

Generic parsing/export methods adapted from the independently authored MIT
funding-residual packet evidence.py SHA e0ae2ad01e490e474fde86f7296a90f21732aaf9d49b1579c1fc5f96ae155e91.
No runtime dependency on that contribution; only merged baseline ELF/DWARF
parsers are imported. No captured instructions are evaluated.
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
    imports={0x576e488:'memcmp',0x576e0e0:'memmove',0x576dfe0:'memcpy'}
    if slot in imports:
        need(kind == 6 and result.get('symbol') == imports[slot], 'copy/compare import symbol binding')
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
        if 'target' in r:
            r['target_file_offset']=elf.offset(int(r['target'],16),1,True)
        if 'rip_target' in r:
            target=int(r['rip_target'],16)
            widths=[('XMMWORD PTR',16),('QWORD PTR',8),('DWORD PTR',4),('WORD PTR',2),('BYTE PTR',1)]
            width=next((n for label,n in widths if label in asm),1)
            mappings=[x for x in elf.loads if x[3]<=target and target+width<=x[3]+x[6]]
            need(len(mappings)==1,'RIP address memory span')
            h=mappings[0];backed=target+width<=h[3]+h[5]
            r['rip_span']=dict(width=width,load_start=hex(h[3]),flags=h[1],file_backed=backed,
                               file_offset=h[2]+target-h[3] if backed else None,
                               address_only=op=='lea')
        if 'transfer' in r or 'rip_target' in r:refs.append(r)
    return refs


# The table addresses and complete destinations are manually read obligations,
# not inferred from apparent symbol names or guessed enum cardinalities.
TABLES = {
    0x6f700c: (0x467486c, 0x4674966, 0x4674954, 0x467495d, 0x467494b, 0x46749db),
    0x6f6e98: (0x466bc79, 0x466bc85, 0x466bcd3, 0x466bcbb),
    0x6f6ea8: (0x466bd76, 0x466bd8e, 0x466bd82, 0x466bdc5),
    0x6f6eb8: (0x466bed6, 0x466beee, 0x466bee2, 0x466bf25),
    0x6f6ec8: (0x466d8b7, 0x466d8c4, 0x466d945, 0x466d92d),
    0x6f6ed8: (0x466d9e7, 0x466da01, 0x466d9f4, 0x466da8c),
    0x6f6ee8: (0x466db37, 0x466db51, 0x466db44, 0x466dbdc),
}
DISPATCH = {0x467486a: 0x6f700c, 0x466bc77: 0x6f6e98,
            0x466bd74: 0x6f6ea8, 0x466bed4: 0x6f6eb8,
            0x466d8b4: 0x6f6ec8, 0x466d9e4: 0x6f6ed8, 0x466db34: 0x6f6ee8}
REGISTER_CALLS = {
    0x4217c5a: (0x4217c53, 'rbx', 0x576dfe0),
    0x4217c7c: (0x4217c53, 'rbx', 0x576dfe0),
    0x4217d65: (0x4217d5b, 'r12', 0x576e0e0),
    0x4217da4: (0x4217d5b, 'r12', 0x576e0e0),
    0x4218061: (0x421805a, 'r15', 0x576dfe0),
    0x4218094: (0x421805a, 'r15', 0x576dfe0),
    0x4218576: (0x4218568, 'r15', 0x576e0e0),
    0x42185b3: (0x4218568, 'r15', 0x576e0e0),
    0x4218606: (0x4218568, 'r15', 0x576e0e0),
    **{x: (0x485bbcb, 'r12', 0x576dfe0) for x in (0x485bbdd, 0x485bbf0, 0x485bc08, 0x485bc20)},
    0x494e6e5: (0x494e6c3, 'rbx', 0x576e010),
    0x494e736: (0x494e706, 'rbx', 0x576e010),
    0x49b5da6: (0x49b5c80, 'r12', 0x576e010),
    0x49b5f25: (0x49b5eff, 'r12', 0x576e010),
}


def leb(raw, p, end, signed=False):
    start = p; value = shift = 0
    while True:
        need(p < end and p-start < 10, 'bounded LEB')
        byte = raw[p]; p += 1; value |= (byte & 127) << shift; shift += 7
        if not byte & 128:
            if signed and byte & 64:
                value -= 1 << shift
            return value, p


def lsda(elf, fde, starts):
    address = fde['lsda']
    if address is None:
        return None
    sec = elf.byname['.gcc_except_table']; secend = sec['address'] + sec['size']
    need(sec['address'] <= address < secend, 'LSDA section')
    upper = min([x['lsda'] for x in elf.fdes if x['lsda'] and address < x['lsda'] < secend] + [secend])
    raw = elf.read(address, upper-address)
    need(len(raw) >= 4 and raw[0] == 0xff, 'omitted LPStart')
    p = 2
    if raw[1] == 0xff:
        type_base = len(raw)
    else:
        need(raw[1] == 0x9b, 'selected type table encoding')
        distance, p = leb(raw, p, len(raw)); type_base = p + distance
        need(type_base <= len(raw), 'type table upper bound')
    need(raw[p] == 1, 'ULEB call site encoding'); p += 1
    length, p = leb(raw, p, len(raw)); end = p + length
    need(end <= type_base, 'callsite table extent')
    result = []; previous = fde['start']
    while p < end:
        values = []
        for _ in range(4):
            value, p = leb(raw, p, end); values.append(value)
        offset, size, pad, action = values
        start = fde['start'] + offset; stop = start + size
        landing = fde['start'] + pad if pad else None
        need(fde['start'] <= start < stop <= fde['end'] and start >= previous, 'ordered LSDA callsite')
        need(start in starts and (stop == fde['end'] or stop in starts), 'LSDA instruction endpoints')
        need(landing is None or landing in starts, 'LSDA landing boundary')
        previous = stop; seen = set(); chain = []; at = end + action - 1 if action else None
        while at is not None:
            need(end <= at < type_base and at not in seen, 'LSDA action range/cycle')
            seen.add(at); filt, second = leb(raw, at, type_base, True)
            delta, after = leb(raw, second, type_base, True)
            chain.append(dict(va=hex(address+at), filter=filt, displacement=delta, raw=raw[at:after].hex()))
            at = second + delta if delta else None
        result.append(dict(start=hex(start), end=hex(stop), landing=hex(landing) if landing else None,
                           action=action, chain=chain))
    cie = elf.cies[fde['cie']]
    need(cie['personality_slot'] is not None, 'LSDA CIE personality')
    return dict(va=hex(address), file_offset=elf.offset(address, len(raw)),
                upper_bound=hex(upper), upper_bound_is_object_size=False, raw=raw.hex(),
                personality=relocation(elf, cie['personality_slot']), callsites=result,
                limit='Call-site/action bytes only; no personality, filter matching or unwind execution theorem.')


def branch_target(row):
    raw = row['raw']; va = row['va']
    if len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        return va + 2 + struct.unpack_from('<b', raw, 1)[0]
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    return None


def cfg(rows):
    lookup = {r['va']: r for r in rows}; start = rows[0]['va']; end = rows[-1]['va'] + len(rows[-1]['raw']); graph = {}
    for r in rows:
        va = r['va']; asm = r['asm']; op = asm.split()[0]; nxt = va + len(r['raw']); target = branch_target(r)
        # Prefixes are not a general decoder. Only exactly admitted NOP padding
        # may use these mnemonic spellings; prefixed MOV/JMP cannot hide writes.
        if op in ('data16', 'cs'):
            need('nop' in asm.split(), 'non-NOP prefixed instruction')
        if op in ('ret', 'ud2'):
            edges = []
        elif op == 'jmp':
            if target is not None:
                edges = [target] if start <= target < end else []
            elif va in DISPATCH:
                edges = list(TABLES[DISPATCH[va]])
            else:
                need('[rip' in asm, 'unknown indirect jump')
                edges = []  # external tail-call, recorded separately; no in-FDE successor
        elif op.startswith('j'):
            need(target is not None, 'undecoded conditional branch'); edges = [target, nxt]
        else:
            edges = [nxt] if nxt < end else []
        need(all(x in lookup for x in edges), 'in-FDE CFG instruction target')
        graph[va] = edges
    return graph


def reachable(graph, start, blocked=()):
    todo = [start]; seen = set(); blocked = set(blocked)
    while todo:
        at = todo.pop()
        if at in seen or at in blocked:
            continue
        seen.add(at); todo.extend(graph[at])
    return seen


def register_writes(row, register):
    asm = row['asm'].split('#')[0].strip(); op, _, operands = asm.partition(' ')
    aliases = {'rbx': {'rbx','ebx','bx','bl','bh'}, 'r12': {'r12','r12d','r12w','r12b'}, 'r15': {'r15','r15d','r15w','r15b'}}[register]
    parts = [x.strip() for x in operands.split(',')]
    if op in ('cmp','test','push','call','jmp','ret','nop','data16','cs') or op.startswith('j'):
        return False
    if op == 'xchg':
        return any(x in aliases for x in parts)
    return bool(parts and parts[0] in aliases)


def register_bindings(elf, rows):
    graph = cfg(rows); lookup = {r['va']: r for r in rows}; out = []
    calls = {r['va'] for r in rows if re.fullmatch(r'call\s+(?:rbx|r12|r15)',r['asm'])}
    need(calls == set(REGISTER_CALLS) & set(lookup), 'register call census')
    for call in sorted(calls):
        load, reg, slot = REGISTER_CALLS[call]
        need(load in lookup and call in reachable(graph, rows[0]['va']), 'reachable register call/load')
        need(call not in reachable(graph, rows[0]['va'], [load]), 'register load dominates call')
        refs = references(elf, [lookup[load]])
        need(len(refs) == 1 and refs[0].get('rip_target') == hex(slot), 'register source slot')
        need(re.match(r'mov\s+'+reg+r',QWORD PTR', lookup[load]['asm']), 'register load shape')
        forward = set().union(*(reachable(graph, successor, [load]) for successor in graph[load]))
        backwards = {x: [] for x in graph}
        for a, dests in graph.items():
            for b in dests: backwards[b].append(a)
        corridor = forward & reachable(backwards, call, [load])
        # The dominating load may be revisited by a loop; every such definition
        # loads the same bound slot. All other writes on a call-reaching path fail.
        writes = [x for x in corridor if x != load and register_writes(lookup[x], reg)]
        need(not writes, 'callee register changed on load-call corridor')
        out.append(dict(call=hex(call), load=hex(load), register=reg, slot=hex(slot),
                        relocation=relocation(elf, slot), corridor_instructions=len(corridor),
                        premise='All intervening ordinary calls preserve this SysV callee-saved register; slot binding and unrelated memory remain stable.'))
    return out
RANGES = ((0x42179a0,0x421889f),(0x4589a30,0x4589b2b),(0x466ba80,0x466bba3),
 (0x466bbb0,0x466bc09),(0x466bc10,0x466bd03),(0x466bd10,0x466bdf5),(0x466be70,0x466bf55),
 (0x466bf60,0x466c13f),(0x466c140,0x466c1a6),(0x466c1b0,0x466c223),(0x466d850,0x466d975),
 (0x466d980,0x466dabc),(0x466dac0,0x466dace),(0x466dad0,0x466dc0c),(0x466de60,0x466df91),
 (0x466e750,0x466eb67),(0x4674820,0x4674b45),(0x471b880,0x471bfb6),(0x485baa0,0x485bc68),
 (0x4900220,0x49002ab),(0x4908500,0x490858b),(0x49300b0,0x493039a),(0x4939020,0x493930a),
 (0x493ded0,0x493e1ba),(0x494e540,0x494e8ed),(0x496ec70,0x496f026),(0x496f030,0x496f36e),
 (0x496f370,0x496f726),(0x49784e0,0x49787f1),(0x49b5c50,0x49b5f9d))


def validate(elf, streams, scope=None, obligations=None, body_identity=True):
    scope = json.loads((HERE/'scope.json').read_text()) if scope is None else scope
    obligations = json.loads((HERE/'obligations.json').read_text()) if obligations is None else obligations
    need(scope['sha256'] == SHA and scope['size'] == SIZE and obligations['target'] == SHA, 'scope target')
    need(tuple((int(x['start'],16),int(x['end'],16)) for x in scope['ranges']) == RANGES, 'exact complete FDE scope')
    need(set(streams) == {start for start,end in RANGES}, 'complete native stream set')
    pinmap = {int(p['va'],16): bytes.fromhex(p['raw']) for p in obligations['instructions']}
    need(len(pinmap) == len(obligations['instructions']) == obligations['instruction_count'] == 4280, 'instruction obligation census')
    need(len(obligations['data']) == 11 and {int(p['va'],16) for p in obligations['data']} ==
         set(TABLES) | {0x6f877f,0x6f878b,0x203580,0x209410}, 'exact data obligation census')
    allrows = {}; refs = []; register = []; ls = []; bodies = []; edges = []; slots = {}
    for item in scope['ranges']:
        start,end = int(item['start'],16),int(item['end'],16)
        need(item['size'] == end-start and item['file_offset'] == elf.offset(start,end-start,True), 'FDE byte mapping')
        matched = [f for f in elf.fdes if f['start']==start and f['end']==end]
        need(len(matched)==1, 'unique exact FDE'); f=matched[0]
        need(hex(f['fde']) == item['fde'] and hex(f['cie']) == item['cie'], 'FDE/CIE association')
        need(elf.record(f['fde']).hex()==item['fde_raw'] and elf.record(f['cie']).hex()==item['cie_raw'], 'FDE/CIE raw identity')
        if body_identity:
            need(digest(elf.read(start,end-start,True)) == item['sha256'], 'whole FDE bytes')
        g,l = streams[start]
        partition(elf,g,start,end); partition(elf,l,start,end)
        need([(r['va'],r['raw']) for r in g] == [(r['va'],r['raw']) for r in l], 'GNU LLVM native partition equivalence')
        need(len(g)==item['rows'], 'native row census')
        graph=cfg(g); allrows.update({r['va']:r for r in g})
        for row in g:
            if 'nop' not in row['asm'].split():
                need(pinmap.get(row['va']) == row['raw'], 'active instruction obligation')
        for a,bs in graph.items():
            row=next(r for r in g if r['va']==a)
            if row['asm'].split()[0].startswith('j'):
                edges.append(dict(at=hex(a),successors=[hex(x) for x in bs]))
        local_refs=references(elf,g); refs.extend(local_refs)
        calls=[]
        for ref in local_refs:
            if 'relocation' in ref: slots[ref['relocation']['slot']]=ref['relocation']
            if ref.get('transfer')!='call': continue
            x={'at':ref['at']}
            if 'relocation' in ref:
                r=ref['relocation'];x.update(slot=r['slot'],rela_type=r['kind'],symbol_index=r['symbol_index'],addend=hex(r['addend']),symbol=r.get('symbol'))
            elif 'target' in ref:x['target']=ref['target']
            else:x['asm']=ref['asm']
            calls.append(x)
        need(calls==item['calls'], 'complete call bindings')
        register.extend(register_bindings(elf,g))
        lsda_value=lsda(elf,f,set(graph))
        if lsda_value: ls.append(dict(function=hex(start),**lsda_value))
        bodies.append(dict(start=hex(start),end=hex(end),bytes=end-start,rows=len(g),sha256=digest(elf.read(start,end-start,True)),context_only=item['context_only']))
    need(set(pinmap) == {va for va,row in allrows.items() if 'nop' not in row['asm'].split()}, 'exact obligation address set')
    data=[]
    for item in obligations['data']:
        va=int(item['va'],16); raw=bytes.fromhex(item['raw']);need(elf.read(va,len(raw))==raw,'literal/table obligation')
        data.append(dict(**item,file_offset=elf.offset(va,len(raw))))
    tables=[]
    for va,expected in TABLES.items():
        actual=tuple(va+x for x in struct.unpack('<'+'i'*len(expected),elf.read(va,4*len(expected))))
        need(actual==expected and all(x in allrows for x in actual),'signed dispatch entries')
        tables.append(dict(va=hex(va),destinations=[hex(x)for x in actual]))
    protected=list(RANGES)+[(int(x['va'],16),int(x['va'],16)+len(bytes.fromhex(x['raw']))) for x in data]
    kinds={}
    for va,rel in elf.relas.items():
        kind=rel['info']&0xffffffff;kinds[kind]=kinds.get(kind,0)+1
        need(kind in (1,6,7,8,18),'complete node94 relocation width census')
        need(not any(va<end and start<va+8 for start,end in protected),'RELA overlaps admitted instruction/data bytes')
    need(len(elf.relas)==80300,'complete relocation count')
    # Scalar byte-shape and copy offsets above have independent manual proofs;
    # this evidence validator binds their exact native instructions, not an ISA interpreter.
    return dict(target_sha256=SHA,target_size=SIZE,full_fdes=len(bodies),core_fdes=28,
        native_bytes=sum(x['bytes']for x in bodies),core_bytes=sum(x['bytes']for x in bodies if not x['context_only']),
        native_rows=len(allrows),instruction_obligations=len(pinmap),data_obligations=len(data),
        all_relocations=len(elf.relas),relocation_kind_counts=kinds,bodies=bodies,call_and_rip_references=refs,
        slots=slots,register_calls=register,branches=edges,dispatch_tables=tables,lsda=ls,data=data,
        scope='Whole native decode and static bindings; manual conditional operation proof, no captured instruction evaluation or personality execution.')


def export(elf, gnu=GNU, llvm=LLVM):
    files={};streams={};commands=[];providers={}
    for name,path in [('gnu',gnu),('llvm',llvm)]:
        r=subprocess.run([path,'--version'],capture_output=True,timeout=30)
        need(r.returncode==0,'native provider version')
        providers[name]=dict(executable_sha256=digest(Path(path).read_bytes()),executable_bytes=Path(path).stat().st_size,
            version_stdout=r.stdout.decode(),version_stderr=r.stderr.decode(),exit_code=r.returncode,recorded_path=str(path))
    with tempfile.TemporaryDirectory(prefix='greeting-static-') as tmp:
        snapshot=Path(tmp)/'hl-node';snapshot.write_bytes(elf.data);snapshot.chmod(0o400)
        for start,end in RANGES:
            pair=[]
            for name,head in [('gnu',[gnu,'-d','-w','-Mintel']),('llvm',[llvm,'-d','--x86-asm-syntax=intel'])]:
                args=head+[f'--start-address={start}',f'--stop-address={end}','hl-node']
                r=subprocess.run(args,cwd=tmp,capture_output=True,env={**os.environ,'LC_ALL':'C'},timeout=60)
                need(r.returncode==0 and not r.stderr,'native provider completion')
                path=f'native/{start:x}.{name}.txt.gz';files[path]=gzip.compress(r.stdout,mtime=0)
                pair.append(native_rows(r.stdout.decode()))
                commands.append(dict(argv=['<'+name.upper()+'>']+args[1:],cwd='<PRIVATE_AUTHENTICATED_READONLY_SNAPSHOT>',
                    exit_code=0,stderr='',stdout_file=path,stdout_sha256=digest(r.stdout),
                    normalization='none; provider invoked on relative filename hl-node from private snapshot cwd'))
            streams[start]=pair
        need(snapshot.read_bytes()==elf.data,'private snapshot changed')
    files['native/commands.json']=(json.dumps(commands,separators=(',',':'))+'\n').encode()
    files['providers.json']=(json.dumps(providers,indent=2)+'\n').encode()
    return streams,files


def collect(target,gnu=GNU,llvm=LLVM):
    elf=Elf(Path(target).read_bytes());streams,files=export(elf,gnu,llvm)
    record=validate(elf,streams)
    files['records.json']=(json.dumps(record,separators=(',',':'))+'\n').encode()
    return files


def write_new(out,files):
    need(not out.exists(),'fresh output directory');out.mkdir(parents=True)
    for name,raw in files.items():
        p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--target',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--gnu',default=GNU);parser.add_argument('--llvm',default=LLVM);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();write_new(args.out,collect(args.target,args.gnu,args.llvm))


if __name__=='__main__':
    main()
