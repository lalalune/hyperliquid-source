#!/usr/bin/env python3
"""Recover node94 provider installation and private precompile materialization.

Static byte inspection only. Semantic labels are hypotheses; the original
operands, FDE records, RELA entries and exception call-site rows are retained.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records, uleb, sleb

ROOT = Path(__file__).resolve().parents[1]
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x247fd20: 'private engine builder and provider override',
    0x2464bd0: 'fork-selected handler construction',
    0x278fae0: 'preexecution handler pairs',
    0x2792da0: 'raw-spec-18 execution handler pairs',
    0x25154a0: 'execution entry with provider invocation and context installation',
    0x2787460: 'load account through private database boundary and journal access',
    0x2788350: 'load account code through private database boundary',
    0x27cc680: 'lookup account state by full address',
    0x2788710: 'provider A context precompile lookup and result handling',
    0x2787af0: 'provider A checkpoint rollback',
    0x2997ab0: 'provider A reverse journal entries',
    0x25b6ca0: 'registry keys to warm-address set',
    0x26b8980: 'extend warm-address set',
    0x276d390: 'runtime call adapter',
    0x244fe00: 'install provider from handler spec byte',
    0x24b6590: 'second provider installation copy',
    0x24448a0: 'provider A constructs standard plus private registry',
    0x247d7f0: 'retain twenty provider captures',
    0x25b6e20: 'provider A borrowed to owned conversion',
    0x26ba880: 'provider A new seeded table from standard iterator',
    0x20482c0: 'provider A clone standard entries into context map',
    0x26ba640: 'provider A extend with twenty private entries',
    0x27c9190: 'provider A insert or replace context value',
    0x277c590: 'provider A context value drop',
    0x258d300: 'provider A remaining array cleanup',
    0x2025340: 'provider A map cleanup',
    0x2456680: 'release twenty provider captures',
    0x3268ce0: 'provider B constructs standard plus private registry',
    0x3421670: 'provider B ensure owned and extend',
    0x3438b20: 'provider B borrowed to owned conversion',
    0x36e35f0: 'provider B new seeded table from standard iterator',
    0x3be4700: 'provider B extend loop and replaced value cleanup',
    0x379c750: 'provider B insert or replace context value',
    0x34d8d70: 'provider B map cleanup',
    0x35775d0: 'provider B clone standard entries into context map',
    0x3433310: 'provider B context value drop',
    0x1fa3f30: 'provider A iterator and map value drop',
    0x25b3780: 'provider A array record drop',
    0x34040b0: 'provider B remaining array cleanup',
    0x3433c90: 'provider B full array cleanup',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


class Image:
    def __init__(self, data):
        require(digest(data) == SHA, 'target digest mismatch')
        self.data = data
        self.secs = sections(data)
        self.cies, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        s = self.section('.rela.dyn')
        require(s['size'] % 24 == 0, 'partial RELA record')
        self.relas = {}
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            require(va not in self.relas, 'duplicate RELA slot')
            self.relas[va] = (info, addend, off)

    def section(self, name):
        rows = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or ambiguous section')
        return rows[0]

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid requested range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'truncated file range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, va):
        rows = self.fdes.get(va, [])
        require(len(rows) == 1, 'missing or duplicate FDE')
        f = rows[0]
        text = self.section('.text')
        require(text['address'] <= va < f['end'] <= text['address'] + text['size'],
                'invalid executable FDE interval')
        return f

    def relative(self, slot):
        require(slot in self.relas, 'missing relocation')
        info, addend, _ = self.relas[slot]
        require(info == 8, 'not a symbol-free RELATIVE relocation')
        return addend

    def expect(self, va, hexbytes):
        raw = bytes.fromhex(hexbytes)
        require(self.read(va, len(raw)) == raw, 'byte predicate mismatch')
        return raw


# Restricted x86-64 length/operand decoder. No text disassembler output enters
# the evidence. It rejects unsupported encodings instead of guessing lengths.
# This decodes operands, not effects; it never executes or emulates a function.
def instruction(code, pos):
    start = pos
    prefixes = []
    def take(n):
        nonlocal pos
        require(n > 0 and pos + n <= len(code), 'truncated instruction')
        v = code[pos:pos+n]
        pos += n
        require(pos - start <= 15, 'oversized instruction')
        return v
    while pos < len(code) and (code[pos] in (0x66, 0x2e, 0x64, 0x65, 0xf0, 0xf2, 0xf3)
                              or 0x40 <= code[pos] <= 0x4f):
        prefixes.append(take(1)[0])
    rex = next((p for p in reversed(prefixes) if 0x40 <= p <= 0x4f), 0)
    word = 2 if 0x66 in prefixes else 4
    op = take(1)[0]
    opcode = [op]
    kind = 'ordinary'
    immediate = 0
    relative = False
    modrm_needed = False
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        immediate = 4 if op in (0xe8, 0xe9) else 1
        relative = True
        kind = 'call' if op == 0xe8 else 'jump' if op in (0xe9,0xeb) else 'conditional'
    elif op in (0xc3,0xcc):
        kind = 'return' if op == 0xc3 else 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90,0x98,0x99):
        pass
    elif 0xb0 <= op <= 0xb7 or op in (0x04,0x0c,0x24,0x2c,0x34,0x3c,0xa8,0x6a):
        immediate = 1
    elif 0xb8 <= op <= 0xbf:
        immediate = 8 if rex & 8 else word
    elif op in (0x05,0x0d,0x25,0x2d,0x35,0x3d,0xa9,0x68):
        immediate = word
    elif op == 0x0f:
        op2 = take(1)[0]
        opcode.append(op2)
        if 0x80 <= op2 <= 0x8f:
            relative, immediate, kind = True, 4, 'conditional'
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f or op2 in
              (0x10,0x11,0x1f,0x28,0x29,0x54,0x55,0x56,0x57,0x60,0x61,0x62,
               0x6c,0x6d,0x6e,0x6f,0x74,0x75,0x76,0x7e,0x7f,0xaf,0xb0,0xb1,
               0xb6,0xb7,0xbc,0xbd,0xbe,0xbf,0xc1,0xd4,0xd6,0xd7,0xdb,0xdf,0xeb,0xef,0xfb)):
            modrm_needed = True
        elif op2 in (0x70,0x71,0x72,0x73,0xba,0xc2,0xc4,0xc5,0xc6):
            modrm_needed, immediate = True, 1
        else:
            raise ValueError('unsupported two-byte opcode')
    elif op in (0x80,0x83,0xc0,0xc1,0xc6,0x6b):
        modrm_needed, immediate = True, 1
    elif op in (0x81,0xc7,0x69):
        modrm_needed, immediate = True, word
    elif op in (0xf6,0xf7,0xfe,0xff,0x63,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,
                0xd0,0xd1,0xd2,0xd3) or (op < 0x40 and op % 8 < 4):
        modrm_needed = True
    else:
        raise ValueError('unsupported opcode')
    row = {'kind': kind, 'opcode': bytes(opcode).hex(), 'rex': rex}
    rip_disp = None
    if modrm_needed:
        mr = take(1)[0]
        mod, reg, rm = mr >> 6, (mr >> 3) & 7, mr & 7
        row['modrm'] = mr
        if op == 0xff and reg in (2,4):
            row['kind'] = 'indirect-call' if reg == 2 else 'indirect-jump'
        if op in (0xf6,0xf7) and reg == 0:
            immediate = 1 if op == 0xf6 else word
        displacement = 0
        if mod != 3 and rm == 4:
            sib = take(1)[0]
            row['sib'] = sib
            if mod == 0 and sib & 7 == 5:
                displacement = 4
        elif mod == 0 and rm == 5:
            displacement = 4
            rip_disp = pos
        if mod in (1,2):
            displacement = 1 if mod == 1 else 4
        if displacement:
            row['displacement'] = int.from_bytes(take(displacement), 'little', signed=True)
    if immediate:
        raw = take(immediate)
        row['immediate'] = int.from_bytes(raw, 'little')
        if relative:
            row['target_offset'] = pos + int.from_bytes(raw, 'little', signed=True)
    if rip_disp is not None:
        row['rip_offset'] = pos + struct.unpack_from('<i', code, rip_disp)[0]
    if row['kind'] == 'conditional':
        row['condition'] = opcode[-1] & 15
    row['size'] = pos - start
    row['bytes'] = code[start:pos].hex()
    return row


def decode(code, base):
    rows = []
    pos = 0
    while pos < len(code):
        try:
            row = instruction(code, pos)
        except ValueError as e:
            raise ValueError(f'instruction at {base+pos:#x}: {e}') from e
        row['va'] = base + pos
        for source, dest in [('target_offset','target'),('rip_offset','rip')]:
            if source in row:
                row[dest] = base + row.pop(source)
        rows.append(row)
        pos += row['size']
    boundaries = {r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base <= r['target'] < base + len(code):
            require(r['target'] in boundaries, 'branch into instruction')
    return rows


def tsv(rows, keys):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def js(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + '\n'


def collect(image):
    funcs, insns, controls, riprefs = [], [], [], []
    for va, role in sorted(FUNCTIONS.items()):
        f = image.fde(va)
        raw = image.read(va, f['end']-va)
        rows = decode(raw, va)
        funcs.append(dict(start=hex(va), end=hex(f['end']), bytes=len(raw),
                          file_offset=hex(image.offset(va,len(raw))), fde=hex(f['fde']),
                          cie=hex(f['cie']), lsda=hex(f['lsda']) if f['lsda'] else '',
                          sha256=digest(raw), instructions=len(rows), role=role))
        for r in rows:
            r['function'] = va
            insns.append(r)
            if r['kind'] != 'ordinary':
                c = dict(function=hex(va), site=hex(r['va']), kind=r['kind'], bytes=r['bytes'],
                         target=hex(r['target']) if 'target' in r else '',
                         fallthrough=hex(r['va']+r['size']) if r['kind'] in ('conditional','call','indirect-call') else '',
                         slot='', relocation_target='')
                if r['kind'] in ('indirect-call','indirect-jump') and 'rip' in r:
                    c['slot'] = hex(r['rip'])
                    if r['rip'] in image.relas and image.relas[r['rip']][0] == 8:
                        c['relocation_target'] = hex(image.relative(r['rip']))
                controls.append(c)
            if 'rip' in r:
                riprefs.append(dict(function=hex(va), site=hex(r['va']), target=hex(r['rip']), bytes=r['bytes']))
    out = {'functions.tsv':tsv(funcs,list(funcs[0])),
           'instructions.json':json.dumps(insns,sort_keys=True,separators=(',',':'))+'\n',
           'control-flow.tsv':tsv(controls,list(controls[0])),
           'rip-references.tsv':tsv(riprefs,list(riprefs[0]))}
    out.update(details(image, insns))
    out.update(path_details(image, insns))
    out.update(verify_hash_windows(image))
    closure=[]
    dependency={0x4e9d240,0x4ea2d70,0x4ea2df0,0x4e9d2a0}
    for r in controls:
        if r['kind'] not in ('call','indirect-call','indirect-jump'):
            continue
        target=r['target'] or r['relocation_target']
        value=int(target,16) if target else None
        classification=('selected-FDE-entry' if value in FUNCTIONS else
                        'prior-precompile-dependency' if value in dependency else
                        'external-static-target' if target else 'dynamic-unresolved')
        closure.append(dict(site=r['site'],function=r['function'],kind=r['kind'],
                            target=target,classification=classification))
    out['edge-closure.tsv']=tsv(closure,list(closure[0]))
    out['summary.json'] = js(dict(target_sha256=SHA, functions=len(funcs),
                                  code_bytes=sum(f['bytes'] for f in funcs), instructions=len(insns),
                                  control_records=len(controls), rip_references=len(riprefs)))
    return out


def private_records(image, insns, function):
    code = [r for r in insns if r['function'] == function]
    result = []
    for index, r in enumerate(code[:-2]):
        nxt, last = code[index+1:index+3]
        if not (r['opcode'] == '0f10' and r.get('modrm') == 5 and 'rip' in r
                and nxt['opcode'] == '0f29' and nxt.get('sib') == 0x24
                and last['opcode'] == 'c7' and last.get('sib') == 0x24):
            continue
        base = nxt['displacement']
        require(last['displacement'] == base + 16, 'key suffix stack placement')
        key = image.read(r['rip'],16) + struct.pack('<I', last['immediate'])
        tags = [x for x in code if x['opcode'] == 'c7' and x.get('rex') == 0x48
                and x.get('sib') == 0x24 and x.get('displacement') == base + 24]
        require(len(tags) == 1 and tags[0]['immediate'] == 2, 'private record tag')
        pointers = [x for x in code if x['opcode'] == '89' and x.get('sib') == 0x24
                    and x.get('displacement') == base+32]
        require(len(pointers) == 1, 'private record capture store')
        tables = [(x,y) for x,y in zip(code,code[1:]) if x['opcode']=='8d' and 'rip' in x
                  and y['opcode']=='89' and y.get('sib')==0x24 and y.get('displacement')==base+40]
        require(len(tables) == 1, 'private record vtable store')
        load, store = tables[0]
        vt = load['rip']
        raw = image.read(vt,32)
        words = struct.unpack('<4Q',raw)
        require(words == (0,80,8,0), 'private vtable size/alignment/method placeholder')
        result.append(dict(provider=hex(function), ordinal=len(result), stack_record=hex(base),
                           key=key.hex(), address=hex(int.from_bytes(key,'big')),
                           key_prefix_va=hex(r['rip']), key_load=hex(r['va']),
                           suffix_store=hex(last['va']), suffix_bytes=last['bytes'],
                           tag=tags[0]['immediate'], tag_store=hex(tags[0]['va']),
                           capture_store=hex(pointers[0]['va']), capture_bytes=pointers[0]['bytes'],
                           vtable=hex(vt), vtable_load=hex(load['va']), vtable_bytes=raw.hex(),
                           size=words[1], alignment=words[2],
                           drop=hex(image.relative(vt)) if vt in image.relas else hex(words[0]), method=hex(image.relative(vt+24))))
    require(len(result)==20, 'private entry count')
    require({int(r['address'],16) for r in result} == set(range(0x800,0x814)), 'private address set')
    return result


def call_sites(image, function, boundaries):
    f = image.fde(function)
    if not f['lsda']:
        return [], None
    sec = image.section('.gcc_except_table')
    end = sec['offset'] + sec['size']
    require(sec['address'] <= f['lsda'] < sec['address']+sec['size'], 'LSDA outside exception section')
    pos = image.offset(f['lsda'],1)
    require(pos+3 <= end, 'truncated LSDA header')
    initial = pos
    data = image.data
    require(data[pos] == 0xff, 'unsupported LSDA LPStart')
    pos += 1
    type_encoding = data[pos]
    pos += 1
    type_base = None
    if type_encoding != 0xff:
        require(type_encoding == 0x9b, 'unsupported LSDA type encoding')
        delta,pos = uleb(data,pos,end)
        type_base = pos + delta
        require(type_base <= end, 'LSDA type base out of section')
    require(data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length,pos = uleb(data,pos,end)
    limit = pos + length
    require(limit <= end and (type_base is None or limit <= type_base), 'call-site table out of range')
    rows = []
    previous = function
    while pos < limit:
        record = pos
        begin,pos = uleb(data,pos,limit)
        size,pos = uleb(data,pos,limit)
        landing,pos = uleb(data,pos,limit)
        action,pos = uleb(data,pos,limit)
        begin += function
        finish = begin + size
        require(previous <= begin <= finish <= f['end'], 'invalid exception interval')
        require(begin in boundaries and (finish in boundaries or finish == f['end']),
                'exception interval not at instruction boundary')
        require(not landing or (function <= function+landing < f['end']
                                 and function+landing in boundaries), 'invalid landing pad')
        rows.append(dict(function=hex(function), lsda=hex(f['lsda']),
                         site=hex(begin), end=hex(finish),
                         landing=hex(function+landing) if landing else '', action=action,
                         raw=data[record:pos].hex()))
        previous = finish
    return rows, dict(function=hex(function), lsda=hex(f['lsda']),
                      header_and_call_sites=data[initial:limit].hex(),
                      action_table_file_offset=hex(limit),
                      type_table_file_offset=hex(type_base) if type_base is not None else None,
                      limitation='Action chains and type records are not interpreted.')


def overlay(base, records):
    """Abstract key/value preservation model, not captured-code execution."""
    out = dict(base)
    old = []
    for key, value in records:
        require(isinstance(key,bytes) and len(key)==20, 'key must contain twenty bytes')
        old.append(out.get(key))
        out[key] = value
    return out, old


def select_mode(raw_byte, table):
    require(type(raw_byte) is int and raw_byte in (*range(20),255), 'unqualified spec byte')
    require(len(table)==21, 'qualified selector sample extent')
    return table[(raw_byte+1)&255]


def details(image, insns):
    byva = {r['va']:r for r in insns}
    boundaries = set(byva)
    records = private_records(image, insns, 0x24448a0) + private_records(image, insns, 0x3268ce0)
    exceptions, lsda_records, unwind = [], [], []
    for function in sorted(FUNCTIONS):
        f = image.fde(function)
        rows, metadata = call_sites(image,function,boundaries)
        exceptions.extend(rows)
        if metadata:
            lsda_records.append(metadata)
        pair = {}
        for name in ('fde','cie'):
            va=f[name]
            size=struct.unpack('<I',image.read(va,4))[0]+4
            require(4 < size < 4096, 'unexpected unwind record length')
            pair[name] = dict(va=hex(va),raw=image.read(va,size).hex())
        unwind.append(dict(function=hex(function),**pair))
    table_rows = []
    for function, site in [(0x20482c0,0x2048360),(0x35775d0,0x3577670)]:
        r=byva[site]
        require(r['opcode']=='8d' and 'rip' in r, 'clone tag table reference')
        base=r['rip']
        for tag in range(4):
            raw=image.read(base+4*tag,4)
            target=base+struct.unpack('<i',raw)[0]
            require(target in boundaries and byva[target]['function']==function, 'invalid clone table target')
            table_rows.append(dict(function=hex(function), table=hex(base), tag=tag,
                                   raw=raw.hex(), target=hex(target)))
    modes=[]
    # Sample domain is explicitly qualified, not a claim of the full source enum.
    for function, load_site in [(0x24448a0,0x2444a11),(0x3268ce0,0x3268e72)]:
        r=byva[load_site]
        require(r['opcode']=='8d' and 'rip' in r, 'spec conversion table reference')
        table=image.read(r['rip'],21)
        require(table.hex()=='060000000000000101010202030303030303040505', 'spec table bytes')
        for raw in [255]+list(range(20)):
            mode=select_mode(raw,table)
            # The selector body is an existing packet's dependency, not new scope.
            delta_bytes=image.read(0x7c50b8+4*mode,4)
            branch=0x7c50b8+struct.unpack('<i',delta_bytes)[0]
            modes.append(dict(provider=hex(function), input_byte=hex(raw), table=hex(r['rip']),
                              index=(raw+1)&255, mode=mode, dependency_table_word=delta_bytes.hex(),
                              dependency_branch=hex(branch)))
    used_slots={r['rip'] for r in insns if 'rip' in r and r['rip'] in image.relas}
    used_slots.update(int(r['vtable'],16)+24 for r in records)
    used_slots.update((0x56a6850,0x56a6868,0x56a6870,0x56a6878,
                       0x56df878,0x56df890,0x56df898,0x56df8a0,
                       0x56bfab8,0x56bfac0,0x56bfac8,0x56b8050,0x56b8058,0x56b8060))
    relas=[]
    for slot in sorted(used_slots):
        info,addend,off=image.relas[slot]
        relas.append(dict(slot=hex(slot),info=info,addend=hex(addend),
                          file_offset=hex(off),raw=image.data[off:off+24].hex()))
    return {'private-records.tsv':tsv(records,list(records[0])),
            'fork-mode-samples.tsv':tsv(modes,list(modes[0])),
            'clone-tag-table.tsv':tsv(table_rows,list(table_rows[0])),
            'exception-call-sites.tsv':tsv(exceptions,list(exceptions[0])),
            'unwind-records.json':js(unwind),'lsda-records.json':js(lsda_records),
            'relocations.tsv':tsv(relas,list(relas[0]))}


def result_policy(words, gas):
    """Independent model of the post-dispatch integer predicates only."""
    require(len(words)==5 and all(type(v) is int and 0 <= v < 1<<64 for v in words),
            'result must be five unsigned words')
    require(type(gas) is int and 0 <= gas < 1<<64, 'gas outside u64')
    if words[0]:
        if words[4] <= gas:
            return dict(status=2, gas_after=gas-words[4], rollback=False, fatal=False)
        status=0x53
    elif words[1] & 1:
        return dict(status=None, gas_after=None, rollback=None, fatal=True)
    else:
        status=0x53 if words[2]==1<<63 else 0x60
    return dict(status=status, gas_after=gas, rollback=True, fatal=False)


def path_details(image, insns):
    byva={r['va']:r for r in insns}
    # Audited semantic windows. Lengths are byte intervals, not inferred bodies.
    windows=[
        ('builder-layout-and-provider',0x247ff1e,0x248002b),
        ('builder-registration-replay',0x24801aa,0x2480311),
        ('builder-executor-call',0x24804c8,0x24804e0),
        ('handler-spec-guard',0x2464bf3,0x2464c11),
        ('handler-spec-18',0x2465d61,0x2465f8b),
        ('handler-final-layout',0x2466c82,0x2466d81),
        ('execution-handler-output',0x279302d,0x27930fb),
        ('provider-invoke-and-keyset',0x251550e,0x2515564),
        ('context-registry-commit',0x251569d,0x25156c2),
        ('call-handler-invoke',0x2515792,0x25157c7),
        ('runtime-depth-and-checkpoint',0x2788727,0x278888e),
        ('transfer-debit',0x2788b7e,0x2788bf5),
        ('transfer-credit-and-record',0x2788c9d,0x2788dab),
        ('transfer-failure-rollback',0x2789258,0x2789273),
        ('owned-lookup',0x2788db0,0x2788ede),
        ('owned-dispatch',0x2789765,0x278978a),
        ('result-policy',0x27897a6,0x278994f),
        ('rollback-depth-and-journal',0x2787afd,0x2787b87),
    ]
    pins={0x251553c:'ff5128',0x25157c3:'41ff5028',0x27897fe:'4829c8',
          0x2789801:'7341',0x2789829:'40f6c601',0x2789852:'48f7d8',
          0x2789860:'440f40e8',0x2789915:'4180fd05',0x2789919:'731c',
          0x278994a:'e8a1e1ffff',0x2787b82:'e829ff2000'}
    for va,raw in pins.items(): image.expect(va,raw)
    rows=[]
    for label,start,end in windows:
        require(start in byva and end in byva, 'window boundary not decoded')
        require(byva[start]['function']==byva[end]['function'], 'window crosses FDE')
        raw=image.read(start,end-start)
        rows.append(dict(label=label,start=hex(start),end=hex(end),
                         function=hex(byva[start]['function']),raw=raw.hex(),sha256=digest(raw)))
    # Qualified table windows. Counts are checked against recorded targets;
    # this is not a scan-until-plausible-target algorithm or an enum recovery.
    tables=[(0x2464c01,20,'handler spec 0..19'),
            (0x27890a1,4,'account input tag 0..3'),
            (0x27894b8,4,'account code tag 0..3 with scheme 6'),
            (0x278951b,4,'account code tag 0..3 with other scheme'),
            (0x2997bb4,11,'journal tag 0..10 qualified window'),
            (0x2998297,4,'account value drop tag 0..3'),
            (0x2515cc5,4,'execution action tag 0..3')]
    jumps=[]
    for site,count,label in tables:
        r=byva[site];require(r['opcode']=='8d' and 'rip'in r,'table address load')
        base=r['rip']
        for index in range(count):
            raw=image.read(base+index*4,4)
            target=base+struct.unpack('<i',raw)[0]
            require(target in byva and byva[target]['function']==r['function'], 'table target outside function')
            jumps.append(dict(label=label,site=hex(site),table=hex(base),index=index,
                              raw=raw.hex(),target=hex(target)))
    vtables=[]
    for va in [0x56a6850,0x56df878,0x56bfaa0,0x56b8038]:
        for index,value in enumerate(struct.unpack('<6Q',image.read(va,48))):
            slot=va+index*8
            vtables.append(dict(table=hex(va),index=index,raw=hex(value),
                                relocated=hex(image.relative(slot)) if slot in image.relas else ''))
    require(image.relative(0x56a6878)==0x24448a0,'provider callback target')
    require(image.relative(0x56b8060)==0x24b6590,'registration replay callback target')
    require(image.relative(0x56bfac8)==0x276d390,'runtime adapter callback target')
    require(any(r.get('target')==0x2788710 for r in insns if r['function']==0x276d390),
            'adapter runtime edge')
    return {'path-windows.json':js(rows),'path-branch-tables.tsv':tsv(jumps,list(jumps[0])),
            'path-vtables.tsv':tsv(vtables,list(vtables[0]))}


def key_hash(key, process0, process1, seed):
    """Independent algebraic model of the insert and owned-lookup hash windows."""
    require(isinstance(key,bytes) and len(key)==20,'key must contain twenty bytes')
    require(all(type(x) is int and 0<=x<1<<64 for x in (process0,process1,seed)),
            'seed outside u64')
    mask=(1<<64)-1
    def fold(a,b):
        product=a*b
        return (product & mask) ^ (product>>64)
    word=lambda offset:int.from_bytes(key[offset:offset+8],'little')
    first=fold(word(8)^process1,word(12)^process0)
    second=fold(word(0)^seed,word(4)^process0)
    return fold(first^second^len(key),process0)


def lookup_model(key, process0, process1, seed, controls, buckets):
    """Valid synthetic tables only; bounded model, not the captured binary."""
    value=key_hash(key,process0,process1,seed)
    count=len(controls)
    require(count>=16 and count & (count-1)==0,'control count must be power of two')
    require(all(type(c) is int and (0<=c<128 or c in (128,255)) for c in controls),
            'invalid control byte')
    mask=count-1
    position=value & mask
    stride=0
    for _ in range(count//16):
        group=[(position+i)&mask for i in range(16)]
        for index in group:
            if controls[index]==value>>57:
                require(index in buckets,'missing occupied bucket')
                candidate,payload=buckets[index]
                require(isinstance(candidate,bytes) and len(candidate)==20,'invalid bucket key')
                if candidate==key:
                    return payload,index
        if any(controls[index]==255 for index in group):
            return None,None
        stride+=16
        position=(position+stride)&mask
    raise ValueError('synthetic table has no empty group')


def verify_hash_windows(image):
    # Exact entry and lookup opcode windows bind the algebra to both operands.
    image.expect(0x27c91b1,'498b7f0c4c31cf498b0f498b47084833420848f7e7')
    image.expect(0x2788df4,'498b4660498b5664483385080100004c31ca48f7e2')
    return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = Image((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    outputs = collect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(outputs.items()):
        (args.out / name).write_bytes(data.encode('ascii'))


if __name__ == '__main__':
    main()
