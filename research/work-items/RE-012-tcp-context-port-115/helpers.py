#!/usr/bin/env python3
"""Static write/path evidence for two node115 executor insertion helpers.

This checks encoded CFG edges and a manually reviewed destination worksheet.
It does not execute/emulate captured instructions or prove scheduler invariants.
"""
import argparse
import copy
import itertools
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

import capstone
import collect as base

HELPERS = (0x2cd0910, 0x2cd06c0)
DESCRIPTORS = (0x6449600, 0x6449790)
CTOR_CALLS = (0x2cd11e7, 0x2cd1ae7)
FIELD = (0xc8, 0xca)


def decoder():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Helper target')
    md = decoder()
    decoded = {}
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16)
        fdes = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        base.require(len(fdes) == 1, 'Helper exact FDE')
        raw = im.read(start, end-start)
        base.require(base.sha(raw) == r['sha256'], 'Helper full body hash')
        ins = list(md.disasm(raw, start))
        base.require(sum(i.size for i in ins) == end-start, 'Helper full decode')
        decoded[start] = ins
    all_ins = {i.address: i for body in decoded.values() for i in body}
    boundaries = set(all_ins) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        va, raw = int(a['va'], 16), bytes.fromhex(a['bytes_hex'])
        base.require(im.read(va, len(raw)) == raw, 'Helper anchor: ' + a['name'])
        base.require(va in boundaries and va+len(raw) in boundaries, 'Helper anchor boundaries')
    for d in spec['descriptors']:
        va = int(d['va'], 16)
        base.require(im.read(va, 0x50).hex() == d['bytes_hex'], 'Descriptor bytes')
        for slot in d['relative_slots']:
            base.require(im.relocs.get(int(slot['slot'], 16)) == [(8, int(slot['target'], 16))], 'Descriptor unique relocation')
        for offset, key in [(0x38, 'links_offset'), (0x48, 'id_offset')]:
            slot = va+offset
            base.require(slot not in im.relocs, 'Unexpected relocation on descriptor scalar')
            base.require(struct.unpack('<Q', im.read(slot, 8))[0] == d[key], 'Descriptor scalar')
    for r in spec['rip_relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'RIP unique relocation')
        if r['symbol'] is not None:
            base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'RIP symbol')
    for va, dest in zip(CTOR_CALLS, HELPERS):
        i = all_ins[va]
        base.require(i.mnemonic == 'call' and i.operands[0].type == capstone.CS_OP_IMM and i.operands[0].imm == dest, 'Constructor helper call')
    # Opcode classification, not Capstone access flags (known MOVUPS flag issue
    # in this packet). These helper bodies contain only these explicit stores.
    actual = {}
    for start in HELPERS:
        for i in decoded[start]:
            if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:
                continue
            if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp'):
                continue
            base.require(i.mnemonic in ('mov', 'lock cmpxchg', 'lock xadd', 'lock inc'), 'Unclassified memory destination')
            actual[i.address] = i
    annotated = {int(r['va'], 16): r for r in spec['helper_stores']}
    base.require(len(annotated) == len(spec['helper_stores']) and set(actual) == set(annotated), 'Explicit store inventory')
    for va, i in actual.items():
        r = annotated[va]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.operands[0].size == r['width']
                     and i.mnemonic+' '+i.op_str == r['instruction'], 'Store opcode/width')
    return decoded


def path(decoded, start, head_null, tail_nonnull, override=None):
    """Follow chosen encoded edges only. No register/memory execution."""
    ins = {i.address: i for i in decoded[start]}
    # True means taken. Static selected-path premises, not observed branch flags.
    decisions = {start+0x51: False, start+0x5f: True, start+0xf0: False,
                 start+0x102: False, start+0x124: head_null,
                 start+0x13b: tail_nonnull, start+0x152: True}
    if override:
        decisions.update(override)
    va = start; visited = []; used = set()
    while va in ins and va not in visited:
        i = ins[va]; visited.append(va)
        base.require(i.mnemonic not in ('call', 'ud2'), 'Selected path reaches call/trap')
        if i.mnemonic == 'ret':
            base.require(va == start+0x181 and used == set(decisions), 'Selected path return/guards')
            return visited
        if i.mnemonic.startswith('j'):
            base.require(i.operands[0].type == capstone.CS_OP_IMM, 'Unresolved selected edge')
            if i.mnemonic == 'jmp':
                va = i.operands[0].imm
            else:
                base.require(va in decisions, 'Unclassified selected conditional')
                used.add(va)
                va = i.operands[0].imm if decisions[va] else va+i.size
        else:
            va += i.size
    raise ValueError('Selected path leaves FDE or cycles')


def worksheet(stores, links):
    """Intervals are arithmetic over manual register/alias annotations."""
    rows = []
    for r in stores:
        space, off, size = r['space'], r['offset'], r['width']
        if space == 'P_links':
            space, off = 'P', off+links
        base.require(size > 0 and off >= 0, 'Invalid write interval')
        if space == 'P':
            base.require(off+size <= FIELD[0] or off >= FIELD[1], 'Write overlaps tracked word')
        else:
            base.require(space in ('S', 'B', 'T', 'H_links'), 'Unknown destination region')
        rows.append({**r, 'resolved_space': space, 'resolved_offset': hex(off),
                     'field_overlap': False if space == 'P' else 'requires disjoint effective storage'})
    return rows


def controls(im, spec):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted corrupt helper evidence: '+name)
    # Bypass only the outer digest to exercise inner pins/data/relocation guards.
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:
                raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        return bad
    for a in spec['anchors']:
        va = int(a['va'], 16)+len(bytes.fromhex(a['bytes_hex']))-1
        reject('anchor-byte:'+a['name'], lambda: bindings(mutate(va), spec))
    for d in spec['descriptors']:
        for off in (0x38, 0x40, 0x48):
            va = int(d['va'], 16)+off
            reject('descriptor-byte:'+hex(va), lambda: bindings(mutate(va), spec))
    slots = {int(r['slot'], 16) for r in spec['rip_relocations']}
    slots |= {int(r['slot'], 16) for d in spec['descriptors'] for r in d['relative_slots']}
    for slot in sorted(slots):
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im); bad.relocs = dict(im.relocs)
            info, addend = im.relocs[slot][0]
            bad.relocs[slot] = [(info, addend+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+hex(slot), lambda: bindings(bad, spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['ranges'] if x['name'] == r['name'])['end'] = hex(int(r['end'], 16)-1)
        reject('truncated-fde:'+r['name'], lambda: bindings(im, bad))
    for kind in ('missing', 'width'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':
            bad['helper_stores'].pop()
        else:
            bad['helper_stores'][2]['width'] = 1
        reject('store-inventory:'+kind, lambda: bindings(im, bad))
    decoded = bindings(im, spec)
    for start in HELPERS:
        for off, decision in ((0x51, True), (0x5f, False), (0xf0, True), (0x102, True), (0x152, False)):
            reject('excluded-path:'+hex(start+off), lambda: path(decoded, start, True, False, {start+off:decision}))
    # Worksheet-only checks: deliberately make the links overlap [c8,ca).
    for value in (0xc0, 0xc1, 0xc8, 0xc9):
        rows = [r for r in spec['helper_stores'] if r['space'] == 'P_links']
        reject('interval-only-links:'+hex(value), lambda: worksheet(rows, value))
    # Adjacent eight-byte writes and the two-byte field's exclusive upper bound.
    worksheet([{'space':'P','offset':0xc0,'width':8}], 0)
    worksheet([{'space':'P','offset':0xca,'width':8}], 0)
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data); changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def transfers(im, ins):
    result = []
    for i in ins:
        if i.mnemonic not in ('call', 'jmp'):
            continue
        op = i.operands[0]
        row = {'va':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'bytes_hex':i.bytes.hex()}
        if op.type == capstone.CS_OP_IMM:
            row['encoded_target'] = hex(op.imm)
        elif op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip':
            slot = i.address+i.size+op.mem.disp
            row['slot'] = hex(slot)
            row['relocations'] = [{'info':info,'addend':hex(addend),
                'symbol': im.symbol(info>>32) if info>>32 else None} for info,addend in im.relocs.get(slot,[])]
        else:
            row['binding'] = 'register/object derived; selected helper descriptor bindings recorded separately'
        result.append(row)
    return result


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes()
    base.authenticate(data); im = base.Image(data)
    spec = json.loads((base.PACKET/'helpers-spec.json').read_text())
    decoded = bindings(im, spec); rejected = controls(im, spec)
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python':sys.version,'platform':platform.platform(),'capstone':capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):
        versions[tool] = subprocess.check_output([tool,'--version']).decode()
    ranges = []; commands = []; selected = []
    for r in spec['ranges']:
        start, end = int(r['start'],16), int(r['end'],16); ins = decoded[start]
        fde, = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        row = {**r,'file_offset':hex(im.offset(start,end-start)), 'fde':hex(fde['fde']),
               'lsda':hex(fde['lsda']),'bytes':end-start,'instructions':len(ins),'native':[],
               'transfers':transfers(im,ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(
            f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n',encoding='utf-8',newline='\n')
        for tool,options,suffix in [('objdump',['-z','--insn-width=16'],'gnu'),('llvm-objdump',['--disassemble-zeroes'],'llvm')]:
            args = [tool,'-d',*options,f'--start-address={start}',f'--stop-address={end}','artifacts/node/115/hl-node']
            p = subprocess.run(args,cwd=base.ROOT,capture_output=True,check=True)
            name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout); (out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout,im,start,end)
            splits = base.compare_boundaries(parsed,ins)
            row['native'].append({'file':name,'sha256':base.sha(p.stdout),'rows':len(parsed),'lock_prefix_splits':splits})
            commands.append(args)
        ranges.append(row)
    for start,descriptor in zip(HELPERS,DESCRIPTORS):
        links = struct.unpack('<Q',im.read(descriptor+0x38,8))[0]
        for null,tail in itertools.product((False,True),repeat=2):
            visited = path(decoded,start,null,tail)
            stores = [r for r in spec['helper_stores'] if int(r['va'],16) in visited]
            selected.append({'helper':hex(start),'head_null':null,'tail_nonnull':tail,
                'instruction_vas':[hex(v) for v in visited], 'calls':0,'return_va':hex(visited[-1]),
                'stores':worksheet(stores,links), 'implicit_stack_effects':'push/pop/ret; separate valid stack premise'})
    result = {'target_sha256':base.TARGET,'source_base':'05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated':False,'coordinate_system':'linked ELF VAs before load bias',
        'ranges':ranges,'descriptors':spec['descriptors'],'explicit_helper_stores':spec['helper_stores'],
        'selected_call_free_paths':selected,'negative_controls_rejected':rejected,'normalization_masks':[],
        'selected_dynamic_calls':[{'helper':hex(h),'descriptor':hex(d),
            'callback30':hex(im.relocs[d+0x30][0][1]),'callback10':hex(im.relocs[d+0x10][0][1])}
            for h,d in zip(HELPERS,DESCRIPTORS)],
        'limitations':['Manual register/region annotations, not automated alias or value analysis',
            'Selected descriptor remains intact; SysV register contract and separate valid stack',
            'Scheduler, bucket and previous-head link storage do not alias the tracked field',
            'No interfering concurrent write; publication does not prove poll ordering',
            'Excluded contention, nonzero admission flag, assertion and unwind paths have opaque effects',
            'Callback bodies exported; their transitive callees and memory lifetime are not closed',
            'No Rust implementation, captured behavior or whole-node equivalence']}
    for name,value in [('records.json',result),('commands.json',commands),('versions.json',versions)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'full_fdes':len(ranges),'bytes':sum(r['bytes'] for r in ranges),
        'instructions':sum(r['instructions'] for r in ranges),'explicit_helper_stores':len(spec['helper_stores']),
        'call_free_paths':len(selected),'controls_rejected':len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    collect(p.parse_args().out)
