#!/usr/bin/env python3
"""Static node115 selected reallocation paths; no captured execution/emulation."""
import argparse
import copy
import json
from pathlib import Path
import platform
import subprocess
import sys

import capstone
import collect as base
import cleanup
import helpers

REALLOC, PREDICATE = 0x6365660, 0x6363d50
COMMON = {0x63656bd: False, 0x63656ca: False, 0x63656f2: False, 0x6365705: False, 0x6365712: False}
REPLACE = {**COMMON, 0x636574d: False, 0x6365756: False, 0x6365763: False, 0x6365783: False,
           0x63657ae: False, 0x63657bd: False, 0x63658cc: False}
PRED_COMMON = {0x6363d9c: False, 0x6363dc1: False, 0x6363df4: False, 0x6363e01: False,
               0x6363e49: False, 0x6363e69: False, 0x6363e76: True, 0x6363f07: False,
               0x6363f28: False, 0x6363ee0: False}
PATHS = {
 'same_pointer': (REALLOC, 0x63658e6, {**COMMON, 0x636574d: True, 0x63658cc: False}, (0x636573f, 0x6365ba7)),
 'replacement_cache_return': (REALLOC, 0x63658e6, {**REPLACE, 0x63657cb: False, 0x6365825: True,
                           0x6365a97: False, 0x6365ab4: True, 0x63658a9: False}, (0x636573f, 0x63657ea, 0x6365801, 0x6365816)),
 'replacement_null': (REALLOC, 0x63658e6, {**REPLACE, 0x63657cb: True}, (0x636573f,)),
 'local_zero_class': (REALLOC, 0x63658e6, {0x63656bd: False, 0x63656ca: False, 0x63656f2: True, 0x63658cc: False}, ()),
 'predicate_same_class': (PREDICATE, 0x6363ef7, {**PRED_COMMON, 0x6363f44: False, 0x6363eae: False, 0x6363eb8: False}, ()),
 'predicate_growth': (PREDICATE, 0x6363ef7, {**PRED_COMMON, 0x6363f44: True, 0x6363e8c: True}, ()),
 'new_hook_disabled': (0x63b7240, 0x63b728c, {0x63b7268: False, 0x63b7278: False}, ()),
 'old_hook_disabled': (0x63b73a0, 0x63b73ec, {0x63b73c8: False, 0x63b73d8: False}, ()),
 'same_hook_disabled': (0x63b7500, 0x63b754c, {0x63b7528: False, 0x63b7538: False}, ()),
}


def stores(ins):
    out = {}
    for i in ins:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp', 'push'):continue
        base.require(i.mnemonic in ('mov', 'add', 'sub'), 'Unclassified selected reallocation destination')
        out[i.address] = i
    return out


def selected(decoded, name, override=None):
    owner, stop, decisions, calls = PATHS[name];decisions = dict(decisions)
    if override:decisions.update(override)
    ins = cleanup.walk(decoded[owner], owner, stop, decisions, calls)
    base.require(next(i for i in decoded[owner] if i.address == stop).mnemonic == 'ret', 'Selected return')
    return ins


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Reallocation target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        if r['scope'] == 'plt_window':
            base.require(lo == 0x63f0a60 and hi == 0x63f0a70 and any(s['name'] == '.plt' and s['address'] <= lo < hi <= s['address']+s['size'] for s in im.sections), 'PLT window membership')
        else:
            end = int(r['owner_end'], 16)
            base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == end]) == 1, 'Reallocation exact FDE owner')
            base.require(lo < hi <= end and r['scope'] == ('complete_fde' if hi == end else 'entry_prefix'), 'Reallocation scope')
            base.require(base.sha(im.read(lo, end-lo)) == r['owner_sha256'], 'Reallocation full owner hash')
        raw = im.read(lo, hi-lo);base.require(base.sha(raw) == r['sha256'], 'Reallocation interval hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Reallocation complete interval decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(lo in bounds and hi in bounds and len(raw) == hi-lo and im.read(lo, len(raw)) == raw, 'Reallocation anchor '+a['name'])
    for t in spec['direct_calls']:
        i = index[int(t['va'], 16)]
        base.require(i.mnemonic == 'call' and i.operands[0].type == capstone.CS_OP_IMM
                     and i.operands[0].imm == int(t['target'], 16), 'Reallocation selected direct call')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Reallocation unique relocation')
        base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Reallocation import symbol')
    i = index[0x63f0a60];op = i.operands[0]
    base.require(i.mnemonic == 'jmp' and i.reg_name(op.mem.base) == 'rip'
                 and i.address+i.size+op.mem.disp == 0x64ee180, 'memcpy PLT/GOT binding')
    for r in spec['rip_data']:
        i = index[int(r['va'], 16)];op = i.operands[r['operand']]
        va = int(r['target'], 16)
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip'
                     and i.address+i.size+op.mem.disp == va, 'Reallocation data operand')
        base.require(any(s['name'] == r['section'] and s['type'] == r['section_type'] and s['address'] <= va < s['address']+s['size'] for s in im.sections), 'Reallocation data section')
        base.require(r['runtime_value'] is None, 'Invented reallocation runtime data')
    actual = {}
    for name in PATHS:actual.update(stores(selected(decoded, name)))
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']}
    base.require(len(rows) == len(spec['selected_store_union']) and rows.keys() == actual.keys(), 'Selected store union')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction']
                     and op.size == r['width'], 'Selected store bytes/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp)
                     == (r['base'], r['index'], r['scale'], r['offset']), 'Selected store operand')
    return decoded


def path_record(decoded, spec, name):
    ins = selected(decoded, name);owner, stop, decisions, calls = PATHS[name]
    index = {int(r['va'], 16): r for r in spec['selected_store_union']}
    return {'name': name, 'owner': hex(owner), 'ret': hex(stop), 'calls': [hex(v) for v in calls],
            'decisions': {hex(k): v for k, v in decisions.items()}, 'instruction_vas_before_ret': [hex(i.address) for i in ins],
            'selected_explicit_stores': [index[va] for va in stores(ins)],
            'implicit_push_sites': [hex(i.address) for i in ins if i.mnemonic == 'push']}


def copy_amount(old_size, new_class):
    base.require(all(type(v) is int and 0 <= v <= (1 << 64)-1 for v in (old_size, new_class)), 'Unsigned copy-size domain')
    return min(old_size, new_class)


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid reallocation evidence: '+name)
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read;return bad
    for a in spec['anchors']:reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec);rr = next(x for x in bad['ranges'] if x['name'] == r['name'])
        if r['scope'] == 'plt_window':rr['end'] = hex(int(r['end'], 16)-1)
        else:rr['owner_end'] = hex(int(r['owner_end'], 16)-1)
        reject('wrong-extent:'+r['name'], lambda: bindings(im, bad))
    for kind in ('changed', 'duplicate', 'symbol'):
        r = spec['relocations'][0];slot = int(r['slot'], 16);bad = copy.copy(im);bad.relocs = dict(im.relocs)
        if kind == 'symbol':
            bs = copy.deepcopy(spec);bs['relocations'][0]['symbol'] = 'memmove'
            reject('wrong-import-symbol', lambda: bindings(im, bs))
        else:
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation', lambda: bindings(bad, spec))
    for kind in ('missing', 'width', 'destination'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':bad['selected_store_union'].pop()
        elif kind == 'width':bad['selected_store_union'][0]['width'] += 1
        else:bad['selected_store_union'][0]['offset'] += 1
        reject('selected-store:'+kind, lambda: bindings(im, bad))
    for name, (_, _, decisions, _) in PATHS.items():
        # A first-edge flip forces an excluded route; matching masks are not assumed.
        va = next(iter(decisions));reject('excluded-entry-edge:'+name, lambda: selected(decoded, name, {va: not decisions[va]}))
    for name, va in [('same_pointer', 0x63658cc), ('replacement_cache_return', 0x63657ae),
                     ('replacement_cache_return', 0x63657bd), ('replacement_cache_return', 0x63658a9),
                     ('predicate_same_class', 0x6363eb8), ('predicate_same_class', 0x6363ee0),
                     ('new_hook_disabled', 0x63b7278), ('old_hook_disabled', 0x63b73d8), ('same_hook_disabled', 0x63b7538)]:
        reject('excluded-selected-edge:'+hex(va), lambda: selected(decoded, name, {va: not PATHS[name][2][va]}))
    for r in spec['rip_data']:
        bad = copy.deepcopy(spec);next(x for x in bad['rip_data'] if x['va'] == r['va'])['runtime_value'] = 0
        reject('invented-runtime-value:'+r['va'], lambda: bindings(im, bad))
    for args in ((-1, 8), (8, -1), (1 << 64, 8), (8, 1 << 64), (1.5, 8)):
        reject('copy-size-domain:'+str(args), lambda: copy_amount(*args))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'reallocation-spec.json').read_text());decoded = bindings(im, spec)
    paths = [path_record(decoded, spec, name) for name in PATHS];rejected = controls(im, spec, decoded)
    values = [(0, 8, 0), (8, 0, 0), (8, 8, 8), (8, 16, 8), (16, 8, 8), (4096, 8192, 4096),
              ((1 << 64)-1, 8, 8), (8, (1 << 64)-1, 8)]
    for old, new, expected in values:base.require(copy_amount(old, new) == expected, 'Copy unsigned-boundary worksheet')
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16);ins = decoded[lo]
        fde = next((f for f in im.fdes if f['start'] == lo and hex(f['end']) == r.get('owner_end')), None)
        row = {**r, 'fde': hex(fde['fde']) if fde else None, 'file_offset': hex(im.offset(lo, hi-lo)),
               'bytes': hi-lo, 'instructions': len(ins), 'native': [], 'transfers': helpers.transfers(im, ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={lo}', f'--stop-address={hi}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, lo, hi);splits = base.compare_boundaries(parsed, ins)
            if lo == 0x6350210:base.require(base.compare_prior_native(p.stdout, (base.PACKET/('allocator/core_prefix.'+suffix+'.objdump')).read_bytes()), 'Prior core export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
       'captured_code_executed_or_emulated': False, 'ranges': ranges, 'paths': paths,
       'selected_store_union': spec['selected_store_union'], 'direct_calls': spec['direct_calls'],
       'relocations': spec['relocations'], 'rip_data': spec['rip_data'],
       'copy_size_scalar_cases': [{'old_size': old, 'new_class_size': new, 'copy_bytes': expected} for old, new, expected in values],
       'manual_joins': {
         'main_input': 'B=RDI, unused retained word RSI=0, P=RDX, U=RCX(old metadata size), N=R8, R9=0; stack: option D=0, cache K=B+0x358, descriptor H with BYTE[H]=1',
         'predicate_call': '0x636573f -> 0x6363d50(B,P,U,S,0,D, scratch=RS+0x58), S=runtime new-class size',
         'same_pointer': 'Predicate AL=0 -> disabled same-hook -> RAX=P; predicate may decrement DWORD[B+0x98] and writes scratch',
         'replacement': 'Predicate AL!=0 -> pop Q from cache -> disabled new/old hooks -> memcpy(Q,P,min(U,S)) -> push P to old-class cache -> RAX=Q',
         'failure': 'Null Q returns zero after cache cursor/count writes; local zero-class branch returns zero before helper call',
         'hook_guard': 'DWORD[0x6712360]==0 at each call, unchanged canary; enabled hook bodies not closed',
         'cache_return': 'old-class slot C=K+24*j; old cursor L=[C+8]; if low16(L)!=WORD[C+0x1a], [C+8]=L-8 and [L-8]=P',
         'copy_contract': '0x63f0a60 -> GOT 0x64ee180, unique JUMP_SLOT memcpy; imported validity/non-overlap/resolution remain premises'},
       'negative_and_scope_controls': rejected, 'normalization_masks': [],
       'limitations': ['Only the selected small-size/cache-hit/disabled-hook paths; complete exports are not complete behavior coverage',
         'BSS class values, metadata identity, aliasing, cache/list validity and stable state remain premises',
         'Same-pointer path still changes allocator metadata; replacement-null path does not imply no state changes',
         'Cache insertion of P is observed, not an operating-system free or complete ownership proof',
         'Copy length is min(U,S), not min(old logical length,requested N); memcpy contract is not executed or verified here',
         'No captured execution/emulation, Rust reconstruction, independent-agent review or acceptance gate']}
    result['native_prior_transcript_comparisons'] = list(base._NATIVE_PRIOR_COMPARISONS)
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exported_intervals': len(ranges), 'bytes': sum(r['bytes'] for r in ranges),
       'instructions': sum(r['instructions'] for r in ranges), 'selected_paths': len(paths),
       'selected_store_union': len(spec['selected_store_union']), 'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
