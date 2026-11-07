#!/usr/bin/env python3
"""Static #115 post-reallocation accounting and conditional tail-fill evidence.

Encoded-edge selection and scalar worksheets only; never execute/emulate target.
"""
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

CORE, ACCOUNT, FILL, PLT = 0x6350210, 0x63eec80, 0x6349360, 0x63f0a90
MASK = (1 << 64)-1
# owner, entry, stop, selected conditional edges, exact call sites
PATHS = {
    'null_return': (CORE, 0x63503e8, 0x63504fc, {0x63503f2: True, 0x63504e2: False}, ()),
}
for first, second, name in [(False, False, 'below_both'), (True, False, 'first_threshold'),
                             (False, True, 'second_threshold'), (True, True, 'both_thresholds')]:
    PATHS[name] = (CORE, 0x63503e8, 0x63504fc,
        {0x63503f2: False, 0x6350452: first, 0x63504b2: second, 0x63504c4: True, 0x63504e2: False},
        tuple(([0x6350e9b] if first else [])+([0x6350eb3] if second else [])))
for name, first, second, fill in [('fill_option_suppressed', False, False, False),
                                 ('tail_fill', False, False, True), ('both_thresholds_fill', True, True, True)]:
    PATHS[name] = (CORE, 0x63503e8, 0x63504fc,
        {0x63503f2: False, 0x6350452: first, 0x63504b2: second, 0x63504c4: False,
         0x63504cb: fill, 0x63504e2: False},
        tuple(([0x6350e9b] if first else [])+([0x6350eb3] if second else [])+([0x635135b] if fill else [])))
PATHS.update({
    'account_mode_one_leaf': (ACCOUNT, ACCOUNT, 0x63eeef8,
        {0x63eecb9: False, 0x63eecd8: False, 0x63eece1: False, 0x63eecff: True,
         0x63eed5e: True, 0x63eeff0: True, 0x63eee3c: False, 0x63eee78: True, 0x63eeea2: False,
         0x63eeeab: True, 0x63eeec1: True, 0x63eeed7: True, 0x63eeee4: False}, ()),
    'account_mode_zero_leaf': (ACCOUNT, ACCOUNT, 0x63eeef8,
        {0x63eecb9: False, 0x63eecd8: True, 0x63eedea: False, 0x63eedf9: False,
         0x63eee3c: False, 0x63eee78: True, 0x63eeea2: True, 0x63eefa3: True, 0x63eefb0: True}, ()),
    'fill_stub': (FILL, FILL, 0x634936c, {}, ()),
})
# Also retain G1!=0 leaves: both event countdowns still exceed delta.
_one = dict(PATHS['account_mode_one_leaf'][3])
_one.update({0x63eece1: True, 0x63eef57: True, 0x63eeeab: False, 0x63eeeb0: False})
_zero = dict(PATHS['account_mode_zero_leaf'][3])
del _zero[0x63eedf9]
_zero.update({0x63eedea: True, 0x63eef07: True, 0x63ef0a3: True,
              0x63eefa3: False, 0x63eefa7: False})
PATHS['account_mode_one_active_countdown'] = (ACCOUNT, ACCOUNT, 0x63eeef8, _one, ())
PATHS['account_mode_zero_active_countdown'] = (ACCOUNT, ACCOUNT, 0x63eeef8, _zero, ())


def stores(ins):
    result = {}
    for i in ins:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:
            continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp', 'push'):
            continue
        base.require(i.mnemonic in ('mov', 'lock or'), 'Unclassified selected accounting destination')
        result[i.address] = i
    return result


def selected(decoded, name, override=None):
    owner, start, stop, decisions, calls = PATHS[name]
    decisions = dict(decisions)
    if override:
        decisions.update(override)
    ins = cleanup.walk(decoded[owner], start, stop, decisions, calls)
    last = next(i for i in decoded[owner] if i.address == stop)
    base.require(last.mnemonic == ('jmp' if name == 'fill_stub' else 'ret'), 'Accounting endpoint')
    return ins


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Accounting target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        if r['scope'] == 'plt_window':
            base.require(lo == PLT and hi == PLT+16 and any(s['name'] == '.plt' and
                s['address'] <= lo < hi <= s['address']+s['size'] for s in im.sections), 'Accounting PLT extent')
        else:
            base.require(r['scope'] == 'complete_fde' and len([f for f in im.fdes
                if f['start'] == lo and f['end'] == hi]) == 1, 'Accounting exact FDE')
        raw = im.read(lo, hi-lo)
        base.require(base.sha(raw) == r['sha256'], 'Accounting interval hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Accounting complete decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16)
        raw = bytes.fromhex(a['bytes_hex'])
        base.require(lo in bounds and hi in bounds and len(raw) == hi-lo and
                     im.read(lo, hi-lo) == raw, 'Accounting anchor '+a['name'])
    for t in spec['direct_transfers']:
        i = index[int(t['va'], 16)]
        base.require(i.mnemonic == t['mnemonic'] and i.operands[0].type == capstone.CS_OP_IMM
                     and i.operands[0].imm == int(t['target'], 16), 'Accounting direct transfer')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Accounting unique relocation')
        if r['symbol']:
            base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Accounting imported symbol')
    for r in spec['rip_data']:
        i = index[int(r['va'], 16)]
        op = i.operands[r['operand']]
        va = int(r['target'], 16)
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip'
                     and i.address+i.size+op.mem.disp == va, 'Accounting RIP operand')
        base.require(any(s['name'] == r['section'] and s['type'] == r['section_type'] and
                     s['address'] <= va < s['address']+s['size'] for s in im.sections), 'Accounting data section')
        base.require(r['runtime_value'] is None, 'Invented accounting runtime data')
        if r['file_bytes_hex'] is not None:
            raw = bytes.fromhex(r['file_bytes_hex'])
            base.require(im.read(va, len(raw)) == raw, 'Accounting initial data bytes')
    actual = {}
    for name in PATHS:
        actual.update(stores(selected(decoded, name)))
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']}
    base.require(len(rows) == len(spec['selected_store_union']) and rows.keys() == actual.keys(), 'Accounting store union')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction']
                     and op.size == r['width'], 'Accounting store bytes/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp)
                     == (r['base'], r['index'], r['scale'], r['offset']), 'Accounting store operand')
    return decoded


def accounting_scalar(counter, threshold, increment):
    base.require(all(type(v) is int and 0 <= v <= MASK for v in (counter, threshold, increment)), 'Unsigned accounting domain')
    return ((counter+increment) & MASK, increment >= ((threshold-counter) & MASK))


def fill_scalar(old_size, new_size, flag, option):
    base.require(all(type(v) is int and 0 <= v <= MASK for v in (old_size, new_size)) and
                 all(type(v) is int and 0 <= v <= 255 for v in (flag, option)), 'Tail-fill scalar domain')
    return old_size < new_size and bool(flag & 1) and option == 0


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted invalid accounting evidence: '+name)
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
        reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['ranges'] if x['name'] == r['name'])['end'] = hex(int(r['end'], 16)-1)
        reject('wrong-extent:'+r['name'], lambda: bindings(im, bad))
    for r in spec['relocations']:
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im);bad.relocs = dict(im.relocs);slot = int(r['slot'], 16)
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+r['slot'], lambda: bindings(bad, spec))
    bad = copy.deepcopy(spec);bad['relocations'][-1]['symbol'] = 'memcpy'
    reject('wrong-fill-import', lambda: bindings(im, bad))
    for kind in ('missing', 'width', 'destination'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':
            bad['selected_store_union'].pop()
        elif kind == 'width':
            bad['selected_store_union'][0]['width'] += 1
        else:
            bad['selected_store_union'][0]['offset'] += 1
        reject('selected-store:'+kind, lambda: bindings(im, bad))
    for name, (_, _, _, decisions, _) in PATHS.items():
        if decisions:
            va = 0x63eecd8 if name.startswith('account_mode_') else next(iter(decisions))
            reject('changed-entry-edge:'+name, lambda: selected(decoded, name, {va: not decisions[va]}))
    for name, va in [('below_both', 0x63504e2), ('tail_fill', 0x63504cb),
                     ('account_mode_one_leaf', 0x63eece1), ('account_mode_one_leaf', 0x63eecff),
                     ('account_mode_one_leaf', 0x63eeff0), ('account_mode_one_leaf', 0x63eee3c),
                     ('account_mode_zero_leaf', 0x63eedea), ('account_mode_zero_leaf', 0x63eedf9),
                     ('account_mode_zero_leaf', 0x63eee3c),
                     ('account_mode_one_active_countdown', 0x63eef57),
                     ('account_mode_zero_active_countdown', 0x63eef07)]:
        reject('excluded-edge:'+name+':'+hex(va), lambda: selected(decoded, name, {va: not PATHS[name][3][va]}))
    for r in spec['rip_data']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['rip_data'] if x['va'] == r['va'])['runtime_value'] = 0
        reject('invented-runtime-value:'+r['va'], lambda: bindings(im, bad))
        if r['file_bytes_hex'] is not None:
            reject('changed-initial-data:'+r['va'], lambda: bindings(mutate(int(r['target'], 16)), spec))
    for args in [(-1, 8, 1), (0, 1 << 64, 1), (0, 8, 1 << 64), (0, 8, True)]:
        reject('accounting-domain:'+str(args), lambda: accounting_scalar(*args))
    for args in [(0, 8, 256, 0), (0, 8, 1, -1), (-1, 8, 1, 0), (0, 1 << 64, 1, 0)]:
        reject('fill-domain:'+str(args), lambda: fill_scalar(*args))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes()
    base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'accounting-spec.json').read_text())
    decoded = bindings(im, spec);rejected = controls(im, spec, decoded)
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']}
    paths = []
    for name, (owner, start, stop, decisions, calls) in PATHS.items():
        ins = selected(decoded, name)
        paths.append({'name': name, 'owner': hex(owner), 'entry': hex(start), 'stop_before': hex(stop),
            'decisions': {hex(k): v for k, v in decisions.items()}, 'calls': [hex(v) for v in calls],
            'instruction_vas_before_endpoint': [hex(i.address) for i in ins],
            'selected_explicit_stores': [rows[va] for va in stores(ins)],
            'implicit_push_sites': [hex(i.address) for i in ins if i.mnemonic == 'push']})
    counter_cases = [(8, 16, 7, 15, False), (8, 16, 8, 16, True), (8, 16, 9, 17, True),
                     (8, 8, 0, 8, True), (16, 8, 1, 17, False), (MASK, 0, 1, 0, True),
                     (MASK-1, 8, 2, 0, False), (0, MASK, MASK, MASK, True)]
    for a, t, n, result, crossed in counter_cases:
        base.require(accounting_scalar(a, t, n) == (result, crossed), 'Accounting scalar worksheet')
    fill_cases = [(8, 16, 1, 0, True), (8, 16, 2, 0, False), (8, 16, 255, 0, True),
                  (8, 16, 0, 0, False), (8, 16, 1, 1, False), (8, 8, 1, 0, False),
                  (16, 8, 1, 0, False), (0, MASK, 1, 0, True)]
    for u, s, f, d, expected in fill_cases:
        base.require(fill_scalar(u, s, f, d) == expected, 'Tail-fill scalar worksheet')
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):
        versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16);ins = decoded[lo]
        fde = next((f for f in im.fdes if f['start'] == lo and f['end'] == hi), None)
        row = {**r, 'fde': hex(fde['fde']) if fde else None, 'file_offset': hex(im.offset(lo, hi-lo)),
               'bytes': hi-lo, 'instructions': len(ins), 'native': [], 'transfers': helpers.transfers(im, ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}'
            for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={lo}', f'--stop-address={hi}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True)
            name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, lo, hi);splits = base.compare_boundaries(parsed, ins)
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed),
                                  'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated': False, 'ranges': ranges, 'paths': paths,
        'selected_store_union': spec['selected_store_union'], 'direct_transfers': spec['direct_transfers'],
        'relocations': spec['relocations'], 'rip_data': spec['rip_data'],
        'accounting_scalar_cases': [{'counter': a, 'threshold': t, 'increment': n, 'new_counter': r,
                                    'threshold_call': hit} for a, t, n, r, hit in counter_cases],
        'tail_fill_scalar_cases': [{'old_size': u, 'new_size': s, 'flag': f, 'option': d, 'call': hit}
                                   for u, s, f, d, hit in fill_cases],
        'manual_joins': {
            'entry': 'After 0x63503e3: RAX=Q, RBX=B, R14=S, R15=U; add RSP,0x20 restores CS; D=BYTE[CS+4]',
            'null': 'Q=0 skips accounting/fill and returns zero on stable canary; prior callee state changes persist',
            'counter_first': '[B+0x338] += S modulo 2^64 before unsigned S >= ([B+0x10]-old_counter) branch',
            'counter_second': '[B+0x348] += U modulo 2^64 before unsigned U >= ([B+0x20]-old_counter) branch',
            'descriptor': 'H=CS+0xc0: byte mode at +0; pointer to counter at +8, base at +0x10, threshold at +0x18, auxiliary at +0x20; +1..+7 padding unknown',
            'helper_leaf': 'B[0x330]=0; either qword G1=0, or G1!=0 and delta<B[0x28] (mode1) / B[0x30] (mode0); mode1 additionally byte G2=0 and signed qword G3<0; delta=(new_counter-old_base) mod 2^64 < B[0x58] (mode1) or B[0x60] (mode0); stable guards; FSbase=QWORD[FS:0] joins the earlier TLS flag',
            'helper_writes': 'base=new_counter; remaining_counter-=delta; if G1!=0, other_countdown-=delta too; threshold=new_counter+min(remaining_counter,other_countdown if G1!=0 else UINT64_MAX,0x400000) modulo 2^64; auxiliary words copy the current thresholds except values >=0xfffffffffffff001 map to zero; local LOCK OR [RSP],0; no nested call',
            'tail_fill': 'When U<S, flag 0x651174a bit0=1, D=0: indirect call(initial RELATIVE target 0x6349360) with RDI=Q+U, RSI=S-U; stub -> memset(Q+U,0xa5,S-U)',
            'return': 'RBP=Q retained across normal ABI calls and returned after canary check'},
        'negative_and_scope_controls': rejected, 'normalization_masks': [],
        'limitations': ['Full captures do not establish all-path behavior; eight core continuations, four helper leaves, one fill-stub prefix only',
            'Runtime pointer slot, data flags, tables, valid metadata/storage, non-aliasing and no interference remain premises',
            'Threshold helper enabled-event branches, B[0x330]!=0, exhausted remaining counters and canary failure remain open',
            'Tail fill uses initial RELATIVE binding only if the mutable slot still contains that target; imported memset contract is not executed',
            'No complete allocation/ownership or outer transport-word preservation proof; no captured execution, Rust build or equivalence claim',
            'No independent-agent review, acceptance gate, commit or push']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exported_intervals': len(ranges), 'bytes': sum(r['bytes'] for r in ranges),
        'instructions': sum(r['instructions'] for r in ranges), 'selected_paths': len(paths),
        'selected_stores': len(rows), 'controls_rejected': len(rejected), 'scalar_cases': len(counter_cases)+len(fill_cases)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    collect(parser.parse_args().out)
