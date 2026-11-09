#!/usr/bin/env python3
"""Static node115 fresh fallback: selected small cache returns and refill boundaries."""
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
import allocator
import accounting

SLOW, FAST, ERRNO = 0x6353a70, 0x6355830, 0x63f0ad0
COMMON = {0x6353ab4: False, 0x6353ac1: False, 0x6353ae2: False,
          0x6353b04: False, 0x6353b18: False}
# owner, stop-before endpoint, endpoint opcode, branch decisions, call sequence
PATHS = {}
for boundary in (False, True):
    for result in ('below', 'threshold', 'null'):
        name = ('boundary_' if boundary else 'regular_')+result
        choices = {**COMMON, 0x6353b40: boundary, 0x6353b58: result == 'null', 0x6353bc1: False}
        if boundary:
            choices[0x6354128] = False
        if result != 'null':
            choices[0x6353baa] = result == 'threshold'
        calls = (0x6353d3c,) if result == 'null' else (0x6353f88,) if result == 'threshold' else ()
        PATHS[name] = (SLOW, 0x6353bdb, 'ret', choices, calls)
PATHS['invalid_class'] = (SLOW, 0x6353bdb, 'ret',
    {0x6353ab4: False, 0x6353ac1: False, 0x6353ae2: True, 0x6353bc1: False}, (0x6353d3c,))
PATHS['tls_transition_boundary'] = (SLOW, 0x6353d55, 'call', {0x6353ab4: True}, ())
for table_zero, name, stop in [(False, 'refill_table_nonzero_boundary', 0x63541d1),
                               (True, 'refill_table_zero_boundary', 0x6354cda)]:
    PATHS[name] = (SLOW, stop, 'call', {**COMMON, 0x6353b40: True, 0x6354128: True,
        0x6354141: False, 0x6354151: False, 0x6354164: True, 0x63541b0: table_zero}, ())
for name in ('budget_fallback', 'slot_limit_fallback'):
    choices, stop, _ = allocator.FRESH_PATHS[name]
    PATHS['fast_'+name] = (FAST, stop, 'jmp', dict(choices), ())


def stores(ins):
    out = {}
    for i in ins:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:
            continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp', 'push'):
            continue
        base.require(i.mnemonic in ('mov', 'add'), 'Unclassified fresh destination')
        out[i.address] = i
    return out


def selected(decoded, name, override=None):
    owner, stop, opcode, choices, calls = PATHS[name]
    choices = dict(choices)
    if override:
        choices.update(override)
    ins = cleanup.walk(decoded[owner], owner, stop, choices, calls)
    base.require(next(i for i in decoded[owner] if i.address == stop).mnemonic == opcode, 'Fresh endpoint')
    return ins


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Fresh target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        if r['scope'] == 'plt_window':
            base.require(lo == ERRNO and hi == lo+16 and any(s['name'] == '.plt' and
                s['address'] <= lo < hi <= s['address']+s['size'] for s in im.sections), 'Errno PLT extent')
        else:
            base.require(r['scope'] == 'complete_fde' and len([f for f in im.fdes
                if f['start'] == lo and f['end'] == hi]) == 1, 'Fresh exact FDE')
        raw = im.read(lo, hi-lo)
        base.require(base.sha(raw) == r['sha256'], 'Fresh body hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Fresh complete decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16)
        raw = bytes.fromhex(a['bytes_hex'])
        base.require(lo in bounds and hi in bounds and len(raw) == hi-lo and
                     im.read(lo, hi-lo) == raw, 'Fresh anchor '+a['name'])
    for t in spec['direct_transfers']:
        i = index[int(t['va'], 16)]
        base.require(i.mnemonic == t['mnemonic'] and i.operands[0].type == capstone.CS_OP_IMM and
                     i.operands[0].imm == int(t['target'], 16), 'Fresh direct transfer')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Fresh unique relocation')
        base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Fresh import symbol')
    for r in spec['rip_data']:
        i = index[int(r['va'], 16)];op = i.operands[r['operand']];va = int(r['target'], 16)
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip' and
                     i.address+i.size+op.mem.disp == va, 'Fresh RIP operand')
        base.require(any(s['name'] == r['section'] and s['type'] == r['section_type'] and
            s['address'] <= va < s['address']+s['size'] for s in im.sections), 'Fresh data section')
        base.require(r['runtime_value'] is None, 'Invented fresh runtime data')
        if r['file_bytes_hex'] is not None:
            raw = bytes.fromhex(r['file_bytes_hex'])
            base.require(im.read(va, len(raw)) == raw, 'Fresh initial data')
    for r in spec['unclosed_callees']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1 and
                     base.sha(im.read(lo, hi-lo)) == r['sha256'], 'Fresh unclosed callee identity')
        base.require(r['semantics_closed'] is False, 'Invented callee closure')
    actual = {}
    for name in PATHS:
        actual.update(stores(selected(decoded, name)))
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']}
    base.require(len(rows) == len(spec['selected_store_union']) and rows.keys() == actual.keys(), 'Fresh store union')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction'] and
                     op.size == r['width'], 'Fresh store opcode/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp) ==
                     (r['base'], r['index'], r['scale'], r['offset']), 'Fresh store operand')
    return decoded


def threshold_pair(counter, size, auxiliary, threshold):
    base.require(all(type(v) is int and 0 <= v <= accounting.MASK for v in
                     (counter, size, auxiliary, threshold)), 'Fresh threshold domain')
    return ((counter+size) & accounting.MASK) >= auxiliary, accounting.accounting_scalar(counter, threshold, size)[1]


def prior_helper(im):
    source = base.PACKET/'accounting-spec.json'
    spec = json.loads(source.read_text());decoded = accounting.bindings(im, spec)
    paths = []
    for name in ('account_mode_one_leaf', 'account_mode_one_active_countdown'):
        ins = accounting.selected(decoded, name)
        paths.append({'name': name, 'instructions_before_ret': len(ins),
                      'explicit_store_vas': [hex(va) for va in accounting.stores(ins)]})
    return {'spec_sha256': base.sha(source.read_bytes()), 'paths': paths,
            'status': 'Prior mode-one leaves revalidated; these are conditional callee joins, not new paths or runtime observations'}


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted invalid fresh evidence: '+name)
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
    for kind in ('changed', 'duplicate'):
        r = spec['relocations'][0];bad = copy.copy(im);bad.relocs = dict(im.relocs);slot = int(r['slot'], 16)
        bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
        reject(kind+'-relocation', lambda: bindings(bad, spec))
    bad = copy.deepcopy(spec);bad['relocations'][0]['symbol'] = 'malloc'
    reject('wrong-errno-import', lambda: bindings(im, bad))
    for kind in ('missing', 'width', 'destination'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':
            bad['selected_store_union'].pop()
        elif kind == 'width':
            bad['selected_store_union'][0]['width'] += 1
        else:
            bad['selected_store_union'][0]['offset'] += 1
        reject('store:'+kind, lambda: bindings(im, bad))
    for name, (_, _, _, choices, _) in PATHS.items():
        va = next(iter(choices))
        reject('changed-entry-edge:'+name, lambda: selected(decoded, name, {va: not choices[va]}))
    for name, va in [('regular_below', 0x6353b04), ('regular_below', 0x6353bc1),
                     ('regular_below', 0x6353baa), ('regular_null', 0x6353b58),
                     ('boundary_below', 0x6354128), ('refill_table_nonzero_boundary', 0x6354141),
                     ('refill_table_nonzero_boundary', 0x6354151), ('refill_table_nonzero_boundary', 0x6354164),
                     ('refill_table_nonzero_boundary', 0x63541b0), ('refill_table_zero_boundary', 0x63541b0)]:
        reject('excluded-edge:'+name+':'+hex(va), lambda: selected(decoded, name, {va: not PATHS[name][3][va]}))
    for r in spec['rip_data']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['rip_data'] if x['va'] == r['va'])['runtime_value'] = 0
        reject('invented-runtime-value:'+r['va'], lambda: bindings(im, bad))
        if r['file_bytes_hex'] is not None:
            reject('initial-data-byte:'+r['va'], lambda: bindings(mutate(int(r['target'], 16)), spec))
    for r in spec['unclosed_callees']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['unclosed_callees'] if x['start'] == r['start'])['semantics_closed'] = True
        reject('invented-callee-closure:'+r['start'], lambda: bindings(im, bad))
    for args in [(-1, 8, 0, 0), (0, 1 << 64, 0, 0), (0, 8, -1, 0), (0, 8, 0, 1 << 64), (True, 8, 0, 0)]:
        reject('threshold-domain:'+str(args), lambda: threshold_pair(*args))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'fresh-spec.json').read_text());decoded = bindings(im, spec)
    prior = prior_helper(im);rejected = controls(im, spec, decoded)
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']};paths = []
    for name, (owner, stop, opcode, choices, calls) in PATHS.items():
        ins = selected(decoded, name)
        paths.append({'name': name, 'owner': hex(owner), 'stop_before': hex(stop), 'endpoint_opcode': opcode,
            'decisions': {hex(k): v for k, v in choices.items()}, 'calls': [hex(v) for v in calls],
            'instruction_vas_before_endpoint': [hex(i.address) for i in ins],
            'explicit_stores': [rows[va] for va in stores(ins)],
            'implicit_push_sites': [hex(i.address) for i in ins if i.mnemonic == 'push']})
    M = accounting.MASK
    cases = [(8, 8, 16, 16, True, True), (8, 7, 16, 16, False, False),
        (8, 8, 16, 24, True, False), (8, 8, 24, 16, False, True),
        (M, 1, 0, 1, True, False), (16, 1, 8, 8, True, False),
        (0, 0, 0, 0, True, True), (M-1, 2, 8, 8, False, False)]
    for a, s, aux, t, fast, slow in cases:
        base.require(threshold_pair(a, s, aux, t) == (fast, slow), 'Fresh threshold worksheet')
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
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, lo, hi);splits = base.compare_boundaries(parsed, ins)
            if lo == FAST:
                base.require(base.compare_prior_native(p.stdout, (base.PACKET/('allocator/fresh.'+suffix+'.objdump')).read_bytes()), 'Prior fast export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits})
            commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated': False, 'ranges': ranges, 'paths': paths,
        'selected_store_union': spec['selected_store_union'], 'direct_transfers': spec['direct_transfers'],
        'relocations': spec['relocations'], 'rip_data': spec['rip_data'], 'unclosed_callees': spec['unclosed_callees'],
        'revalidated_accounting_helper': prior,
        'threshold_scalar_cases': [{'counter': a, 'class_size': s, 'auxiliary': aux, 'threshold': t,
            'fast_fallback': fast, 'slow_accounting_call': slow} for a, s, aux, t, fast, slow in cases],
        'manual_joins': {
            'small_input': 'N=RDI<=4096; FS[-0xd78]=0; k=BYTE[0x67277c0+ceil(N/8)]<=231; S=QWORD[0x6727a00+8*k]; BYTE[0x6713606]=0',
            'cache': 'B=QWORD[FS:0]-0x10a8; A=B+24*k; L=[A+0x360]; Q=[L]; slot update and count increment precede null test',
            'boundary': 'If low16(L)==WORD[A+0x370] but !=WORD[A+0x374], cursor=L+8, boundary=low16(L+8), count++',
            'error': 'k>231 OR cached Q=0 -> __errno_location import -> DWORD[result]=12 -> RAX=0; prior cache updates persist only on cache-null routes',
            'accounting': 'Q!=0 -> [B+0x338]+=S modulo 2^64; call 0x63eec80(B,SS+0x40) in mode1 if S>=([B+0x10]-old_counter) unsigned',
            'helper': 'Earlier two mode1 leaves apply under their existing premises, notably FSbase=QWORD[FS:0], stable flags and unexpired countdowns',
            'refill': 'Both low16 bounds equal; signed BYTE[B+1]<=0; E=[B+0x90]!=0; DWORD[0x64ffb80]<=2; W=[0x6728868]',
            'refill_nonzero': 'WORD[W+2*k]!=0 -> first call 0x63e9cd0(B,B+0x358,&A[0x360],k,1); stop before call',
            'refill_zero': 'WORD[W+2*k]==0 -> first call 0x6364880(B,E,N,k,0); stop before call',
            'incoming_paths': 'With stable lookup/list data, fast slot-limit fallback must enter the slow both-bounds-equal route, not a regular cached return; budget fallback does not by itself prove the later accounting-call condition'},
        'negative_and_scope_controls': rejected, 'normalization_masks': [],
        'limitations': ['Only selected small-size, zero-state/global-flag paths; exports are not all-path coverage',
            'No payload writes on selected cached return paths except potential aliases of metadata; ownership, size and alignment remain unproved',
            'Errno import validity and ABI are premises; no captured execution or emulation',
            'TLS-transition, refill and alternate provider identities are not callee semantic closure',
            'Runtime tables/flags, TLS identity, valid non-aliasing storage, stable state and canary remain explicit premises',
            'No Rust reconstruction, full-node equivalence, independent-agent review, gate, commit or push']}
    result['native_prior_transcript_comparisons'] = list(base._NATIVE_PRIOR_COMPARISONS)
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exported_intervals': len(ranges), 'bytes': sum(r['bytes'] for r in ranges),
        'instructions': sum(r['instructions'] for r in ranges), 'selected_paths': len(paths),
        'selected_stores': len(rows), 'controls_rejected': len(rejected), 'scalar_cases': len(cases)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    collect(parser.parse_args().out)
