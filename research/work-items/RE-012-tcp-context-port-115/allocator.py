#!/usr/bin/env python3
"""Static #115 allocator entry paths and TLS/table joins; no target execution."""
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

FRESH, EXISTING, CORE, WRITER = 0x6355830, 0x635a7a0, 0x6350210, 0x63e8d90
MASK = (1 << 64)-1
FRESH_PATHS = {
    'slot_regular': ({0x635583b: False, 0x6355877: False, 0x63558a2: False}, 0x63558be, 3),
    'slot_boundary_advance': ({0x635583b: False, 0x6355877: False, 0x63558a2: True, 0x63558cf: False}, 0x63558be, 4),
    'large_fallback': ({0x635583b: True}, 0x63558c0, 0),
    'budget_fallback': ({0x635583b: False, 0x6355877: True}, 0x63558c0, 0),
    'slot_limit_fallback': ({0x635583b: False, 0x6355877: False, 0x63558a2: True, 0x63558cf: True}, 0x63558c0, 0),
}
EXISTING_GUARDS = {0x635a7d7: False, 0x635a7db: False, 0x635a7ee: False}
CORE_GUARDS = {0x635026a: False, 0x6350290: False, 0x63502a8: False, 0x63502b1: False,
               0x63502f6: False, 0x6350324: False, 0x6350331: False, 0x6350360: False,
               0x635039d: False, 0x63503a6: True}


def explicit_stores(body):
    out = {}
    for i in body:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp', 'push'):continue
        base.require(i.mnemonic in ('mov', 'add'), 'Unclassified allocator destination')
        out[i.address] = i
    return out


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Allocator target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi, end = int(r['start'], 16), int(r['end'], 16), int(r['owner_end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == end]) == 1, 'Allocator exact owner FDE')
        base.require(lo < hi <= end and r['scope'] == ('complete_fde' if hi == end else 'entry_prefix'), 'Allocator prefix scope')
        full = im.read(lo, end-lo);raw = im.read(lo, hi-lo)
        base.require(base.sha(full) == r['owner_sha256'] and base.sha(raw) == r['sha256'], 'Allocator body/prefix hashes')
        # Decode only the exported interval. Full owner hash authenticates omitted bytes,
        # but supplies no CFG or write-coverage credit for those bytes.
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Allocator complete interval decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(hi-lo == len(raw) and lo in bounds and hi in bounds and im.read(lo, len(raw)) == raw, 'Allocator anchor '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Allocator unique relocation')
    actual = {}
    for lo in (FRESH, EXISTING, CORE):actual.update(explicit_stores(decoded[lo]))
    rows = {int(r['va'], 16): r for r in spec['stores']}
    base.require(len(rows) == len(spec['stores']) and rows.keys() == actual.keys(), 'Allocator store census')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction']
                     and op.size == r['width'], 'Allocator store opcode/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), i.reg_name(op.mem.segment), op.mem.scale, op.mem.disp)
                     == (r['base'], r['index'], r['segment'], r['scale'], r['offset']), 'Allocator store destination')
        base.require(va in {x.address for x in decoded[int(r['owner'], 16)]}, 'Allocator store owner')
        region = 'local_stack' if r['base'] == 'rsp' else 'fs_counter' if r['segment'] == 'fs' else 'tls_class_slot'
        base.require(region == r['region'], 'Allocator store region')
    for va, target in ((0x63558c0, 0x6353a70), (0x635a80f, CORE), (0x63503e3, 0x6365660)):
        i = index[va]
        base.require(i.mnemonic == ('call' if va == 0x63503e3 else 'jmp') and i.operands[0].type == capstone.CS_OP_IMM
                     and i.operands[0].imm == target, 'Allocator direct transfer')
    for va, opnum, target in ((0x6355841, 1, 0x67277c0), (0x6355857, 1, 0x6727a00),
          (0x635030f, 1, 0x6727a00), (0x6350337, 1, 0x67277c0),
          (0x63e8f44, 1, 0x6727a00), (0x63e9062, 1, 0x67277c0),
          (0x635036e, 1, 0x6713606), (0x6350270, 1, 0x6511738),
          (0x141e106, 0, 0x64df588), (0x141e125, 0, 0x64df480)):
        i = index[va];op = i.operands[opnum]
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip'
                     and i.address+i.size+op.mem.disp == target, 'Allocator RIP/table binding')
    for r in spec['data_regions']:
        va, n = int(r['va'], 16), r['span']
        matches = [s for s in im.sections if s['address'] <= va and va+n <= s['address']+s['size']]
        base.require(len(matches) == 1 and matches[0]['name'] == r['section'] == '.bss'
                     and matches[0]['type'] == r['section_type'] == 8, 'Allocator NOBITS region')
        base.require(r['runtime_values'] is None and r['file_bytes'] is None, 'Invented runtime table/flag values')
    for r in spec['boundary_owners']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1
                     and base.sha(im.read(lo, hi-lo)) == r['sha256'], 'Boundary owner identity')
        base.require(r['scope'] == 'identity_only_no_semantic_closure', 'Boundary scope')
    return decoded


def path(decoded, spec, name, override=None):
    if name in FRESH_PATHS:
        decisions, stop, count = FRESH_PATHS[name];start = FRESH
    elif name == 'existing_tail':decisions, stop, count, start = EXISTING_GUARDS, 0x635a80f, 1, EXISTING
    else:
        base.require(name == 'core_to_first_call', 'Unknown selected path')
        decisions, stop, count, start = CORE_GUARDS, 0x63503e3, 11, CORE
    decisions = dict(decisions)
    if override:decisions.update(override)
    ins = cleanup.walk(decoded[start], start, stop, decisions, ())
    stores = explicit_stores(ins);base.require(len(stores) == count, 'Selected store count')
    rows = {int(r['va'], 16): r for r in spec['stores']}
    return {'name': name, 'start': hex(start), 'endpoint': hex(stop),
            'endpoint_instruction': next(i.mnemonic+' '+i.op_str for i in decoded[start] if i.address == stop),
            'instruction_vas_before_endpoint': [hex(i.address) for i in ins], 'calls_before_endpoint': [],
            'decisions': {hex(k): v for k, v in decisions.items()}, 'selected_explicit_stores': [rows[v] for v in stores],
            'implicit_push_sites': [hex(i.address) for i in ins if i.mnemonic == 'push']}


def writer_recheck(im, decoded):
    p = base.ROOT/'research/work-items/RE-001-node115-lu-tablefill'
    old = json.loads((p/'records.json').read_text())
    base.require(old['target']['sha256'] == base.TARGET and old['function']['range'] == ['0x63e8d90', '0x63e9152'], 'Writer record identity')
    excerpts = []
    for name, row in old['exhibits'].items():
        lo, hi = map(lambda s: int(s, 16), row['range']);raw = bytes.fromhex((p/(name+'.hex')).read_text())
        base.require(len(raw) == hi-lo == row['bytes'] and im.read(lo, len(raw)) == raw, 'Prior writer exhibit')
        excerpts.append({'name': name, 'start': hex(lo), 'bytes': len(raw), 'sha256': base.sha(raw)})
    base.require(not any(i.mnemonic == 'call' for i in decoded[WRITER]), 'Writer call-free body')
    return {'packet': p.relative_to(base.ROOT).as_posix(), 'record_sha256': base.sha((p/'records.json').read_bytes()),
            'manifest_sha256': base.sha((p/'MANIFEST.sha256').read_bytes()), 'revalidated_exhibits': excerpts,
            'scope': 'Five retained raw exhibits, full owner digest/decode and shared table address bindings; no replay of global caller census or source descriptor construction'}


def bucket(n):
    base.require(type(n) is int and 0 <= n <= 4096, 'Small-size index domain')
    return (n+7) >> 3


def tls_offsets(k):
    base.require(type(k) is int and 0 <= k <= 255, 'Unsigned byte class domain')
    return {'class': k, 'cursor': -0x10a8+24*k+0x360, 'count': -0x10a8+24*k+0x368,
            'boundary': -0x10a8+24*k+0x370, 'limit': -0x10a8+24*k+0x374}


def budget_word(counter, amount, limit):
    base.require(all(type(v) is int and 0 <= v <= MASK for v in (counter, amount, limit)), 'Unsigned counter domain')
    total = counter+amount;wrapped = total & MASK
    return {'counter': counter, 'amount': amount, 'limit': limit, 'wrapped_sum': wrapped,
            'carry': total > MASK, 'selected_budget_guard_passes': wrapped < limit}


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid allocator evidence: '+name)
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read;return bad
    for a in spec['anchors']:reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
    for r in spec['relocations']:
        slot = int(r['slot'], 16)
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im);bad.relocs = dict(im.relocs)
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+r['slot'], lambda: bindings(bad, spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec);next(x for x in bad['ranges'] if x['name'] == r['name'])['owner_end'] = hex(int(r['owner_end'], 16)-1)
        reject('truncated-owner:'+r['name'], lambda: bindings(im, bad))
        if r['scope'] == 'entry_prefix':
            reject('omitted-owner-byte:'+r['name'], lambda: bindings(mutate(int(r['owner_end'], 16)-1), spec))
            bad = copy.deepcopy(spec);next(x for x in bad['ranges'] if x['name'] == r['name'])['scope'] = 'complete_fde'
            reject('prefix-as-complete:'+r['name'], lambda: bindings(im, bad))
    for kind in ('missing', 'width', 'segment', 'region'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':bad['stores'].pop()
        elif kind == 'width':bad['stores'][0]['width'] += 1
        elif kind == 'segment':bad['stores'][0]['segment'] = 'gs'
        else:bad['stores'][0]['region'] = 'unknown'
        reject('store-census:'+kind, lambda: bindings(im, bad))
    for r in spec['data_regions']:
        bad = copy.deepcopy(spec);next(x for x in bad['data_regions'] if x['name'] == r['name'])['runtime_values'] = [0]
        reject('invented-bss-values:'+r['name'], lambda: bindings(im, bad))
        reject('bss-as-file-bytes:'+r['name'], lambda: im.read(int(r['va'], 16), r['span']))
    for name, (decisions, _, _) in FRESH_PATHS.items():
        at = next(iter(decisions));reject('changed-fresh-edge:'+name, lambda: path(decoded, spec, name, {at: not decisions[at]}))
    for name, guards in [('existing_tail', EXISTING_GUARDS), ('core_to_first_call', CORE_GUARDS)]:
        for at, value in guards.items():reject('excluded-prefix-edge:'+hex(at), lambda: path(decoded, spec, name, {at: not value}))
    for n in (-1, 4097, MASK, 1.5):reject('bucket-domain:'+str(n), lambda: bucket(n))
    for k in (-1, 256, 1.5):reject('class-domain:'+str(k), lambda: tls_offsets(k))
    for args in ((-1, 1, 2), (0, MASK+1, 2), (0, 1, 1.5)):reject('counter-domain:'+str(args), lambda: budget_word(*args))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'allocator-spec.json').read_text());decoded = bindings(im, spec)
    paths = [path(decoded, spec, name) for name in (*FRESH_PATHS, 'existing_tail', 'core_to_first_call')]
    writer = writer_recheck(im, decoded);rejected = controls(im, spec, decoded)
    histogram = [0]*513
    for n in range(4097):histogram[bucket(n)] += 1
    base.require(histogram == [1]+[8]*512, 'Exhaustive small-size bucket relation')
    offsets = [tls_offsets(k) for k in range(256)]
    base.require(offsets[0] == {'class': 0, 'cursor': -3400, 'count': -3392, 'boundary': -3384, 'limit': -3380}, 'TLS class-zero offsets')
    budgets = [budget_word(*v) for v in ((0, 8, 9), (0, 8, 8), (8, 8, 17), (MASK-3, 8, 8))]
    base.require([r['selected_budget_guard_passes'] for r in budgets] == [True, False, True, True]
                 and budgets[-1]['carry'] and budgets[-1]['wrapped_sum'] == 4, 'Counter carry worksheet')
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16);ins = decoded[lo]
        fde, = [f for f in im.fdes if f['start'] == lo and f['end'] == int(r['owner_end'], 16)]
        row = {**r, 'fde': hex(fde['fde']), 'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
               'file_offset': hex(im.offset(lo, hi-lo)), 'bytes': hi-lo, 'instructions': len(ins),
               'native': [], 'transfers': helpers.transfers(im, ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={lo}', f'--stop-address={hi}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, lo, hi);splits = base.compare_boundaries(parsed, ins)
            if lo == 0x141e0e0:base.require(p.stdout == (base.PACKET/('allocation/allocation_result.'+suffix+'.objdump')).read_bytes(), 'Prior allocation export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
       'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
       'data_regions': spec['data_regions'], 'boundary_owners': spec['boundary_owners'], 'selected_paths': paths,
       'lexical_stores_in_fresh_and_two_prefixes': spec['stores'], 'writer_revalidation': writer,
       'small_size_bucket_histogram': histogram, 'tls_relative_offsets_by_byte_class': offsets, 'budget_word_examples': budgets,
       'manual_joins': {
          'fresh': 'k=BYTE[0x67277c0+ceil(N/8)]; amount=QWORD[0x6727a00+8*k]; runtime values unknown',
          'tls': 'F=FS base; T=QWORD FS:[0]; A=T-0x10a8+24*k; no T==F proof',
          'fresh_return': 'QWORD at old cursor A+0x360; no direct payload writes or zeroing on two selected return paths',
          'existing_tail': '(P!=0,N!=0,unchanged canary) -> 0x6350210(P,N,EDX=0,ECX=1); no earlier call',
          'core': 'Selected TLS initialized/cache-hit/small-size/global-zero path ends before first call at 0x63503e3',
          'core_call_registers': 'RDI=T-0x10a8, RSI=0, RDX=P, RCX=old size-table word, R8=N, R9=0',
          'core_call_stack': 'Before CALL: [RSP]=option byte zero-extended, [RSP+8]=T-0x10a8+0x358, [RSP+16]=core_postprologue_RSP+0xf0',
          'core_descriptor': 'CS+f0: BYTE1, CS+f8:P, CS+100:N, CS+108:QWORD0, CS+110:QWORD0; padding not initialized here'},
       'negative_and_scope_controls': rejected, 'normalization_masks': [],
       'limitations': ['Only complete fresh entry plus two selected prefixes; full owner hashes do not establish omitted CFG behavior',
           'BSS initialization/readiness and actual table values remain unproved; original writer evidence is only partially replayed',
           'TLS identity, valid slots, no aliasing/interference and normal returned storage are external premises',
           'Unsigned budget add may wrap; passing its comparison alone is not a capacity or allocation validity proof',
           'No payload-preservation/free/failure-ownership conclusion for 0x6353a70 or 0x6365660',
           'No captured execution, Rust implementation, independent-agent review or acceptance gate']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exported_intervals': len(ranges), 'complete_fdes': 3, 'entry_prefixes': 2,
       'bytes': sum(r['bytes'] for r in ranges), 'instructions': sum(r['instructions'] for r in ranges),
       'selected_paths': len(paths), 'lexical_explicit_stores': len(spec['stores']),
       'bucket_inputs': 4097, 'prior_writer_exhibits': len(writer['revalidated_exhibits']), 'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
