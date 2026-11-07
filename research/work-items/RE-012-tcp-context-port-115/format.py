#!/usr/bin/env python3
"""Static #115 lookup-to-formatter join; no captured execution or emulation."""
import argparse
import copy
import importlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import capstone
import collect as base
import handoff
import helpers

LOOKUP, FORMAT, DISPATCH = 0x1546570, 0x141e3a0, 0x1680500
U64 = (1 << 64)-1


def parse_template(raw):
    """Only the C0/short-literal subset observed at these two call sites."""
    pos = 0;tokens = [];ordinal = 0
    while pos < len(raw):
        at = pos;tag = raw[pos];pos += 1
        if tag == 0:
            base.require(pos == len(raw), 'Trailing template data')
            return tokens
        if tag == 0xc0:
            tokens.append({'offset': at, 'kind': 'argument', 'ordinal': ordinal});ordinal += 1
        else:
            base.require(1 <= tag <= 127 and pos+tag < len(raw), 'Unsupported/truncated template token')
            tokens.append({'offset': at, 'kind': 'literal', 'bytes_hex': raw[pos:pos+tag].hex(), 'length': tag})
            pos += tag
    raise ValueError('Missing template terminator')


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Format target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1, 'Format exact FDE')
        raw = im.read(lo, hi-lo);base.require(base.sha(raw) == r['sha256'], 'Format body hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Format full decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(hi-lo == len(raw) and lo in bounds and hi in bounds, 'Format anchor extent')
        base.require(im.read(lo, len(raw)) == raw, 'Format anchor '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Format unique relocation')
        if r['symbol']:base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Format import')
    actual = {}
    for start, body in decoded.items():
        if start != LOOKUP:actual.update(handoff.explicit_stores(body))
    rows = {int(r['va'], 16): r for r in spec['stores']}
    base.require(len(rows) == len(spec['stores']) and rows.keys() == actual.keys(), 'Format store census')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction']
                     and op.size == r['width'], 'Format store opcode/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp)
                     == (r['base'], r['index'], r['scale'], r['offset']), 'Format store destination')
        base.require(va in {x.address for x in decoded[int(r['owner'], 16)]}, 'Format store owner')
        region = 'local_stack' if r['base'] in ('rsp', 'rbp') else 'output' if int(r['owner'], 16) == FORMAT else 'header'
        base.require(r['region'] == region, 'Format store region')
    table = spec['table'];va = int(table['va'], 16);raw = bytes.fromhex(table['bytes_hex'])
    base.require(va == 0x63f3d50 and len(raw) == 48 and im.read(va, 48) == raw, 'Format table bytes')
    resolved = []
    for off in range(0, 48, 8):
        if off in (8, 16):
            base.require(va+off not in im.relocs, 'Table scalar unexpectedly relocated')
            value = int.from_bytes(raw[off:off+8], 'little')
        else:
            (info, value), = im.relocs[va+off]
            base.require(info == 8, 'Table RELATIVE entry')
        resolved.append(hex(value))
    base.require(resolved == table['resolved_words'], 'Format table resolved words')
    def rip_target(at, operand):
        i = index[at];op = i.operands[operand]
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip', 'Expected RIP operand')
        return i.address+i.size+op.mem.disp
    for at, slot in ((0x154661a, 0x64df6e8), (0x15466aa, 0x64df6e8), (0x141e4be, 0x64df6f0)):
        base.require(index[at].mnemonic == 'call' and rip_target(at, 0) == slot, 'Format call binding')
    for at, target in ((0x15465ce, 0x15ebba0), (0x1546677, 0x15ebba0), (0x141e4ad, va)):
        base.require(index[at].mnemonic == 'lea' and rip_target(at, 1) == target, 'Format LEA binding')
    for at, slot in ((0x15465e4, 0x64e0b68), (0x154668d, 0x64e0b68), (0x15465fa, 0x64e0b70)):
        base.require(index[at].mnemonic == 'mov' and rip_target(at, 1) == slot, 'Callback slot binding')
    for t in spec['templates']:
        raw = bytes.fromhex(t['bytes_hex']);tv = int(t['va'], 16)
        base.require(im.read(tv, len(raw)) == raw, 'Format template bytes')
        lea, expected = (0x1546699, [0x15ebba0, 0x150ce90]) if t['name'] == 'plain' else (0x1546606, [0x15ebba0, 0x150ce90, 0x150cf50])
        base.require(rip_target(lea, 1) == tv, 'Template pointer binding')
        base.require(t['callback_targets'] == [hex(v) for v in expected]
                     and sum(x['kind'] == 'argument' for x in parse_template(raw)) == len(expected), 'Template callback ordinals')
    return decoded


def edge_tape(body, start, stop, decisions, expected_calls):
    """Traverse encoded edges using a manual finite tape; evaluate no CPU state."""
    index = {i.address: i for i in body};queues = copy.deepcopy(decisions);visited = [];calls = [];va = start
    while va != stop:
        base.require(va in index and len(visited) < 2000, 'Tape leaves body or exceeds finite budget')
        i = index[va];visited.append(va)
        base.require(i.mnemonic not in ('ret', 'ud2'), 'Unexpected tape terminator')
        if i.mnemonic == 'call':
            base.require(len(calls) < len(expected_calls) and va == expected_calls[len(calls)], 'Unexpected tape call')
            calls.append(va)
        if i.mnemonic.startswith('j'):
            base.require(i.operands[0].type == capstone.CS_OP_IMM, 'Indirect tape edge')
            if i.mnemonic == 'jmp':take = True
            else:
                base.require(va in queues and bool(queues[va]), 'Missing tape decision')
                take = queues[va].pop(0)
            va = i.operands[0].imm if take else va+i.size
        else:va += i.size
    base.require(index[stop].mnemonic == 'ret' and all(not q for q in queues.values())
                 and calls == expected_calls, 'Unconsumed tape decisions/calls')
    return {'instruction_vas_before_ret': [hex(v) for v in visited], 'calls': [hex(v) for v in calls]}


def template_paths(decoded, t, override=None):
    tokens = parse_template(bytes.fromhex(t['bytes_hex']))
    literal_count = sum(x.get('length', 0) for x in tokens)
    base.require(tokens[0]['kind'] == 'argument' and literal_count in (1, 9), 'Selected zero-capacity templates')
    fmt = {0x141e3bc: [False], 0x141e3c8: [False], 0x141e3f5: [], 0x141e3fc: [],
           0x141e3ee: [], 0x141e464: [False], 0x141e477: [True], 0x141e4c6: [False]}
    dsp = {0x168051d: [False], 0x168052a: [False], 0x168056a: [], 0x1680592: [], 0x168059b: [],
           0x168066c: [], 0x168057a: [], 0x168055a: []};calls = []
    for k, token in enumerate(tokens):
        arg = token['kind'] == 'argument';last = k == len(tokens)-1
        fmt[0x141e3f5].append(not arg);fmt[0x141e3ee].append(last)
        if arg:fmt[0x141e3fc].append(True)
        dsp[0x168056a].append(arg);dsp[0x168055a].append(last)
        if arg:
            for at in (0x1680592, 0x168059b, 0x168066c):dsp[at].append(False)
            calls.append(0x1680666)
        else:dsp[0x168057a].append(False);calls.append(0x1680575)
    if override:
        target, at, value = override;(fmt if target == 'formatter' else dsp)[at][0] = value
    return {**t, 'tokens': tokens, 'literal_bytes': literal_count,
            'initial_header': {'capacity': 0, 'pointer': 1, 'length': 0},
            'formatter_tape': edge_tape(decoded[FORMAT], FORMAT, 0x141e4e6, fmt, [0x141e4be]),
            'dispatcher_tape': edge_tape(decoded[DISPATCH], DISPATCH, 0x16806bf, dsp, calls),
            'premises': ['Even argument-block pointer', 'Every callback/literal writer returns AL=0',
                         'No unwind; finite edge tapes annotate the pinned bytes, not runtime execution']}


def growth(capacity, length, request):
    """Scalar worksheet for pinned unsigned arithmetic; no allocation simulated."""
    base.require(all(type(v) is int for v in (capacity, length, request)), 'Integer growth domain')
    base.require(0 <= length <= capacity <= (1 << 63)-1 and 0 <= request <= U64, 'Admitted valid header domain')
    total = length+request;base.require(total <= U64, 'Length-plus-request carry')
    needs = request > capacity-length
    return {'capacity': capacity, 'length': length, 'request': request, 'needs_growth': needs,
            'new_length': total, 'requested_capacity': max(8, 2*capacity, total) if needs else capacity}


def append_paths(decoded, override=None):
    cases = [
        ('zero_fit', 0x141e8f0, 0x141e936, {0x141e90e: [False], 0x141e913: [True]}, []),
        ('positive_fit', 0x141e8f0, 0x141e936, {0x141e90e: [False], 0x141e913: [False]}, [0x141e91f]),
        ('positive_growth', 0x141e8f0, 0x141e936, {0x141e90e: [True]}, [0x141e943, 0x141e91f]),
        ('grow_return', 0x141c980, 0x141c9db, {0x141c98e: [False], 0x141c9c6: [False]}, [0x141c9bd])]
    result = []
    for name, start, stop, decisions, calls in cases:
        if override and name == override[0]:decisions[override[1]][0] = override[2]
        result.append({'name': name, **edge_tape(decoded[start], start, stop, decisions, calls)})
    return result


def references(data):
    result = []
    for module, fn, packet, key in (
        ('flag_group_format_static', 'consumer_trace', 'RE-015-node115-flag-group-format', 'consumer'),
        ('flag_group_write_static', 'write_target_trace', 'RE-015-node115-flag-group-write-target', 'write_target'),
        ('table_method_static', 'method_trace', 'RE-015-node115-table-method', 'method')):
        mod = importlib.import_module(module);p = base.ROOT/'research/work-items'/packet
        original = json.loads((p/'records.json').read_text())
        fresh = getattr(mod, fn)(data)
        base.require(fresh == original[key], 'Prior static trace changed: '+module)
        result.append({'packet': p.relative_to(base.ROOT).as_posix(), 'replayed_function': fn,
                       'record_key': key, 'trace_equal': True,
                       'module_sha256': base.sha(Path(mod.__file__).read_bytes()),
                       'records_sha256': base.sha((p/'records.json').read_bytes()),
                       'manifest_sha256': base.sha((p/'MANIFEST.sha256').read_bytes()),
                       'scope': 'Only named static trace; no global caller census or original test-suite replay'})
    return result


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid formatter evidence: '+name)
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read;return bad
    for a in spec['anchors']:reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
    for t in spec['templates']:reject('template-byte:'+t['name'], lambda: bindings(mutate(int(t['va'], 16)), spec))
    for off in (0, 8, 16, 24):reject('table-byte:'+str(off), lambda: bindings(mutate(0x63f3d50+off), spec))
    for r in spec['relocations']:
        slot = int(r['slot'], 16)
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im);bad.relocs = dict(im.relocs)
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+r['slot'], lambda: bindings(bad, spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['ranges'] if x['name'] == r['name'])['end'] = hex(int(r['end'], 16)-1)
        reject('truncated-fde:'+r['name'], lambda: bindings(im, bad))
    for kind in ('missing', 'width', 'index', 'region'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':bad['stores'].pop()
        elif kind == 'width':bad['stores'][0]['width'] += 1
        elif kind == 'index':bad['stores'][0]['index'] = 'r15'
        else:bad['stores'][0]['region'] = 'unknown'
        reject('store-census:'+kind, lambda: bindings(im, bad))
    for raw in (b'', b'\xc0', b'\x02/\0', b'\x80\0', b'\0\0', b'\xff\0'):
        reject('unsupported-or-truncated-template:'+raw.hex(), lambda: parse_template(raw))
    for target, va, value in [('formatter', 0x141e3bc, True), ('formatter', 0x141e477, False),
                             ('formatter', 0x141e4c6, True), ('dispatcher', 0x168051d, True),
                             ('dispatcher', 0x168066c, True), ('dispatcher', 0x168057a, True)]:
        reject('excluded-edge:'+hex(va), lambda: template_paths(decoded, spec['templates'][0], (target, va, value)))
    for name, va, value in [('zero_fit', 0x141e913, False), ('positive_fit', 0x141e90e, True),
                            ('grow_return', 0x141c98e, True), ('grow_return', 0x141c9c6, True)]:
        reject('excluded-append-edge:'+hex(va), lambda: append_paths(decoded, (name, va, value)))
    for args in ((-1, 0, 0), (0, 1, 0), (1 << 63, 0, 1), (8, 0, -1), (8, 8, U64), (0, 0, U64+1)):
        reject('growth-domain:'+str(args), lambda: growth(*args))
    for lo in (0x171, 0x188, 0x189):reject('output-alias:'+hex(lo), lambda: handoff.interval_disjoint(lo, 24, 0x188))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'format-spec.json').read_text());decoded = bindings(im, spec)
    paths = [template_paths(decoded, t) for t in spec['templates']]
    prior = references(data);rejected = controls(im, spec, decoded)
    examples = [growth(*args) for args in ((0, 0, 0), (0, 0, 1), (0, 0, 8), (0, 0, 9),
                (8, 3, 5), (8, 3, 6), (8, 8, 0), (8, 8, 1), (8, 8, 20), ((1 << 63)-1, (1 << 63)-1, 1))]
    base.require([(e['needs_growth'], e['new_length'], e['requested_capacity']) for e in examples] ==
                 [(False, 0, 0), (True, 1, 8), (True, 8, 8), (True, 9, 9), (False, 8, 8),
                  (True, 9, 16), (False, 8, 8), (True, 9, 16), (True, 28, 28),
                  (True, 1 << 63, (1 << 64)-2)], 'Growth boundary worksheet')
    apaths = append_paths(decoded)
    for lo in (-0x1d0, -0x140):handoff.interval_disjoint(lo, 24, 0x188)
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16);ins = decoded[start]
        fde, = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        row = {**r, 'fde': hex(fde['fde']), 'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
               'file_offset': hex(im.offset(start, end-start)), 'bytes': end-start, 'instructions': len(ins),
               'native': [], 'transfers': helpers.transfers(im, ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={start}', f'--stop-address={end}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, start, end);splits = base.compare_boundaries(parsed, ins)
            if start == LOOKUP:
                base.require(p.stdout == (base.PACKET/('lookup/lookup.'+suffix+'.objdump')).read_bytes(), 'Prior lookup export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
              'table': spec['table'], 'explicit_stores_excluding_lookup': spec['stores'], 'template_paths': paths,
              'prior_static_trace_replays': prior, 'growth_scalar_worksheet': examples,
              'append_and_grow_tapes': apaths,
              'manual_argument_join': [
                  {'ordinal': 0, 'value': 'LS+0x58: 16 bytes copied from C+8', 'callback': '0x15ebba0',
                   'read_widths': [8, 8], 'forwarded_to': '0x167fa70 via 0x64df720; body not closed here'},
                  {'ordinal': 1, 'value': 'LS+0xc: DWORD K', 'callback': '0x150ce90', 'read_widths': [4],
                   'forwarded_to': 'Nested 0x1680500 dispatch with 0x150e1d0; body not closed here'},
                  {'ordinal': 2, 'value': 'LS+0xb: BYTE B; tagged only', 'callback': '0x150cf50', 'read_widths': [1],
                   'forwarded_to': hex(im.relocs[0x64dfa00][0][1])+' via 0x64dfa00; body not closed here'}],
              'manual_stack_join': {'LS': 'OS-0x180 (prior lookup/caller join)', 'arguments': 'LS+0x10, stride 16',
                                    'formatter_header': 'LS-0x50 = OS-0x1d0, 24 bytes',
                                    'formatter_output': 'LS+0x40 = OS-0x140, 24 bytes',
                                    'tracked_word': 'OS+[0x188,0x18a)'},
              'negative_and_scope_controls': rejected, 'normalization_masks': [],
              'limitations': ['Finite manually chosen normal-edge tapes, not CPU emulation or observed execution',
                              'Only two actual C0/short-literal templates; all callbacks/literal writers must return AL=0',
                              'Zero initial capacity does not imply no later allocation or zero final capacity',
                              '0x141e0e0 allocation result, nested callbacks, source aliases, lifetimes and allocator writes remain open',
                              '29 lexical explicit stores exclude implicit pushes/call return slots and transitive callees',
                              'No standalone whole-node equivalence, runtime ownership, Rust implementation or acceptance gate']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'fdes': len(ranges), 'bytes': sum(r['bytes'] for r in ranges), 'instructions': sum(r['instructions'] for r in ranges),
                      'templates': len(paths), 'explicit_stores': len(spec['stores']), 'prior_static_trace_replays': len(prior),
                      'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
