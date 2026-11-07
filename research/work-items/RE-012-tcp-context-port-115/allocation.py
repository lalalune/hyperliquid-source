#!/usr/bin/env python3
"""Static #115 allocation-result and grow-error join; no target execution."""
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
import handoff
import helpers

RESULT, GROW, ERROR = 0x141e0e0, 0x141c980, 0x141e264
LIMIT = (1 << 63)-1
U64 = (1 << 64)-1
CASES = {
    'size_high_bit': ({0x141e0f6: True}, (), 8, 1, '0', None),
    'empty_fresh': ({0x141e0f6: False, 0x141e0fe: True, 0x141e120: True}, (), 16, 0, '1', '0'),
    'fresh_null': ({0x141e0f6: False, 0x141e0fe: True, 0x141e120: False, 0x141e12e: False}, (0x141e125,), 16, 1, '1', 'requested_size'),
    'fresh_nonnull': ({0x141e0f6: False, 0x141e0fe: True, 0x141e120: False, 0x141e12e: True}, (0x141e125,), 16, 0, 'allocator_result', 'requested_size'),
    'existing_null': ({0x141e0f6: False, 0x141e0fe: False, 0x141e10f: False}, (0x141e106,), 16, 1, '1', 'requested_size'),
    'existing_nonnull': ({0x141e0f6: False, 0x141e0fe: False, 0x141e10f: True}, (0x141e106,), 16, 0, 'allocator_result', 'requested_size'),
}


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Allocation target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1, 'Allocation exact FDE')
        raw = im.read(lo, hi-lo);base.require(base.sha(raw) == r['sha256'], 'Allocation body hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Allocation full decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(hi-lo == len(raw) and lo in bounds and hi in bounds, 'Allocation anchor extent')
        base.require(im.read(lo, len(raw)) == raw, 'Allocation anchor '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Allocation unique relocation')
        if r['symbol']:base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Allocation import')
    actual = {}
    for body in decoded.values():actual.update(handoff.explicit_stores(body))
    rows = {int(r['va'], 16): r for r in spec['stores']}
    base.require(len(rows) == len(spec['stores']) and actual.keys() == rows.keys(), 'Allocation store census')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and op.size == r['width']
                     and i.mnemonic+' '+i.op_str == r['instruction'], 'Allocation store opcode/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp)
                     == (r['base'], r['index'], r['scale'], r['offset']), 'Allocation store destination')
        base.require(va in {x.address for x in decoded[int(r['owner'], 16)]}, 'Allocation store owner')
        base.require(r['region'] == ('result' if int(r['owner'], 16) == RESULT else 'header'), 'Allocation store region')
    for va, slot in ((0x141e106, 0x64df588), (0x141e125, 0x64df480), (0x141c9de, 0x64df498),
                     (0x141c9ec, 0x64df498), (0x141e26d, 0x64df6b0), (0x141e273, 0x64df490),
                     (0x141e297, 0x64df6b8), (0x141e25e, 0x64df6a8)):
        i = index[va];op = i.operands[0]
        base.require(i.mnemonic == 'call' and op.type == capstone.CS_OP_MEM
                     and i.reg_name(op.mem.base) == 'rip' and i.address+i.size+op.mem.disp == slot, 'Allocation call-slot binding')
    i = index[0x141c9bd]
    base.require(i.mnemonic == 'call' and i.operands[0].type == capstone.CS_OP_IMM
                 and i.operands[0].imm == RESULT, 'Grow-to-result call')
    lit = spec['diagnostic_data_window'];va = int(lit['va'], 16);raw = bytes.fromhex(lit['bytes_hex'])
    i = index[0x141e284]
    base.require(i.address+i.size+i.operands[1].mem.disp == va and len(raw) == lit['capture_bytes'] == 35
                 and im.read(va, len(raw)) == raw and index[0x141e292].operands[1].imm == lit['esi_value'] == 35,
                 'Diagnostic data window and separate argument')
    base.require(lit['consumed_length'] is None, 'Diagnostic consumed length is unresolved')
    return decoded


def result_path(decoded, spec, name, override=None):
    decisions, calls, indexed_offset, tag, word8, word16 = CASES[name];decisions = dict(decisions)
    if override:decisions.update(override)
    ins = cleanup.walk(decoded[RESULT], RESULT, 0x141e161, decisions, calls)
    base.require(next(i for i in decoded[RESULT] if i.address == 0x141e161).mnemonic == 'ret', 'Result return')
    visited = {i.address for i in ins};writes = [];mask = set()
    for r in spec['stores']:
        if int(r['va'], 16) not in visited:continue
        base.require(r['region'] == 'result' and r['base'] == 'rbx', 'Result write region')
        off = indexed_offset if r['index'] == 'rax' else r['offset']
        base.require(r['index'] in (None, 'rax') and 0 <= off < off+r['width'] <= 24, 'Result write envelope')
        mask.update(range(off, off+r['width']));writes.append({**r, 'selected_offset': off})
    expected = list(range(16 if name == 'size_high_bit' else 24))
    base.require(sorted(mask) == expected, 'Result write mask')
    return {'name': name, 'decisions': {hex(k): v for k, v in decisions.items()},
            'instruction_vas_before_ret': [hex(i.address) for i in ins], 'calls': [hex(v) for v in calls],
            'selected_explicit_stores': writes, 'written_byte_offsets': sorted(mask),
            'unwritten_byte_offsets': [v for v in range(24) if v not in mask],
            'manual_value_annotation': {'qword_0': tag, 'qword_8': word8, 'qword_16': word16},
            'value_annotation_basis': 'Pinned immediate/register-copy operands on the named path; no CPU state evaluation'}


def prefix(decoded, owner, stop, decisions, calls):
    ins = cleanup.walk(decoded[owner], owner, stop, decisions, calls)
    terminal = next(i for i in decoded[owner] if i.address == stop)
    base.require(terminal.mnemonic in ('call', 'ret'), 'Prefix endpoint')
    return {'owner': hex(owner), 'endpoint': hex(stop), 'endpoint_instruction': terminal.mnemonic+' '+terminal.op_str,
            'instruction_vas_before_endpoint': [hex(i.address) for i in ins],
            'calls_before_endpoint': [hex(v) for v in calls],
            'explicit_stores_before_endpoint': [hex(v) for v in handoff.explicit_stores(ins)]}


def consumer_paths(decoded):
    return [
        {'name': 'grow_success', **prefix(decoded, GROW, 0x141c9db, {0x141c98e: False, 0x141c9c6: False}, (0x141c9bd,))},
        {'name': 'grow_add_carry', **prefix(decoded, GROW, 0x141c9de, {0x141c98e: True}, ())},
        {'name': 'grow_result_error', **prefix(decoded, GROW, 0x141c9ec, {0x141c98e: False, 0x141c9c6: True}, (0x141c9bd,))},
        {'name': 'zero_error_word8', **prefix(decoded, ERROR, 0x141e26d, {0x141e26b: False}, ())},
        {'name': 'nonzero_error_word8', **prefix(decoded, ERROR, 0x141e273, {0x141e26b: True}, ())},
        {'name': 'size_diagnostic', **prefix(decoded, 0x141e280, 0x141e297, {}, ())},
        {'name': 'allocation_error_bridge', **prefix(decoded, 0x141e251, 0x141e25e, {}, ())}]


def growth_admission(capacity, length, request):
    """Scalar limits joining pinned append/grow/result comparisons, no allocation."""
    base.require(all(type(v) is int for v in (capacity, length, request)), 'Integer size inputs')
    base.require(0 <= length <= capacity <= LIMIT and 0 <= request <= U64, 'Admitted header/request domain')
    if request <= capacity-length:return {'route': 'fits', 'new_length': length+request, 'requested_capacity': capacity}
    total = length+request
    if total > U64:return {'route': 'add_carry_error', 'wrapped_sum': total & U64}
    new = max(8, 2*capacity, total)
    route = 'size_high_bit_error' if new > LIMIT else 'fresh_allocator' if capacity == 0 else 'existing_allocator'
    return {'route': route, 'new_length': total, 'requested_capacity': new}


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid allocation evidence: '+name)
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read;return bad
    for a in spec['anchors']:reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
    reject('diagnostic-data-byte', lambda: bindings(mutate(int(spec['diagnostic_data_window']['va'], 16)), spec))
    bad = copy.deepcopy(spec);bad['diagnostic_data_window']['esi_value'] = 17
    reject('wrong-diagnostic-argument', lambda: bindings(im, bad))
    for r in spec['relocations']:
        slot = int(r['slot'], 16)
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im);bad.relocs = dict(im.relocs)
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+r['slot'], lambda: bindings(bad, spec))
    for r in spec['ranges']:
        bad = copy.deepcopy(spec);next(x for x in bad['ranges'] if x['name'] == r['name'])['end'] = hex(int(r['end'], 16)-1)
        reject('truncated-fde:'+r['name'], lambda: bindings(im, bad))
    for key in ('missing', 'width', 'index', 'region'):
        bad = copy.deepcopy(spec)
        if key == 'missing':bad['stores'].pop()
        elif key == 'width':bad['stores'][0]['width'] += 1
        elif key == 'index':bad['stores'][0]['index'] = 'r15'
        else:bad['stores'][0]['region'] = 'unknown'
        reject('store-census:'+key, lambda: bindings(im, bad))
    for name, (decisions, *_) in CASES.items():
        # Flip the first branch: the named path must fail its call/decision/mask contract.
        at = next(iter(decisions));reject('wrong-result-path:'+name, lambda: result_path(decoded, spec, name, {at: not decisions[at]}))
    for args in ((-1, 0, 0), (0, 1, 0), (LIMIT+1, 0, 1), (8, 0, -1), (0, 0, U64+1), (8, 1.0, 1)):
        reject('growth-domain:'+str(args), lambda: growth_admission(*args))
    for lo in (0x171, 0x188, 0x189):reject('output-alias:'+hex(lo), lambda: handoff.interval_disjoint(lo, 24, 0x188))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'allocation-spec.json').read_text());decoded = bindings(im, spec)
    paths = [result_path(decoded, spec, name) for name in CASES];consumers = consumer_paths(decoded)
    rejected = controls(im, spec, decoded)
    cases = [((0, 0, 0), 'fits', 0), ((0, 0, 1), 'fresh_allocator', 8), ((0, 0, 8), 'fresh_allocator', 8),
             ((0, 0, 9), 'fresh_allocator', 9), ((8, 3, 5), 'fits', 8), ((8, 3, 6), 'existing_allocator', 16),
             ((0, 0, LIMIT), 'fresh_allocator', LIMIT), ((0, 0, LIMIT+1), 'size_high_bit_error', LIMIT+1),
             ((0, 0, U64), 'size_high_bit_error', U64),
             ((LIMIT//2, LIMIT//2, 1), 'existing_allocator', LIMIT-1),
             ((LIMIT//2+1, LIMIT//2+1, 1), 'size_high_bit_error', LIMIT+1),
             ((8, 8, U64-8), 'size_high_bit_error', U64), ((8, 8, U64-7), 'add_carry_error', None),
             ((LIMIT, LIMIT, 0), 'fits', LIMIT), ((LIMIT, LIMIT, 1), 'size_high_bit_error', U64-1)]
    examples = []
    for args, route, capacity in cases:
        actual = growth_admission(*args)
        base.require(actual['route'] == route and actual.get('requested_capacity') == capacity, 'Growth size-boundary worksheet')
        examples.append({'capacity': args[0], 'length': args[1], 'request': args[2], **actual})
    # Grow's result slot is below its own RBP. Header is the formatter's retained local object.
    handoff.interval_disjoint(-0x1d0, 24, 0x188)
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
            if start == GROW:base.require(p.stdout == (base.PACKET/('format/grow.'+suffix+'.objdump')).read_bytes(), 'Prior grow export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
              'explicit_stores': spec['stores'], 'result_paths': paths, 'consumer_prefixes': consumers,
              'growth_scalar_boundaries': examples, 'diagnostic_data_window': spec['diagnostic_data_window'],
              'manual_call_abi': {'result_inputs': 'O=RDI, old_capacity=RSI, old_buffer=RDX, requested_size=RCX',
                 'fresh_call': '0x141e125 -> 0x64df480 -> 0x6355830; RDI=requested_size',
                 'existing_call': '0x141e106 -> 0x64df588 -> 0x635a7a0; RDI=old_buffer, RSI=requested_size',
                 'grow_output': 'G_RBP-0x28, 24-byte envelope; no old-buffer payload write in this wrapper',
                 'grow_header': 'OS-0x1d0 retained formatter header; direct writes +8 then +0 only after result tag !=1',
                 'size_error': 'word8=0 selects 0x141e280; incoming RSI overwritten with 35 before first diagnostic dispatch',
                 'allocation_error': 'word8=1 selects 0x141e251; (1,size) swapped to (size,1) before 0x64df6a8'},
              'negative_and_scope_controls': rejected, 'normalization_masks': [],
              'limitations': ['Six static result paths; valid memory, ABI, nonaliasing and selected allocator returns are premises',
                 'QWORD result +16 is unwritten on high-bit size rejection; do not invent a fully initialized result type',
                 'Allocator contents preservation, freeing, failure ownership, alignment, TLS/global writes and return provenance remain open',
                 'Diagnostic prefixes end at calls; no panic/abort/unwind/noreturn behavior is claimed',
                 'No captured execution/emulation, reconstructed Rust, independent-agent review or acceptance gate']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'fdes': len(ranges), 'bytes': sum(r['bytes'] for r in ranges), 'instructions': sum(r['instructions'] for r in ranges),
                      'result_paths': len(paths), 'consumer_prefixes': len(consumers), 'explicit_stores': len(spec['stores']),
                      'growth_boundary_examples': len(examples), 'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
