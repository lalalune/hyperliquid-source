#!/usr/bin/env python3
"""Static node115 lookup/result-width and classifier join. No target execution."""
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

LOOKUP = 0x1546570
CLASSIFIER = 0x1567ad0
CALLER = 0x2d4d540
MIN = 1 << 63
CASES = {
    'plain_match': ({0x1546589: True, 0x154664a: False}, (), True),
    'plain_change': ({0x1546589: True, 0x154664a: True}, (0x15466aa,), False),
    'tagged_match': ({0x1546589: False, 0x15465a3: False, 0x15465ac: True}, (0x154659a,), True),
    'tagged_tag_change': ({0x1546589: False, 0x15465a3: True}, (0x154659a, 0x154661a), False),
    'tagged_key_change': ({0x1546589: False, 0x15465a3: False, 0x15465ac: False}, (0x154659a, 0x154661a), False),
}


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Lookup target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1, 'Lookup exact FDE')
        raw = im.read(lo, hi-lo);base.require(base.sha(raw) == r['sha256'], 'Lookup body hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Lookup full decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(hi-lo == len(raw) and lo in bounds and hi in bounds, 'Lookup anchor bounds')
        base.require(im.read(lo, len(raw)) == raw, 'Lookup anchor '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Lookup relocation')
        if r['symbol']:base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Lookup import')
    actual = {}
    for start in (LOOKUP, CLASSIFIER):actual.update(handoff.explicit_stores(decoded[start]))
    rows = {int(r['va'], 16): r for r in spec['stores']}
    base.require(len(rows) == len(spec['stores']) and actual.keys() == rows.keys(), 'Lookup store census')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and op.size == r['width']
                     and i.mnemonic+' '+i.op_str == r['instruction'], 'Lookup store bytes/width')
        base.require(i.reg_name(op.mem.base) == ('rbx' if r['region'] == 'output' else 'rsp')
                     and op.mem.disp == r['offset'] and r['region'] in ('output', 'stack'), 'Store destination annotation')
    for va, slot in ((0x2d4d5b0, 0x64e0f80), (0x154659a, 0x64e0f58),
                     (0x154661a, 0x64df6e8), (0x15466aa, 0x64df6e8)):
        i = index[va];op = i.operands[0]
        base.require(i.mnemonic == 'call' and op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip'
                     and i.address+i.size+op.mem.disp == slot, 'Lookup call-slot binding')
    return decoded


def output_mask(rows):
    offsets = set()
    for r in rows:
        if r['region'] != 'output':continue
        base.require(0 <= r['offset'] < r['offset']+r['width'] <= 32, 'Output store exceeds retained envelope')
        offsets.update(range(r['offset'], r['offset']+r['width']))
    return sorted(offsets)


def path(decoded, spec, name, override=None):
    decisions, calls, sentinel = CASES[name];decisions = dict(decisions)
    if override:decisions.update(override)
    ins = cleanup.walk(decoded[LOOKUP], LOOKUP, 0x15466f2, decisions, calls)
    base.require(next(i for i in decoded[LOOKUP] if i.address == 0x15466f2).mnemonic == 'ret', 'Lookup return')
    visited = {i.address for i in ins};rows = [r for r in spec['stores'] if int(r['va'], 16) in visited]
    mask = output_mask(rows)
    expected = list(range(8, 16)) if sentinel else [v for v in range(32) if name != 'plain_change' or v != 5]
    base.require(mask == expected, 'Lookup path output mask')
    return {'name': name, 'sentinel': sentinel, 'instruction_vas_before_ret': [hex(i.address) for i in ins],
            'calls': [hex(v) for v in calls], 'explicit_stores': rows, 'written_output_byte_offsets': mask,
            'unwritten_output_byte_offsets': [v for v in range(32) if v not in mask]}


def classifier_path(decoded, override=None):
    decisions = {0x1567ade: False, 0x1567af9: False}
    if override:decisions.update(override)
    return cleanup.walk(decoded[CLASSIFIER], CLASSIFIER, 0x1567b00, decisions, ())


def classifier_projection(value):
    """Scalar interpretation of pinned operands, not instruction execution."""
    base.require(type(value) is int and 0 <= value < 90000, 'Outside classifier normal-return domain')
    raw = (value*0x91a2b3c5) >> 43
    base.require(raw == value//3600 and 0 <= raw <= 24, 'Classifier division relation')
    return raw & 255


def caller_sentinel_paths(decoded):
    out = []
    for context_min in (True, False):
        decisions = {0x2d4d5c1: not context_min}
        decisions[0x2d4d5c6 if context_min else 0x2d4d5ee] = True
        stop = 0x2d4d710 if context_min else 0x2d4d6a5
        ins = cleanup.walk(decoded[CALLER], 0x2d4d5b6, stop, decisions, ())
        # Only the +8 result word is loaded before these chosen endpoints.
        output_reads = []
        for i in ins:
            for op in i.operands[1:]:
                if op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rsp' and 0x50 <= op.mem.disp < 0x70:
                    output_reads.append((i.address, op.mem.disp-0x50, op.size))
        base.require(output_reads == [(0x2d4d5bc, 8, 8)], 'Sentinel consumer read census')
        out.append({'context_word_48_is_signed_min': context_min, 'stop': hex(stop),
                    'stop_kind': 'return' if context_min else 'before_call_0x25f0250',
                    'instructions': [hex(i.address) for i in ins], 'calls_before_stop': 0,
                    'output_reads': [{'va': hex(v), 'offset': off, 'width': width} for v, off, width in output_reads]})
    return out


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:fn()
        except ValueError:rejected.append(name)
        else:raise ValueError('Accepted invalid lookup evidence: '+name)
    def mutate(va):
        bad = copy.copy(im)
        def read(start, count):
            raw = bytearray(im.read(start, count))
            if start <= va < start+count:raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        return bad
    for a in spec['anchors']:
        reject('anchor-byte:'+a['name'], lambda: bindings(mutate(int(a['end'], 16)-1), spec))
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
    for kind in ('missing', 'width', 'destination'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':bad['stores'].pop()
        elif kind == 'width':bad['stores'][0]['width'] += 1
        else:bad['stores'][0]['offset'] += 1
        reject('store-census:'+kind, lambda: bindings(im, bad))
    for name, va, decision in [('plain_match', 0x154664a, True), ('plain_change', 0x154664a, False),
                              ('tagged_match', 0x15465ac, False), ('tagged_tag_change', 0x15465a3, False),
                              ('tagged_key_change', 0x15465ac, True)]:
        reject('changed-result-path:'+name, lambda: path(decoded, spec, name, {va: decision}))
    for va in (0x1567ade, 0x1567af9):
        reject('classifier-panic-edge:'+hex(va), lambda: classifier_path(decoded, {va: True}))
    for value in (-1, 90000, 921599, 921600, (1 << 32)-1, 1 << 32):
        reject('classifier-domain:'+str(value), lambda: classifier_projection(value))
    for off, width in ((-1, 8), (31, 2)):
        reject('output-envelope:'+str((off, width)), lambda: output_mask([{'region': 'output', 'offset': off, 'width': width}]))
    for lo in (0x169, 0x188, 0x189):
        reject('output-alias:'+hex(lo), lambda: handoff.interval_disjoint(lo, 32, 0x188))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'lookup-spec.json').read_text());decoded = bindings(im, spec)
    paths = [path(decoded, spec, name) for name in CASES]
    cpath = classifier_path(decoded);consumers = caller_sentinel_paths(decoded)
    counts = [0]*25
    for value in range(90000):counts[classifier_projection(value)] += 1
    base.require(counts == [3600]*25, 'Classifier exhaustive normal-domain buckets')
    rejected = controls(im, spec, decoded)
    # Cmp 0,x has signed-subtraction overflow exactly for the signed minimum.
    examples = []
    for value in (0, 1, MIN-1, MIN, MIN+1, (1 << 64)-1):
        negated = (-value) & ((1 << 64)-1);overflow = bool(value & negated & MIN)
        base.require(overflow == (value == MIN), 'Caller overflow worksheet')
        examples.append({'context_word': hex(value), 'overflow': overflow})
    handoff.interval_disjoint(-0xa0, 32, 0x188)
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
            if start == CALLER:
                base.require(p.stdout == (base.PACKET/('handoff/context_helper.'+suffix+'.objdump')).read_bytes(), 'Prior caller export differs')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
              'lookup_and_classifier_explicit_stores': spec['stores'], 'lookup_paths': paths,
              'classifier': {'normal_path_before_ret': [hex(i.address) for i in cpath], 'normal_domain_count': 90000,
                             'bucket_populations': counts, 'projection': '((u32 * 0x91a2b3c5) >> 43) & 255 == u32 // 3600 on [0,90000)',
                             'first_reject_threshold': 921600, 'second_reject_threshold': 90000,
                             'no_clock_unit_or_timezone_claim': True},
              'sentinel_consumer_paths': consumers, 'caller_overflow_worksheet': examples,
              'manual_stack_join': {'caller_frame': 'CS = OS - 0xf0', 'lookup_output': 'CS+0x50 = OS-0xa0, envelope 32 bytes',
                                    'lookup_input': 'CS = OS-0xf0', 'lookup_context': 'H+0x18',
                                    'lookup_stack': 'LS = CS-0x90 = OS-0x180', 'tracked_word': 'OS+[0x188,0x18a)'},
              'negative_and_scope_controls': rejected, 'normalization_masks': [],
              'limitations': ['Selected normal calls and manually joined ABI/stack coordinates; no alias or lifetime proof',
                              'Sentinel writes only output +8..+16; plain-change output byte +5 is not written, yet the nonsentinel caller reads it',
                              'Output +6/+7 come from low bytes of an argument pointer; no semantic field type is assigned',
                              'Formatter/callback/allocation and classifier diagnostic paths remain unclosed',
                              'Matching output does not imply the parent context helper returns without other side effects',
                              'No captured execution, Rust implementation, independent-agent review or acceptance gate']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'fdes': len(ranges), 'bytes': sum(r['bytes'] for r in ranges), 'instructions': sum(r['instructions'] for r in ranges),
                      'lookup_paths': len(paths), 'explicit_stores': len(spec['stores']), 'classifier_normal_inputs': 90000,
                      'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
