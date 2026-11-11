#!/usr/bin/env python3
"""Node115 outer handoff write/call census; static evidence, no CPU emulation."""
import argparse
import copy
import itertools
import json
from pathlib import Path
import platform
import subprocess
import sys

import capstone
import collect as base
import cleanup
import helpers

OUTER = 0x2ad5980
CONTEXT = 0x2d4d540
TUPLE = 0x1629690
START = 0x2ad5e5e
STOPS = (0x2ad6325, 0x2ad633a)
CALLS = (0x2ad60e9, 0x2ad6128, 0x2ad6140, 0x2ad6196, 0x2ad629a, 0x2ad62da, 0x2ad6307)


def explicit_stores(ins):
    result = {}
    for i in ins:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:
            continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp'):
            continue
        base.require(i.mnemonic in ('mov', 'movups', 'movaps', 'lock inc', 'lock cmpxchg', 'lock xadd'),
                     'Unclassified explicit destination')
        result[i.address] = i
    return result


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Handoff target')
    decoded = {}
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == start and f['end'] == end]) == 1, 'Handoff FDE')
        raw = im.read(start, end-start)
        base.require(base.sha(raw) == r['sha256'], 'Handoff full-body hash')
        decoded[start] = list(helpers.decoder().disasm(raw, start))
        base.require(sum(i.size for i in decoded[start]) == end-start, 'Handoff complete decode')
    index = {i.address: i for ins in decoded.values() for i in ins}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        start, end = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(end-start == len(raw) and start in bounds and end in bounds, 'Anchor boundaries')
        base.require(im.read(start, len(raw)) == raw, 'Anchor bytes '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Unique relocation')
        if r['symbol']:
            base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Imported name')
    actual = {}
    for start, ins in decoded.items():
        actual.update(explicit_stores([i for i in ins if start != OUTER or START <= i.address < 0x2ad633f]))
    rows = {int(r['va'], 16): r for r in spec['stores']}
    base.require(len(rows) == len(spec['stores']) and rows.keys() == actual.keys(), 'Handoff store census')
    for va, i in actual.items():
        r = rows[va]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.operands[0].size == r['width']
                     and i.mnemonic+' '+i.op_str == r['instruction'], 'Store bytes/width')
    for va, target in ((0x2ad60e9, CONTEXT), (STOPS[0], 0x2b3f300), (STOPS[1], 0x2b403a0)):
        i = index[va]
        base.require(i.mnemonic == 'call' and i.operands[0].type == capstone.CS_OP_IMM
                     and i.operands[0].imm == target, 'Selected direct call')
    for c in spec['copies']:
        i = index[int(c['length_va'], 16)]
        base.require(i.mnemonic == 'mov' and i.op_str == 'edx, '+hex(c['length']), 'Copy length')
        i = index[int(c['call'], 16)];op = i.operands[0]
        base.require(i.mnemonic == 'call', 'Copy call opcode')
        if i.address in (0x2ad6128, 0x2ad6140):
            load = index[0x2ad611c];source = load.operands[1]
            base.require(op.type == capstone.CS_OP_REG and i.reg_name(op.reg) == 'r12'
                         and load.op_str.startswith('r12, ') and load.reg_name(source.mem.base) == 'rip'
                         and load.address+load.size+source.mem.disp == 0x64df508, 'Retained memcpy binding')
        else:
            base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip'
                         and i.address+i.size+op.mem.disp == 0x64df508, 'RIP memcpy binding')
    # Preserve the prior packet. Revalidate just the reused owner identity and
    # its five instruction pins; do not inherit its whole packet or its prose.
    old_path = base.ROOT/'research/work-items/RE-005-node115-spawn-payload-fields/records.json'
    old = json.loads(old_path.read_text());owner = old['owners']['direct540']
    base.require(owner['start'] == hex(CONTEXT) and owner['end'] == '0x2d4d749'
                 and owner['sha256'] == base.sha(im.read(CONTEXT, 521)), 'Reused helper owner')
    for va, raw in old['pins']['direct540'].items():
        base.require(im.read(int(va, 16), len(bytes.fromhex(raw))).hex() == raw, 'Reused helper pin')
    return decoded


def selected_path(decoded, skip_first, skip_second, executor_b, override=None):
    base.require(all(type(v) is bool for v in (skip_first, skip_second, executor_b)), 'Boolean path selectors')
    guards = [0x2ad5e69, 0x2ad5e7a, 0x2ad5ede, 0x2ad608a, 0x2ad6109]
    if not skip_first:
        guards += [0x2ad5e97, 0x2ad5ead, 0x2ad5ec3]
    if not skip_second:
        guards += [0x2ad5eff, 0x2ad5f10, 0x2ad5f29, 0x2ad5f3b, 0x2ad5f67, 0x2ad5f79]
    decisions = {va: False for va in guards}
    decisions.update({0x2ad5e8a: skip_first, 0x2ad5eee: skip_second, 0x2ad6060: True,
                      0x2ad60a7: False, 0x2ad60f8: False, 0x2ad615d: False,
                      0x2ad61d8: True, 0x2ad62b2: False, 0x2ad62e4: False, 0x2ad6318: executor_b})
    if override:
        decisions.update(override)
    return cleanup.walk(decoded[OUTER], START, STOPS[int(executor_b)], decisions, CALLS)


def interval_disjoint(lo, width, field):
    base.require(all(type(v) is int for v in (lo, width, field)) and width > 0, 'Invalid interval')
    base.require(lo+width <= field or lo >= field+2, 'Tracked word overlap')


def write_worksheet(rows):
    out = []
    for r in rows:
        va = int(r['va'], 16)
        field = 0x188 if va < 0x2ad6140 else 0x220 if va < 0x2ad6196 else 0x3420 if va < 0x2ad6307 else 0x9420
        if r['region'] == 'stack':
            interval_disjoint(r['offset'], r['width'], field);condition = 'disjoint relative stack intervals'
        else:
            base.require(r['region'] in ('pointee', 'TLS', 'global'), 'Unexpected selected region')
            condition = 'requires disjoint effective addresses/ownership; no alias proof'
        out.append({**r, 'primary_field_before': hex(field), 'preservation': condition})
    return out


def copy_worksheet(copies):
    field = 0x188;out = []
    for c in copies:
        src, dst, n = c['source'], c['destination'], c['length']
        base.require(all(type(v) is int and v >= 0 for v in (src, dst, n)) and n > 0, 'Invalid copy interval')
        base.require(src+n <= dst or dst+n <= src, 'Overlapping memcpy intervals')
        copied = dst+field-src if src <= field and field+2 <= src+n else None
        if c['move_primary']:
            base.require(copied is not None, 'Copy omits tracked word')
        else:
            interval_disjoint(dst, n, field)
        out.append({**c, 'primary_before': hex(field), 'copied_word': hex(copied) if copied is not None else None,
                    'primary_after': hex(copied) if c['move_primary'] else hex(field)})
        if c['move_primary']:
            field = copied
    base.require(field == 0x9420, 'Wrong handoff field endpoint')
    return out


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted invalid handoff evidence: '+name)
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
    for kind in ('missing', 'width'):
        bad = copy.deepcopy(spec)
        if kind == 'missing':bad['stores'].pop()
        else:bad['stores'][0]['width'] = 1
        reject('store-census:'+kind, lambda: bindings(im, bad))
    for va, taken in ((0x2ad5e69, True), (0x2ad6060, False), (0x2ad60a7, True), (0x2ad60f8, True),
                      (0x2ad615d, True), (0x2ad61d8, False), (0x2ad62b2, True), (0x2ad62e4, True)):
        reject('excluded-edge:'+hex(va), lambda: selected_path(decoded, False, False, False, {va: taken}))
    for c in spec['copies']:
        bad = copy.deepcopy(spec['copies'])
        next(x for x in bad if x['call'] == c['call'])['destination'] = c['source']
        reject('overlapping-copy:'+c['call'], lambda: copy_worksheet(bad))
        if c['move_primary']:
            bad = copy.deepcopy(spec['copies'])
            # Drop only the tracked word's second byte, per the retained route.
            before = {0x2ad6140: 0x188, 0x2ad6196: 0x220, 0x2ad6307: 0x3420}[int(c['call'], 16)]
            next(x for x in bad if x['call'] == c['call'])['length'] = before-c['source']+1
            reject('truncated-field-copy:'+c['call'], lambda: copy_worksheet(bad))
    for field in (0x188, 0x220, 0x3420, 0x9420):
        interval_disjoint(field-8, 8, field);interval_disjoint(field+2, 8, field)
        for lo in (field-7, field, field+1):
            reject('interval-overlap:'+str((field, lo)), lambda: interval_disjoint(lo, 8, field))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'handoff-spec.json').read_text());decoded = bindings(im, spec)
    paths = [];union = set()
    for a, b, executor_b in itertools.product((False, True), repeat=3):
        ins = selected_path(decoded, a, b, executor_b);visited = {i.address for i in ins};union |= visited
        rows = [r for r in spec['stores'] if int(r['va'], 16) in visited]
        paths.append({'skip_group_at_R_178_eq_4': a, 'skip_group_at_R_e8_nonzero': b,
                      'executor': 'B' if executor_b else 'A', 'stop_before_call': hex(STOPS[int(executor_b)]),
                      'instructions': [hex(i.address) for i in ins], 'calls_before_executor': [hex(v) for v in CALLS],
                      'writes': write_worksheet(rows)})
    rejected = controls(im, spec, decoded);copy_rows = copy_worksheet(spec['copies'])
    # The deeper helper demonstrably writes the first 12 bytes of the caller's
    # OS+0x6388 scratch argument. That is distinct from the tracked word at +0x188.
    tuple_stores = [r for r in spec['stores'] if r['region'] == 'tuple_output']
    base.require([(r['offset'], r['width']) for r in tuple_stores] == [(0, 4), (4, 4), (8, 4)], 'Tuple output extent')
    for r in tuple_stores:interval_disjoint(0x6388+r['offset'], r['width'], 0x188)
    out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16);ins = decoded[start]
        fde, = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        row = {**r, 'fde': hex(fde['fde']), 'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
               'file_offset': hex(im.offset(start, end-start)), 'bytes': end-start, 'instructions': len(ins), 'native': [],
               'transfers': helpers.transfers(im, ins)}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={start}', f'--stop-address={end}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, start, end);splits = base.compare_boundaries(parsed, ins)
            if start == OUTER:
                base.require(base.compare_prior_native(p.stdout, (base.PACKET/('factory/body-2ad5980.'+suffix+'.objdump')).read_bytes()), 'Prior outer native bytes differ')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    reference = base.ROOT/'research/work-items/RE-005-node115-spawn-payload-fields'
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
              'lexical_explicit_stores': spec['stores'], 'selected_paths': paths, 'copy_worksheet': copy_rows,
              'selected_outer_unique_stores': len([r for r in spec['stores'] if int(r['va'], 16) in union]),
              'reused_reference': {'files': {f.relative_to(base.ROOT).as_posix(): base.sha(f.read_bytes()) for f in
                                           (reference/'records.json', reference/'MANIFEST.sha256')},
                                   'revalidated_scope': 'direct540 owner hash and five byte pins only; not whole packet replay'},
              'tuple_write_join': {'call': '0x2d4d564', 'slot': '0x64e0990', 'target': hex(TUPLE),
                                   'outer_destination': 'OS+[0x6388,0x6394)', 'tracked_word_at_call': 'OS+[0x188,0x18a)',
                                   'normal_output_stores': tuple_stores},
              'negative_and_scope_controls': rejected, 'normalization_masks': [],
              'limitations': ['Manual selected CFG/coordinate worksheets, not execution or alias analysis',
                              'Selected nontrapping increments, first lock/unlock CAS success, first global-token iteration nonzero, TLS flag 1 and admitted executor branch',
                              'Ordinary memcpy/ABI behavior and no concurrent/asynchronous mutation; separate state/pointee/global/TLS/stack storage',
                              'Context-helper and tuple-writer callees remain unclosed; direct store census is not a transitive no-write proof',
                              'Skipped optional groups do not establish initialized contents for all copied bytes',
                              'No scheduler invocation, resource-lifetime, Rust equivalence or full-scope gate']}
    result['native_prior_transcript_comparisons'] = list(base._NATIVE_PRIOR_COMPARISONS)
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'fdes': len(ranges), 'bytes': sum(r['bytes'] for r in ranges), 'instructions': sum(r['instructions'] for r in ranges),
                      'paths': len(paths), 'lexical_stores': len(spec['stores']), 'selected_outer_unique_stores': result['selected_outer_unique_stores'],
                      'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
