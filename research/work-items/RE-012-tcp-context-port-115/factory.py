#!/usr/bin/env python3
"""Static accept-to-executor field joins for the sole node #115 target."""
import argparse
import copy
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

import capstone
import collect as base

MEMCPY = 0x64df508
ENDPOINTS = {
    'accept': (('accept_stack', 0x1a0), ('accept_output', 0x90)),
    'outer': (('outer_stack', 0x400), ('outer_stack', 0x9420)),
    'executor_a': (('child_input', 0x90), ('allocation_a', 0xc8)),
    'executor_b': (('child_input', 0x90), ('allocation_b', 0xc8)),
}


def decoder():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Factory spec target')
    for anchor in spec['anchors']:
        raw = bytes.fromhex(anchor['bytes_hex'])
        base.require(im.read(int(anchor['va'], 16), len(raw)) == raw, 'Factory anchor: ' + anchor['name'])
    for row in spec['relocations']:
        base.require(im.relocs.get(int(row['slot'], 16)) == [(8, int(row['target'], 16))],
                     'Factory unique RELATIVE relocation')
    imports = im.relocs.get(MEMCPY, [])
    base.require(len(imports) == 1, 'Factory unique memcpy import')
    info, addend = imports[0]
    base.require(info & 0xffffffff == 6 and addend == 0 and im.symbol(info >> 32) == 'memcpy',
                 'Factory memcpy kind/name/addend')
    for row in spec['direct_calls']:
        va = int(row['va'], 16)
        raw = im.read(va, 5)
        base.require(raw[:1] == b'\xe8' and va + 5 + struct.unpack('<i', raw[1:])[0] == int(row['target'], 16),
                     'Factory direct call target')
    md = decoder()
    for route in spec['routes']:
        for edge in route['edges']:
            va = int(edge['length_va'], 16)
            size = next(md.disasm(im.read(va, 15), va))
            base.require(size.mnemonic == 'mov' and size.op_str == 'edx, ' + hex(edge['length']), 'Copy length')
            va = int(edge['call_va'], 16)
            call = next(md.disasm(im.read(va, 15), va))
            base.require(call.mnemonic == 'call', 'Factory copy call')
            bound = edge['binding']
            base.require(int(bound['slot'], 16) == MEMCPY, 'Annotated memcpy slot')
            op = call.operands[0]
            if bound['kind'] == 'rip':
                base.require(op.type == capstone.CS_OP_MEM and call.reg_name(op.mem.base) == 'rip'
                             and va + call.size + op.mem.disp == MEMCPY, 'RIP memcpy call')
            else:
                base.require(bound['kind'] == 'register' and op.type == capstone.CS_OP_REG
                             and call.reg_name(op.reg) == bound['register'], 'Retained copy register')
                va = int(bound['load_va'], 16)
                load = next(md.disasm(im.read(va, 15), va))
                base.require(load.mnemonic == 'mov' and load.operands[0].type == capstone.CS_OP_REG
                             and load.reg_name(load.operands[0].reg) == bound['register']
                             and load.operands[1].type == capstone.CS_OP_MEM
                             and load.reg_name(load.operands[1].mem.base) == 'rip'
                             and va + load.size + load.operands[1].mem.disp == MEMCPY, 'Selected memcpy load')


def worksheet(route):
    """Range algebra on manually checked coordinates; not instruction emulation."""
    point = lambda p: (p['space'], int(p['offset'], 16))
    expected_start, expected_end = ENDPOINTS[route['name']]
    current = point(route['initial'])
    width = route['width']
    base.require(current == expected_start and point(route['final']) == expected_end and width == 2,
                 'Factory worksheet endpoints/width')
    rows = []
    for edge in route['edges']:
        ss, so = point(edge['source']); ds, do = point(edge['destination'])
        length = edge['length']; delta = current[1] - so
        base.require(current[0] == ss and 0 <= delta and delta + width <= length, 'Word outside copy source')
        base.require(ss != ds or so + length <= do or do + length <= so, 'Overlapping memcpy ranges')
        after = (ds, do + delta)
        rows.append({'call_va': edge['call_va'], 'length': length, 'relative_offset': hex(delta),
                     'before': {'space': current[0], 'offset': hex(current[1])},
                     'after': {'space': after[0], 'offset': hex(after[1])}, 'width': width})
        current = after
    base.require(current == expected_end, 'Wrong factory field endpoint')
    return rows


def corruption_controls(im, spec):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted corrupt factory evidence: ' + name)
    for anchor in spec['anchors']:
        va = int(anchor['va'], 16) + len(bytes.fromhex(anchor['bytes_hex'])) - 1
        bad = copy.copy(im)
        def read(start, count, va=va):
            raw = bytearray(im.read(start, count))
            if start <= va < start + count:
                raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        reject('anchor-byte:' + anchor['name'], lambda: bindings(bad, spec))
    for slot in [MEMCPY, *[int(r['slot'], 16) for r in spec['relocations']]]:
        bad = copy.copy(im); bad.relocs = dict(im.relocs)
        bad.relocs[slot] = im.relocs[slot] * 2
        reject('duplicate-relocation:' + hex(slot), lambda: bindings(bad, spec))
        info, addend = im.relocs[slot][0]
        bad.relocs[slot] = [(info, addend+1)]
        reject('changed-relocation:' + hex(slot), lambda: bindings(bad, spec))
    for route in spec['routes']:
        rows = worksheet(route)
        for index, row in enumerate(rows):
            bad = copy.deepcopy(route)
            bad['edges'][index]['length'] = int(row['relative_offset'], 16) + 1
            reject('interval-truncated-word:' + route['name'] + ':' + str(index+1), lambda: worksheet(bad))
        bad = copy.deepcopy(route)
        last = bad['edges'][-1]['destination']
        last['offset'] = hex(int(last['offset'], 16)+1)
        reject('interval-shifted-endpoint:' + route['name'], lambda: worksheet(bad))
    reject('wrong-target', lambda: base.authenticate(b'wrong target'))
    # Digest guard on a full-size changed input, separate from bypassed in-memory pins.
    changed = bytearray(im.data); changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT / 'artifacts/node/115/hl-node').read_bytes()
    base.authenticate(data)
    im = base.Image(data)
    spec = json.loads((base.PACKET / 'factory-spec.json').read_text())
    bindings(im, spec)
    rejected = corruption_controls(im, spec)
    out.mkdir(parents=True, exist_ok=False)
    md = decoder(); records = []; commands = []; covered = set()
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ['objdump', 'llvm-objdump']:
        versions[tool] = subprocess.check_output([tool, '--version']).decode()
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16)
        fdes = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        base.require(len(fdes) == 1, 'Factory FDE')
        body = im.read(start, end-start)
        base.require(base.sha(body) == r['sha256'], 'Factory body hash')
        ins = list(md.disasm(body, start))
        base.require(sum(i.size for i in ins) == len(body), 'Factory full decode')
        bounds = {i.address for i in ins} | {end}
        for anchor in spec['anchors']:
            va = int(anchor['va'], 16)
            if start <= va < end:
                base.require(va in bounds and va + len(bytes.fromhex(anchor['bytes_hex'])) in bounds, 'Factory pin boundary')
                covered.add(anchor['name'])
        row = {**r, 'fde': hex(fdes[0]['fde']), 'bytes': len(body), 'instructions': len(ins), 'native': []}
        (out / (r['name'] + '.capstone.txt')).write_text('\n'.join(
            f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins) + '\n', encoding='utf-8', newline='\n')
        for tool, options, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *options, f'--start-address={start}', f'--stop-address={end}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True)
            name = r['name'] + '.' + suffix + '.objdump'
            (out / name).write_bytes(p.stdout); (out / (name + '.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, start, end)
            split = base.compare_boundaries(parsed, ins)
            prior = r['prior_native_directory']
            if prior:
                base.require(base.compare_prior_native(p.stdout, (base.PACKET / prior / name).read_bytes()), 'Prior factory native export changed')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed),
                                  'lock_prefix_splits': split, 'prior_raw_export_equal': bool(prior) and base._NATIVE_PRIOR_COMPARISONS[-1]['raw_equal']})
            commands.append(args)
        records.append(row)
    base.require(len(covered) == len(spec['anchors']), 'Factory anchor coverage')
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': records,
              'copy_worksheets': {r['name']: worksheet(r) for r in spec['routes']},
              'manual_coordinate_joins': spec['joins'], 'selected_direct_calls': spec['direct_calls'],
              'selected_relative_relocations': spec['relocations'], 'anchor_spans': len(spec['anchors']),
              'negative_controls_rejected': rejected, 'normalization_masks': [], 'assumptions': spec['assumptions'],
              'not_established': ['Complete helper/alias mutation closure', 'Actual scheduling or execution',
                  'All legal resume/error/unwind states', 'Twin large B initial origin',
                  'Typed Rust object or whole-node reconstruction']}
    result['native_prior_transcript_comparisons'] = list(base._NATIVE_PRIOR_COMPARISONS)
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'copy_calls': sum(len(r['edges']) for r in spec['routes']), 'anchors': len(spec['anchors']),
                      'controls_rejected': len(rejected), 'exported_bytes': sum(r['bytes'] for r in records),
                      'instructions': sum(r['instructions'] for r in records), 'selected_executor_paths': 2}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    collect(parser.parse_args().out)
