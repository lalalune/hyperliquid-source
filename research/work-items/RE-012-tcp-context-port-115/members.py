#!/usr/bin/env python3
"""Static selected-copy relation and explicit operand inventory for node #115."""
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

PARENTS = [0x2accee0, 0x2ad0db0]
MEMCPY = 0x64df508
CLOSE = 0x64dfe78
CLEANUP = 0x2ab9750


def decoder():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Spec target')
    for a in spec['anchors']:
        raw = bytes.fromhex(a['bytes_hex'])
        base.require(im.read(int(a['va'], 16), len(raw)) == raw, 'Member anchor: ' + a['name'])
    for slot, symbol in [(MEMCPY, 'memcpy'), (CLOSE, 'close')]:
        rows = im.relocs.get(slot, [])
        base.require(len(rows) == 1, 'Unique member import')
        info, addend = rows[0]
        base.require(info & 0xffffffff == 6 and addend == 0 and im.symbol(info >> 32) == symbol,
                     'Member import name/kind/addend')
    for row in spec['dispatch']:
        table = int(row['base'], 16)
        displacement = struct.unpack('<i', im.read(table, 4))[0]
        base.require(table + displacement == int(row['destination'], 16), 'Member state-zero dispatch')
    md = decoder()
    for route in spec['routes']:
        for edge in route['edges']:
            va = int(edge['length_instruction_va'], 16)
            ins = next(md.disasm(im.read(va, 15), va))
            base.require(ins.mnemonic == 'mov' and ins.op_str == 'edx, ' + hex(edge['length']),
                         'Copy length annotation differs from actual instruction')
            va = int(edge['call_va'], 16)
            ins = next(md.disasm(im.read(va, 15), va))
            base.require(ins.mnemonic == 'call', 'Selected copy call')
            binding = edge['callee_binding']
            if binding['kind'] == 'rip-relative':
                op = ins.operands[0]
                base.require(op.type == capstone.CS_OP_MEM and ins.reg_name(op.mem.base) == 'rip'
                             and ins.address + ins.size + op.mem.disp == MEMCPY, 'Direct memcpy slot')
            else:
                base.require(ins.operands[0].type == capstone.CS_OP_REG
                             and ins.reg_name(ins.operands[0].reg) == binding['register'], 'Copy call register')
                va = int(binding['load_va'], 16)
                load = next(md.disasm(im.read(va, 15), va))
                base.require(load.mnemonic == 'mov' and load.operands[0].type == capstone.CS_OP_REG
                             and load.reg_name(load.operands[0].reg) == binding['register']
                             and load.operands[1].type == capstone.CS_OP_MEM
                             and load.reg_name(load.operands[1].mem.base) == 'rip'
                             and va + load.size + load.operands[1].mem.disp == MEMCPY, 'Retained memcpy load')


def worksheet(route):
    """Interval algebra on annotated copies; never interprets target instructions."""
    current = (route['initial']['space'], int(route['initial']['offset'], 16))
    width = route['tracked_width']
    rows = []
    for edge in route['edges']:
        src, dst = edge['source'], edge['destination']
        so, do, length = int(src['offset'], 16), int(dst['offset'], 16), edge['length']
        delta = current[1] - so
        base.require(current[0] == src['space'] and 0 <= delta and delta + width <= length,
                     'Tracked word not fully contained in copy source')
        base.require(src['space'] != dst['space'] or do + length <= so or so + length <= do,
                     'Selected memcpy coordinates overlap')
        after = (dst['space'], do + delta)
        rows.append({'call_va': edge['call_va'], 'length': length,
                     'before': {'space': current[0], 'offset': hex(current[1])},
                     'relative_offset': hex(delta),
                     'after': {'space': after[0], 'offset': hex(after[1])}, 'width': width})
        current = after
    want = route['expected_final']
    base.require(current == (want['space'], int(want['offset'], 16)), 'Selected copy endpoint')
    base.require(current == ('P', 0x1118 + 0x90) and width == 2, 'Context field endpoint')
    return rows


def inventory(ins):
    operands, address_sites, cleanup_calls = [], [], []
    for n, i in enumerate(ins):
        for index, op in enumerate(i.operands):
            if op.type != capstone.CS_OP_MEM or i.reg_name(op.mem.base) != 'rbx' or op.mem.index:
                continue
            start, end = op.mem.disp, op.mem.disp + op.size
            if start < 0x11b0 and 0x1118 < end:
                operands.append({'va': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str,
                                 'operand_index': index, 'displacement': hex(start), 'width': op.size,
                                 'address_calculation_only': i.mnemonic == 'lea',
                                 'overlaps_low_word_at_11a8': start < 0x11aa and 0x11a8 < end})
            if i.mnemonic == 'lea' and start == 0x1118:
                address_sites.append({'va': hex(i.address), 'bytes_hex': i.bytes.hex(),
                                      'destination_register': i.reg_name(i.operands[0].reg)})
                if n + 1 < len(ins):
                    nxt = ins[n+1]
                    if nxt.mnemonic == 'call' and nxt.operands[0].type == capstone.CS_OP_IMM and nxt.operands[0].imm == CLEANUP:
                        cleanup_calls.append({'setup_va': hex(i.address), 'call_va': hex(nxt.address),
                                              'target': hex(CLEANUP), 'bytes_hex': nxt.bytes.hex()})
    return {'explicit_rbx_operand_overlap': operands, 'explicit_context_address_sites': address_sites,
            'immediate_cleanup_calls': cleanup_calls,
            'scope': 'Syntactic RBX-plus-constant memory operands and adjacent LEA/call pairs only. LEA does not access memory. No alias, indirect/helper write or whole-CFG liveness closure.'}


def controls(im, spec):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted member corruption: ' + name)
    for a in spec['anchors']:
        va = int(a['va'], 16) + len(bytes.fromhex(a['bytes_hex'])) - 1
        bad = copy.copy(im)
        def read(start, count, va=va):
            raw = bytearray(im.read(start, count))
            if start <= va < start + count:
                raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        reject('byte:' + a['name'], lambda: bindings(bad, spec))
    for d in spec['dispatch']:
        va = int(d['base'], 16)
        bad = copy.copy(im)
        def read(start, count, va=va):
            raw = bytearray(im.read(start, count))
            if start <= va < start + count:
                raw[va-start] ^= 1
            return bytes(raw)
        bad.read = read
        reject('dispatch:' + hex(va), lambda: bindings(bad, spec))
    for slot in [MEMCPY, CLOSE]:
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
            # This interval-only counterfactual carries one byte but loses the second.
            bad['edges'][index]['length'] = int(row['relative_offset'], 16) + 1
            reject('worksheet-truncated-word:' + route['name'] + ':' + str(index+1), lambda: worksheet(bad))
        bad = copy.deepcopy(route)
        bad['edges'][-1]['destination']['offset'] = '0x10a9'
        reject('worksheet-shifted-endpoint:' + route['name'], lambda: worksheet(bad))
    return rejected


def collect(out):
    data = (base.ROOT / 'artifacts/node/115/hl-node').read_bytes()
    base.authenticate(data)
    im = base.Image(data)
    spec = json.loads((base.PACKET / 'members-spec.json').read_text())
    bindings(im, spec)
    rejected = controls(im, spec)
    out.mkdir(parents=True, exist_ok=False)
    md = decoder(); records = []; commands = []; covered = set(); inventories = {}
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ['objdump', 'llvm-objdump']:
        versions[tool] = subprocess.check_output([tool, '--version']).decode()
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16)
        fdes = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        base.require(len(fdes) == 1, 'Member FDE')
        body = im.read(start, end-start)
        base.require(base.sha(body) == r['sha256'], 'Member body digest')
        ins = list(md.disasm(body, start))
        base.require(sum(i.size for i in ins) == len(body), 'Member full decode')
        bounds = {i.address for i in ins} | {end}
        for a in spec['anchors']:
            va = int(a['va'], 16)
            if start <= va < end:
                base.require(va in bounds and va + len(bytes.fromhex(a['bytes_hex'])) in bounds, 'Member anchor boundary')
                covered.add(a['name'])
        row = {**r, 'fde': hex(fdes[0]['fde']), 'bytes': len(body), 'instructions': len(ins), 'native': []}
        if start in PARENTS:
            inv = inventory(ins)
            base.require(len(inv['explicit_context_address_sites']) == 8 and len(inv['immediate_cleanup_calls']) == 5,
                         'Context-address/cleanup site inventory changed')
            base.require(not any(o['overlaps_low_word_at_11a8'] for o in inv['explicit_rbx_operand_overlap']),
                         'New direct low-word operand')
            inventories[hex(start)] = inv
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
                base.require(base.compare_prior_native(p.stdout, (base.PACKET / prior / name).read_bytes()), 'Prior full native export changed')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': split,
                                  'prior_raw_export_equal': bool(prior) and base._NATIVE_PRIOR_COMPARISONS[-1]['raw_equal']})
            commands.append(args)
        records.append(row)
    base.require(len(covered) == len(spec['anchors']), 'Member pin coverage')
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': records,
              'copy_worksheets': {r['name']: worksheet(r) for r in spec['routes']},
              'explicit_operand_inventories': inventories, 'anchor_spans': len(spec['anchors']),
              'negative_controls_rejected': rejected, 'normalization_masks': [], 'assumptions': spec['assumptions'],
              'not_established': ['All intervening helper effects and aliases', 'All legal resume/error/unwind paths',
                  'Caller construction of the initial context', 'Universal immutable field or complete Rust layout',
                  'CPU behavior, source-build equivalence or component gate completion']}
    result['native_prior_transcript_comparisons'] = list(base._NATIVE_PRIOR_COMPARISONS)
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'copy_edges': sum(len(r['edges']) for r in spec['routes']), 'anchor_spans': len(spec['anchors']),
                      'controls_rejected': len(rejected), 'exported_bytes': sum(r['bytes'] for r in records),
                      'instructions': sum(r['instructions'] for r in records), 'context_cleanup_call_sites': 10}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    collect(parser.parse_args().out)
