#!/usr/bin/env python3
"""Static #115 accept-state cleanup join; no captured execution or emulation.

CFG walks choose encoded edges from explicit premises. Stack/copy intervals
are manual-coordinate worksheets, not observed runtime ownership.
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
import helpers

CLEANUP = 0x2a9dcd0
FIELD = (0x368, 0x36a)  # Relative to outer post-prologue RSP, before second copy.


def memory_destinations(ins):
    result = {}
    for i in ins:
        if i.operands and i.operands[0].type == capstone.CS_OP_MEM:
            if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp'):
                continue
            base.require(i.mnemonic in ('mov', 'lock dec'), 'Unclassified explicit destination')
            result[i.address] = i
    return result


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Cleanup target')
    decoded = {}
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16)
        base.require(len([f for f in im.fdes if f['start'] == start and f['end'] == end]) == 1,
                     'Cleanup exact FDE')
        raw = im.read(start, end-start)
        base.require(base.sha(raw) == r['sha256'], 'Cleanup body hash')
        ins = list(helpers.decoder().disasm(raw, start))
        base.require(sum(i.size for i in ins) == end-start, 'Cleanup complete decode')
        decoded[start] = ins
    all_ins = {i.address: i for body in decoded.values() for i in body}
    bounds = set(all_ins) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        va, end = int(a['va'], 16), int(a['end'], 16)
        raw = bytes.fromhex(a['bytes_hex'])
        base.require(end-va == len(raw) and va in bounds and end in bounds, 'Anchor extent')
        base.require(im.read(va, len(raw)) == raw, 'Anchor bytes: '+a['name'])
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Unique relocation')
        if r['symbol']:
            base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Imported name')
    actual = memory_destinations(decoded[CLEANUP])
    rows = {int(r['va'], 16): r for r in spec['explicit_stores']}
    base.require(len(rows) == len(spec['explicit_stores']) and actual.keys() == rows.keys(), 'Store inventory')
    for va, i in actual.items():
        r = rows[va]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.operands[0].size == r['width']
                     and i.mnemonic+' '+i.op_str == r['instruction'], 'Store opcode/width')
    for va, target in ((0x2ad5dfd, 0x2afae20), (0x2ad5e3e, CLEANUP)):
        i = all_ins[va]
        base.require(i.mnemonic == 'call' and i.operands[0].type == capstone.CS_OP_IMM
                     and i.operands[0].imm == target, 'Direct call target')
    for va in (0x2afb75b, 0x2ad5e25, 0x2ad5e58):
        i = all_ins[va];op = i.operands[0]
        base.require(i.mnemonic == 'call' and op.type == capstone.CS_OP_MEM
                     and i.reg_name(op.mem.base) == 'rip'
                     and i.address+i.size+op.mem.disp == 0x64df508, 'Selected memcpy slot')
    return decoded


def walk(ins, start, stop, decisions, calls):
    """Follow manually selected encoded CFG edges; never evaluate CPU state."""
    index = {i.address: i for i in ins};visited = [];used = set();called = []
    va = start
    while va != stop:
        base.require(va in index and va not in visited, 'Path leaves interval or cycles')
        i = index[va];visited.append(va)
        base.require(i.mnemonic not in ('ret', 'ud2'), 'Unexpected terminator')
        if i.mnemonic == 'call':
            base.require(va in calls, 'Unexpected path call');called.append(va)
        if i.mnemonic.startswith('j'):
            base.require(i.operands[0].type == capstone.CS_OP_IMM, 'Unresolved branch')
            if i.mnemonic == 'jmp':
                va = i.operands[0].imm
            else:
                base.require(va in decisions, 'Unclassified conditional');used.add(va)
                va = i.operands[0].imm if decisions[va] else va+i.size
        else:
            va += i.size
    base.require(used == set(decisions) and called == list(calls), 'Unused decisions/calls')
    return [index[a] for a in visited]


def immediate_path(decoded, tag=1, override=None):
    base.require(type(tag) is int and 0 <= tag < 256 and tag not in (3, 4), 'Outside immediate-return tags')
    # Pinned CMP eax,3 / JE, then CMP eax,4 / JNE. No general state-machine model.
    decisions = {0x2a9dce1: False, 0x2a9dce6: True}
    if override:
        decisions.update(override)
    ins = walk(decoded[CLEANUP], CLEANUP, 0x2a9dd85, decisions, ())
    ret = next(i for i in decoded[CLEANUP] if i.address == 0x2a9dd85)
    base.require(ret.mnemonic == 'ret' and not memory_destinations(ins), 'Immediate path writes or bad return')
    base.require([i.mnemonic+' '+i.op_str for i in ins if i.mnemonic == 'push'] ==
                 ['push r14', 'push rbx', 'push rax'], 'Implicit push census')
    return ins+[ret]


def disjoint(lo, width):
    base.require(type(lo) is int and type(width) is int and width > 0, 'Invalid interval')
    base.require(lo+width <= FIELD[0] or lo >= FIELD[1], 'Overlapping tracked word')
    return {'write_relative_to_outer_rsp': [lo, lo+width], 'field': list(FIELD), 'disjoint': True}


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted invalid cleanup evidence: '+name)
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
        if kind == 'missing':
            bad['explicit_stores'].pop()
        else:
            bad['explicit_stores'][0]['width'] = 1
        reject('store-inventory:'+kind, lambda: bindings(im, bad))
    for va, decision in ((0x2a9dce1, True), (0x2a9dce6, False)):
        reject('excluded-branch:'+hex(va), lambda: immediate_path(decoded, override={va: decision}))
    for tag in (-1, 3, 4, 256):
        reject('tag-scope:'+str(tag), lambda: immediate_path(decoded, tag))
    for lo, size in ((0x361, 8), (0x368, 1), (0x369, 1), (0x360, 0)):
        reject('interval-scope:'+str((lo, size)), lambda: disjoint(lo, size))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected, reject


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'cleanup-spec.json').read_text());decoded = bindings(im, spec)
    selected = immediate_path(decoded)
    returned = walk(decoded[0x2afae20], 0x2afb761, 0x2afb8bf, {}, ())
    base.require(list(memory_destinations(returned)) == [0x2afb8a8], 'Return state-write census')
    bridge = walk(decoded[0x2ad5980], 0x2ad5e02, 0x2ad5e43, {0x2ad5e0a: False}, (0x2ad5e25, 0x2ad5e3e))
    base.require(not memory_destinations(bridge), 'Outer bridge explicit store')
    tags = [tag for tag in range(256) if tag not in (3, 4)]
    for tag in tags:
        base.require([i.address for i in immediate_path(decoded, tag)] == [i.address for i in selected], 'Tag partition')
    rejected, reject = controls(im, spec, decoded);out.mkdir(parents=True, exist_ok=False)
    versions = {'python': sys.version, 'platform': platform.platform(), 'capstone': capstone.__version__}
    for tool in ('objdump', 'llvm-objdump'):
        versions[tool] = subprocess.check_output([tool, '--version']).decode()
    ranges = [];commands = []
    for r in spec['ranges']:
        start, end = int(r['start'], 16), int(r['end'], 16);ins = decoded[start]
        fde, = [f for f in im.fdes if f['start'] == start and f['end'] == end]
        row = {**r, 'fde': hex(fde['fde']), 'lsda': hex(fde['lsda']), 'file_offset': hex(im.offset(start, end-start)),
               'bytes': end-start, 'instructions': len(ins), 'native': []}
        (out/(r['name']+'.capstone.txt')).write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n', encoding='utf-8', newline='\n')
        for tool, opts, suffix in [('objdump', ['-z', '--insn-width=16'], 'gnu'), ('llvm-objdump', ['--disassemble-zeroes'], 'llvm')]:
            args = [tool, '-d', *opts, f'--start-address={start}', f'--stop-address={end}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=base.ROOT, capture_output=True, check=True);name = r['name']+'.'+suffix+'.objdump'
            (out/name).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            parsed = base.native_rows(p.stdout, im, start, end);splits = base.compare_boundaries(parsed, ins)
            if r['prior_native']:
                base.require(p.stdout == (base.PACKET/(r['prior_native']+'.'+suffix+'.objdump')).read_bytes(), 'Prior native output differs')
            else:
                reject('truncated-native:'+suffix, lambda: base.native_rows(p.stdout[:len(p.stdout)//2], im, start, end))
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits});commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'captured_code_executed_or_emulated': False, 'ranges': ranges, 'relocations': spec['relocations'],
              'cleanup_all_state_explicit_stores': spec['explicit_stores'],
              'cleanup_all_state_transfers': helpers.transfers(im, decoded[CLEANUP]),
              'selected_paths': {'acceptor_return_before_ret': [hex(i.address) for i in returned],
                                 'outer_bridge_before_second_copy': [hex(i.address) for i in bridge],
                                 'cleanup_including_ret': [hex(i.address) for i in selected]},
              'immediate_return_tag_partition': {'count': len(tags), 'excluded_tags': [3, 4], 'joined_tag': 1,
                                                'not_a_valid_state_domain_claim': True},
              'implicit_stack_worksheet': [disjoint(lo, 8) for lo in (-8, -16, -24, -32)],
              'adjacent_interval_controls': [disjoint(0x360, 8), disjoint(0x36a, 8)],
              'manual_coordinate_join': {'state_base': 'outer state R + 0x198 = AP',
                                          'tag': 'AP + 0xc9 = R + 0x261',
                                          'return_copy_field': 'outer stack OS + 0x400',
                                          'first_copy': 'OS+[0x370,0x408) -> OS+[0x2d8,0x370)',
                                          'field_across_cleanup': 'OS+[0x368,0x36a)',
                                          'next_copy_field': 'OS+[0x188,0x18a)'},
              'negative_and_scope_controls': rejected, 'normalization_masks': [],
              'limitations': ['Selected successful acceptor return and outer result tag != 2; not every result path',
                              'State tag survives intervening memcpy: ordinary imported behavior, distinct state/stack storage and no concurrent mutation',
                              'SysV callee-saved registers, valid stack and no asynchronous interference are premises',
                              'Other tags, cleanup callees, dynamic callbacks, exceptions and lifetime remain open',
                              'No Rust implementation, runtime observation, complete caller inventory or full-scope gate']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'fdes': len(ranges), 'bytes': sum(r['bytes'] for r in ranges),
                      'instructions': sum(r['instructions'] for r in ranges), 'cleanup_instructions': len(decoded[CLEANUP]),
                      'selected_cleanup_instructions': len(selected), 'controls_rejected': len(rejected)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--out', type=Path, required=True)
    collect(p.parse_args().out)
