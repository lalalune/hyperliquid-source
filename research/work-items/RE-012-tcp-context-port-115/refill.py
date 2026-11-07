#!/usr/bin/env python3
"""Node115 static refill-chain joins; explicit CFG choices, no captured execution."""
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
import fresh

PREP, WRAPPER, WORKER = 0x63e9cd0, 0x63e9c40, 0x6362190
DIRECT, MARKER, MAPPER, POPCOUNT = 0x6364880, 0x63b6c50, 0x63e94a0, 0x63f0960
MASK = (1 << 64)-1
# owner, entry, endpoint (excluded), branch choices, exact calls
PATHS = {}
for name, status, null, threshold in [('status_empty', False, True, False),
    ('status_pointer_null', True, True, False), ('status_success', True, False, False),
    ('status_success_accounting', True, False, True)]:
    choices = dict(fresh.PATHS['refill_table_nonzero_boundary'][3])
    choices.update({0x63541f8: status, 0x6353bc1: False})
    if status:
        choices[0x6353b58] = null
    if not null:
        choices[0x6353baa] = threshold
    calls = [0x63541d1, 0x63541eb]
    calls += [0x6353d3c] if null else [0x6353f88] if threshold else []
    PATHS['caller_'+name] = (fresh.SLOW, fresh.SLOW, 0x6353bdb, choices, tuple(calls))
for name, null, threshold in [('null', True, False), ('success', False, False), ('success_accounting', False, True)]:
    choices = dict(fresh.PATHS['refill_table_zero_boundary'][3])
    choices.update({0x6353b58: null, 0x6353bc1: False})
    if not null:
        choices[0x6353baa] = threshold
    calls = [0x6354cda]+([0x6353d3c] if null else [0x6353f88] if threshold else [])
    PATHS['caller_direct_'+name] = (fresh.SLOW, fresh.SLOW, 0x6353bdb, choices, tuple(calls))
PATHS['prepare_zero'] = (PREP, PREP, 0x63e9d5a, {0x63e9d37: False, 0x63e9d46: False}, ())
PREP_ONE = {0x63e9d37: True, 0x63e9dea: True, 0x63e9e0e: False,
    0x63e9e4d: True, 0x63e9e70: False, 0x63e9f29: False, 0x63e9f79: False,
    0x63e9f8c: True, 0x63e9f9a: False, 0x63e9ff0: False, 0x63ea00b: True,
    0x63eaa3a: False, 0x63eaa96: False, 0x63eaaa0: True, 0x63ea028: False,
    0x63ea3c2: False, 0x63ea3d9: False, 0x63ea3e1: True, 0x63ea7a1: True,
    0x63ea908: True, 0x63e9d46: False}
for other in (False, True):
    PATHS['prepare_one_'+('new_owner' if other else 'same_owner')] = (PREP, PREP, 0x63e9d5a,
        {**PREP_ONE, 0x63e9f8c: not other}, (0x63e9d9c, 0x63e9e35, 0x63e9f72, 0x63ea3af))
PATHS['marker_one_valid'] = (MARKER, MARKER, 0x63b6db3,
    {0x63b6c69: False, 0x63b6ca1: False, 0x63b6ca7: True,
     0x63b6cf8: True, 0x63b6e0c: False, 0x63b6e1b: False, 0x63b6d13: True}, ())
PATHS['mapper_one_cached'] = (MAPPER, MAPPER, 0x63e96b1,
    {0x63e94a3: False, 0x63e94d6: True, 0x63e96dd: False, 0x63e9703: False,
     0x63e9596: False, 0x63e959c: True, 0x63e9611: True}, ())
PATHS['popcount_leaf'] = (POPCOUNT, POPCOUNT, 0x63f09c1, {}, ())
for kind, first, second in [('regular', False, None), ('boundary', True, False), ('empty', True, True)]:
    choices = {0x63e9c91: first}
    if second is not None:
        choices[0x63e9cb4] = second
    PATHS['wrapper_'+kind] = (WRAPPER, WRAPPER, 0x63e9cad, choices, (0x63e9c78,))
WORKER_END = {0x6362783: True, 0x63627ea: False, 0x63627f6: False,
              0x63627ff: False, 0x6362816: False}
WORKER_BEGIN = {0x63621f8: False, 0x6362202: False, 0x636228b: False}
for other in (False, True):
    owner = 'new_owner' if other else 'same_owner'
    PATHS['worker_zero_'+owner] = (WORKER, WORKER, 0x636282d,
        {**WORKER_BEGIN, **WORKER_END, 0x63622a1: not other, 0x63622b6: True},
        (0x6362284, 0x6362778))
    PATHS['worker_one_'+owner] = (WORKER, WORKER, 0x636282d,
        {**WORKER_BEGIN, **WORKER_END, 0x63622a1: not other, 0x63622b6: False,
         0x6362386: False, 0x6362398: False, 0x63623f6: True, 0x6362530: True,
         0x636265f: False, 0x636266d: False, 0x636269e: False},
        (0x6362284, 0x63624ee, 0x6362778))
    PATHS['direct_one_'+owner] = (DIRECT, DIRECT, 0x6364ae5,
        {0x63648b6: False, 0x63648bf: False, 0x63648df: False, 0x6364909: False,
         0x636494e: False, 0x636495d: not other, 0x6364972: False, 0x6364981: True,
         0x6364a1a: True, 0x6364a6e: False, 0x6364aa6: False, 0x6364aaf: False,
         0x6364aba: False, 0x6364ace: False}, (0x6364947, 0x6364a9c))


def stores(ins):
    out = {}
    for i in ins:
        if not i.operands or i.operands[0].type != capstone.CS_OP_MEM:
            continue
        if i.mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp', 'push', 'prefetcht0'):
            continue
        base.require(i.mnemonic in ('mov', 'movups', 'add', 'sub', 'xor', 'or'), 'Unclassified refill store '+hex(i.address))
        out[i.address] = i
    return out


def selected(decoded, name, override=None):
    owner, start, end, choices, calls = PATHS[name]
    choices = dict(choices)
    if override:
        choices.update(override)
    ins = cleanup.walk(decoded[owner], start, end, choices, calls)
    base.require(next(i for i in decoded[owner] if i.address == end).mnemonic == 'ret', 'Refill RET endpoint')
    return ins


def bindings(im, spec):
    base.require(spec['target_sha256'] == base.TARGET, 'Refill target')
    decoded = {}
    for r in spec['ranges']:
        lo, hi = int(r['start'], 16), int(r['end'], 16)
        if r['scope'] == 'complete_fde':
            base.require(len([f for f in im.fdes if f['start'] == lo and f['end'] == hi]) == 1, 'Refill exact FDE')
        elif r['scope'] == 'plt_window':
            base.require(lo in (0x63f17b0, 0x63f0b70, 0x63f0ad0) and hi == lo+16 and any(
                s['name'] == '.plt' and s['address'] <= lo < hi <= s['address']+s['size'] for s in im.sections), 'Refill PLT membership')
        else:
            base.require(r['scope'] == 'call_target_to_ret_window' and lo == POPCOUNT and hi == 0x63f09c2 and
                not any(f['start'] <= lo < f['end'] for f in im.fdes) and any(s['name'] == '.text' and
                s['address'] <= lo < hi <= s['address']+s['size'] for s in im.sections), 'Popcount non-FDE window')
        raw = im.read(lo, hi-lo)
        base.require(base.sha(raw) == r['sha256'], 'Refill body hash')
        decoded[lo] = list(helpers.decoder().disasm(raw, lo))
        base.require(sum(i.size for i in decoded[lo]) == hi-lo, 'Refill complete interval decode')
    index = {i.address: i for body in decoded.values() for i in body}
    bounds = set(index) | {int(r['end'], 16) for r in spec['ranges']}
    for a in spec['anchors']:
        lo, hi = int(a['va'], 16), int(a['end'], 16);raw = bytes.fromhex(a['bytes_hex'])
        base.require(lo in bounds and hi in bounds and hi-lo == len(raw) and im.read(lo, hi-lo) == raw, 'Refill anchor '+a['name'])
    for r in spec['transfers']:
        i = index[int(r['va'], 16)]
        base.require(i.mnemonic == r['mnemonic'] and i.operands[0].type == capstone.CS_OP_IMM and
                     i.operands[0].imm == int(r['target'], 16), 'Refill encoded transfer')
    for r in spec['relocations']:
        base.require(im.relocs.get(int(r['slot'], 16)) == [(r['info'], r['addend'])], 'Refill unique relocation')
        if r['symbol']:
            base.require(im.symbol(r['info'] >> 32) == r['symbol'], 'Refill import symbol')
    for r in spec['rip_data']:
        i = index[int(r['va'], 16)];op = i.operands[r['operand']];va = int(r['target'], 16)
        base.require(op.type == capstone.CS_OP_MEM and i.reg_name(op.mem.base) == 'rip' and
                     i.address+i.size+op.mem.disp == va, 'Refill RIP data operand')
        base.require(any(s['name'] == r['section'] and s['type'] == r['section_type'] and
            s['address'] <= va < s['address']+s['size'] for s in im.sections), 'Refill data section')
        base.require(r['runtime_value'] is None, 'Invented refill runtime value')
        if r['file_bytes_hex'] is not None:
            raw = bytes.fromhex(r['file_bytes_hex'])
            base.require(im.read(va, len(raw)) == raw, 'Refill initial data')
    actual = {}
    for name in PATHS:
        actual.update(stores(selected(decoded, name)))
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']}
    base.require(len(rows) == len(spec['selected_store_union']) and rows.keys() == actual.keys(), 'Refill selected store union')
    for va, i in actual.items():
        r = rows[va];op = i.operands[0]
        base.require(i.bytes.hex() == r['bytes_hex'] and i.mnemonic+' '+i.op_str == r['instruction'] and
                     op.size == r['width'], 'Refill store opcode/width')
        base.require((i.reg_name(op.mem.base), i.reg_name(op.mem.index), op.mem.scale, op.mem.disp) ==
                     (r['base'], r['index'], r['scale'], r['offset']), 'Refill store destination')
    pop = decoded[POPCOUNT]
    base.require(not stores(pop) and not any(i.mnemonic.startswith(('call', 'j')) for i in pop) and
                 sum(i.mnemonic == 'ret' for i in pop) == 1, 'Popcount straight-line no-store leaf')
    return decoded


def prepare_count(mid, end, batch):
    base.require(all(type(x) is int and 0 <= x <= 65535 for x in (mid, end, batch)), 'Prepare u16 domain')
    return ((mid-end+8*batch) & 65535) >> 3


def refill_request(batch, shift):
    base.require(type(batch) is int and 0 <= batch <= 65535 and type(shift) is int and
                 0 <= shift <= 255, 'Refill request domain')
    return batch >> (shift & 31)


def popcount_scalar(x):
    base.require(type(x) is int and 0 <= x <= MASK, 'Popcount unsigned domain')
    # Independently written lane-count arithmetic, not a CPU/interpreter model.
    pairs = x-((x >> 1) & 0x5555555555555555)
    nibbles = (pairs & 0x3333333333333333)+((pairs >> 2) & 0x3333333333333333)
    octets = (nibbles+(nibbles >> 4)) & 0x0f0f0f0f0f0f0f0f
    total = ((octets >> 32)+(octets & 0xffffffff)) & 0xffffffff
    total = ((total >> 16)+total) & 0xffffffff
    return ((total >> 8)+total) & 127


def prior_exhibits(im):
    packet = base.ROOT/'research/work-items/RE-001-node115-lu-ctxfeed'
    rec = json.loads((packet/'records.json').read_text())
    base.require(rec['binary_sha256'] == base.TARGET, 'Prior ctxfeed target')
    out = []
    for name, row in sorted(rec['exhibits'].items()):
        lo, hi = map(lambda v: int(v, 16), row['range'])
        raw = bytes.fromhex((packet/(name+'.hex')).read_text())
        base.require(len(raw) == row['bytes'] == hi-lo and im.read(lo, hi-lo) == raw, 'Prior ctxfeed exhibit')
        out.append({'name': name, 'start': hex(lo), 'end': hex(hi), 'bytes': len(raw), 'sha256': base.sha(raw)})
    return {'records_sha256': base.sha((packet/'records.json').read_bytes()),
        'manifest_sha256': base.sha((packet/'MANIFEST.sha256').read_bytes()), 'exhibits': out,
        'scope_correction': 'Original 0x63ead50 boundary includes four trailing INT3 bytes; exact FDE ends at 0x63ead4c',
        'not_replayed': 'Old whole-text caller census, old tool/test success, and full-path narrative are not inherited'}


def scalar_worksheets():
    # Finite mathematical checks of the formulas; not interpreted machine code.
    count_cases = [(0x1000, 0x1000, 1, 1), (0xff8, 0x1000, 1, 0),
                   (0xfff, 0x1000, 1, 0), (0, 65535, 1, 1),
                   (0, 0, 8192, 0), (65535, 0, 0, 8191), (7, 0, 0, 0), (8, 0, 0, 1)]
    shift_cases = [(1, 0, 1), (1, 1, 0), (65535, 15, 1), (65535, 16, 0),
                   (65535, 31, 0), (65535, 32, 65535), (1, 128, 1), (65535, 255, 0)]
    for a, z, t, expected in count_cases:
        base.require(prepare_count(a, z, t) == expected, 'Prepare scalar case')
    for t, s, expected in shift_cases:
        base.require(refill_request(t, s) == expected, 'Refill shift scalar case')
    pop_cases = 0
    for shift in (0, 16, 32, 48):
        for value in range(65536):
            x = value << shift
            base.require(popcount_scalar(x) == value.bit_count(), 'Popcount isolated 16-bit lane')
            pop_cases += 1
    mixed = [0, MASK, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa]
    mixed += [1 << bit for bit in range(64)]
    mixed += [(0x9e3779b97f4a7c15*n) & MASK for n in range(1, 257)]
    for x in mixed:
        base.require(popcount_scalar(x) == x.bit_count(), 'Popcount mixed-lane case')
        pop_cases += 1
    # All values of the low-16 difference and batch modulo its 8,192 period.
    periodic_cases = 0
    for batch in (0, 1, 8191, 8192, 65535):
        for delta in range(65536):
            expected = ((delta+8*(batch % 8192)) & 65535) // 8
            base.require(prepare_count(delta, 0, batch) == expected, 'Prepare modulo worksheet')
            periodic_cases += 1
    scenarios = []
    for drained in (0, 1):
        for requested in (0, 1):
            end = 0x1000;batch = 1;mid = end-8+8*drained;shift = 1-requested
            base.require(prepare_count(mid, end, batch) == drained and refill_request(batch, shift) == requested,
                         'Synthetic join arithmetic')
            # With one grant from the first bitmap word, write at old_end-8.
            cursor_after_worker = end-8*requested
            base.require(((cursor_after_worker & 65535) != end) == bool(requested), 'Joined wrapper boundary')
            scenarios.append({'prepare_items': drained, 'refill_request': requested, 'word_batch': batch,
                'mid_word': mid, 'end_low16': end, 'shift_byte': shift,
                'worker_cursor_offset_from_initial': -8*requested,
                'wrapper_cursor_offset_from_initial': 0,
                'final_front_and_end_words': end, 'final_mid_word': end-8,
                'final_cache_count': requested,
                'wrapper_status': requested, 'caller_count_increment': requested,
                'context_counter_decrements': drained+1,
                'same_shard_deltas': {'offset_0x38': drained+1, 'offset_0x70': requested,
                    'offset_0x78': drained, 'offset_0x80': 'initial C+8 exactly once',
                    'offset_0x88': requested-drained, 'offset_0x90': 1, 'offset_0x98': drained},
                'same_shard_owner_constraint': 'When prepare_items=1, prepare leaves J+0x30=B, so worker takes same-owner branch under no interference',
                'conditions': 'Same shard requires the preparation provider/key/shard to agree with E and BYTE[B+k+0xa1]; successful mutex imports, valid existing head/bitmap and nonnull Q for request=1, readable cursor even for request=0, nonnegative post-subtraction counters, disjoint metadata/stack/payload, stable tables and no interference; not a runtime fixture'})
    return {'prepare_cases': count_cases, 'shift_cases': shift_cases,
        'popcount_scalar_checks': pop_cases, 'prepare_modulo_checks': periodic_cases,
        'synthetic_join_constraints': scenarios}


def controls(im, spec, decoded):
    rejected = []
    def reject(name, fn):
        try:
            fn()
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted invalid refill evidence: '+name)
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
    bad = copy.deepcopy(spec)
    next(x for x in bad['ranges'] if x['start'] == hex(POPCOUNT))['scope'] = 'complete_fde'
    reject('invented-popcount-FDE', lambda: bindings(im, bad))
    for r in spec['relocations']:
        for kind in ('changed', 'duplicate'):
            bad = copy.copy(im);bad.relocs = dict(im.relocs);slot = int(r['slot'], 16)
            bad.relocs[slot] = [(r['info'], r['addend']+1)] if kind == 'changed' else im.relocs[slot]*2
            reject(kind+'-relocation:'+r['slot'], lambda: bindings(bad, spec))
        if r['symbol']:
            bad = copy.deepcopy(spec)
            next(x for x in bad['relocations'] if x['slot'] == r['slot'])['symbol'] = 'wrong_import'
            reject('wrong-import:'+r['slot'], lambda: bindings(im, bad))
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
        if not choices:
            continue
        va = next(iter(choices))
        reject('changed-entry-edge:'+name, lambda: selected(decoded, name, {va: not choices[va]}))
    for name, va in [('prepare_zero', 0x63e9d46), ('prepare_one_same_owner', 0x63e9f79),
        ('prepare_one_same_owner', 0x63eaa96), ('prepare_one_same_owner', 0x63ea3d9),
        ('prepare_one_same_owner', 0x63ea908), ('marker_one_valid', 0x63b6e1b),
        ('mapper_one_cached', 0x63e96dd), ('worker_one_same_owner', 0x636228b),
        ('worker_one_same_owner', 0x6362386), ('worker_one_same_owner', 0x6362398),
        ('worker_one_same_owner', 0x636265f), ('worker_one_same_owner', 0x63627ea),
        ('worker_zero_same_owner', 0x63627ff), ('direct_one_same_owner', 0x636494e),
        ('direct_one_same_owner', 0x6364972), ('direct_one_same_owner', 0x6364a1a),
        ('direct_one_same_owner', 0x6364aa6), ('direct_one_same_owner', 0x6364aba),
        ('caller_status_success', 0x6353bc1)]:
        reject('excluded-edge:'+name+':'+hex(va), lambda: selected(decoded, name, {va: not PATHS[name][3][va]}))
    for r in spec['rip_data']:
        bad = copy.deepcopy(spec)
        next(x for x in bad['rip_data'] if x['va'] == r['va'])['runtime_value'] = 0
        reject('invented-runtime-value:'+r['va'], lambda: bindings(im, bad))
        if r['file_bytes_hex'] is not None:
            reject('changed-initial-data:'+r['va'], lambda: bindings(mutate(int(r['target'], 16)), spec))
    for args in [(-1, 0, 1), (0, 65536, 1), (0, 0, 65536), (True, 0, 1)]:
        reject('prepare-domain:'+str(args), lambda: prepare_count(*args))
    for args in [(-1, 0), (65536, 0), (1, 256), (1, -1)]:
        reject('request-domain:'+str(args), lambda: refill_request(*args))
    for x in (-1, 1 << 64, True, 1.5):
        reject('popcount-domain:'+str(x), lambda: popcount_scalar(x))
    reject('wrong-target', lambda: base.authenticate(b'not node115'))
    changed = bytearray(im.data);changed[-1] ^= 1
    reject('changed-full-target', lambda: base.authenticate(changed))
    return rejected


def collect(out):
    data = (base.ROOT/'artifacts/node/115/hl-node').read_bytes();base.authenticate(data);im = base.Image(data)
    spec = json.loads((base.PACKET/'refill-spec.json').read_text());decoded = bindings(im, spec)
    reused = prior_exhibits(im);arithmetic = scalar_worksheets();rejected = controls(im, spec, decoded)
    rows = {int(r['va'], 16): r for r in spec['selected_store_union']};paths = []
    for name, (owner, entry, end, choices, calls) in PATHS.items():
        ins = selected(decoded, name)
        paths.append({'name': name, 'owner': hex(owner), 'entry': hex(entry), 'ret': hex(end),
            'decisions': {hex(k): v for k, v in choices.items()}, 'calls': [hex(v) for v in calls],
            'instruction_vas_before_ret': [hex(i.address) for i in ins],
            'explicit_stores': [rows[va] for va in stores(ins)],
            'implicit_push_sites': [hex(i.address) for i in ins if i.mnemonic == 'push'],
            'prefetch_sites': [hex(i.address) for i in ins if i.mnemonic.startswith('prefetch')]})
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
            if lo == fresh.SLOW:
                base.require(p.stdout == (base.PACKET/('fresh/fresh_fallback.'+suffix+'.objdump')).read_bytes(), 'Prior caller native export')
            row['native'].append({'file': name, 'sha256': base.sha(p.stdout), 'rows': len(parsed), 'lock_prefix_splits': splits})
            commands.append(args)
        ranges.append(row)
    result = {'target_sha256': base.TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated': False, 'ranges': ranges, 'paths': paths,
        'selected_store_union': spec['selected_store_union'], 'transfers': spec['transfers'],
        'relocations': spec['relocations'], 'rip_data': spec['rip_data'],
        'revalidated_ctxfeed_exhibits': reused, 'scalar_worksheets': arithmetic,
        'manual_joins': {
            'prepare': 'C=&A[0x360], K=B+0x358, t=WORD[W+2*k]; count=((WORD[C+0x12]-WORD[C+0x14]+8*t) mod 65536)>>3; zero returns with local stores only',
            'prepare_one': 'One item, marker checks valid, metadata-cache hit, successful lock, matching drain object/key/shard, incremented ten-bit header field neither class-table value nor 1, counter post-subtraction sign clear; toggle bitmap, increment header by 2^28, drain C+8, update shard stats, set C+0x12=low16(end-8*t)',
            'wrapper': 'D=[K]; request=t>>(BYTE[D+k+0x34]&31); call worker(B,E,C,&W[k],k,request); BYTE[D+k+0x58]=1; pop using two low16 bounds; status 1 can accompany Q=0',
            'worker_one': 'One requested item, existing head with nonzero ten-bit header field and first bitmap word nonzero; clear its lowest set bit, write base+bit*stride at end-8, subtract 2^28 from the header, drain C+8, update shard stats, set C=end-8, decrement DWORD[B+0x98]',
            'worker_zero': 'Still lock/unlock, update shard visit/drain stats, clear C+8, store cursor=end and decrement DWORD[B+0x98]; no bitmap/pointer-array write',
            'direct_one': 'Zero-table caller -> existing-head direct allocation; first bitmap word nonzero; toggle lowest set bit, decrement header by 2^28, return base+bit*stride nonzero; update shard stats and decrement B+0x98; R8D=0 skips memset',
            'caller': 'Wrapper status1 increments C+8 before Q null test; status0 goes directly to errno12. Direct alternative has no cache count increment. Nonnull results join earlier accounting mode1.',
            'popcount': '98-byte directly-called straight-line interval through RET, no containing FDE; no explicit stores/calls; lane-count formula corroborated separately'},
        'negative_and_scope_controls': rejected, 'normalization_masks': [],
        'limitations': ['Seven complete FDE exports plus one call-target-to-RET interval and three PLT windows do not imply all-path coverage',
            'Selected zero/one-item paths; general loops, contention, missing heads, fallback/provider creation and negative counters remain open',
            'Tables, bitmap/count agreement, valid non-aliasing storage, canonical addresses, ABI, CPU TZCNT semantics and no interference are premises',
            'Mutex and errno imports are bound by relocations, not executed or behaviorally verified',
            'Historical ctxfeed exhibits are revalidated, not its broad caller census or all-path claims; source packet remains unchanged',
            'Scalar arithmetic and synthetic join constraints are not runtime fixtures or CPU emulation',
            'No full allocator ownership or outer transport-word preservation proof; no Rust equivalence, agent review, gate, commit or push']}
    for name, value in [('records.json', result), ('commands.json', commands), ('versions.json', versions)]:
        (out/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'exported_intervals': len(ranges), 'bytes': sum(r['bytes'] for r in ranges),
        'instructions': sum(r['instructions'] for r in ranges), 'selected_paths': len(paths),
        'selected_store_union': len(rows), 'controls_rejected': len(rejected),
        'popcount_scalar_checks': arithmetic['popcount_scalar_checks'], 'prepare_modulo_checks': arithmetic['prepare_modulo_checks']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    collect(parser.parse_args().out)
