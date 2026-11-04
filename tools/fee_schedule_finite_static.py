#!/usr/bin/env python3
"""RE-001: the node115 fee-schedule finiteness gate 0x3d3b6c0 and what it covers.

Second follow-up to RE-001-node115-fee-schedule-gate. The validator
0x36a1c20 calls 0x3d3b6c0 at 0x36a2651, after building its slices and before
the ordering chain, and fails (jne 0x36a2ad6) when it returns AL != 0. This
tool decodes from captured bytes:

* the callee's chained state machine (state word +0x48), each part's
  begin/end fields, and the per-element predicate
  `(bits & MASK) > LIMIT` (signed), with MASK/LIMIT read from the movabs
  immediates: with MASK = 0x7fffffffffffffff and LIMIT = 0x7fefffffffffffff
  this is "x is NaN or +/-inf";
* the caller's construction of the 0xe8-byte state at [rsp+0x140]: which
  local slices and values each part iterates.

It also checks that every store the callee makes goes through RBX (its own
state). No captured code is executed.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import fee_schedule_gate_static as gate
from fee_schedule_gate_static import require, code, rel32, rel8, SHA, SIZE, CALLER
from fee_schedule_sources_static import match, disp

PACKET = gate.ROOT/'research/work-items/RE-001-node115-fee-schedule-finite'
CALLEE = (0x3d3b6c0, 0x3d3bb55)
CALLEE_SHA = 'e002601a62bf37864307fa8445d7778864f7b5b7cd0228be43bc529b5b66ad94'
STATE_BASE = 0x140


def rbx_load(data, va):
    """mov r64,[rbx+disp] (disp8/disp32); returns disp."""
    b = code(data, va, 7)
    require(b[0] in (0x48, 0x4c) and b[1] == 0x8b and b[2] & 7 == 3 and b[2] >> 6 in (1, 2), f'expected [rbx+d] load at {va:#x}')
    return b[3] if b[2] >> 6 == 1 else struct.unpack_from('<i', b, 3)[0]


def movabs(data, va):
    b = code(data, va, 10)
    require(b[0] in (0x48, 0x49) and 0xb8 <= b[1] <= 0xbf, f'expected movabs at {va:#x}')
    return struct.unpack_from('<Q', b, 2)[0]


def nonfinite(x, mask, limit, flag_if):
    """Interpretation of one decoded element test on the f64 bit pattern."""
    bits = struct.unpack('<q', struct.pack('<d', x))[0] & mask
    bits = bits - (1 << 64) if bits >= 1 << 63 else bits
    return {'jg': bits > limit, 'not jle': not bits <= limit}[flag_if]


# (part, entry state, begin site, end site, mask site, limit site, continue/flag jcc site, state-store site)
RANGE_PARTS = [('front', 1, 0x3d3b707, 0x3d3b713, 0x3d3b71a, 0x3d3b724, 0x3d3b74c, None),
               ('back', 1, 0x3d3b770, 0x3d3b780, 0x3d3b787, 0x3d3b791, 0x3d3b7bd, 0x3d3b843),
               ('s2', 2, 0x3d3b84b, 0x3d3b857, 0x3d3b85e, 0x3d3b868, 0x3d3b89e, 0x3d3b8a5),
               ('s3', 3, 0x3d3b8ad, 0x3d3b8b9, 0x3d3b8c0, 0x3d3b8ca, 0x3d3b8fe, 0x3d3b905),
               ('s4', 4, 0x3d3b90d, 0x3d3b919, 0x3d3b920, 0x3d3b92a, 0x3d3b95e, 0x3d3b965),
               ('s5', 5, 0x3d3b96d, 0x3d3b979, 0x3d3b980, 0x3d3b98a, 0x3d3b9bc, 0x3d3b9c0),
               ('s6', 6, 0x3d3b9c8, 0x3d3b9d4, 0x3d3b9db, 0x3d3b9e5, 0x3d3ba0c, 0x3d3ba12)]


def callee_parts(data):
    parts = []
    # Dispatch: rcx = [rbx+0x48]; 7,6,5,4,3,2 jump to their part, else fall to state<=1.
    match(data, 0x3d3b6c9, '4889fb' '488b4f48')
    dispatch = {}
    at = 0x3d3b6d0
    for want in (7, 6, 5, 4, 3, 2):
        b = code(data, at, 10)
        if b[0] == 0x48:
            require(b[:3] == bytes.fromhex('4883f9'), 'dispatch compare changed')
            imm, jat = b[3], at+4
        else:
            require(b[:2] == bytes.fromhex('83f9'), 'dispatch compare changed')
            imm, jat = b[2], at+3
        require(code(data, jat, 2) == bytes.fromhex('0f84'), 'dispatch branch changed')
        dispatch[imm] = rel32(jat, code(data, jat, 6), 6)
        at = jat+6
    for name, state, b0, e0, m0, l0, j0, s0 in RANGE_PARTS:
        cc = code(data, j0, 1)[0]
        part = {'part': name, 'state': state, 'begin_field': hex(rbx_load(data, b0)), 'end_field': hex(rbx_load(data, e0)),
                'mask': hex(movabs(data, m0)), 'limit': hex(movabs(data, l0)),
                'flag_if': {0x7e: 'not jle', 0x7f: 'jg'}.get(cc, 'unrecognized')}
        if state >= 2:
            require(dispatch.get(state) == b0, f'dispatch to state {state} changed')
        if s0 is not None:
            nxt = code(data, s0, 8)
            require(nxt[:4] == bytes.fromhex('48c74348'), 'state store changed')
            part['next_state'] = struct.unpack_from('<I', nxt, 4)[0]
            require(part['next_state'] == (2 if name == 'back' else state+1), 'state successor changed')
        parts.append(part)
    # Array part (state 1): for idx in [+0x50,+0x58): vec=[rbx+idx*8+0x60]; scan [vec+8] x [vec+0x10].
    match(data, 0x3d3b753, '83f901' '750d')
    lo, hi = rbx_load(data, 0x3d3b758), rbx_load(data, 0x3d3b75c)
    table = disp(match(data, 0x3d3b7d8, '488b7cc3..'))
    vptr, vlen = disp(match(data, 0x3d3b7e0, '4c8b47..')), disp(match(data, 0x3d3b7e4, '4c8b4f..'))
    cc = code(data, 0x3d3b806, 1)[0]
    parts.insert(1, {'part': 'array', 'state': 1, 'index_field': hex(lo), 'end_field': hex(hi), 'table_field': hex(table),
                     'vector_pointer': hex(vptr), 'vector_length': hex(vlen),
                     'mask': hex(movabs(data, 0x3d3b7c4)), 'limit': hex(movabs(data, 0x3d3b7ce)),
                     'flag_if': {0x7e: 'not jle', 0x7f: 'jg'}.get(cc, 'unrecognized')})
    # Map part (state 7): tag [rbx]; 3 = none, 2 = two 32-byte ranges, else iterator 0x37c7260.
    require(dispatch.get(7) == 0x3d3ba1a, 'dispatch to state 7 changed')
    match(data, 0x3d3ba1a, '488b03' '4883f803' '750c' '31c0')
    vstride = disp(match(data, 0x3d3ba60, '488d7e..'))
    vfield = disp(match(data, 0x3d3ba6c, '4c8b46..'))
    vcc = code(data, 0x3d3ba79, 1)[0]
    call = rel32(0x3d3bac3, code(data, 0x3d3bac3, 5), 5)
    require(code(data, 0x3d3bac3, 1) == b'\xe8', 'map iterator call changed')
    match(data, 0x3d3bb1e, '488b0a' '4c21e1' '4c39e9')
    tcc = code(data, 0x3d3bb27, 2)
    parts.append({'part': 'map', 'state': 7, 'tag_field': '0x0',
                  'contiguous_tag2': {'ranges': ['+0x8..+0x10', '+0x18..+0x20'], 'stride': vstride, 'value_field': hex(vfield),
                                      'mask': hex(movabs(data, 0x3d3ba44)), 'limit': hex(movabs(data, 0x3d3ba4e)),
                                      'flag_if': {0x7f: 'jg'}.get(vcc, 'unrecognized')},
                  'iterator_other_tags': {'call': hex(call), 'value_pointer': 'rdx on return',
                                          'mask': hex(movabs(data, 0x3d3baa6)), 'limit': hex(movabs(data, 0x3d3bab0)),
                                          'flag_if': 'jg' if tcc == bytes.fromhex('0f8f') else 'unrecognized'},
                  'tag3': 'no items'})
    match(data, 0x3d3ba23, '31c0' '5b415c415d415e415f' 'c3')
    return parts


# Caller construction of the callee state at [rsp+0x140] (callee offset = rsp disp - 0x140).
def caller_state(data):
    def store(va):
        b = code(data, va, 12)
        require(b[0] in (0x48, 0x4c) and b[1] in (0x89, 0xc7) and b[3] == 0x24 and b[2] & 0xc7 == 0x84, f'expected [rsp+d] store at {va:#x}')
        return struct.unpack_from('<i', b, 4)[0] - STATE_BASE
    def lea_rsp(va):
        b = code(data, va, 8)
        require(b[0] == 0x4c and b[1] == 0x8d and b[3] == 0x24, f'expected lea r,[rsp+d] at {va:#x}')
        return struct.unpack_from('<i', b, 4)[0]
    def slice_load(va):
        return disp(match(data, va, code(data, va, 4).hex() + '..'))
    out = {}
    out[hex(store(0x36a263d))] = {'value': struct.unpack('<I', code(data, 0x36a2645, 4))[0], 'role': 'initial state'}
    out[hex(store(0x36a255e))] = {'value': struct.unpack('<I', code(data, 0x36a2566, 4))[0], 'role': 'array index'}
    out[hex(store(0x36a256a))] = {'value': struct.unpack('<I', code(data, 0x36a2572, 4))[0], 'role': 'array end'}
    for lea, st in [(0x36a2576, 0x36a257e), (0x36a2586, 0x36a258e), (0x36a2596, 0x36a259e), (0x36a25a6, 0x36a25ae)]:
        out[hex(store(st))] = {'role': 'array element', 'vector_header': hex(lea_rsp(lea))}
    out[hex(store(0x36a25b6))] = {'role': 'front range begin', 'value': 0}
    out[hex(store(0x36a25c2))] = {'role': 'back range begin', 'value': 0}
    # Slice begin/end pairs from the vector pointer/length slots loaded at 0x36a2444..
    match(data, 0x36a2552, '4e8d04c2')       # r8 = rdx + r8*8
    match(data, 0x36a25de, '488d14f9')       # rdx = rcx + rdi*8
    match(data, 0x36a25f2, '488d0cf0')       # rcx = rax + rsi*8
    p5, l5 = slice_load(0x36a2444), slice_load(0x36a2449)
    p6, l6 = slice_load(0x36a244e), slice_load(0x36a2453)
    p9, l9 = slice_load(0x36a2458), slice_load(0x36a245d)
    for (b, e), (p, l) in [((0x36a25ce, 0x36a25d6), (p5, l5)), ((0x36a25e2, 0x36a25ea), (p6, l6)), ((0x36a25f6, 0x36a2606), (p9, l9))]:
        out[hex(store(b))] = {'role': 'range begin', 'pointer_slot': hex(p)}
        out[hex(store(e))] = {'role': 'range end', 'length_slot': hex(l)}
    match(data, 0x36a2611, '4b8d0cfe')       # rcx = r14 + r15*8
    out[hex(store(0x36a2615))] = {'role': 'range begin', 'pointer_register': 'r14'}
    out[hex(store(0x36a261d))] = {'role': 'range end', 'length_register': 'r15'}
    out[hex(store(0x36a262d))] = {'role': 'range begin', 'pointer': f'rsp+{lea_rsp(0x36a2625):#x}'}
    lea = code(data, 0x36a25fe, 8)
    require(lea[:4] == bytes.fromhex('488d8424'), 'range end lea changed')
    out[hex(store(0x36a2635))] = {'role': 'range end', 'pointer': f"rsp+{struct.unpack_from('<i', lea, 4)[0]:#x}"}
    match(data, 0x36a2462, '660f28842400010000' '660f29842430020000')   # [rsp+0x230..0x240) = [rsp+0x100..0x110)
    out['0x0'] = {'role': 'map tag', 'register': 'r13'}
    match(data, 0x36a2438, '4c8d5d48')       # r11 = input+0x48
    match(data, 0x36a2474, '4d8b0b' '4d89ca' '49f7da')    # neg [input+0x48]: OF iff value == i64::MIN
    require(code(data, 0x36a2482, 1) == b'\x71', 'map niche branch changed')
    match(data, 0x36a2508, '41bd02000000')   # contiguous form uses tag 2
    for va, reg in [(0x36a2649, 'rdi'), ]:
        require(lea_rsp_any(data, va) == STATE_BASE, 'callee state pointer changed')
    require(code(data, 0x36a2651, 1) == b'\xe8' and rel32(0x36a2651, code(data, 0x36a2651, 5), 5) == CALLEE[0], 'callee call changed')
    match(data, 0x36a2656, '84c0' '0f85')
    require(rel32(0x36a2658, code(data, 0x36a2658, 6), 6) == gate.FAIL, 'finiteness failure target changed')
    return out


def lea_rsp_any(data, va):
    b = code(data, va, 8)
    require(b[1] == 0x8d and b[3] == 0x24, 'expected lea')
    return struct.unpack_from('<i', b, 4)[0]


def certificate(data):
    parts = callee_parts(data)
    state = caller_state(data)
    by_off = {int(k, 16): v for k, v in state.items()}
    covered = []
    for p in parts:
        if p['part'] == 'array':
            idx = by_off[int(p['index_field'], 16)]['value']
            end = by_off[int(p['end_field'], 16)]['value']
            tbl = int(p['table_field'], 16)
            for i in range(idx, end):
                h = by_off[tbl+8*i]['vector_header']
                covered.append({'part': 'array', 'source': f'vector header {h}', 'pointer_slot': hex(int(h, 16)+int(p['vector_pointer'], 16)),
                                'mask': p['mask'], 'limit': p['limit'], 'flag_if': p['flag_if']})
        elif p['part'] == 'map':
            covered.append({'part': 'map', 'source': 'input+0x48 structure', 'mask': p['contiguous_tag2']['mask'],
                            'limit': p['contiguous_tag2']['limit'], 'flag_if': p['contiguous_tag2']['flag_if']})
        else:
            begin = by_off.get(int(p['begin_field'], 16))
            src = 'empty (begin 0)' if begin and begin.get('value') == 0 else \
                (begin.get('pointer_slot') or begin.get('pointer_register') or begin.get('pointer')) if begin else None
            covered.append({'part': p['part'], 'state': p['state'], 'source': src, 'mask': p['mask'], 'limit': p['limit'], 'flag_if': p['flag_if']})
    return {'callee_parts': parts, 'caller_state_fields': state, 'coverage': covered}


def store_bases(asm):
    """Base registers of every memory-destination store in a native decode."""
    bases = set()
    for line in asm.splitlines():
        m = re.match(r'^\s*[0-9a-f]+:\t(?:[0-9a-f]{2} )+\s*\t(mov|movups|movaps|movsd|movq|add|sub|and|or|xor|inc|dec)\s+\w*\s*(?:PTR )?\[([a-z0-9]+)', line)
        if m:
            bases.add(m[2])
    return sorted(bases)


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    return _analyze(data)


def _analyze(data):
    cert = certificate(data)
    require(cert['caller_state_fields']['0x48']['value'] == 1, 'callee does not start at state 1')
    for c in cert['coverage']:
        require(c['mask'] == '0x7fffffffffffffff' and c['limit'] == '0x7fefffffffffffff' and c['flag_if'] in ('jg', 'not jle'),
                'element predicate is not the non-finite test')
    gate_report = gate._analyze(data)
    _, fs, _ = gate.fde_extents(data)
    fde = next((f for f in fs if (f['start'], f['end']) == CALLEE), None)
    require(fde is not None, 'callee FDE changed')
    raw = code(data, CALLEE[0], CALLEE[1]-CALLEE[0])
    require(hashlib.sha256(raw).hexdigest() == CALLEE_SHA, 'callee body changed')
    records = {}
    for kind in ['fde', 'cie']:
        v = fde[kind]
        n = struct.unpack('<I', code(data, v, 4))[0]+4
        records[kind] = {'va': hex(v), 'bytes_hex': code(data, v, n).hex()}
    slices = {'0x90': 1, '0xa8': 2, '0xc0': 3, '0xd8': 4, '0x20': 5, '0x38': 6, 'r14': 8, '0x50': 9}
    covered_slices = sorted(slices[c['pointer_slot']] if c['part'] == 'array' else slices.get(c['source'], 0)
                            for c in cert['coverage'] if c['part'] != 'map' and c['source'] and 'empty' not in c['source']
                            and not c['source'].startswith('rsp+'))
    return {'target_sha256': SHA, 'callee': {'start': hex(CALLEE[0]), 'end': hex(CALLEE[1]), 'bytes': CALLEE[1]-CALLEE[0],
                                            'sha256': CALLEE_SHA, 'frames': records},
            'caller_sha256': gate.BODY_SHA[CALLER], 'depends_on_packets': ['RE-001-node115-fee-schedule-gate', 'RE-001-node115-fee-schedule-sources'],
            'certificate': cert, 'slices_fully_checked_finite': covered_slices,
            'also_checked_finite': ['input+0x88 and input+0x90 (via [rsp+0x230..0x240) copied from [rsp+0x100])', 'values of the input+0x48 structure'],
            'not_checked': ['slice 7 (u64)', 'stake pairs at input+0x38/+0x40'],
            'captured_code_executed': False,
            'limits': 'Normal-path, ABI-preserving calls assumed. 0x37c7260 (map iterator) is opaque: its returned value pointer and any state it writes are not closed here. The VecDeque/BTreeMap reading of input+0x48 is an inference from the niche test and ring-buffer arithmetic.'}


def generate(binary, output):
    data = binary.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snap = Path(directory)/'node115.elf'
        snap.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snap)], text=True)
        rows = [l for l in frames.splitlines() if f'pc={CALLEE[0]:016x}..{CALLEE[1]:016x}' in l]
        require(len(rows) == 1, 'native FDE disagreement')
        for name, (a, b) in {'callee': CALLEE, 'caller_state': (0x36a2429, 0x36a265e)}.items():
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snap)], text=True)
            gate.decode_export(asm, a, b, code(data, a, b-a))
            if name == 'callee':
                bases = store_bases(asm)
                calls = sorted(set(re.findall(r'\tcall\s+([0-9a-f]+)', asm)))
                require(bases == ['r14', 'rbx'] and calls == ['37c7260'], 'callee writes outside its state or calls elsewhere')
            (output/f'{name}.objdump.txt').write_bytes(asm.replace(str(snap), '<authenticated-node115>').encode('utf-8'))
    (output/'frames.txt').write_bytes((rows[0]+'\n').encode('utf-8'))
    (output/'callee-effects.json').write_bytes((json.dumps({'store_base_registers': bases, 'r14': 'rbx+0x8 (lea at 0x3d3ba2f)',
                                                           'direct_calls': ['0x' + c for c in calls], 'indirect_calls': 0}, indent=2)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report, indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=gate.TARGET)
    p.add_argument('--output', type=Path, default=gate.ROOT/'work/fee-schedule-finite115')
    args = p.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'slices_finite': r['slices_fully_checked_finite'], 'executed': False}))
