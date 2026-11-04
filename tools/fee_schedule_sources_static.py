#!/usr/bin/env python3
"""RE-001: sources of the node115 fee-schedule gate's ordered slices.

Follow-up to `fee_schedule_gate_static.py` (RE-001-node115-fee-schedule-gate).
That packet decodes nine ordering predicates over local slices but binds only
each slice's element 0. This tool decodes, from captured bytes, which input
fields every later element of each slice comes from:

* the 48-byte record list at input+0x08/+0x10, walked by a five-state
  jump-table loop that appends record fields to six local vectors;
* the 16-byte record list at input+0x20/+0x28, appended by three
  vectorised extend loops (body, remainder and unrolled paths).

No captured code is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import fee_schedule_gate_static as gate
from fee_schedule_gate_static import require, code, rel32, rel8, SHA, SIZE, CALLER

PACKET = gate.ROOT/'research/work-items/RE-001-node115-fee-schedule-sources'
JUMP_TABLE = 0x799c8c
STATES = 5


def match(data, va, template):
    """Match hex `template` ('..' = wildcard byte); return the wildcard bytes."""
    parts = [template[i:i+2] for i in range(0, len(template), 2)]
    raw = code(data, va, len(parts))
    wild = bytearray()
    for p, b in zip(parts, raw):
        if p == '..':
            wild.append(b)
        else:
            require(int(p, 16) == b, f'template mismatch at {va:#x}')
    return bytes(wild)


def disp(b):
    return struct.unpack('<b', b)[0] if len(b) == 1 else struct.unpack('<i', b)[0]


def stack_store(data, va):
    """movsd [rsp+d],xmmN (disp8 or disp32); returns (xmm, d)."""
    b = code(data, va, 9)
    require(b[:3] == bytes.fromhex('f20f11'), f'expected movsd store at {va:#x}')
    modrm = b[3]
    require(b[4] == 0x24 and modrm & 0xc7 in (0x44, 0x84), f'expected rsp store at {va:#x}')
    d = b[5] if modrm & 0xc0 == 0x40 else struct.unpack_from('<i', b, 5)[0]
    return (modrm >> 3) & 7, d


def stack_load_xmm0(data, va):
    b = code(data, va, 9)
    require(b[:5] in (bytes.fromhex('f20f104424'), bytes.fromhex('f20f108424')), f'expected movsd xmm0,[rsp+d] at {va:#x}')
    return b[5] if b[3] == 0x44 else struct.unpack_from('<i', b, 5)[0]


def tier_loop(data):
    """Decode record fields, the dispatch states and each state's vector/value."""
    # List base and stride: rcx = [input+0x08]; end = rcx + len*3*16; next = rcx+0x30.
    match(data, 0x36a1df7, '488b4310')                   # rax = [input+0x10] (len)
    match(data, 0x36a1e0c, '488b4908')                   # rcx = [input+0x08] (ptr)
    match(data, 0x36a1e10, '488d0440' '48c1e004')         # len*3 << 4
    stride = struct.unpack('<b', match(data, 0x36a1e48, '4883c1..'))[0]
    require(stride == 0x30 and 3*16 == stride, 'tier stride changed')
    # Per-record field loads (rcx = record) and the stack slots they reach.
    fields = {}
    off = disp(match(data, 0x36a1e76, '488b41..'))
    slot = disp(match(data, 0x36a1e7a, '48898424........'))
    fields[off] = {'kind': 'u64', 'slot': slot}
    require(match(data, 0x36a1e82, 'f20f1009') == b'', 'record +0 load changed')
    s1, d1 = stack_store(data, 0x36a1ef3)
    s2, d2 = stack_store(data, 0x36a1efc)
    require(s1 == s2 == 1, 'record +0 store changed')
    fields[0] = {'kind': 'f64', 'slot': d2, 'copy_slot': d1}
    for load, store in [(0x36a1e86, 0x36a1e8b), (0x36a1e91, 0x36a1e96), (0x36a1e9f, 0x36a1ea4), (0x36a1ec4, 0x36a1ec9)]:
        off = disp(match(data, load, 'f20f1041..'))
        x, d = stack_store(data, store)
        require(x == 0, 'record field store register changed')
        fields[off] = {'kind': 'f64', 'slot': d}
    # Dispatch: index = state>=4 ? 4 : state; state' = min(state,3)+1.
    match(data, 0x36a1ead, '31d2' '4883fa03' 'b803000000' '480f42c2')
    match(data, 0x36a1ed2, '48ffc0' '4883fa04' 'b900000000' '410f43cf' '0fb6c9' '48634c8d00' '4801e9')
    require(match(data, 0x36a1e23, '41bf..000000') == b'\x04', 'saturating state changed')
    table = rel32(0x36a1e31, code(data, 0x36a1e31, 7), 7)
    require(table == JUMP_TABLE, 'jump table base changed')
    match(data, 0x36a1f3c, '4983fe03' 'b803000000' '490f42c6' '48ffc0' '4983fe04' '450f43f7' '410fb6ce' '48634c8d00' '4801e9')
    targets = [JUMP_TABLE+x for x in struct.unpack('<5i', code(data, JUMP_TABLE, 20))]
    default_header = disp(match(data, 0x36a1e29, '4c8dac24........'))   # r13
    require(match(data, 0x36a1ef0, '4d89ec') == b'' and match(data, 0x36a1f63, '4d89ec') == b'', 'default vector changed')
    require(stack_load_xmm0(data, 0x36a1f66) == fields[0]['copy_slot']
            and stack_store(data, 0x36a1f6f) == (0, fields[0]['slot']), 'state-0 value reload changed')
    states = []
    for i, t in enumerate(targets):
        if t == 0x36a1f10:
            states.append({'state': i, 'target': hex(t), 'vector_header': default_header, 'value_slot': fields[0]['slot']})
            continue
        if t in (0x36a1f77, 0x36a1f90, 0x36a1fb0):
            require(match(data, t, '4989c6') == b'', 'state prologue changed')
            header = disp(match(data, t+3, '4c8da424........'))
            value = stack_load_xmm0(data, t+11)
            states.append({'state': i, 'target': hex(t), 'vector_header': header, 'value_slot': value})
            continue
        require(t == 0x36a1ff0, 'unexpected jump-table target')
        # Final state: push the u64 to the vector at [rsp+0x60], then the f64 at
        # [rsp+0x248] to the vector whose len lives at [rsp+0x58] (header 0x48).
        h = disp(match(data, t, '488b5c24..'))-0x10
        require(disp(match(data, t+5, '483b5c24..')) == h, 'u64 vector capacity test changed')
        require(disp(match(data, 0x36a2007, '488b4424..')) == h+8, 'u64 vector pointer changed')
        u64 = disp(match(data, 0x36a200c, '488b8c24........'))
        match(data, 0x36a2014, '48890cd8')
        lenslot = disp(match(data, 0x36a2020, '4c8b7424..'))
        require(disp(match(data, 0x36a2025, '4c3b7424..')) == lenslot-0x10, 'f64 vector capacity test changed')
        require(disp(match(data, 0x36a1e4c, '488b4424..')) == lenslot-8, 'f64 vector pointer changed')
        f64 = stack_load_xmm0(data, 0x36a1e51)
        match(data, 0x36a1e5a, 'f2420f1104f0')
        require(disp(match(data, 0x36a1e63, '4c897424..')) == lenslot, 'f64 vector length store changed')
        states.append({'state': i, 'target': hex(t), 'pushes': [{'vector_header': h, 'value_slot': u64, 'kind': 'u64'},
                                                                 {'vector_header': lenslot-0x10, 'value_slot': f64, 'kind': 'f64'}]})
    # The generic push writes [rsp+8] to vector r12: len +0x10, cap +0, ptr +8.
    match(data, 0x36a1f10, '498b5c2410' '493b1c24')
    match(data, 0x36a1f24, '498b442408' 'f20f10442408' 'f20f1104d8' '48ffc3' '49895c2410')
    match(data, 0x36a1fd0, 'f20f11442408' '498b5c2410' '493b1c24')
    by_slot = {v['slot']: off for off, v in fields.items()}
    by_slot[fields[0]['copy_slot']] = 0
    appends = []
    for s in states:
        for p in s.get('pushes', [s]):
            require(p['value_slot'] in by_slot, 'appended value slot is not a decoded record field')
            appends.append({'state': s['state'], 'vector_header': hex(p['vector_header']),
                            'pointer_slot': hex(p['vector_header']+8), 'record_field': hex(by_slot[p['value_slot']])})
    # Per-record state sequence from the decoded constants: index = min(state, 4)
    # (cmovae to r15d=4), next = min(state, 3) + 1; state 4 ends the record.
    clamp_next, clamp_index = 3, 4
    seq, state = [], 0
    while True:
        index = clamp_index if state >= clamp_index else state
        seq.append(index)
        if targets[index] == 0x36a1ff0:
            break
        state = min(state, clamp_next) + 1
        require(len(seq) <= STATES, 'dispatch does not terminate per record')
    return {'list': {'pointer': 'input+0x08', 'length': 'input+0x10', 'stride': stride},
            'state_sequence_per_record': seq,
            'fields': {hex(k): {'kind': v['kind'], 'slot': hex(v['slot'])} for k, v in sorted(fields.items())},
            'jump_table': hex(JUMP_TABLE), 'state_targets': [hex(t) for t in targets],
            'appends_per_record_in_state_order': appends}


def mm_extends(data):
    """Three extends over the 16-byte list at input+0x20 (ptr) / +0x28 (len)."""
    match(data, 0x36a20ad, '488bac2438010000')        # rbp = spilled input
    require(disp(match(data, 0x36a20b5, '488b5d..')) == 0x20 and disp(match(data, 0x36a20b9, '4c8b7d..')) == 0x28, 'second list binding changed')
    groups = []
    # (vector header, body, base lea, remainder load, unrolled pre-add site, unrolled first load)
    for header, body, base_lea, rem, pre in [(0x18, 0x36a2150, 0x36a213a, 0x36a21b0, 0x36a21f7),
                                             (0x30, 0x36a22e0, 0x36a22d7, 0x36a2340, 0x36a2387),
                                             (0xe8, 0x36a2c83, 0x36a2c7d, 0x36a2ccb, None)]:
        lea = code(data, base_lea, 4)
        require(lea[:3] in (bytes.fromhex('488d7b'), bytes.fromhex('488d53')), 'vector base changed')
        base = lea[3]
        raw = code(data, body, 19)
        require(raw[:3] == bytes.fromhex('f20f10') and raw[5:8] == bytes.fromhex('660f16') and raw[10:13] == bytes.fromhex('f20f10')
                and raw[15:18] == bytes.fromhex('660f16'), 'vector body changed')
        ds = [disp(raw[4:5]), disp(raw[9:10]), disp(raw[14:15]), 0]
        require([b-a for a, b in zip(ds, ds[1:])] == [16, 16, 16], 'vector body stride changed')
        body_fields = sorted({(base+d) % 16 for d in ds})
        # Remainder path.
        if header == 0xe8:
            match(data, rem, 'f20f1006')                    # movsd xmm0,[rsi]; rsi = list + i*16
            match(data, 0x36a2cbf, '48c1e604' '4801de')
            require(disp(match(data, 0x36a2cda, '4883c6..')) == 16, 'remainder stride changed')
            rem_field = 0
        else:
            match(data, rem, 'f2430f100450')               # movsd xmm0,[r8+r10*2]; r10 starts at ...
            r10 = struct.unpack('<I', match(data, rem-0x18, '41ba........'))[0]
            require(disp(match(data, rem+0x10, '4983c2..')) == 8, 'remainder stride changed')
            rem_field = 2*r10
        # Unrolled path: base (+8 pre-add or not) + 2*r8 - 0x30, r8 starting at 0x18.
        if pre is None:
            match(data, 0x36a2d09, '4801d3')                # rbx += i*16, no pre-add
            r8 = struct.unpack('<I', match(data, 0x36a2d0f, 'be........'))[0]
            d0 = disp(match(data, 0x36a2d16, 'f20f104473..'))
            unrolled_field = (2*r8 + d0) % 16
        else:
            add = disp(match(data, pre, '4883c1..'))
            r8 = struct.unpack('<I', match(data, pre+0x7, '41b8........'))[0]
            d0 = disp(match(data, pre+0x19, 'f2420f104441..'))
            unrolled_field = (add + 2*r8 + d0) % 16
        groups.append({'vector_header': hex(header), 'pointer_slot': hex(header+8),
                       'body_fields_mod16': body_fields, 'remainder_field': rem_field, 'unrolled_field': unrolled_field})
    return {'list': {'pointer': 'input+0x20', 'length': 'input+0x28', 'stride': 16}, 'extends': groups}


def seeds_for_mm_slices(data):
    """Element 0 of the two vectors extended with the 16-byte list's +8 field."""
    out = []
    for load_va, slot_store_va, seed_load_va, ptr_va, header in [(0x36a1c42, 0x36a1c47, 0x36a2054, 0x36a206a, 0x18),
                                                                  (0x36a1c5e, 0x36a1c66, 0x36a208c, 0x36a209f, 0x30)]:
        b = code(data, load_va, 8)
        require(b[:3] == bytes.fromhex('f20f10') and b[3] in (0x47, 0x87), 'seed input load changed')
        field = b[4] if b[3] == 0x47 else struct.unpack_from('<i', b, 4)[0]
        _, slot = stack_store(data, slot_store_va)
        require(stack_load_xmm0(data, seed_load_va) == slot, 'seed slot reload changed')
        require(disp(match(data, ptr_va, '48894424..')) == header+8, 'seed vector pointer changed')
        out.append({'vector_header': hex(header), 'element0': f'input+{field:#x}', 'via_slot': hex(slot)})
    return out


# Slice 8 is checked through registers r14 (pointer) / rbx (length); these sites
# tie them to the vector whose header is [rsp+0xe8] ({cap, ptr, len}).
SLICE8_BINDING = {0x36a23ff: '4989c6', 0x36a2402: '48c70000000000', 0x36a2415: '48898424f0000000',
                  0x36a2429: '41bd01000000', 0x36a242f: '4584e4' '0f846c050000',
                  0x36a29c4: '4c8bb424f0000000', 0x36a29cc: '4c8bac24f8000000',
                  0x36a2c73: '4901c5', 0x36a2ce3: '4929fd', 0x36a2d51: '4929d5',
                  0x36a2cf8: '0f873af7ffff', 0x36a2d54: 'e9dff6ffff',
                  0x36a243c: '4c89ac24f8000000', 0x36a2484: '4d89ef', 0x36a24d0: '4d89ef',
                  0x36a24e3: '4d89ef', 0x36a260e: '4c89fb', 0x36a27f6: '498d4608'}


def slice8_binding(data):
    for va, hexa in SLICE8_BINDING.items():
        match(data, va, hexa)
    return {'pointer': 'r14 = [rsp+0xf0] (header 0xe8), reloaded after growth at 0x36a29c4',
            'length': 'rbx = r15 = r13, the element count stored to [rsp+0xf8] at 0x36a243c',
            'element0': '+0.0 bit pattern (u64 0 stored at 0x36a2402)',
            'empty_second_list': 'r12b set: the extend at 0x36a29a4 is skipped (test r12b at 0x36a242f)'}


def certificate(data):
    return {'tier_loop': tier_loop(data), 'second_list': mm_extends(data), 'mm_slice_seeds': seeds_for_mm_slices(data),
            'slice8_registers': slice8_binding(data)}


def slice_sources(cert, gate_cert):
    """Join decoded appends with the gate packet's slice pointer slots."""
    appended = {a['pointer_slot']: f"tier[i]+{a['record_field']}"
                for a in cert['tier_loop']['appends_per_record_in_state_order']}
    for g in cert['second_list']['extends']:
        fs = set(g['body_fields_mod16']) | {g['remainder_field'], g['unrolled_field']}
        appended[g['pointer_slot']] = f'second[i]+{fs.pop():#x}' if len(fs) == 1 else 'INCONSISTENT'
    out = []
    for i, loop in enumerate(gate_cert['loops'], 1):
        p = loop['source']['pointer']
        key = '0xf0' if p == 'r14' else p.replace('rsp+', '')
        out.append({'slice': i, 'pointer': p, 'appended': appended.get(key)})
    out.append({'slice': 9, 'pointer': 'rsp+0x50', 'appended': appended.get('0x50')})
    return out


def model_slices(schedule, sources, seeds):
    """Build slices 1..9 from a synthetic schedule using the decoded sources."""
    def field(src, rec):
        lst, off = src.split('+')
        return rec[int(off, 16)]
    slices = {}
    for s in sources:
        lst = 'tiers' if s['appended'].startswith('tier') else 'second'
        slices[s['slice']] = [seeds[s['slice']](schedule)] + [field(s['appended'], r) for r in schedule[lst]]
    return slices


def gate_passes(schedule, gate_cert, sources):
    """Claimed ordering/range gate over a synthetic schedule (normal path only)."""
    seeds = {1: lambda s: s['in'][0x68], 2: lambda s: s['in'][0x70], 3: lambda s: s['in'][0x78],
             4: lambda s: s['in'][0x80], 5: lambda s: s['in'][0x70], 6: lambda s: s['in'][0x80],
             7: lambda s: 0, 8: lambda s: 0.0, 9: lambda s: 1.0}
    sl = model_slices(schedule, sources, seeds)
    for i, loop in enumerate(gate_cert['loops'], 1):
        if not gate.loop_passes(loop, sl[i]):
            return False
    if gate.helper_any(gate_cert['helper'], gate_cert['helper_window_size'], sl[9]):
        return False
    if not gate.pair_passes(gate_cert['pairs'], schedule['stake']):
        return False
    return all(gate.range_passes(r, schedule['in'][off]) for r, off in zip(gate_cert['ranges'], (0x88, 0x90)))


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    return _analyze(data)


def _analyze(data):
    cert = certificate(data)
    gate_report = gate._analyze(data)            # pins both FDE bodies, Location, seeds, failure return
    sources = slice_sources(cert, gate_report['certificate'])
    require(all(s['appended'] and s['appended'] != 'INCONSISTENT' for s in sources), 'slice source unresolved')
    return {'target_sha256': SHA, 'caller': [hex(CALLER[0]), hex(CALLER[1])],
            'caller_sha256': gate.BODY_SHA[CALLER], 'depends_on_packet': 'RE-001-node115-fee-schedule-gate',
            'certificate': cert, 'slice_sources': sources,
            'captured_code_executed': False,
            'call_between_construction_and_checks': '0x3d3b6c0 at 0x36a2651 receives the addresses of vector headers 0x88/0xa0/0xb8/0xd0 and begin/end pairs of slices 5, 6, 9 and 8; the slices equal the constructed contents only if it does not mutate them (not proved here)',
            'limits': 'Normal-path, ABI-preserving calls assumed (vector growth helpers 0x64e6148/0x64e8d58/0x43bd910 are opaque and assumed to keep {cap,ptr,len} with existing elements). Alias/overlap fallbacks of the extend loops are reached only through the same three paths decoded here. No source names, no 0x3d3b6c0 gate, no success path.'}


def generate(binary, output):
    data = binary.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as directory:
        snap = Path(directory)/'node115.elf'
        snap.write_bytes(data)
        for name, (a, b) in {'tier_loop': (0x36a1df7, 0x36a2040), 'second_list': (0x36a2040, 0x36a2438),
                             'maker_extend': (0x36a29a4, 0x36a2a0d), 'maker_extend_tail': (0x36a2c56, 0x36a2d59)}.items():
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snap)], text=True)
            gate.decode_export(asm, a, b, code(data, a, b-a))
            (output/f'{name}.objdump.txt').write_bytes(asm.replace(str(snap), '<authenticated-node115>').encode('utf-8'))
    (output/'jump-table.txt').write_bytes(('VA 0x799c8c .rodata, five int32 entries relative to the table base\n' +
                                           code(data, JUMP_TABLE, 20).hex() + '\n' +
                                           '\n'.join(report['certificate']['tier_loop']['state_targets']) + '\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report, indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=gate.TARGET)
    p.add_argument('--output', type=Path, default=gate.ROOT/'work/fee-schedule-sources115')
    args = p.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'slices': len(r['slice_sources']), 'executed': False}))
