#!/usr/bin/env python3
"""RE-001: the node115 fee-schedule validator's post-gate path and true return.

Third follow-up to RE-001-node115-fee-schedule-gate. After the ordering and
range chain (0x36a265e..0x36a2a8b) the validator 0x36a1c20 runs, in order:

1. a sum over the values of the input+0x48 structure (opaque iterator
   0x3c6d100 / 0x4504fe0), starting from -0.0, failing if sum > 1.0;
2. two range tests on [rsp+0x10] (the last stake pair's second component,
   or +0.0 when the stake list is empty);
3. two calls to 0x36a58d0 with decoded argument records (perp and spot);
4. a range test over every element of slices 1 then 3 (inline chain);
5. a range test over every element of slices 2, 5, 4 (chain iterator
   0x36e1b90, complete FDE) and then 6 (inline tail);
6. the success epilogue setting BL/BPL = 1.

Every predicate is decoded from bytes (operands, condition codes, RIP-relative
literals and the 16-byte abs mask). No captured code is executed.
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
from fee_schedule_gate_static import require, code, rel32, rel8, SHA, SIZE, CALLER, FAIL, RANGE_FAIL
from fee_schedule_sources_static import match, disp

PACKET = gate.ROOT/'research/work-items/RE-001-node115-fee-schedule-post'
CHAIN = (0x36e1b90, 0x36e1bff)
CC = {0x76: 'jbe', 0x77: 'ja', 0x86: 'jbe', 0x87: 'ja', 0x84: 'je', 0x85: 'jne'}


def rip_f64(data, va, length):
    """Target and value of the RIP-relative operand ending an instruction of `length`."""
    t = rel32(va, code(data, va, length), length)
    return t, struct.unpack('<d', code(data, t, 8))[0]


def jcc(data, va):
    """Short or near conditional jump at va -> (cc, target)."""
    b = code(data, va, 6)
    if b[0] == 0x0f:
        return CC.get(b[1]), rel32(va, b, 6)
    return CC.get(b[0]), rel8(va, b[:2])


def map_sum(data):
    match(data, 0x36a2a8b, '488dbc2470020000' '488b742408' 'e8')
    init = rel32(0x36a2a98, code(data, 0x36a2a98, 5), 5)
    start_va, start = rip_f64(data, 0x36a2a9d, 8)
    require(code(data, 0x36a2a9d, 4) == bytes.fromhex('f20f1005'), 'sum start load changed')
    match(data, 0x36a2aa5, 'f20f11442408' '4c8dbc2470020000' '4c89ff' 'e8')
    nxt = rel32(0x36a2ab6, code(data, 0x36a2ab6, 5), 5)
    match(data, 0x36a2abb, '4885c0' '0f84')
    require(rel32(0x36a2abe, code(data, 0x36a2abe, 6), 6) == 0x36a2d59, 'sum exit changed')
    match(data, 0x36a2ac4, 'f20f10442408' 'f20f5802' 'f20f11442408' 'ebdd')
    cmp = code(data, 0x36a2d7d, 6)
    require(cmp == bytes.fromhex('f20f10442408'), 'sum reload changed')
    limit_va, limit = rip_f64(data, 0x36a2d83, 8)
    cc, target = jcc(data, 0x36a2d8b)
    require(target == RANGE_FAIL, 'sum failure target changed')
    return {'iterator_init': hex(init), 'iterator_next': hex(nxt), 'iterator_source': '[rsp+0x8] = &input+0x48 (0x36a247d)',
            'value': 'f64 at returned rdx', 'start': start, 'start_bits': code(data, start_va, 8)[::-1].hex(),
            'fail_if': f'sum {cc} {limit}', 'limit_va': hex(limit_va)}


def discount_range(data):
    match(data, 0x36a2d59, 'f20f10442410' '660f2e05')
    hi_va, hi = rip_f64(data, 0x36a2d5f, 8)
    cc1, t1 = jcc(data, 0x36a2d67)
    match(data, 0x36a2d6d, '660f57c0' '660f2e442410')
    cc2, t2 = jcc(data, 0x36a2d77)
    require(t1 == RANGE_FAIL and t2 == RANGE_FAIL, 'discount failure target changed')
    return {'value': '[rsp+0x10]', 'fail_if': [f'value {cc1} {hi}', f'0.0 {cc2} value'], 'upper_va': hex(hi_va),
            'value_origin': '0x36a2a31 stores +0.0; 0x36a2a41 stores the last stake pair second when the list is nonempty'}


def floor_calls(data):
    calls = []
    for start, call in [(0x36a2d91, 0x36a2e1c), (0x36a2e29, 0x36a2eba)]:
        rec = {}
        at = start
        while at < call - 8:
            b = code(data, at, 12)
            if b[:3] == bytes.fromhex('488d84') or b[:3] == bytes.fromhex('488d44'):       # lea rax,[rsp+d]
                d = b[4] if b[2] == 0x44 else struct.unpack_from('<i', b, 4)[0]
                n = 5 if b[2] == 0x44 else 8
                st = code(data, at+n, 8)
                require(st[:4] == bytes.fromhex('48898424'), 'argument store changed')
                rec[hex(struct.unpack_from('<i', st, 4)[0]-0x140)] = f'&[rsp+{d:#x}]'
                at += n+8
            elif b[:4] == bytes.fromhex('4c89a424'):                                          # mov [rsp+d],r12
                rec[hex(struct.unpack_from('<i', b, 4)[0]-0x140)] = 'r12 (=&[rsp+0x88], 0x36a2576)'
                at += 8
            elif b[:3] in (bytes.fromhex('f20f10'), bytes.fromhex('0f2884'), bytes.fromhex('660f28')):
                if b[0] == 0x0f:                                   # movaps xmm0,[rsp+d32]
                    src = struct.unpack_from('<i', b, 4)[0]; n = 8
                elif b[3] == 0x44:                                 # f2/66 0f xx 44 24 d8
                    src = b[5]; n = 6
                else:                                              # f2/66 0f xx 84 24 d32
                    src = struct.unpack_from('<i', b, 5)[0]; n = 9
                at += n
                while True:
                    st = code(data, at, 9)
                    if st[:5] != bytes.fromhex('f20f118424'):
                        break
                    rec[hex(struct.unpack_from('<i', st, 5)[0]-0x140)] = f'[rsp+{src:#x}]'
                    at += 9
            else:
                raise ValueError(f'unrecognised floor-argument instruction at {at:#x}')
        match(data, call-8, '488dbc2440010000')
        require(code(data, call, 1) == b'\xe8' and rel32(call, code(data, call, 5), 5) == 0x36a58d0, 'floor call changed')
        cc, t = jcc(data, call+7)
        require(code(data, call+5, 2) == bytes.fromhex('84c0') and cc == 'je' and t == RANGE_FAIL, 'floor result gate changed')
        calls.append({'call': hex(call), 'callee': '0x36a58d0', 'record_at': 'rsp+0x140', 'fields': dict(sorted(rec.items(), key=lambda x: int(x[0], 16))),
                      'fails_if': 'AL == 0'})
    return calls


def cross_range(data):
    match(data, 0x36a2ec7, '488b942490000000' '488b842498000000' '488d04c2' '488bb424c0000000' '488b8c24c8000000' '488d0cce' '660f57c0')
    min_va, mn = rip_f64(data, 0x36a2ef3, 8)
    require(code(data, 0x36a2ef3, 4) == bytes.fromhex('f20f1015'), 'cross minimum load changed')
    match(data, 0x36a2efb, '4885d2' '740e' '4839c2' '7409' '4c8d4208' '4889f7' 'eb0f' '4839ce' '7443' '488d7e08' '4531c0' '4889f2' 'f20f100a')
    match(data, 0x36a2f21, '660f2ec1')
    cc1, t1 = jcc(data, 0x36a2f25)
    max_va, mx = rip_f64(data, 0x36a2f2b, 8)
    cc2, t2 = jcc(data, 0x36a2f33)
    match(data, 0x36a2f39, '660f2ec8' '4c89c2' '4889fe')
    cc3, t3 = jcc(data, 0x36a2f43)
    match(data, 0x36a2f45, '660f2ed1' '4c89c2' '4889fe')
    cc4, t4 = jcc(data, 0x36a2f4f)
    match(data, 0x36a2f51, 'e9')
    require(t1 == t2 == RANGE_FAIL and t3 == t4 == 0x36a2efb and rel32(0x36a2f51, code(data, 0x36a2f51, 5), 5) == RANGE_FAIL, 'cross branch targets changed')
    return {'slices': ['rsp+0x90 / rsp+0x98 (slice 1)', 'rsp+0xc0 / rsp+0xc8 (slice 3)'],
            'fail_if': [f'0.0 {cc1} x', f'x {cc2} {mx}'], 'positive_test': f'continue if x {cc3} 0.0',
            'positive_minimum': f'continue if {mn} {cc4} x, else fail', 'max_va': hex(max_va), 'min_va': hex(min_va)}


def add_range(data):
    match(data, 0x36a2f56, '488b8424a8000000' '488b8c24b0000000' '488d0cc8' '488b542420' '488b742428' '488d34f2'
          '488bbc24d8000000' '4c8b8424e0000000' '4e8d04c7' '4c8b4c2438' '4c8b542440' '4f8d14d1')
    match(data, 0x36a2f9a, '48c784244001000001000000' '48898424480100' '00' '48898c2450010000' '4889942458010000'
          '4889b42460010000' '4889bc2468010000' '4c89842470010000' '4c898c2478010000' '4c89942480010000'
          '488d9c2440010000' '4889df' 'e8')
    require(rel32(0x36a2ff1, code(data, 0x36a2ff1, 5), 5) == CHAIN[0], 'chain iterator call changed')
    # Chain iterator: tag [rdi]: 1 -> A [+8,+0x10) then B [+0x18,+0x20) then tag 0; 0 -> C [+0x28,+0x30); 2 -> done.
    match(data, CHAIN[0], '488b07' '4885c0' '7445' '83f802' '7503' '31c0' 'c3'
          '488b4708' '4885c0' '7415' '31c9' '483b4710' '488d5008' '480f45ca' '48894f08' '7401' 'c3'
          '488b4718' '4885c0' '740f' '483b4720' '7409' '488d4808' '48894f18' 'c3'
          '48c70700000000'
          '488b4728' '4885c0' '740f' '483b4730' '7409' '488d4808' '48894f28' 'c3'
          '48c70702000000' '31c0' 'c3')
    match(data, 0x36a2ff6, '4885c0' '7523' '488b842478010000' '4885c0' '7451' '483b842480010000' '7447' '488d4808' '48898c2478010000')
    match(data, 0x36a301e, 'f20f1000' '660f28c8' '660f540d')
    mask_va = rel32(0x36a3026, code(data, 0x36a3026, 8), 8)
    mask = code(data, mask_va, 16)
    max_va, mx = rip_f64(data, 0x36a302e, 8)
    require(code(data, 0x36a302e, 4) == bytes.fromhex('660f2e0d'), 'add maximum compare changed')
    cc1, t1 = jcc(data, 0x36a3036)
    match(data, 0x36a303c, '660f57c9' '660f2ec1')
    cc2, t2 = jcc(data, 0x36a3044)
    min_va, mn = rip_f64(data, 0x36a3046, 8)
    match(data, 0x36a304e, '660f2ec8')
    cc3, t3 = jcc(data, 0x36a3052)
    require(t1 == RANGE_FAIL and t2 == t3 == 0x36a2fee and code(data, 0x36a3054, 1) == b'\xe9'
            and rel32(0x36a3054, code(data, 0x36a3054, 5), 5) == RANGE_FAIL, 'add branch targets changed')
    return {'slices': ['A rsp+0xa8/0xb0 (slice 2)', 'B rsp+0x20/0x28 (slice 5)', 'C rsp+0xd8/0xe0 (slice 4)', 'D rsp+0x38/0x40 (slice 6, inline tail)'],
            'chain_iterator': {'start': hex(CHAIN[0]), 'end': hex(CHAIN[1]), 'tag1': 'A then B, then tag 0', 'tag0': 'C, then tag 2', 'tag2': 'exhausted'},
            'abs_mask': mask.hex(), 'fail_if': [f'|x| {cc1} {mx}'], 'positive_test': f'continue if x {cc2} 0.0',
            'positive_minimum': f'continue if {mn} {cc3} x, else fail', 'max_va': hex(max_va), 'min_va': hex(min_va)}


def success(data):
    match(data, 0x36a30cb, '40b501' 'b301' '4885f6' '0f858e faffff'.replace(' ', ''))
    return {'sets': 'BPL=1 (0x36a30cb), BL=1 (0x36a30ce); epilogue mov eax,ebx (0x36a2bfe)',
            'result': 'AL=1; upper bits of EAX are not defined by these writes'}


def certificate(data):
    return {'map_sum': map_sum(data), 'discount_range': discount_range(data), 'floor_calls': floor_calls(data),
            'cross_range': cross_range(data), 'add_range': add_range(data), 'success': success(data)}


def taken(cc, lhs, rhs):
    cf, zf = gate.flags('f64', lhs, rhs)
    return gate.taken(cc, cf, zf)


def cross_ok(cert, x):
    c = cert['cross_range']
    mx = float(c['fail_if'][1].split()[2])
    mn = float(c['positive_minimum'].split()[2])
    if taken(c['fail_if'][0].split()[1], 0.0, x) or taken(c['fail_if'][1].split()[1], x, mx):
        return False
    if taken(c['positive_test'].split()[3], x, 0.0):
        return True
    return taken(c['positive_minimum'].split()[3], mn, x)


def add_ok(cert, x):
    c = cert['add_range']
    mx = float(c['fail_if'][0].split()[2])
    mn = float(c['positive_minimum'].split()[2])
    if taken(c['fail_if'][0].split()[1], abs(x), mx):
        return False
    if taken(c['positive_test'].split()[3], x, 0.0):
        return True
    return taken(c['positive_minimum'].split()[3], mn, x)


def post_passes(cert, slices, map_values, last_discount, floors_ok=(True, True)):
    """Decoded post-gate path over prepared slices (floor helper supplied as an oracle)."""
    s = cert['map_sum']
    total = s['start']
    for v in map_values:
        total += v
    if taken(s['fail_if'].split()[1], total, float(s['fail_if'].split()[2])):
        return False
    d = cert['discount_range']['fail_if']
    if taken(d[0].split()[1], last_discount, float(d[0].split()[2])) or taken(d[1].split()[1], 0.0, last_discount):
        return False
    if not all(floors_ok):
        return False
    if not all(cross_ok(cert, x) for i in (1, 3) for x in slices[i]):
        return False
    return all(add_ok(cert, x) for i in (2, 5, 4, 6) for x in slices[i])


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    return _analyze(data)


def _analyze(data):
    cert = certificate(data)
    require(cert['map_sum']['start_bits'] == '8000000000000000' and cert['map_sum']['fail_if'] == 'sum ja 1.0', 'map sum changed')
    require(cert['discount_range']['fail_if'] == ['value ja 1.0', '0.0 ja value'], 'discount range changed')
    require(cert['cross_range']['fail_if'] == ['0.0 ja x', 'x ja 0.001'] and cert['cross_range']['positive_minimum'] == 'continue if 0.0001 jbe x, else fail', 'cross range changed')
    require(cert['add_range']['abs_mask'] == 'ffffffffffffff7fffffffffffffff7f' and cert['add_range']['fail_if'] == ['|x| ja 0.001']
            and cert['add_range']['positive_minimum'] == 'continue if 0.0001 jbe x, else fail', 'add range changed')
    gate._analyze(data)
    _, fs, _ = gate.fde_extents(data)
    fde = next((f for f in fs if (f['start'], f['end']) == CHAIN), None)
    require(fde is not None, 'chain iterator FDE changed')
    raw = code(data, CHAIN[0], CHAIN[1]-CHAIN[0])
    records = {}
    for kind in ['fde', 'cie']:
        v = fde[kind]
        n = struct.unpack('<I', code(data, v, 4))[0]+4
        records[kind] = {'va': hex(v), 'bytes_hex': code(data, v, n).hex()}
    return {'target_sha256': SHA, 'caller_sha256': gate.BODY_SHA[CALLER],
            'chain_iterator': {'start': hex(CHAIN[0]), 'end': hex(CHAIN[1]), 'bytes': CHAIN[1]-CHAIN[0],
                               'sha256': hashlib.sha256(raw).hexdigest(), 'frames': records},
            'depends_on_packets': ['RE-001-node115-fee-schedule-gate', 'RE-001-node115-fee-schedule-sources', 'RE-001-node115-fee-schedule-finite'],
            'certificate': cert,
            'validator_result': 'AL=1 only after: finiteness gate (0x3d3b6c0), ordering/pair/range chain, map sum <= 1.0, last stake discount in [0,1], both 0x36a58d0 calls true, cross range over slices 1 and 3, add range over slices 2, 5, 4, 6. Every failure returns EAX=0.',
            'redundant_on_normal_path': 'discount range: the gate packet already requires the stake list second components to be strictly increasing from +0.0 with the last at most 0.5, so [rsp+0x10] is +0.0 (empty list) or in (0, 0.5]',
            'captured_code_executed': False,
            'limits': '0x36a58d0 (1,136-byte floor helper), 0x3c6d100/0x4504fe0 (map iterator) are opaque; normal-path ABI-preserving returns assumed. No panic/unwind/allocator-failure claims.'}


def generate(binary, output):
    data = binary.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA, 'expected pinned node115')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snap = Path(directory)/'node115.elf'
        snap.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snap)], text=True)
        rows = [l for l in frames.splitlines() if f'pc={CHAIN[0]:016x}..{CHAIN[1]:016x}' in l]
        require(len(rows) == 1, 'native FDE disagreement')
        for name, (a, b) in {'map_sum': (0x36a2a8b, 0x36a2ad6), 'post_gate': (0x36a2d59, 0x36a30de), 'chain_iterator': CHAIN}.items():
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={a:#x}', f'--stop-address={b:#x}', str(snap)], text=True)
            gate.decode_export(asm, a, b, code(data, a, b-a))
            (output/f'{name}.objdump.txt').write_bytes(asm.replace(str(snap), '<authenticated-node115>').encode('utf-8'))
        full = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                        f'--start-address={CALLER[0]:#x}', f'--stop-address={CALLER[1]:#x}', str(snap)], text=True)
    succ, text, indirect = gate.native_cfg(full, *CALLER)
    def stores_to(pattern):
        return {a for a, t in text.items() if re.match(r'^\w+\s+(?:QWORD|XMMWORD) PTR \[' + pattern + r'\],', t)}
    r12_w = {a for a, t in text.items() if gate.writes(t, {'r12', 'r12d', 'r12w', 'r12b'})}
    flow = {
        'r12_written_between_0x36a2576_and_0x36a2dae': gate.path_through(succ, succ[0x36a2576][0], 0x36a2dae, r12_w),
        'rsp_0x8_stored_between_0x36a247d_and_0x36a2a93': gate.path_through(succ, succ[0x36a247d][0], 0x36a2a93, stores_to(r'rsp\+0x8')),
        'rsp_0x10_stored_between_0x36a2a41_and_0x36a2d59': gate.path_through(succ, succ[0x36a2a41][0], 0x36a2d59, stores_to(r'rsp\+0x10') - {0x36a2a41}),
        'indirect_jumps_reachable_0x36a2576_to_0x36a2dae': sorted(hex(a) for a in indirect if a in gate.reach_until(succ, succ[0x36a2576][0], 0x36a2dae)),
        'scope': 'direct-edge GNU decode of the caller; indirect jumps listed, not followed'}
    require(not any(v for k, v in flow.items() if k.startswith(('r12', 'rsp'))) and not flow['indirect_jumps_reachable_0x36a2576_to_0x36a2dae'],
            'native dataflow disagreement')
    (output/'frames.txt').write_bytes((rows[0]+'\n').encode('utf-8'))
    (output/'dataflow.json').write_bytes((json.dumps(flow, indent=2)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report, indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=gate.TARGET)
    p.add_argument('--output', type=Path, default=gate.ROOT/'work/fee-schedule-post115')
    args = p.parse_args()
    r = generate(args.binary, args.output)
    print(json.dumps({'floor_calls': len(r['certificate']['floor_calls']), 'executed': False}))
