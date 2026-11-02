#!/usr/bin/env python3
"""Extract bounded app-hash tuple writer evidence from node 94 ELF bytes."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = {
    0x1e5e450: (0x1e5e764, '2f4b31006c3b59fee957650bc82d0687f1c661c676341ee4235bd7b074283496'),
    0x1e5ed40: (0x1e5f00f, '755118d9699d4eabc2405257ab15d4822df389f101720b02d04ef99fa35bd16d'),
    0x1e5d9b0: (0x1e5de4c, '4d6e9974eb647bc394e9636a849b10a0efd57a5a7a618d979abc58f4efd1d3b1'),
    0x1e0f310: (0x1e0f44f, 'b508ad97f293d7d2d6b22596e8e6adb8b496c7471dfc7ba4137fc147d3c6a77c'),
    0x1e0fed0: (0x1e100ba, '36391cb3f6bdc999be0c69f8d8263534a77cedae96395c38681287f4648a30f4'),
    0x1e0f450: (0x1e0f586, 'dc0af08404a61c390b0da9db5ee20b187292c677b468b8f88e46cb8eca2ff732'),
    0x1e0ef60: (0x1e0f164, '0e40fc8373bed23068b082d03bbe25b5d5dfd006b93ea60f6770b43ba52b1408'),
    0x1e0fcc0: (0x1e0fec4, '8e51023ca4c8495e2a68cd4e152fe63cd8c4c4058f37900ee140f77c1461979a'),
    0x1e0e190: (0x1e0e2cf, '004bb2eb9f8e516a35aaac913dcea4eb0f76cc776e38dd9463a50f4183cce0ac'),
    0x1e0f820: (0x1e0fa52, 'b041bb842cc76ef2804b57d7fe9f6f8a19e02285cd3e1ef7f3efc41dbf78ad2f'),
    0x1e10960: (0x1e10b62, '8041f1c5075e2b4df9cf07f0b049deab7b4fd003e7ea337c8500ff4bdc3ca287'),
}


def require_identity(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target SHA-256 mismatch')


class View:
    def __init__(self, data):
        self.data = data
        self.sections = [s for s in sections(data) if s['type'] != 8 and s['size']]

    def read(self, va, size):
        if va < 0 or size < 0:
            raise ValueError('invalid range')
        matches = [s for s in self.sections if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('range has no unique file-backed section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def call(view, va):
    raw = view.read(va, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def branch(view, va):
    raw = view.read(va, 2)
    if raw[0] == 0x75:
        return va + 2 + struct.unpack('b', raw[1:])[0]
    if raw == b'\x0f\x85':
        return va + 6 + struct.unpack('<i', view.read(va + 2, 4))[0]
    raise ValueError('expected jne')


def check(view, va, expected):
    b = bytes.fromhex(expected)
    actual = view.read(va, len(b))
    if actual != b:
        raise ValueError('unexpected instruction bytes')
    return {'va': hex(va), 'bytes': actual.hex()}


def child_rows(view, start, end, expected_count, failure):
    # Fixed instruction sequence: load a box pointer, set up arguments, call,
    # compare the returned tag with the common success sentinel, branch on error.
    code = view.read(start, end - start)
    pattern = re.compile(rb'\x49\x8b\x56(.)\x48\x89\xe7\x48\x8d\x74\x24\x18\xe8(....)\x4c\x39\x24\x24', re.S)
    rows = []
    for m in pattern.finditer(code):
        site = start + m.start()
        c = site + 12
        br = site + 21
        target = call(view, c)
        fail = branch(view, br)
        if fail != failure:
            raise ValueError('unexpected child failure target')
        rows.append({'box_offset': m.group(1)[0], 'load_va': hex(site),
                     'call_va': hex(c), 'callee': hex(target),
                     'error_branch_va': hex(br), 'error_target': hex(fail)})
    if len(rows) != expected_count or [r['box_offset'] for r in rows] != list(range(8, 8 * (expected_count + 1), 8)):
        raise ValueError('unexpected child load sequence')
    return rows


def build(data):
    require_identity(data)
    return analyse(data)


def analyse(data):
    """Analyse already authenticated bytes; exposed for corruption controls."""
    view = View(data)
    _, fdes, _ = fde_extents(data)
    by_start = {f['start']: f for f in fdes}
    bodies = []
    for start, (end, digest) in sorted(BODIES.items()):
        if start not in by_start or by_start[start]['end'] != end:
            raise ValueError('FDE extent mismatch')
        raw = view.read(start, end - start)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != digest:
            raise ValueError('body SHA-256 mismatch')
        bodies.append({'start': hex(start), 'end_exclusive': hex(end), 'size': len(raw), 'sha256': actual})
    pins = [check(view, va, raw) for va, raw in [
        (0x1e5e472, 'c744244800040001'), (0x1e5e48a, 'ba0f000000'),
        (0x1e5e4c7, '498b060fb600'), (0x1e5e4cd, '488d0dbced55fe486304814801c8ffe0'),
        (0x1e5ed62, 'c744244800040001'), (0x1e5ed7a, 'ba10000000'),
        (0x1e5edbb, '498b06f20f10004c89ff'),
        (0x1e5d9d6, 'c784248000000000040001'), (0x1e5d9f6, 'ba08000000'),
        (0x1e5da37, '498b06833800'), (0x1e5da3d, '0f8477010000'), (0x1e5dbdc, 'c60430c0'),
        (0x1e5db88, '488d35be2358feba0a000000'),
        (0x1e5dc12, '488d35b7d43afeba08000000'),
        (0x1e5dc28, '488d353b2258feba07000000'),
        (0x1e5db70, '498b46180fb60085c0'), (0x1e5db7f, '83f801'),
        (0x1e0f3df, '488b124889e74c89f6'),
        (0x1e0ffa4, '0fb62a'), (0x1e0ffb6, '4080cdc2400fb6fd'),
        (0x1e0f51f, 'f20f10024c89ff'),
        (0x1e1098d, '833a01'), (0x1e10996, 'f20f1042084c89f7'),
        (0x1e10a79, 'c60430c0'), (0x1e0ef8d, '833a01'), (0x1e0ef96, '488b5208'),
        (0x1e0f085, 'c60430c0'), (0x1e0fced, '833a01'), (0x1e0fcf6, '488b5208'),
        (0x1e0fde5, 'c60430c0'), (0x1e0e25f, '488b124889e74c89f6'),
        (0x1e0f84d, '803a01'), (0x1e0f856, '48ffc2'),
        (0x1e0f870, 'be2a000000b914000000'), (0x1e0f87d, 'ff159d389603'), (0x1e0f969, 'c60430c0'),
    ]]
    groups = [
        {'writer': hex(0x1e5e450), 'count': struct.unpack('<I', view.read(0x1e5e48b, 4))[0],
         'first': 'four-way string selector',
         'children': child_rows(view, 0x1e5e55e, 0x1e5e6cb, 14, 0x1e5e709)},
        {'writer': hex(0x1e5ed40), 'count': struct.unpack('<I', view.read(0x1e5ed7b, 4))[0],
         'first': '64-bit scalar to floating-point writer',
         'children': child_rows(view, 0x1e5edd4, 0x1e5ef60, 15, 0x1e5efb4)},
    ]
    enum = []
    cases = [(0x1e5e4dd, 0x3dff5e, 5), (0x1e5e53e, 0x3dff63, 7),
             (0x1e5e50e, 0x3dff6a, 7), (0x1e5e526, 0x3dff71, 7)]
    for i, (arm, literal, length) in enumerate(cases):
        slot = 0x3bd290 + 4 * i
        dest = 0x3bd290 + struct.unpack('<i', view.read(slot, 4))[0]
        if dest != arm:
            raise ValueError('enum table mismatch')
        raw = view.read(arm, 7)
        if raw[:3] != b'\x48\x8d\x35' or arm + 7 + struct.unpack_from('<i', raw, 3)[0] != literal:
            raise ValueError('enum string reference mismatch')
        length_insn = view.read(arm + 12, 5)
        if length_insn[0] != 0xba or struct.unpack_from('<I', length_insn, 1)[0] != length:
            raise ValueError('enum string length mismatch')
        enum.append({'tag': i, 'table_entry_va': hex(slot), 'arm_va': hex(dest),
                     'literal_va': hex(literal), 'literal': view.read(literal, length).decode('ascii')})
    if [row['literal'] for row in enum] != ['Local', 'Sandbox', 'Testnet', 'Mainnet']:
        raise ValueError('enum literals differ')
    third = []
    for index, load, site, error in [(1,0x1e5da7a,0x1e5da88,0x1e5da92),
                                     (2,0x1e5da98,0x1e5db60,0x1e5db6a),
                                     (4,0x1e5dc46,0x1e5dc52,0x1e5dc5c),
                                     (5,0x1e5dc5e,0x1e5dc6c,0x1e5dc76),
                                     (6,0x1e5dc78,0x1e5dc86,0x1e5dc90),
                                     (7,0x1e5dc92,0x1e5dca0,0x1e5dcaa)]:
        op = view.read(load, 4)
        if op[:3] not in (b'\x49\x8b\x56', b'\x49\x8b\x76') or op[3] != index * 8:
            raise ValueError('unexpected third tuple pointer load')
        third.append({'element': index, 'box_offset': op[3], 'load_va': hex(load),
                      'call_va': hex(site), 'callee': hex(call(view, site)),
                      'error_branch_va': hex(error), 'error_target': hex(branch(view, error))})
    enum3 = []
    for tag, address, length in [(0,0x20b0d0,8),(1,0x3dff4d,10),(2,0x3dfe6a,7)]:
        enum3.append({'case': (str(tag) if tag < 2 else 'other'), 'literal_va': hex(address), 'literal': view.read(address,length).decode('ascii')})
    if [row['literal'] for row in enum3] != ['disabled', 'reduceOnly', 'enabled']:
        raise ValueError('third group literals differ')
    links = []
    for ordinal, site, expected in [(38, 0x281796c, 0x1e5e450),
                                    (39, 0x281861c, 0x1e5ed40),
                                    (40, 0x281754c, 0x1e5d9b0)]:
        target = call(view, site)
        if target != expected:
            raise ValueError('contextual call target mismatch')
        links.append({'prior_row': ordinal, 'call_va': hex(site), 'target': hex(target)})
    call_sites = [0x1e5e48f, 0x1e5ed7f, 0x1e5edc5, 0x1e5d9fb,
                  0x1e5da67, 0x1e5dac3, 0x1e5db10, 0x1e5dc21, 0x1e5db97, 0x1e5dc37,
                  0x1e0f3e8, 0x1e0ffbe, 0x1e0f526, 0x1e1099e, 0x1e0efa2, 0x1e0fd02, 0x1e0e268, 0x1e0f889]
    calls = [{'va': hex(a), 'target': hex(call(view, a))} for a in call_sites]
    branch_sites = [0x1e5e49c,0x1e5e558,0x1e5ed8c,0x1e5edce,0x1e5da09,
                    0x1e5da74,0x1e5da92,0x1e5dad1,0x1e5db1e,0x1e5db6a,
                    0x1e5db82,0x1e5dc40,0x1e5dc5c,0x1e5dc76,0x1e5dc90,0x1e5dcaa]
    branches = [{'va': hex(a), 'target': hex(branch(view,a))} for a in branch_sites]
    return {'input_sha256': hashlib.sha256(data).hexdigest(), 'coordinate_system': 'unrelocated ELF virtual address',
            'bodies': bodies, 'contextual_row_calls': links, 'instruction_pins': pins, 'groups': groups, 'first_group_enum': enum,
            'third_group': {'writer': hex(0x1e5d9b0), 'count': struct.unpack('<I',view.read(0x1e5d9f7,4))[0],
                            'children': third, 'string_cases': enum3},
            'selected_calls': calls, 'selected_jne_branches': branches}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    result = build(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    lines = ['writer\telement\tbox_offset\tload_va\tcall_va\tcallee\terror_target']
    for group in result['groups']:
        for i, row in enumerate(group['children'], 1):
            lines.append('\t'.join([group['writer'], str(i), hex(row['box_offset']), row['load_va'], row['call_va'], row['callee'], row['error_target']]))
    for row in result['third_group']['children']:
        lines.append('\t'.join([result['third_group']['writer'], str(row['element']), hex(row['box_offset']), row['load_va'], row['call_va'], row['callee'], row['error_target']]))
    (args.out / 'fields.tsv').write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
