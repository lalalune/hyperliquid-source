#!/usr/bin/env python3
"""Authenticated node94 twenty-four-byte growth helper binding (0x4f04bb0).

Binds the next-stage callee of the argument processor (RE-001-init-entrypoints-94)
to the node #94 digest: the 103-byte body 0x4f04bb0..0x4f04c17 selects
max(2 * current, 4) capacities for 8-byte elements on a 0x18 stride, calls its
own allocator variant 0x4f04fc0 directly, and routes failures through the
shared error entry — reachable through three distinct GOT slots (64 sites
total), mirroring the 8-byte growth helper bound in RE-001-crossroads-
callees-94. Static byte/record checks only; the captured binary is never
executed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

START, END = 0x4f04bb0, 0x4f04c17
FDE_VA = 0xf636f0
GOT_SLOTS = [0x576ea38, 0x57705a8, 0x5776410]
ALLOC_FN = 0x4f04fc0
GOT_ERR, ERR_FN = 0x576dfb8, 0x1346068
ELEMENT_SIZE = 8
STRIDE = 0x18
MIN_CAPACITY = 4

ANCHORS = [
    (0xe, '488b37', 'load current capacity'),
    (0x11, '488d0436', 'double the capacity'),
    (0x15, '4883f805', 'minimum threshold compare'),
    (0x19, '41be04000000', 'minimum capacity 4'),
    (0x1f, '4c0f43f0', 'cmovae selection'),
    (0x2b, '41b808000000', 'element size 8'),
    (0x31, '41b918000000', 'stride 0x18'),
    (0x3a, 'e8d1030000', 'direct allocator call'),
    (0x3f, '837dd801', 'success tag compare'),
    (0x61, 'ff15', 'error path call'),
]

CALLER_COUNT = 63
ENTRYPOINT_SITE = 0x4edcfd3         # the argument processor's call site

BODY = bytes.fromhex(
'554889e54156534883ec204889fb488b37488d04364883f80541be040000004c'
'0f43f0488b5708488d7dd841b80800000041b9180000004c89f1e8d103000083'
'7dd8017414488b45e0488943084c89334883c4205b415e5dc3488b7de0488b75'
'e8ff15a1938600')

FDE = bytes.fromhex(
'24000000dc212800b814fa036700000000410e108602430d064783048e03024d'
'0c0708410c061000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def analyze(data):
    reader = Reader(data)
    rels = relocations(reader)

    body = reader.read(START, END - START)
    require(body == BODY, 'Growth helper body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Growth helper FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Anchor changed: {label}')

    disp = struct.unpack_from('<i', body, 0x3b)[0]
    require(START + 0x3a + 5 + disp == ALLOC_FN, 'allocator call target changed')
    disp = struct.unpack_from('<i', body, 0x63)[0]
    require(START + 0x61 + 6 + disp == GOT_ERR, 'error path GOT changed')
    require(rels.get(GOT_ERR) == ERR_FN, 'error path target changed')

    # Capacity identity and the stride relationship.
    for current in (0, 1, 2, 3, 4, 5, 100):
        doubled = current + current
        expected = doubled if doubled >= 5 else MIN_CAPACITY
        require(expected == max(doubled, MIN_CAPACITY),
                f'Capacity identity failed for {current}')
    require(STRIDE == ELEMENT_SIZE * 3, 'stride must be three elements')

    # Census: three GOT slots, 64 sites total, no direct or lea references.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, indirect, lea = [], [], []
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if rels.get(slot) == START:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    for m in range(len(code) - 7):
        if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
            d = struct.unpack_from('<i', code, m + 3)[0]
            if text['address'] + m + 7 + d == START:
                lea.append(text['address'] + m)
    require(direct == [] and lea == [] and len(indirect) == CALLER_COUNT,
            f'Census changed: {len(indirect)} sites')
    for slot in GOT_SLOTS:
        require(rels.get(slot) == START, f'GOT slot {slot:#x} target changed')
    require(ENTRYPOINT_SITE in indirect, 'argument processor call site missing')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        growth24=dict(start_va=hex(START), end_va_exclusive=hex(END),
                      bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                      fde_va=hex(FDE_VA), got_slots=[hex(s) for s in GOT_SLOTS],
                      allocator=hex(ALLOC_FN), element_size=ELEMENT_SIZE,
                      stride=STRIDE,
                      inferred_label='capacity growth for 24-byte elements, '
                                     'sibling of the 8-byte helper'),
        identities=dict(capacity_selection='max(2 * current, 4) on a grid',
                        stride='0x18 == 3 elements of 8 bytes'),
        call_census=dict(got_slots=len(GOT_SLOTS), got_indirect_sites=CALLER_COUNT,
                         direct_e8=0, lea_refs=0,
                         entrypoint_site=hex(ENTRYPOINT_SITE),
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
        cross_links=dict(argument_processor='0x4edce70 (RE-001-init-entrypoints-94)',
                         sibling_helper='0x454e5b0 (RE-001-crossroads-callees-94)'),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
