#!/usr/bin/env python3
"""Authenticated node94 RawVec allocator-shim binding (0x454f420).

Binds the allocator the capacity growth helper calls (RE-001-crossroads-
callees-94) to the node #94 digest: the 234-byte body 0x454f420..0x454f50a
computes the aligned byte count (align + cap - 1) & -align multiplied by the
element size under an overflow guard against 0x8000000000000000 - align,
selects between four allocator entry points through a null-pointer branch and
a tzcnt power-of-two alignment check, and stores the {flag, pointer} result
— called directly from 253 sites across the complete .text. Static
byte/record checks only; the captured binary is never executed.
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

START, END = 0x454f420, 0x454f50a
FDE_VA = 0xedb6d4
OVERFLOW_BOUND = 0x8000000000000000
ERR_OVERFLOW = 8
ERR_OK = 0x10

# (offset, GOT slot, relocation target) allocator dispatch sites.
ALLOC_SITES = [
    (0x74, 0x576e288, 0x54c5610),   # grow, aligned
    (0x82, 0x576e030, 0x54c5620),   # grow
    (0xa7, 0x576e290, 0x54c2670),   # shrink, aligned
    (0xb2, 0x576dfd8, 0x54c06b0),   # alloc / dealloc
]

ANCHORS = [
    (0x11, '4b8d140f', 'align + capacity - 1'),
    (0x1e, '4821d0', 'aligned mask and'),
    (0x21, '48f7e1', 'multiply by element size'),
    (0x27, '0f90c0', 'multiply overflow flag'),
    (0x2a, '48b90000000000000080', 'i64::MIN bound constant'),
    (0x47, 'b808000000', 'overflow error code 8'),
    (0x59, '4983ff10', 'alignment 16 threshold'),
    (0x64, 'f3490fbcd7', 'tzcnt alignment power check'),
    (0x9a, 'f3490fbcf7', 'tzcnt alignment power check (second)'),
    (0xc1, 'b810000000', 'success code 16'),
    (0xd4, '4531e4', 'clear the failure flag'),
]

GROWTH_CALLER = 0x454e5e5          # RE-001-crossroads-callees-94 call site

BODY = bytes.fromhex(
'41574156415453504d89c74989d04889fb4b8d140f48ffca4c89f848f7d84821'
'd048f7e14989c60f90c048b900000000000000804c29f94939ce0f97c108c141'
'bc01000000740db8080000004531f6e9830000004885f674314983ff1077054d'
'39f77618f3490fbcd74885d2740e4c89c74c89f6ff15eeed2101eb3c4c89c74c'
'89f6ff1588eb2101eb2e4d85f674394983ff1077054d39f77615f3490fbcf748'
'85f6740b4c89f7ff15c3ed2101eb094c89f7ff1500eb21014885c0750e4c897b'
'08b810000000eb0f4c89f848894308b8100000004531e44c8934034c89234883'
'c4085b415c415e415fc3')

FDE = bytes.fromhex(
'34000000c0a11f00443d6703ea00000000420e10420e18420e20410e28410e30'
'83058c048e038f0202da0e28410e20420e18420e10420e08')

CALLERS = [
    0x42c81fe, 0x42cb7a0, 0x42d7e32, 0x42da1bb, 0x42e2b30, 0x42e2f33, 0x42e3b84, 0x432cb35,
    0x4335d22, 0x438a9da, 0x43b6b9e, 0x43b7549, 0x43ba200, 0x43d1d5c, 0x43e441b, 0x43e4c20,
    0x43e53a7, 0x43e6d88, 0x43e828d, 0x43f49d3, 0x43f4ebe, 0x43f6820, 0x43f6b70, 0x43f8c30,
    0x43f9670, 0x43f99ce, 0x43fa32c, 0x43fa4b2, 0x43facb6, 0x43fae8b, 0x43faefe, 0x43fb0bf,
    0x43fb406, 0x43fb53c, 0x43fbb6f, 0x43fbd66, 0x43fc338, 0x43fc804, 0x43fca1d, 0x43fcd18,
    0x440e6b3, 0x440e777, 0x440ef64, 0x440f016, 0x44354f0, 0x443564a, 0x4435943, 0x443bd1e,
    0x443bd92, 0x4442cfc, 0x4443cca, 0x4444bc4, 0x4445128, 0x444544c, 0x4445e09, 0x444ef94,
    0x446d78a, 0x44e3c8a, 0x44e3e99, 0x44e47d3, 0x44e4845, 0x44e4a2e, 0x44e4a76, 0x454e265,
    0x454e2d5, 0x454e345, 0x454e3b5, 0x454e425, 0x454e495, 0x454e505, 0x454e575, 0x454e5e5,
    0x454e655, 0x454e6c5, 0x454e735, 0x454e7a5, 0x454e815, 0x454e885, 0x454e8f5, 0x454e965,
    0x454e9d5, 0x454ea45, 0x454eab5, 0x454eb25, 0x454eb95, 0x454ec05, 0x454ec75, 0x454ece5,
    0x454ed55, 0x454edc5, 0x454ee35, 0x454eea5, 0x454ef15, 0x454ef85, 0x454eff5, 0x454f065,
    0x454f0d5, 0x454f145, 0x454f1b5, 0x454f225, 0x454f295, 0x454f305, 0x454f375, 0x454f3e5,
    0x454f593, 0x454f62f, 0x45a0eab, 0x466b62f, 0x46c045f, 0x46cdc27, 0x46cdcd0, 0x46d2574,
    0x46d478a, 0x46e1c98, 0x46e3864, 0x47500d2, 0x47ada5f, 0x47adc49, 0x47ae2f0, 0x48b2f9d,
    0x48b4fbc, 0x48bacaa, 0x48bafda, 0x48bb2b8, 0x48bbfb8, 0x48bcb6f, 0x48bddca, 0x48bead8,
    0x48bf3a8, 0x48bf6ba, 0x48bfdea, 0x48ccd87, 0x48ccde1, 0x48cce37, 0x48dae12, 0x48de5dd,
    0x48de754, 0x48e1f9e, 0x48e201d, 0x48e2071, 0x48e20e4, 0x48e2f74, 0x48e3496, 0x48fa2d5,
    0x48fb0d1, 0x48fbb01, 0x48feaf0, 0x4973cf9, 0x497428a, 0x4974822, 0x4974f7c, 0x497536c,
    0x49765f8, 0x4977479, 0x49e5ed4, 0x49e7675, 0x49e7a3d, 0x49e863d, 0x49fce28, 0x4ab01bf,
    0x4ab026c, 0x4aba0b3, 0x4aba2b6, 0x4abba37, 0x4abc602, 0x4ae99e1, 0x4ae9acc, 0x4ae9b34,
    0x4aea0aa, 0x4aea146, 0x4aea271, 0x4aea2b9, 0x4aea35d, 0x4aea501, 0x4aea5ec, 0x4aea654,
    0x4aea8f6, 0x4aea991, 0x4aeaa4c, 0x4aeaaac, 0x4aead8f, 0x4aeaea5, 0x4aeaf33, 0x4aeb054,
    0x4aeb0e3, 0x4aeb298, 0x4aeb339, 0x4aeb3ea, 0x4aeb491, 0x4aeb4de, 0x4aeba0e, 0x4aebbfa,
    0x4aebc8a, 0x4aebd54, 0x4aebe39, 0x4aebec8, 0x4aebf8f, 0x4aec036, 0x4aec65f, 0x4aecb63,
    0x4aecc1b, 0x4aece04, 0x4aece7c, 0x4aecf8c, 0x4aed00d, 0x4aed1bc, 0x4aed23b, 0x4aed3ee,
    0x4aed471, 0x4c0677d, 0x4c1456f, 0x4c1f810, 0x4c1f888, 0x4c1f8cf, 0x4c24843, 0x4c2fdc2,
    0x4c3bc68, 0x4c3e056, 0x4c3e0cc, 0x4c4467a, 0x4c44708, 0x4c47ff8, 0x4c4a9ea, 0x4c4ce38,
    0x4c51a3d, 0x4c53dac, 0x4c54023, 0x4c81a8a, 0x4c81ed2, 0x4c826b9, 0x4c82da2, 0x4cbe0d8,
    0x4cbe143, 0x4cbe1b7, 0x4cd7308, 0x4cd7380, 0x4cd7d36, 0x4d8999d, 0x4d8a13a, 0x4da1370,
    0x4da3b21, 0x4df649d, 0x4df6cda, 0x4df6fdc, 0x4df7304, 0x4df757c, 0x4df76b6, 0x4df7a40,
    0x4df80d0, 0x4df8500, 0x4df9095, 0x4dfc915, 0x4dfd066,
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def aligned_bytes(align, capacity, size):
    """Decoded 0x454f431..0x454f447: ceil-pow2 alignment times element size."""
    return ((align + capacity - 1) & -align) * size


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
    require(body == BODY, 'Allocator shim body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Allocator shim FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Anchor changed: {label}')

    for offset, got, target in ALLOC_SITES:
        require(body[offset:offset + 2] == bytes.fromhex('ff15'),
                f'allocator call opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', body, offset + 2)[0]
        require(START + offset + 6 + disp == got, f'allocator GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'allocator target for GOT {got:#x} changed')

    # Aligned-bytes identity on a grid.
    for align in (1, 2, 4, 8, 16, 32):
        require(align & (align - 1) == 0, 'grid aligns must be powers of two')
        for capacity in (0, 1, 2, 3, 5, 8, 15, 16, 17, 100, 4096):
            for size in (1, 8, 24):
                got = aligned_bytes(align, capacity, size)
                expected = -(-capacity // align) * align * size if capacity else 0
                require(got == expected,
                        f'Aligned-bytes identity failed for {align}/{capacity}/{size}')
                require(got <= OVERFLOW_BOUND - align,
                        'grid result would trip the overflow guard')

    # Census over the whole .text: direct-call shim, no GOT slot, no lea.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, indirect, lea = [], [], []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if rels.get(slot) == START:
                indirect.append(text['address'] + pos)
        pos += 2
    for m in range(len(code) - 7):
        if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
            d = struct.unpack_from('<i', code, m + 3)[0]
            if text['address'] + m + 7 + d == START:
                lea.append(text['address'] + m)
    require(direct == CALLERS,
            f'Direct caller census changed: {len(direct)} sites')
    require(indirect == [] and lea == [], 'Unexpected indirect or lea references')
    require(GROWTH_CALLER in direct, 'growth helper call site missing')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        alloc_shim=dict(start_va=hex(START), end_va_exclusive=hex(END),
                        bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                        fde_va=hex(FDE_VA),
                        inferred_label='RawVec-style allocator shim with an '
                                       'aligned-capacity overflow guard'),
        alignment=dict(formula='((align + capacity - 1) & -align) * size',
                       overflow_bound='0x8000000000000000 minus align',
                       grid='powers of two x capacities x sizes, all below the bound',
                       threshold=16, tzcnt_checks=2),
        dispatch=[dict(offset=hex(o), got=hex(g), target=hex(t))
                  for o, g, t in ALLOC_SITES],
        error_codes=dict(overflow=ERR_OVERFLOW, success=ERR_OK),
        call_census=dict(direct_sites=len(CALLERS), got_indirect=0, lea_refs=0,
                         growth_caller=hex(GROWTH_CALLER),
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
        cross_links=dict(growth_helper='0x454e5b0 (RE-001-crossroads-callees-94)'),
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
