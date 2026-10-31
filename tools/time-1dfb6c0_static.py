#!/usr/bin/env python3
"""Authenticated node94 time-1dfb6c0 binding (0x1dfb6c0).

Machine-derived static binding: FDE record, body bytes, every branch
destination, every direct and GOT-mediated call site, every panic
Location, and the whole-.text caller census, all checked byte-exactly
against the authenticated node #94 digest. Static checks only; the
captured binary is never executed.
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

START, END = 0x1dfb6c0, 0x1dfbc8c
FDE_VA = 0x104472c
FDE = bytes.fromhex(
    '50000000046b08008c6fdb00cc05000004d3de94ff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f03860203eb040e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004989cd4989f44889fb49be00000000'
    '00000080488b364889f048f7d8711a48895c24284d8b7c242841807f0c02751c'
    '4c896c244831c0eb4241807c241c020f859f00000031c0e9ba0000004889d348'
    '8d7c24104c89feba02000000e89fe47a00488b4424104883f8020f854c010000'
    '4c896c24484c89f04889da488944247848c78424800000000100000048c78424'
    '88000000000000004c89bc2490000000c784249800000002000000488d7c2410'
    '488d742478e816190100498d5e0448395c24100f85c20000004c8b7c24784d39'
    'f70f850e0200004c8bac2490000000e9bf020000498b4424104839c60f840504'
    '0000498b4c2408c604019248ffc049894424104c89f0488944245048c7442458'
    '0100000048c7442460000000004c89642468c744247002000000488d7c241048'
    '8d742450e8b71e01004d8d7e044c397c24107518488b4424504c39f00f858400'
    '0000488b6c2468e94f010000488b44242048894424400f104424100f29442430'
    '4c8b7424504a8d0475000000004885c00f84b6020000e9d5020000488b442420'
    '488b4c2428488941100f104424100f11014c8b7424784a8d0475000000004885'
    'c00f842e030000e916030000488b4c2418488b5424284c89324889420848894a'
    '10e90f0300004889442408bf3bf90a00ff15da2f970385c00f8437030000bf3b'
    'f90a00ff15c72f970385c00f8424030000488b6c24688b542470488dbc24a800'
    '00004889eee8b6e17a00488b8424a80000004883f8020f85a80100004c89bc24'
    'a00000004c896c244848895c24284c8b7c24584c8b6c24604d85ed743231db90'
    '410fb6141f488dbc24a80000004889eee80b047b00488b8424a80000004883f8'
    '020f857101000048ffc34939dd75d1488b7424084885f6740b4c89ff31d2ff15'
    'ac2697034c89742450488b5c24284c8b6c24484c8bbc24a0000000488d7c2410'
    '4c89ee4889eae845a4ae004c397c24100f854b010000488d7c2430488d742450'
    'e8db7001004c397c24300f8463010000e992010000bf3bf90a00ff15d02e9703'
    '85c00f8449020000bf3bf90a00ff15bd2e970385c00f84360200004c8bac2490'
    '0000008b942498000000488d7c24304c89eee8d9e17a00488b4424304883f802'
    '0f85a80000004c897c24084c8bbc24800000004c8ba424880000004d85e47439'
    '31ed66666666662e0f1f840000000000410fb6142f488d7c24304c89eee88e06'
    '7b00488b4424304883f8020f850901000048ffc54939ec75d7488b7424084885'
    'f6740b4c89ff31d2ff15a22597034c89742478488d7c2410488b7424484c89ea'
    'e81bb5ae0048395c2410488b7c24280f85e6000000488d742478e821710100e9'
    '11010000488b8c24b0000000eb1f488b4c2438e9ac000000488b8c24b0000000'
    '488b5c24284c8bbc24a00000004c89742410488944241848894c24204c8b7424'
    '08488b4424204889442440488b4424104889442430488b44241848894424384a'
    '8d0475000000004885c075244c397c24307534418b44242083f8ff0f84e30000'
    '00ffc041894424204c893be985000000488b7c24584c89f631d2ff15d0249703'
    '4c397c243074cc488b442440488943100f284424300f1103eb5b488b4c24384c'
    '8b7c24084c89742410488944241848894c24204d89fe488b7c2428488b442420'
    '48894710488b442410488907488b442418488947084a8d0475000000004885c0'
    '7413488bbc24800000004c89f631d2ff155b2497034881c4b80000005b415c41'
    '5d415e415f5dc34989df4889d3ba01000000b90100000041b8010000004c89e7'
    'e88bf471004889da4c89fb498b442410e9cdfbffff488d3dfcee8603ff156e28'
    '9703eb1a488d3d4d2e8903ff1507259703488d3de0ee8603ff15522897030f0b'
    '4889c3eb124889c3eb364889c3488b4424784889442408488b442408488d0445'
    '000000004885c0743b488bbc2480000000eb244889c3488b4424504889442408'
    '488b442408488d0445000000004885c07412488b7c2458488b74240831d2ff15'
    '8c2397034889dfe884448603'
)
BODY_SHA256 = '71dfc84de573bad9e18f130da276800e11b439736341e12a81e4cf8723299aa8'
BRANCHES = [
    (0x2d, '711a', 1, 2, 0x1dfb709),
    (0x3e, '751c', 1, 2, 0x1dfb71c),
    (0x47, 'eb42', 1, 2, 0x1dfb74b),
    (0x4f, '0f859f000000', 2, 6, 0x1dfb7b4),
    (0x57, 'e9ba000000', 1, 5, 0x1dfb7d6),
    (0x7a, '0f854c010000', 2, 6, 0x1dfb88c),
    (0xd3, '0f85c2000000', 2, 6, 0x1dfb85b),
    (0xe1, '0f850e020000', 2, 6, 0x1dfb9b5),
    (0xef, 'e9bf020000', 1, 5, 0x1dfba73),
    (0xfc, '0f8405040000', 2, 6, 0x1dfbbc7),
    (0x152, '7518', 1, 2, 0x1dfb82c),
    (0x15c, '0f8584000000', 2, 6, 0x1dfb8a6),
    (0x167, 'e94f010000', 1, 5, 0x1dfb97b),
    (0x190, '0f84b6020000', 2, 6, 0x1dfbb0c),
    (0x196, 'e9d5020000', 1, 5, 0x1dfbb30),
    (0x1c1, '0f842e030000', 2, 6, 0x1dfbbb5),
    (0x1c7, 'e916030000', 1, 5, 0x1dfbba2),
    (0x1e1, 'e90f030000', 1, 5, 0x1dfbbb5),
    (0x1f8, '0f8437030000', 2, 6, 0x1dfbbf5),
    (0x20b, '0f8424030000', 2, 6, 0x1dfbbf5),
    (0x236, '0f85a8010000', 2, 6, 0x1dfbaa4),
    (0x25b, '7432', 1, 2, 0x1dfb94f),
    (0x281, '0f8571010000', 2, 6, 0x1dfbab8),
    (0x28d, '75d1', 1, 2, 0x1dfb920),
    (0x297, '740b', 1, 2, 0x1dfb964),
    (0x2d0, '0f854b010000', 2, 6, 0x1dfbae1),
    (0x2ea, '0f8463010000', 2, 6, 0x1dfbb13),
    (0x2f0, 'e992010000', 1, 5, 0x1dfbb47),
    (0x302, '0f8449020000', 2, 6, 0x1dfbc11),
    (0x315, '0f8436020000', 2, 6, 0x1dfbc11),
    (0x340, '0f85a8000000', 2, 6, 0x1dfbaae),
    (0x35e, '7439', 1, 2, 0x1dfba59),
    (0x38b, '0f8509010000', 2, 6, 0x1dfbb5a),
    (0x397, '75d7', 1, 2, 0x1dfba30),
    (0x3a1, '740b', 1, 2, 0x1dfba6e),
    (0x3cf, '0f85e6000000', 2, 6, 0x1dfbb7b),
    (0x3df, 'e911010000', 1, 5, 0x1dfbbb5),
    (0x3ec, 'eb1f', 1, 2, 0x1dfbacd),
    (0x3f3, 'e9ac000000', 1, 5, 0x1dfbb64),
    (0x44a, '7524', 1, 2, 0x1dfbb30),
    (0x451, '7534', 1, 2, 0x1dfbb47),
    (0x45b, '0f84e3000000', 2, 6, 0x1dfbc04),
    (0x46b, 'e985000000', 1, 5, 0x1dfbbb5),
    (0x485, '74cc', 1, 2, 0x1dfbb13),
    (0x498, 'eb5b', 1, 2, 0x1dfbbb5),
    (0x4e0, '7413', 1, 2, 0x1dfbbb5),
    (0x530, 'e9cdfbffff', 1, 5, 0x1dfb7c2),
    (0x542, 'eb1a', 1, 2, 0x1dfbc1e),
    (0x563, 'eb12', 1, 2, 0x1dfbc37),
    (0x568, 'eb36', 1, 2, 0x1dfbc60),
    (0x587, '743b', 1, 2, 0x1dfbc84),
    (0x591, 'eb24', 1, 2, 0x1dfbc77),
    (0x5b0, '7412', 1, 2, 0x1dfbc84),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x1dfb72c, 0x25a9bd0),
    (0x1dfb785, 0x1e0d0a0),
    (0x1dfb804, 0x1e0d6c0),
    (0x1dfb8e5, 0x25a9aa0),
    (0x1dfb930, 0x25abd40),
    (0x1dfb986, 0x28e5dd0),
    (0x1dfb9a0, 0x1e12a80),
    (0x1dfb9f2, 0x25a9bd0),
    (0x1dfba3d, 0x25ac0d0),
    (0x1dfba80, 0x28e6fa0),
    (0x1dfba9a, 0x1e12bc0),
    (0x1dfbbe0, 0x251b070),
    (0x1dfbc87, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x1dfb8b0, 0x576e890),
    (0x1dfb8c3, 0x576e890),
    (0x1dfb95e, 0x576e010),
    (0x1dfb9ba, 0x576e890),
    (0x1dfb9cd, 0x576e890),
    (0x1dfba68, 0x576e010),
    (0x1dfbb3a, 0x576e010),
    (0x1dfbbaf, 0x576e010),
    (0x1dfbbfc, 0x576e470),
    (0x1dfbc0b, 0x576e118),
    (0x1dfbc18, 0x576e470),
    (0x1dfbc7e, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x1dfbbf5, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
    (0x1dfbc04, 0x568ea58, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f726d702d73657264652d312e332e302f7372632f656e636f64652e7273'), 525, 17),
    (0x1dfbc11, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
]
CALLERS = [0x1e3123f, 0x1e3136e]
CALLER_FUNCTIONS = {'0x1e3123f': ('0x1e31180', '0x1e3140b'), '0x1e3136e': ('0x1e31180', '0x1e3140b')}
LEA_REFS = 0
OWN_GOT_SLOTS = []
GOT_SITES = {}


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
    body = reader.read(START, END - START)
    require(body == BODY, 'Body bytes changed')
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Body hash changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'],
            'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in BRANCHES:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Branch instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(START <= destination < END, 'Branch escapes body')

    for offset, pattern, rel_pos, insn_len, destination in TAIL_CALLS:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Tail-jump instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Tail-jump destination changed at +{offset:#x}')
        require(not (START <= destination < END), 'Tail jump stayed inside the body')

    for site, target in DIRECT_CALLS:
        off = site - START
        require(body[off] == 0xe8, f'Direct call opcode changed at {site:#x}')
        rel = struct.unpack_from('<i', body, off + 1)[0]
        require(site + 5 + rel == target,
                f'Direct call destination changed at {site:#x}')

    rels = relocations(reader)
    for site, slot in INDIRECT_CALLS:
        off = site - START
        require(body[off:off + 2] == b'\xff\x15',
                f'Indirect call opcode changed at {site:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(site + 6 + disp == slot,
                f'Indirect call slot changed at {site:#x}')

    seen = []
    for site, loc_va, path, line, column in LOCATIONS:
        off = site - START
        require(body[off:off + 3] in (b'\x48\x8d\x3d', b'\x48\x8d\x15',
                                      b'\x4c\x8d\x1d'),
                f'Location lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == loc_va,
                f'Location address changed at {site:#x}')
        path_va = rels.get(loc_va)
        require(path_va is not None, f'Location relocation missing at {loc_va:#x}')
        length_, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, line_, column_) == (len(path), line, column),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'panic path changed at {loc_va:#x}')
        seen.append(dict(location_va=hex(loc_va), line=line, column=column,
                         path=path.decode().rsplit('src/', 1)[-1]))

    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = (text['address'] + pos + 5
                           + struct.unpack_from('<i', code, pos + 1)[0])
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, f'Direct caller census changed: {[hex(x) for x in direct]}')

    lea_refs = 0
    pos = 0
    while (pos := code.find(b'\x48\x8d', pos)) >= 0:
        if pos + 7 <= len(code) and (code[pos + 2] & 0xC7) == 0x05:
            destination = (text['address'] + pos + 7
                           + struct.unpack_from('<i', code, pos + 3)[0])
            if destination == START:
                lea_refs += 1
        pos += 1
    require(lea_refs == LEA_REFS, f'lea census changed: {lea_refs}')

    from collections import Counter
    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        body=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                  sha256=BODY_SHA256, fde_va=hex(FDE_VA)),
        locations=seen,
        direct_calls={hex(t): n for t, n in Counter(t for _, t in DIRECT_CALLS).items()},
        tail_calls={hex(t): n for t, n in Counter(t for _, _, _, _, t in TAIL_CALLS).items()},
        indirect_got={hex(slot): n for slot, n in
                      Counter(slot for _, slot in INDIRECT_CALLS).items()},
        call_census=dict(direct_e8=[hex(x) for x in CALLERS], lea_references=LEA_REFS,
                         caller_functions=CALLER_FUNCTIONS,
                         own_got_slots=OWN_GOT_SLOTS, got_sites=GOT_SITES,
                         denominator='complete .text scan for e8 and lea encodings'),
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

