#!/usr/bin/env python3
"""Authenticated node94 books-371cf40 binding (0x371cf40).

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

START, END = 0x371cf40, 0x371d113
FDE_VA = 0xe4c5fc
FDE = bytes.fromhex(
    '60000000e8b016003c098d02d301000000420e10420e18420e20420e28410e30'
    '83068c058d048e038f0202950e28420e20420e18420e10420e08450e3002b50e'
    '28420e20420e18420e10420e08450e30430e28420e20420e18420e10420e0841'
    '0e300000'
)
BODY = bytes.fromhex(
    '4157415641554154534885f60f845b010000488b8f980100004839ce0f835701'
    '0000488d5f104c8b87900100004869c6e80000004d8b4c00584d8b540060488b'
    '8778010000488bb7800100004e8d1cd5000000004531f6660f1f840000000000'
    '4d39f374464b8b3c314839f70f83140100004989ff49c1e7054983c6084a837c'
    '38080075db488b72104839f70f83010100004869ffd800000048037a085b415c'
    '415d415e415fe9e5b0b5ff4d85d20f84b90000004d8b314939f60f83e0000000'
    '4c89f748c1e705488b7c38084839cf0f83a40000004869ffe8000000498b4c38'
    '584d8b44386049c1e0034531c90f1f004d39c874784a8b3c094839f70f838400'
    '00004989fa49c1e2054983c1084a837c10080075db4c8b7a104c39ff0f838e00'
    '00004c8b62084869ffd80000004c01e7e85bb0b5ff4d39fe0f83820000004989'
    'c54969c6d80000004901c44c89e7e83db0b5ff4c89ef4889c64c89f24889d95b'
    '415c415d415e415fe9e340b6ff31c05b415c415d415e415fc3488d3d3051fd01'
    'ff15aa130502488d150b4ffd01ff15f50e0502488d15ce2cfc01ff15e80e0502'
    '488d15f14efd014c89f7ff15d80e0502488d15b12cfc014c89feff15c80e0502'
    '488d15a12cfc014c89f74c89feff15b50e0502'
)
BODY_SHA256 = 'fb1c9c8a08523c12769a53fba12c6f80f74a6293dd2dd3f8d7ceb893846215b2'
BRANCHES = [
    (0xc, '0f845b010000', 2, 6, 0x371d0ad),
    (0x1c, '0f8357010000', 2, 6, 0x371d0b9),
    (0x63, '7446', 1, 2, 0x371cfeb),
    (0x6c, '0f8314010000', 2, 6, 0x371d0c6),
    (0x83, '75db', 1, 2, 0x371cfa0),
    (0x8c, '0f8301010000', 2, 6, 0x371d0d3),
    (0xae, '0f84b9000000', 2, 6, 0x371d0ad),
    (0xba, '0f83e0000000', 2, 6, 0x371d0e0),
    (0xcf, '0f83a4000000', 2, 6, 0x371d0b9),
    (0xf3, '7478', 1, 2, 0x371d0ad),
    (0xfc, '0f8384000000', 2, 6, 0x371d0c6),
    (0x113, '75db', 1, 2, 0x371d030),
    (0x11c, '0f838e000000', 2, 6, 0x371d0f0),
    (0x138, '0f8382000000', 2, 6, 0x371d100),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
    (0xa6, 'e9e5b0b5ff', 1, 5, 0x32780d0),
    (0x168, 'e9e340b6ff', 1, 5, 0x3281190),
]
DIRECT_CALLS = [
    (0x371d070, 0x32780d0),
    (0x371d08e, 0x32780d0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x371d0c0, 0x576e470),
    (0x371d0cd, 0x576dfc8),
    (0x371d0da, 0x576dfc8),
    (0x371d0ea, 0x576dfc8),
    (0x371d0fa, 0x576dfc8),
    (0x371d10d, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x371d0b9, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x371d0c6, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x371d0d3, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x371d0e0, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x371d0f0, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x371d100, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774910']
GOT_SITES = {'0x5774910': ['0x26fd6cf', '0x26fdb4e', '0x2700a80', '0x2700ad7', '0x2700bdf', '0x2701266', '0x2711029', '0x271159c', '0x2713cfa', '0x2715f3f', '0x271679a', '0x2716cf8', '0x2716d42', '0x2717207', '0x27286bc', '0x272c326', '0x2734a47', '0x3273d8c', '0x3273ec4', '0x371b73b', '0x371fcda', '0x4ce505f', '0x4ce57cf', '0x4ce5c46', '0x4ce60ee', '0x4ceaeb7', '0x4ceaf01', '0x4ceaff7', '0x4ceb6b2', '0x4cec969', '0x4cec9c6', '0x4cecac2', '0x4ced194', '0x4d02639', '0x4d02c49', '0x4d031bc', '0x4d037fc', '0x4d06d5b', '0x4d0851b', '0x4d0b345', '0x4d0bb81', '0x4d0cc15', '0x4d0d451', '0x4d0d9a8', '0x4d0d9f2', '0x4d0dd68', '0x4d0ddb2', '0x4d0e267', '0x4d0ea97', '0x4d306f9', '0x4d31069', '0x4d37db6', '0x4d39051', '0x4d410b7', '0x4d4504d']}


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

