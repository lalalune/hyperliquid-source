#!/usr/bin/env python3
"""Authenticated node94 books-3730b40 binding (0x3730b40).

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

START, END = 0x3730b40, 0x3730d69
FDE_VA = 0xe4d430
FDE = bytes.fromhex(
    '400000001cbf160008378e022902000000420e10420e18420e20420e28410e30'
    '440e5083068c058d048e038f0203e1010e30410e28420e20420e18420e10420e'
    '08410e50'
)
BODY = bytes.fromhex(
    '4157415641554154534883ec204889f3488bb7800100004839f30f83e9010000'
    '4989d64989fd4c8d7f10488b87780100004889d948c1e1054c8b24084c89ff4c'
    '89e6ff151026040284c074400fb6c083f8010f8590000000498b76104839f30f'
    '83b4010000498b46084869cbd8000000488d34084881c680000000488d7c2408'
    'e8ab7f4e0031c0e95e010000498b76104839f30f8380010000498b46084869cb'
    'd8000000488d34084881c680000000488d7c2408e8777f4e00488b4c2408488b'
    '5424104889d64821ce4889d04831c848d1e84801f04885d2480f44c24885c948'
    '0f44c1e9020100004c896424084983bd98000000000f84ed000000498dbda000'
    '0000488d742408e854b826004889c648c1ee39498b8d80000000498b95880000'
    '00660f6ec6660f60c0f20f70c000660f70c044488d71f031ff660f76c94821d0'
    'f30f6f1401660f6fda660f74d866440fd7c34585c0742af3450fbcc84901c149'
    '21d14d89ca49c1e2044989f34d29d34d3b237428458d48ff664521c14589c875'
    'd6660f74d166440fd7c24585c075594801f84883c0104883c710eba149f7d949'
    'c1e1044a8b5409f84c893c24488d7c2408b9010000004c89fe4989d84d89f1ff'
    '15fb500402807c240801741c488b4c2410488b4424184885c90f94c24885c040'
    '0f94c64008d6741031c04883c4205b415c415d415e415fc34889c24821ca4831'
    'c848d1e84801d0ebe1488d158812fc014889dfff156fd20302488d1548f0fa01'
    '4889dfff155fd20302'
)
BODY_SHA256 = '18e1188af8ee39d049be1a60b5004e1024e8a1d33257c95cd180ea585db9652d'
BRANCHES = [
    (0x1a, '0f83e9010000', 2, 6, 0x3730d49),
    (0x4a, '7440', 1, 2, 0x3730bcc),
    (0x52, '0f8590000000', 2, 6, 0x3730c28),
    (0x5f, '0f83b4010000', 2, 6, 0x3730d59),
    (0x87, 'e95e010000', 1, 5, 0x3730d2a),
    (0x93, '0f8380010000', 2, 6, 0x3730d59),
    (0xe3, 'e902010000', 1, 5, 0x3730d2a),
    (0xf5, '0f84ed000000', 2, 6, 0x3730d28),
    (0x155, '742a', 1, 2, 0x3730cc1),
    (0x172, '7428', 1, 2, 0x3730cdc),
    (0x17f, '75d6', 1, 2, 0x3730c97),
    (0x18d, '7559', 1, 2, 0x3730d28),
    (0x19a, 'eba1', 1, 2, 0x3730c7d),
    (0x1ca, '741c', 1, 2, 0x3730d28),
    (0x1e6, '7410', 1, 2, 0x3730d38),
    (0x207, 'ebe1', 1, 2, 0x3730d2a),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3730bc0, 0x3c18b70),
    (0x3730bf4, 0x3c18b70),
    (0x3730c47, 0x399c4a0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3730b82, 0x5773198),
    (0x3730cff, 0x5775e00),
    (0x3730d53, 0x576dfc8),
    (0x3730d63, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3730d49, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x3730d59, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774e10']
GOT_SITES = {'0x5774e10': ['0x2774098', '0x4336eb9', '0x4337ae9']}


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

