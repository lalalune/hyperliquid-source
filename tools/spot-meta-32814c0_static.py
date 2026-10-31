#!/usr/bin/env python3
"""Authenticated node94 spot-meta-32814c0 binding (0x32814c0).

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

START, END = 0x32814c0, 0x32815ef
FDE_VA = 0xde5eac
FDE = bytes.fromhex(
    '24000000984910000cb649022f01000000410e1002600e08410e104d0e08410e'
    '1002be0e08000000'
)
BODY = bytes.fromhex(
    '504989d041b9010000004885f6742c483bb1880100000f83ef000000488b8980'
    '0100004869d6e80000000fb64411492a4411480f82af00000075354889f849f7'
    'e00f80ae0000004889c14c09c948c1e920740f31d249f7f14889c2b801000000'
    '59c331d241f7f189c2b80100000059c30fb6c8f6c101740b41b90a00000083f9'
    '0174b8a802740e4d6bc96489ca83e2fe83fa0274a6a80474114d69c910270000'
    '89ca83e2fc83fa047491a80874154d69c900e1f50589ca83e2f883fa080f8478'
    'ffffffa810742148ba0000c16ff28623004c89c848f7e2700f4989c183e1f083'
    'f9100f8453ffffff488d3dc10c4702ff15bbce4e024889f84c09c848c1e82074'
    '174889f831d249f7f1eb14488d3d1e0c4702ff1598ce4e0289f831d241f7f149'
    'f7e04889c2b8000000000f91c059c3'
)
BODY_SHA256 = 'e23ca524203c393153a2c299c09e993d962353136783cd0610e598647f1cc23a'
BRANCHES = [
    (0xd, '742c', 1, 2, 0x32814fb),
    (0x16, '0f83ef000000', 2, 6, 0x32815cb),
    (0x33, '0f82af000000', 2, 6, 0x32815a8),
    (0x39, '7535', 1, 2, 0x3281530),
    (0x41, '0f80ae000000', 2, 6, 0x32815b5),
    (0x51, '740f', 1, 2, 0x3281522),
    (0x76, '740b', 1, 2, 0x3281543),
    (0x81, '74b8', 1, 2, 0x32814fb),
    (0x85, '740e', 1, 2, 0x3281555),
    (0x93, '74a6', 1, 2, 0x32814fb),
    (0x97, '7411', 1, 2, 0x328156a),
    (0xa8, '7491', 1, 2, 0x32814fb),
    (0xac, '7415', 1, 2, 0x3281583),
    (0xbd, '0f8478ffffff', 2, 6, 0x32814fb),
    (0xc5, '7421', 1, 2, 0x32815a8),
    (0xd7, '700f', 1, 2, 0x32815a8),
    (0xe2, '0f8453ffffff', 2, 6, 0x32814fb),
    (0xff, '7417', 1, 2, 0x32815d8),
    (0x109, 'eb14', 1, 2, 0x32815df),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x32815af, 0x576e470),
    (0x32815d2, 0x576e470),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x32815a8, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x32815cb, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
]
CALLERS = [0x26fd9cf, 0x26feb1c, 0x2723dd8, 0x272425e, 0x3262385, 0x371d55c, 0x371d579, 0x372dccb, 0x372dcfd, 0x372def4, 0x372dfef, 0x372fc52, 0x3756d6f, 0x375fb22, 0x4ce535f, 0x4ce5acf, 0x4ce79ac, 0x4ce7e9c, 0x4d298ce, 0x4d29d9e, 0x4d2a228]
CALLER_FUNCTIONS = {'0x26fd9cf': ('0x26fd370', '0x26fdae8'), '0x26feb1c': ('0x26fe810', '0x26fecfe'), '0x2723dd8': ('0x2723c70', '0x27240a3'), '0x272425e': ('0x27240b0', '0x272457e'), '0x3262385': ('0x3261c40', '0x3262583'), '0x371d55c': ('0x371d120', '0x371d621'), '0x371d579': ('0x371d120', '0x371d621'), '0x372dccb': ('0x372d970', '0x372e097'), '0x372dcfd': ('0x372d970', '0x372e097'), '0x372def4': ('0x372d970', '0x372e097'), '0x372dfef': ('0x372d970', '0x372e097'), '0x372fc52': ('0x372faa0', '0x3730b3d'), '0x3756d6f': ('0x37568b0', '0x3757149'), '0x375fb22': ('0x375fa80', '0x375fb47'), '0x4ce535f': ('0x4ce4d00', '0x4ce5470'), '0x4ce5acf': ('0x4ce5470', '0x4ce5be0'), '0x4ce79ac': ('0x4ce76a0', '0x4ce7b8e'), '0x4ce7e9c': ('0x4ce7b90', '0x4ce807e'), '0x4d298ce': ('0x4d29720', '0x4d29bee'), '0x4d29d9e': ('0x4d29bf0', '0x4d2a0be'), '0x4d2a228': ('0x4d2a0c0', '0x4d2a4f3')}
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

