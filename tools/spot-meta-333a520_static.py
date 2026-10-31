#!/usr/bin/env python3
"""Authenticated node94 spot-meta-333a520 binding (0x333a520).

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

START, END = 0x333a520, 0x333a6c4
FDE_VA = 0xdf7130
FDE = bytes.fromhex(
    '380000001c5c1100e8335402a401000000410e10420e18420e20410e28410e30'
    '83058e048f0386020322010e28410e20420e18420e10410e08410e30'
)
BODY = bytes.fromhex(
    '55415741565350833a010f850d010000488b4208483b82980100000f83500100'
    '004c8b82900100004869c0e80000004d8b5400584d8b5c0060488b9a78010000'
    '4c8b8a8001000049c1e30331d24531c04d39c30f84c60000004b8b04024c39c8'
    '0f83180100004989c649c1e6054983c0084a837c33080075d731d24531f66690'
    '4d39f30f84960000004f8b04324d39c80f83fb0000004d89c749c1e7054983c6'
    '084a394c3b0875d8488b0e4885c9746d488b760831d2440fb7997a030000468d'
    '0cdd000000004b8d1cc949c7c2ffffffff4531c96666662e0f1f840000000000'
    '4c39cb74254a3b44d110400f97c54080dd0049ffc24983c1484080fd0174e144'
    '0fb6dd4585db7505eb264d89da4883ee01720c4a8b8cd180030000eb9931d248'
    '89174889f84883c4085b415e415f5dc34a8b440950f2420f1044095848c1e802'
    '48bac3f5285c8fc2f52848f7e248c1ea02f2420f104c09284c89470848895710'
    'f20f114f18f20f114720ba01000000ebae488d3d587b3b02ff15d23d4302488d'
    '1533793b024889c74c89ceff1517394302488d1520793b024c89c74c89ceff15'
    '04394302'
)
BODY_SHA256 = 'cca4e558dba078db6445ab0ca2b649073af11fc840e6f6af36d31593b98bec83'
BRANCHES = [
    (0xa, '0f850d010000', 2, 6, 0x333a63d),
    (0x1b, '0f8350010000', 2, 6, 0x333a691),
    (0x53, '0f84c6000000', 2, 6, 0x333a63f),
    (0x60, '0f8318010000', 2, 6, 0x333a69e),
    (0x77, '75d7', 1, 2, 0x333a570),
    (0x83, '0f8496000000', 2, 6, 0x333a63f),
    (0x90, '0f83fb000000', 2, 6, 0x333a6b1),
    (0xa6, '75d8', 1, 2, 0x333a5a0),
    (0xae, '746d', 1, 2, 0x333a63d),
    (0xe3, '7425', 1, 2, 0x333a62a),
    (0xfd, '74e1', 1, 2, 0x333a600),
    (0x106, '7505', 1, 2, 0x333a62d),
    (0x108, 'eb26', 1, 2, 0x333a650),
    (0x111, '720c', 1, 2, 0x333a63f),
    (0x11b, 'eb99', 1, 2, 0x333a5d6),
    (0x16f, 'ebae', 1, 2, 0x333a63f),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x333a698, 0x576e470),
    (0x333a6ab, 0x576dfc8),
    (0x333a6be, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x333a691, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x333a69e, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x333a6b1, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774c10']
GOT_SITES = {'0x5774c10': ['0x27477c6', '0x4d62576', '0x4d62d36']}


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

