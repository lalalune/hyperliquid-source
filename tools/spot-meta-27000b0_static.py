#!/usr/bin/env python3
"""Authenticated node94 spot-meta-27000b0 binding (0x27000b0).

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

START, END = 0x27000b0, 0x2700383
FDE_VA = 0x10ed684
FDE = bytes.fromhex(
    '4c0000005cfa1200242a6101d3020000049ffb92ff410e10420e18420e20420e'
    '28420e30410e38410e4083078c068d058e048f0386020372020e38410e30420e'
    '28420e20420e18420e10410e08410e40'
)
BODY = bytes.fromhex(
    '55415741564155415453504889d34989fe488b3a488b4a104885ff0f95c04885'
    'c90f95c220c280fa010f85130200004c8b5b08488b96180200004c8b86100200'
    '004c8b8ef8010000488b86000200004531d2eb1a6666662e0f1f840000000000'
    'bf0000000048ffc90f84d40100004d85d2741d450fb77a624d39fb0f839f0000'
    '004d89d74d89dce9b20000000f1f40004d85db74354d89df4989fa4983e70774'
    '2e4531e46666662e0f1f8400000000004d8b527049ffc44d39e775f44c89df4c'
    '29e74983fb087318eb3c4989faeb374c89df4983fb08722e0f1f840000000000'
    '4d8b52704d8b52704d8b52704d8b52704d8b52704d8b52704d8b52704d8b5270'
    '4883c7f875da31ff4531db450fb77a624d39fb0f8268ffffff0f1f8000000000'
    '4d8b3a4d85ff0f846b01000048ffc7450fb762604d89fa66453b676273e24885'
    'ff0f84790000004f8d1ce74983c3784989fd4983e5070f84d400000031ed6690'
    '4d8b134d8d5a7048ffc54939ed75f14989fd4929ed4883ff08722e0f1f440000'
    '498b3b488b7f70488b7f70488b7f70488b7f70488b7f70488b7f704c8b57704d'
    '8d5a704983c5f875d74531db43807c2764010f85a8feffffeb1a660f1f440000'
    '4d8d5c24014d89fa43807c2764010f858cfeffff4b8b7ce7084839d70f83a600'
    '00004869ffe80000004d8b7c38584d8b64386049c1e4034531ed660f1f440000'
    '4d39ec74634b8b3c2f4839c70f839400000048c1e7054983c50849837c390800'
    '75dee939feffff660f1f8400000000004989fd4883ff080f8343ffffffe967ff'
    'ffff488d86680200004889df4889f34889c6ff15003b07034889dfe860d0ffff'
    '6641c7068601eb0e6641c706ea004889dfe8aa261b004c89f04883c4085b415c'
    '415d415e415f5dc3488d3db11eff02ff152be10603eb1f488d3df251fc02ff15'
    '1ce10603eb10488d157b1cff024889c6ff1562dc06030f0b0f0b4989c64889df'
    'e85b261b004c89f7e893fdf502ff15a5dd0603'
)
BODY_SHA256 = '41b8b64495fe6f489fcab59884986ccf584ee77020f37b42159f7d1249277b97'
BRANCHES = [
    (0x29, '0f8513020000', 2, 6, 0x27002f2),
    (0x52, 'eb1a', 1, 2, 0x270011e),
    (0x68, '0f84d4010000', 2, 6, 0x27002f2),
    (0x71, '741d', 1, 2, 0x2700140),
    (0x7b, '0f839f000000', 2, 6, 0x27001d0),
    (0x87, 'e9b2000000', 1, 5, 0x27001ee),
    (0x93, '7435', 1, 2, 0x270017a),
    (0x9f, '742e', 1, 2, 0x270017f),
    (0xba, '75f4', 1, 2, 0x2700160),
    (0xc6, '7318', 1, 2, 0x2700190),
    (0xc8, 'eb3c', 1, 2, 0x27001b6),
    (0xcd, 'eb37', 1, 2, 0x27001b6),
    (0xd6, '722e', 1, 2, 0x27001b6),
    (0x104, '75da', 1, 2, 0x2700190),
    (0x113, '0f8268ffffff', 2, 6, 0x2700131),
    (0x126, '0f846b010000', 2, 6, 0x2700347),
    (0x13c, '73e2', 1, 2, 0x27001d0),
    (0x141, '0f8479000000', 2, 6, 0x2700270),
    (0x156, '0f84d4000000', 2, 6, 0x27002e0),
    (0x16d, '75f1', 1, 2, 0x2700210),
    (0x179, '722e', 1, 2, 0x2700259),
    (0x1a7, '75d7', 1, 2, 0x2700230),
    (0x1b2, '0f85a8feffff', 2, 6, 0x2700110),
    (0x1b8, 'eb1a', 1, 2, 0x2700284),
    (0x1ce, '0f858cfeffff', 2, 6, 0x2700110),
    (0x1dc, '0f83a6000000', 2, 6, 0x2700338),
    (0x203, '7463', 1, 2, 0x2700318),
    (0x20c, '0f8394000000', 2, 6, 0x2700356),
    (0x220, '75de', 1, 2, 0x27002b0),
    (0x222, 'e939feffff', 1, 5, 0x2700110),
    (0x237, '0f8343ffffff', 2, 6, 0x2700230),
    (0x23d, 'e967ffffff', 1, 5, 0x2700259),
    (0x266, 'eb0e', 1, 2, 0x2700326),
    (0x295, 'eb1f', 1, 2, 0x2700366),
    (0x2a4, 'eb10', 1, 2, 0x2700366),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x270030b, 0x26fd370),
    (0x2700321, 0x28b29d0),
    (0x2700370, 0x28b29d0),
    (0x2700378, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2700302, 0x5773e08),
    (0x270033f, 0x576e470),
    (0x270034e, 0x576e470),
    (0x2700360, 0x576dfc8),
    (0x270037d, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2700338, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2700347, 0x56c5540, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x2700356, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x23567c1]
CALLER_FUNCTIONS = {'0x23567c1': ('0x2355f40', '0x235e836')}
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

