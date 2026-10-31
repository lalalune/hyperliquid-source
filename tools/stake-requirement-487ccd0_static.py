#!/usr/bin/env python3
"""Authenticated node94 stake-requirement-487ccd0 binding (0x487ccd0).

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

START, END = 0x487ccd0, 0x487ced1
FDE_VA = 0x12a0944
FDE = bytes.fromhex(
    '500000001c2d2e0084c35d0301020000048b268eff410e10420e18420e20420e'
    '28420e30410e38440e900183078c068d058e048f0386020381010e38410e3042'
    '0e28420e20420e18420e10410e08410e90010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec584989f64889fb488b56304889f7e8b001f4ff'
    'a8010f84360100004989d7498b463066813886017531498b4620498b4e284889'
    'ca4801c20f826f0100004883fa040f92c2be040000004829c64839ce0f92c084'
    'c20f855f010000bf20000000ff159612ef004885c00f842e0100004989c54c89'
    '3848c744240804000000488944241048c744241801000000498b463048894424'
    '50410f1006410f104e10410f1056200f295424400f294c24300f2944242041be'
    '010000004c8d7c24204c8d642408eb2dba01000000b90800000041b808000000'
    '4c89e74c89f6e81528cdff4c8b6c24104b896cf50049ffc64c89742418488b54'
    '24504c89ffe8c600f4ffa80174694889d54c3b74240875d8488b442450668138'
    '860175ac488b442440488b4c24484889ca4801c272644883fa040f92c2be0400'
    '00004829c64839ce0f92c084c27481488d3d6a27ea00ff152413ef00eb4948c7'
    '030000000048c743080800000048c7431000000000eb11488b44241848894310'
    '0f104424080f11034889d84883c4585b415c415d415e415f5dc3488d3d1f27ea'
    '00ff15a112ef000f0bbf08000000be20000000ff152f11ef00488d3d0027ea00'
    'ff158212ef00488d3df326ea00ff15ad12ef004889c3eb0d4889c34c8b742408'
    '4d85f67414488b7c241049c1e6034c89f631d2ff154711ef004889dfe83f32de'
    '00'
)
BODY_SHA256 = 'c4b3b2a81799472eac225ba61d6a822eb8f584d8ab7c6dacbef89d2708b3a933'
BRANCHES = [
    (0x22, '0f8436010000', 2, 6, 0x487ce2e),
    (0x34, '7531', 1, 2, 0x487cd37),
    (0x44, '0f826f010000', 2, 6, 0x487ce89),
    (0x61, '0f855f010000', 2, 6, 0x487ce96),
    (0x75, '0f842e010000', 2, 6, 0x487ce79),
    (0xce, 'eb2d', 1, 2, 0x487cdcd),
    (0x10c, '7469', 1, 2, 0x487ce47),
    (0x116, '75d8', 1, 2, 0x487cdc0),
    (0x122, '75ac', 1, 2, 0x487cda0),
    (0x134, '7264', 1, 2, 0x487ce6a),
    (0x14d, '7481', 1, 2, 0x487cda0),
    (0x15c, 'eb49', 1, 2, 0x487ce77),
    (0x175, 'eb11', 1, 2, 0x487ce58),
    (0x1d6, 'eb0d', 1, 2, 0x487ceb5),
    (0x1e3, '7414', 1, 2, 0x487cec9),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x487cceb, 0x47bcea0),
    (0x487cdb6, 0x454f5d0),
    (0x487cdd5, 0x47bcea0),
    (0x487cecc, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x487cd3c, 0x576dfd8),
    (0x487ce26, 0x576e150),
    (0x487ce71, 0x576e118),
    (0x487ce83, 0x576dfb8),
    (0x487ce90, 0x576e118),
    (0x487ce9d, 0x576e150),
    (0x487cec3, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x487ce1f, 0x571f590, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x487ce6a, 0x571f590, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x487ce89, 0x571f590, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x487ce96, 0x571f590, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
]
CALLERS = [0x4ce41b7, 0x4d77357, 0x4d81e2e]
CALLER_FUNCTIONS = {'0x4ce41b7': ('0x4ce3360', '0x4ce4cf4'), '0x4d77357': ('0x4d77030', '0x4d77596'), '0x4d81e2e': ('0x4d81d60', '0x4d82186')}
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

