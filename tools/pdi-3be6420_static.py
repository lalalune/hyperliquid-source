#!/usr/bin/env python3
"""Authenticated node94 pdi-3be6420 binding (0x3be6420).

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

START, END = 0x3be6420, 0x3be6654
FDE_VA = 0xe9cc68
FDE = bytes.fromhex(
    '4800000054b71b00b097d4023402000000410e10420e18420e20420e28420e30'
    '410e38410e4083078c068d058e048f03860203f1010e38410e30420e28420e20'
    '420e18420e10410e08410e40'
)
BODY = bytes.fromhex(
    '55415741564155415453504c8b57104c8b1f488b4f08488b1a4c8b72080f1f00'
    '4c39d10f83c70100004c8d61014c896708b81027000049f763300f80c7010000'
    '4989c04901c80f82c8010000488b034885c00f84a8000000488b53080fb788ba'
    '00000089cdc1e50349c7c5a8ffffff49c7c1ffffffff662e0f1f840000000000'
    '4989ef4d01ef4983ffa874344e3b44c810410f97c74180df004983c5f849ffc1'
    '4180ff0174da410fb6cf85c974324883ea017315eb4a662e0f1f840000000000'
    '4989c94883ea0172374a8b84c8c0000000eb89666666662e0f1f840000000000'
    '4c29e8498b96700100004885d27562e9dc0000006666662e0f1f840000000000'
    '4c89c048b94b598638d6c56d3448f7e148c1ea0b4869ca102700004c89c04829'
    'c84d8b4e704c39c80f83f3000000498b4e68488d044048c1e0054801c84883c0'
    '20498b96700100004885d20f847f0000004d8b8e780100000fb7aaba00000089'
    'e9c1e10349c7c5ffffffff0f1f4400004885c9742b4e3b44ea10410f97c74180'
    'df0049ffc54883c1f84180ff0174e1410fb6cf85c974294983e901730ceb3190'
    '4989ed4983e90172274a8b94eac0000000eba5666666662e0f1f840000000000'
    '4a8b4cea60488b004885c0790deb1d9031c9488b004885c07812480fafc1700c'
    '4801c64c89e10f8134feffff31c0eb05b8010000004889f24883c4085b415c41'
    '5d415e415f5dc3488d3d8ae7b201ff157c7bb801488d3d7de7b201ff15d77ab8'
    '01488d1510e6b2014889c74c89ceff157479b801'
)
BODY_SHA256 = '30a1c827a2b154ceac8a8c78802a9e09666eac448c3eec45113431412f8fff48'
BRANCHES = [
    (0x23, '0f83c7010000', 2, 6, 0x3be6610),
    (0x3a, '0f80c7010000', 2, 6, 0x3be6627),
    (0x46, '0f82c8010000', 2, 6, 0x3be6634),
    (0x52, '0f84a8000000', 2, 6, 0x3be6520),
    (0x8a, '7434', 1, 2, 0x3be64e0),
    (0xa4, '74da', 1, 2, 0x3be64a0),
    (0xac, '7432', 1, 2, 0x3be6500),
    (0xb2, '7315', 1, 2, 0x3be64e9),
    (0xb4, 'eb4a', 1, 2, 0x3be6520),
    (0xc7, '7237', 1, 2, 0x3be6520),
    (0xd1, 'eb89', 1, 2, 0x3be647c),
    (0xed, '7562', 1, 2, 0x3be6571),
    (0xef, 'e9dc000000', 1, 5, 0x3be65f0),
    (0x128, '0f83f3000000', 2, 6, 0x3be6641),
    (0x14b, '0f847f000000', 2, 6, 0x3be65f0),
    (0x173, '742b', 1, 2, 0x3be65c0),
    (0x18d, '74e1', 1, 2, 0x3be6590),
    (0x195, '7429', 1, 2, 0x3be65e0),
    (0x19b, '730c', 1, 2, 0x3be65c9),
    (0x19d, 'eb31', 1, 2, 0x3be65f0),
    (0x1a7, '7227', 1, 2, 0x3be65f0),
    (0x1b1, 'eba5', 1, 2, 0x3be6578),
    (0x1cb, '790d', 1, 2, 0x3be65fa),
    (0x1cd, 'eb1d', 1, 2, 0x3be660c),
    (0x1d8, '7812', 1, 2, 0x3be660c),
    (0x1de, '700c', 1, 2, 0x3be660c),
    (0x1e6, '0f8134feffff', 2, 6, 0x3be6440),
    (0x1ee, 'eb05', 1, 2, 0x3be6615),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3be662e, 0x576e1b0),
    (0x3be663b, 0x576e118),
    (0x3be664e, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3be6634, 0x5714db8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f61737365742f7064692e7273'), 30, 14),
    (0x3be6641, 0x5714c58, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x3709237]
CALLER_FUNCTIONS = {'0x3709237': ('0x3709040', '0x3709552')}
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

