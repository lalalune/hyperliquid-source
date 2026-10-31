#!/usr/bin/env python3
"""Authenticated node94 pdi-2a22520 binding (0x2a22520).

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

START, END = 0x2a22520, 0x2a2273a
FDE_VA = 0x1121330
FDE = bytes.fromhex(
    '5000000008371600e81190011a020000041be691ff410e10420e18420e20420e'
    '28420e30410e38470ee00183078c068d058e048f038602039c010e38410e3042'
    '0e28420e20420e18420e10410e08410ee0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca8000000488b0648894424104c8b4608488b1f'
    '488b47084839c30f8471010000488b4f2048894c2428488b4f2848894c242048'
    '8b4f1848894c24384829d848b9abaaaaaaaaaaaaaa48f7e14989d74c8b771049'
    'c1ef054b8d044048c1e0044803461048894424184531ed48895c24300f1f4000'
    'b810270000488b4c243848f761304c894424080f801f0100004889c54c01f50f'
    '8222010000420fb6442b2a884424074a8b742b084e8b642b104d85e474324c89'
    '7424404d89fe4989f74c89e7ff15e6b9d4024885c00f84120100004889c34c89'
    'fe4d89f74c8b742440eb0a0f1f440000bb010000004889df4c89e2ff15bfb9d4'
    '024c8964244848895c24504c89642458488b5c2430420fb7442b284a8b4c2b20'
    '0fb65424078854247266894424704a8b442b18488944246048894c2468488d7c'
    '24784889ee488d542448488b4c24284c8b442420e8279400000f104424780f10'
    '8c24880000000f10942498000000488b442418420f11542820420f114c281042'
    '0f11042849ffc64c8b44240874484983c53049ffc049ffcf0f85e2feffff488b'
    '4424104c89004881c4a80000005b415c415d415e415f5dc3488d3d7927cb02ff'
    '15cbbad402eb34488d3d6a27cb02ff1524bad402eb2549ffc04c89442408488d'
    '3dab26cb02ff150dbad402eb0ebf010000004c89e6ff159db8d4020f0beb06eb'
    '04eb02eb00488b4c2410488b5424084889114889c7e8d6d9c302'
)
BODY_SHA256 = 'e3e49c3fd0aa08ec2d56ae114f9cd0f302e11b4e29b910f7c379a9a7cbc6dff0'
BRANCHES = [
    (0x27, '0f8471010000', 2, 6, 0x2a226be),
    (0x93, '0f801f010000', 2, 6, 0x2a226d8),
    (0x9f, '0f8222010000', 2, 6, 0x2a226e7),
    (0xbc, '7432', 1, 2, 0x2a22610),
    (0xd5, '0f8412010000', 2, 6, 0x2a2270d),
    (0xe9, 'eb0a', 1, 2, 0x2a22615),
    (0x18c, '7448', 1, 2, 0x2a226f6),
    (0x198, '0f85e2feffff', 2, 6, 0x2a225a0),
    (0x1c5, 'eb34', 1, 2, 0x2a2271b),
    (0x1d4, 'eb25', 1, 2, 0x2a2271b),
    (0x1eb, 'eb0e', 1, 2, 0x2a2271b),
    (0x1fd, 'eb06', 1, 2, 0x2a22725),
    (0x1ff, 'eb04', 1, 2, 0x2a22725),
    (0x201, 'eb02', 1, 2, 0x2a22725),
    (0x203, 'eb00', 1, 2, 0x2a22725),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2a22674, 0x2a2baa0),
    (0x2a22735, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2a225ec, 0x576dfd8),
    (0x2a2261b, 0x576dfe0),
    (0x2a226df, 0x576e1b0),
    (0x2a226ee, 0x576e118),
    (0x2a22705, 0x576e118),
    (0x2a22715, 0x576dfb8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2a226e7, 0x56d4e58, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f61737365742f7064692e7273'), 30, 14),
    (0x2a226fe, 0x56d4db0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f636f72652f7372632f697465722f61646170746572732f656e756d65726174652e7273'), 141, 17),
]
CALLERS = [0x2a1063f]
CALLER_FUNCTIONS = {'0x2a1063f': ('0x2a10590', '0x2a10682')}
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

