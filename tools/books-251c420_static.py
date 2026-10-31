#!/usr/bin/env python3
"""Authenticated node94 books-251c420 binding (0x251c420).

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

START, END = 0x251c420, 0x251c673
FDE_VA = 0x10c86d4
FDE = bytes.fromhex(
    '50000000acaa1000443d450153020000048fc193ff410e10420e18420e20420e'
    '28420e30410e38440e800183078c068d058e048f03860203cf010e38410e3042'
    '0e28420e20420e18420e10410e08410e80010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec4848897c24304c8b214c8b51084c8b71104c8b'
    '59184885d20f849a0100004989f7488d1cd64c895c244048895c2438eb4c6690'
    '4c8b6424180fb644240788c34b8d04764d892cc449895cc408f20f10442428f2'
    '410f1144c41049ffc64c8b6424104c8b5424184c8b5c2440488b5c24384983c7'
    '084939df0f843b0100004d8b2f498b0b488b014885c07458488b49080fb77062'
    '89f7c1e70348c7c2ffffffff0f1f40004885ff742b4c3b6cd010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f674a64883e901730ceb1190'
    '4889f24883e9017207488b44d068ebac4c89e848b94b598638d6c56d3448f7e1'
    '498b430848c1ea0b4869ca102700004c89ef4829cf488b70104839f74c895424'
    '080f83c1000000498b4b18488b71104839f70f83bf0000004c69c7d80000004c'
    '034008488b4108488d0c7f48c1e105488b2c08498b73104d8b4b20488d7c2410'
    '4c89ea4889e9ff151c80250331db48837c2418000f944424077415f20f104424'
    '10f20f11442428eb0c0f1f800000000048896c24284c89e04c896424104c8b64'
    '24084c896424184c897424204939c60f8590feffff488d7c2410ff15d07f2503'
    'e97bfeffff488b4424304c89204c8950084c8970104c8958184883c4485b415c'
    '415d415e415f5dc3488d1551ee1903ff15b3192503eb0d488d159abf1903ff15'
    'a41925030f0b4989c7488b4424104885c0741b4989c4488b4424184889442408'
    'eb14eb02eb004989c74d85e475084c89ffe8ba3a140349c1e4034b8d3464488b'
    '7c240831d2ff15a51925034c89ffe89d3a1403'
)
BODY_SHA256 = 'ac9ab7a0efa4631ad58861913326acee181ebee2fa3a0b6433257396479062d7'
BRANCHES = [
    (0x25, '0f849a010000', 2, 6, 0x251c5e5),
    (0x3c, 'eb4c', 1, 2, 0x251c4aa),
    (0x84, '0f843b010000', 2, 6, 0x251c5e5),
    (0x96, '7458', 1, 2, 0x251c510),
    (0xb3, '742b', 1, 2, 0x251c500),
    (0xcd, '74e1', 1, 2, 0x251c4d0),
    (0xd5, '74a6', 1, 2, 0x251c49d),
    (0xdb, '730c', 1, 2, 0x251c509),
    (0xdd, 'eb11', 1, 2, 0x251c510),
    (0xe7, '7207', 1, 2, 0x251c510),
    (0xee, 'ebac', 1, 2, 0x251c4bc),
    (0x121, '0f83c1000000', 2, 6, 0x251c608),
    (0x132, '0f83bf000000', 2, 6, 0x251c617),
    (0x179, '7415', 1, 2, 0x251c5b0),
    (0x187, 'eb0c', 1, 2, 0x251c5b5),
    (0x1af, '0f8590feffff', 2, 6, 0x251c465),
    (0x1c0, 'e97bfeffff', 1, 5, 0x251c460),
    (0x1f5, 'eb0d', 1, 2, 0x251c624),
    (0x211, '741b', 1, 2, 0x251c64e),
    (0x220, 'eb14', 1, 2, 0x251c656),
    (0x222, 'eb02', 1, 2, 0x251c646),
    (0x224, 'eb00', 1, 2, 0x251c646),
    (0x22c, '7508', 1, 2, 0x251c656),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x251c651, 0x5660110),
    (0x251c66e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x251c586, 0x57745a8),
    (0x251c5da, 0x57745b0),
    (0x251c60f, 0x576dfc8),
    (0x251c61e, 0x576dfc8),
    (0x251c665, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x251c608, 0x56bb460, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x251c617, 0x56b85b8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 202, 18),
]
CALLERS = [0x228f478]
CALLER_FUNCTIONS = {'0x228f478': ('0x228f410', '0x228f62e')}
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

