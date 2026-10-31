#!/usr/bin/env python3
"""Authenticated node94 mod-49e3930 binding (0x49e3930).

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

START, END = 0x49e3930, 0x49e3d1b
FDE_VA = 0x12b4fc0
FDE = bytes.fromhex(
    '5000000098732f0068e97203eb03000004f7a88dff410e10420e18420e20420e'
    '28420e30410e38470ed00183078c068d058e048f0386020389030e38410e3042'
    '0e28420e20420e18420e10410e08410ed0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec9800000085d2b880000000b998000000480f45'
    'c8488b040e4885c00f84a003000048837c0e10000f84940300004889fb488b4c'
    '0e084885c974774889ca4883e2070f84a901000031ff662e0f1f840000000000'
    '488b80c801000048ffc74839fa75f14889ca4829fa4883f90872430f1f440000'
    '488b80c8010000488b80c8010000488b80c8010000488b80c8010000488b80c8'
    '010000488b80c8010000488b80c8010000488b80c80100004883c2f875c26683'
    'b8c201000000740431c9eb274889c290488b82600100004885c00f84df020000'
    '0fb78ac00100004889c2663b88c201000073dd0fb7c9c1e105803c08000f84af'
    '020000488b440808483b46100f83930200004c8b6e084869c0f8000000498b6c'
    '05004883fd020f84790200004901c54d8b65604e8d34e5000000004c89e048c1'
    'e83d0f95c048b9f8ffffffffffff7f4939ce0f97c108c1740b31ff4c89f6ff15'
    '24a5d800498b45084889442438498b45104889442430498b4518488944242841'
    '0fb685f40000008844240d410f1085c80000000f29442450410fb685f5000000'
    '8844240e498b85a80000004889442418498b45204889442448498b4528488944'
    '2440410fb685b00000008844240f498b75584d85f6743848897424204c89f7ff'
    '15c3a4d8004885c00f84ed0100004989c74c89642410488b742420eb214889ca'
    '4883f9080f8376feffffe9affeffff41bf0800000048c7442410000000004c89'
    'ff4c89f2ff1586a4d8004180bdb1000000017511410f1085b20000000f294424'
    '60b001eb0231c04c8b742418498b4d30498b5538498b7540498b7d48410f1085'
    '9000000041837d68017522410f104d70410f1095800000000f29942480000000'
    '0f294c247041ba01000000eb034531d20f284c2450450fb685c20000004d8b9d'
    'a00000004c8b4c24104c894b504c897b584c8963604d8b8dd800000048892b4c'
    '8b7c24384c897b084c8b7c24304c897b104c8b7c24284c897b180fb66c240d40'
    '88abf40000000f118bc8000000410f108de00000000f118be0000000418badf0'
    '00000089abf00000000fb66c240e4088abf50000004c8b7c24484c897b204c8b'
    '7c24404c897b2848894b30488953384889734048897b484c8953680f284c2470'
    '0f289424800000000f114b700f1193800000000f1183900000004c899ba00000'
    '004c89b3a80000000fb64c240f888bb00000008883b10000000f284424600f11'
    '83b2000000448883c20000004c898bd80000004881c4980000005b415c415d41'
    '5e415f5dc3488d3dec25d500ff158ea7d800488d3dc725d500ff1581a7d80048'
    '8d3d5a02d500ff1574a7d8000f0b488d3d9325d500ff1565a7d800bf08000000'
    '4c89f6ff159fa2d8000f0b'
)
BODY_SHA256 = '4e4affc1c5dd87385d48e5e7fe49ff3f9db6efe03e866253044cfafe2a5ae1ec'
BRANCHES = [
    (0x28, '0f84a0030000', 2, 6, 0x49e3cfe),
    (0x34, '0f8494030000', 2, 6, 0x49e3cfe),
    (0x45, '7477', 1, 2, 0x49e39ee),
    (0x4e, '0f84a9010000', 2, 6, 0x49e3b2d),
    (0x6d, '75f1', 1, 2, 0x49e3990),
    (0x79, '7243', 1, 2, 0x49e39ee),
    (0xbc, '75c2', 1, 2, 0x49e39b0),
    (0xc6, '7404', 1, 2, 0x49e39fc),
    (0xca, 'eb27', 1, 2, 0x49e3a23),
    (0xda, '0f84df020000', 2, 6, 0x49e3cef),
    (0xf1, '73dd', 1, 2, 0x49e3a00),
    (0xfd, '0f84af020000', 2, 6, 0x49e3ce2),
    (0x10c, '0f8393020000', 2, 6, 0x49e3cd5),
    (0x126, '0f8479020000', 2, 6, 0x49e3cd5),
    (0x157, '740b', 1, 2, 0x49e3a94),
    (0x1d5, '7438', 1, 2, 0x49e3b3f),
    (0x1e8, '0f84ed010000', 2, 6, 0x49e3d0b),
    (0x1fb, 'eb21', 1, 2, 0x49e3b4e),
    (0x204, '0f8376feffff', 2, 6, 0x49e39b0),
    (0x20a, 'e9affeffff', 1, 5, 0x49e39ee),
    (0x232, '7511', 1, 2, 0x49e3b75),
    (0x243, 'eb02', 1, 2, 0x49e3b77),
    (0x269, '7522', 1, 2, 0x49e3bbd),
    (0x28b, 'eb03', 1, 2, 0x49e3bc0),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x49e3a8e, 0x576dfb8),
    (0x49e3b0f, 0x576dfd8),
    (0x49e3b54, 0x576dfe0),
    (0x49e3cdc, 0x576e470),
    (0x49e3ce9, 0x576e470),
    (0x49e3cf6, 0x576e470),
    (0x49e3d05, 0x576e470),
    (0x49e3d13, 0x576dfb8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x49e3cd5, 0x57362c8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b2f626f6f6b2f6d6f642e7273'), 1044, 68),
    (0x49e3ce2, 0x57362b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b2f626f6f6b2f6d6f642e7273'), 1044, 58),
    (0x49e3cef, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x49e3cfe, 0x5736298, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b2f626f6f6b2f6d6f642e7273'), 1043, 83),
]
CALLERS = [0x4a06f87, 0x4a06f9c]
CALLER_FUNCTIONS = {'0x4a06f87': ('0x4a06f70', '0x4a0701a'), '0x4a06f9c': ('0x4a06f70', '0x4a0701a')}
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

