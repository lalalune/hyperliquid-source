#!/usr/bin/env python3
"""Authenticated node94 spot-meta-375fb50 binding (0x375fb50).

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

START, END = 0x375fb50, 0x375fc29
FDE_VA = 0xe4ffcc
FDE = bytes.fromhex(
    '18000000b8ea16007cfb9002d900000000410e107d0e08410e100000'
)
BODY = bytes.fromhex(
    '50488b87880100004885c00f84ae0000004839c60f83a5000000488b87800100'
    '000fb648494869d6e80000002a4c10480f8296000000b801000000750259c30f'
    'b6f140f6c601740ab80a00000083fe0174ebf6c102740e486bc06489f283e2fe'
    '83fa0274d8f6c10474114869c01027000089f283e2fc83fa0474c2f6c1087411'
    '4869c000e1f50589f283e2f883fa0874acf6c110741c48b90000c16ff2862300'
    '48f7e10f90c183e6f083fe10750484c9748b488d3d3726f901ff1561e8000248'
    '8d3dda25f901ff1554e80002488d3d3526f901ff1527e50002'
)
BODY_SHA256 = '9e7837ee3279f2307969716cd11132989bf70776c11876ab6e22dfb1d1254b1b'
BRANCHES = [
    (0xb, '0f84ae000000', 2, 6, 0x375fc0f),
    (0x14, '0f83a5000000', 2, 6, 0x375fc0f),
    (0x30, '0f8296000000', 2, 6, 0x375fc1c),
    (0x3b, '7502', 1, 2, 0x375fb8f),
    (0x46, '740a', 1, 2, 0x375fba2),
    (0x50, '74eb', 1, 2, 0x375fb8d),
    (0x55, '740e', 1, 2, 0x375fbb5),
    (0x63, '74d8', 1, 2, 0x375fb8d),
    (0x68, '7411', 1, 2, 0x375fbcb),
    (0x79, '74c2', 1, 2, 0x375fb8d),
    (0x7e, '7411', 1, 2, 0x375fbe1),
    (0x8f, '74ac', 1, 2, 0x375fb8d),
    (0x94, '741c', 1, 2, 0x375fc02),
    (0xac, '7504', 1, 2, 0x375fc02),
    (0xb0, '748b', 1, 2, 0x375fb8d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x375fc09, 0x576e470),
    (0x375fc16, 0x576e470),
    (0x375fc23, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x375fc02, 0x56f2240, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1005, 69),
    (0x375fc0f, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x375fc1c, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774548']
GOT_SITES = {'0x5774548': ['0x24f85ab', '0x24f86fb', '0x24f89cb', '0x24f8cc0', '0x26e8df7', '0x26fd9bb', '0x26feb08', '0x270fe48', '0x2710fd8', '0x271155b', '0x2711df3', '0x2712139', '0x2715f6e', '0x27172c0', '0x271aa28', '0x271e0c3', '0x2723dc6', '0x2723ec0', '0x2724246', '0x2724378', '0x2739374', '0x274762e', '0x27476d1', '0x372dae0', '0x372ddc3', '0x372f566', '0x372f709', '0x372f8a5', '0x372fc40', '0x373097e', '0x3743c8d', '0x375fb10', '0x430e27d', '0x431966d', '0x46e8650', '0x46e90f6', '0x46f1404', '0x46f1cf4', '0x4ae0edb', '0x4ae102b', '0x4ae12fb', '0x4ae144b', '0x4ae171b', '0x4ae1a10', '0x4ae1bcb', '0x4ae1ec0', '0x4ce534b', '0x4ce5abb', '0x4ce7998', '0x4ce7e88', '0x4d025e8', '0x4d02bf8', '0x4d0317b', '0x4d037bb', '0x4d04053', '0x4d04399', '0x4d049a3', '0x4d04ce9', '0x4d0b374', '0x4d0cc44', '0x4d0e320', '0x4d0eb50', '0x4d18808', '0x4d19628', '0x4d1ff03', '0x4d20653', '0x4d298b6', '0x4d299e8', '0x4d29d86', '0x4d29eb8', '0x4d2a216', '0x4d2a310', '0x4d623de', '0x4d62481', '0x4d62b9e', '0x4d62c41']}


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

