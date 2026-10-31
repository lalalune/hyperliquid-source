#!/usr/bin/env python3
"""Authenticated node94 spot-meta-327f720 binding (0x327f720).

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

START, END = 0x327f720, 0x327f8fb
FDE_VA = 0xde5b10
FDE = bytes.fromhex(
    '48000000fc451000089c4902db01000000410e10420e18420e20420e28420e30'
    '410e38410e4083078c068d058e048f03860203a8010e38410e30420e28420e20'
    '420e18420e10410e08410e40'
)
BODY = bytes.fromhex(
    '55415741564155415453504989f64889fb488b7c2448488bb7700100004939f6'
    '0f83a50100004d89c789cd4889d1488b87680100004c89f248c1e205488b3410'
    '48b8000064a7b3b6e00d31d249f7f0483bb7880100000f83620100004989c448'
    '8b97800100004869f6e80000000fb64432492a4432480f8298000000be010000'
    '00751d4c89c84809f048c1e8200f848e0000004c89c831d248f7f6e988000000'
    '0fb6f840f6c701740abe0a00000083ff0174d0a802740e486bf66489fa83e2fe'
    '83fa0274bea80474114869f61027000089fa83e2fc83fa0474a9a80874114869'
    'f600e1f50589fa83e2f883fa087494a810742148ba0000c16ff28623004889f0'
    '48f7e2700f4889c683e7f083ff100f846fffffff488d3d352a4702ff152fec4e'
    '024489c831d2f7f64c39e04c0f42e04c89f849f7e44989c50f90c048bafeffff'
    'ffffffff7f4939d50f97c208c2740948c70302000000eb54488b7424408b4108'
    '898320020000488b0148898318020000baf00100004889dfff1542e74e024c89'
    'bbf00100004c89b3f80100004c89a3000200004c89ab0802000048c783100200'
    '00000000004088ab240200004889d84883c4085b415c415d415e415f5dc3488d'
    '3d0b294702ff1585eb4e02488d1536ff45024c89f7ff15cde64e02'
)
BODY_SHA256 = 'd9635f25137e9bdaf2fec00045540598aa0723cdfede1188a79fa7d7cdbe591b'
BRANCHES = [
    (0x20, '0f83a5010000', 2, 6, 0x327f8eb),
    (0x56, '0f8362010000', 2, 6, 0x327f8de),
    (0x76, '0f8298000000', 2, 6, 0x327f834),
    (0x81, '751d', 1, 2, 0x327f7c0),
    (0x8d, '0f848e000000', 2, 6, 0x327f841),
    (0x9b, 'e988000000', 1, 5, 0x327f848),
    (0xa7, '740a', 1, 2, 0x327f7d3),
    (0xb1, '74d0', 1, 2, 0x327f7a3),
    (0xb5, '740e', 1, 2, 0x327f7e5),
    (0xc3, '74be', 1, 2, 0x327f7a3),
    (0xc7, '7411', 1, 2, 0x327f7fa),
    (0xd8, '74a9', 1, 2, 0x327f7a3),
    (0xdc, '7411', 1, 2, 0x327f80f),
    (0xed, '7494', 1, 2, 0x327f7a3),
    (0xf1, '7421', 1, 2, 0x327f834),
    (0x103, '700f', 1, 2, 0x327f834),
    (0x10e, '0f846fffffff', 2, 6, 0x327f7a3),
    (0x14d, '7409', 1, 2, 0x327f878),
    (0x156, 'eb54', 1, 2, 0x327f8cc),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x327f83b, 0x576e470),
    (0x327f898, 0x576dfe0),
    (0x327f8e5, 0x576e470),
    (0x327f8f5, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x327f834, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x327f8de, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x327f8eb, 0x56df828, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774e20']
GOT_SITES = {'0x5774e20': ['0x2774f3e', '0x3719c9d', '0x3719fd1', '0x4c6c26e']}


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

