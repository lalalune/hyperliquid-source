#!/usr/bin/env python3
"""Authenticated node94 spot-meta-333e310 binding (0x333e310).

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

START, END = 0x333e310, 0x333e441
FDE_VA = 0xdf7494
FDE = bytes.fromhex(
    '38000000805f1100746e54023101000000410e10420e18420e20410e28410e30'
    '83058e048f038602028c0e28410e20420e18420e10410e08410e3000'
)
BODY = bytes.fromhex(
    '55415741565350493bb0880100000f831001000089cd4889d3498b8080010000'
    '4869cee80000000fb65408492a5408480f82e1000000b801000000755d48f7e7'
    '4989d64989c74889c74889d64889da31c9ff1541fe42024889c14889d64084ed'
    '74224889c848f7e3480fafde4801d34929c74919de31c04d09fe0f95c04801c1'
    '4883d60031c04885f60f94c04889ca4883c4085b415e415f5dc30fb6caf6c101'
    '740ab80a00000083f9017491f6c2027412486bc06489ce83e6fe83fe020f847a'
    'fffffff6c20474154869c01027000089ce83e6fc83fe040f8460fffffff6c208'
    '74154869c000e1f50589ce83e6f883fe080f8446fffffff6c210741b48ba0000'
    'c16ff286230048f7e2700c83e1f083f9100f8426ffffff488d3d423e3b02ff15'
    '3c004302488d3db53d3b02ff152f004302'
)
BODY_SHA256 = '5e768538299899a3071265fc2a652c512c722218b2b41c18e70ccacbf09e9406'
BRANCHES = [
    (0xe, '0f8310010000', 2, 6, 0x333e434),
    (0x30, '0f82e1000000', 2, 6, 0x333e427),
    (0x3b, '755d', 1, 2, 0x333e3aa),
    (0x60, '7422', 1, 2, 0x333e394),
    (0xa0, '740a', 1, 2, 0x333e3bc),
    (0xaa, '7491', 1, 2, 0x333e34d),
    (0xaf, '7412', 1, 2, 0x333e3d3),
    (0xbd, '0f847affffff', 2, 6, 0x333e34d),
    (0xc6, '7415', 1, 2, 0x333e3ed),
    (0xd7, '0f8460ffffff', 2, 6, 0x333e34d),
    (0xe0, '7415', 1, 2, 0x333e407),
    (0xf1, '0f8446ffffff', 2, 6, 0x333e34d),
    (0xfa, '741b', 1, 2, 0x333e427),
    (0x109, '700c', 1, 2, 0x333e427),
    (0x111, '0f8426ffffff', 2, 6, 0x333e34d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x333e361, 0x576e1a8),
    (0x333e42e, 0x576e470),
    (0x333e43b, 0x576e470),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x333e427, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x333e434, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
]
CALLERS = [0x2711e0b, 0x2715f88, 0x27172ea, 0x2723ed8, 0x272438f, 0x372f726, 0x3734470, 0x3734a3e, 0x3734b73, 0x3738f70, 0x3743ca5, 0x3790707, 0x3c01912, 0x3c01991, 0x4d0406b, 0x4d049bb, 0x4d0b38e, 0x4d0cc5e, 0x4d0e34a, 0x4d0eb7a, 0x4d299ff, 0x4d29ecf, 0x4d2a328]
CALLER_FUNCTIONS = {'0x2711e0b': ('0x2711a80', '0x27123c7'), '0x2715f88': ('0x2715320', '0x2716bb7'), '0x27172ea': ('0x2716f90', '0x27177be'), '0x2723ed8': ('0x2723c70', '0x27240a3'), '0x272438f': ('0x27240b0', '0x272457e'), '0x372f726': ('0x372f3c0', '0x372f7f2'), '0x3734470': ('0x3734320', '0x3734491'), '0x3734a3e': ('0x37344a0', '0x3734bc3'), '0x3734b73': ('0x37344a0', '0x3734bc3'), '0x3738f70': ('0x3736bd0', '0x3739bd9'), '0x3743ca5': ('0x3743930', '0x3743deb'), '0x3790707': ('0x3790680', '0x37907d9'), '0x3c01912': ('0x3c018a0', '0x3c01be3'), '0x3c01991': ('0x3c018a0', '0x3c01be3'), '0x4d0406b': ('0x4d03ce0', '0x4d04627'), '0x4d049bb': ('0x4d04630', '0x4d04f77'), '0x4d0b38e': ('0x4d0a6d0', '0x4d0bf96'), '0x4d0cc5e': ('0x4d0bfa0', '0x4d0d866'), '0x4d0e34a': ('0x4d0dff0', '0x4d0e81e'), '0x4d0eb7a': ('0x4d0e820', '0x4d0f04e'), '0x4d299ff': ('0x4d29720', '0x4d29bee'), '0x4d29ecf': ('0x4d29bf0', '0x4d2a0be'), '0x4d2a328': ('0x4d2a0c0', '0x4d2a4f3')}
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

