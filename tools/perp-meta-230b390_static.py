#!/usr/bin/env python3
"""Authenticated node94 perp-meta-230b390 binding (0x230b390).

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

START, END = 0x230b390, 0x230b584
FDE_VA = 0xd4721c
FDE = bytes.fromhex(
    '18000000085d06006c415c01f401000000410e1003d8010e08410e10'
)
BODY = bytes.fromhex(
    '50b9010000004881faa08601000f8240010000b90a0000004881fa40420f000f'
    '822e010000b9640000004881fa809698000f821c010000b9e80300004881fa00'
    'e1f5050f820a010000b9102700004881fa00ca9a3b0f82f80000004889d048c1'
    'e80ab9a0860100483df90295000f82e00000004889d048c1e80bb940420f0048'
    '3ddd0ee9020f82c80000004889d048c1e80cb980969800483d514a8d0e0f82b0'
    '0000004889d048c1e80db900e1f505483d9573c2480f829800000048b8ff3f7a'
    '10f35a0000b900ca9a3b4839c20f868000000048b9ff7fc6a47e8d03004839ca'
    '764049b80000c16ff28623004c39c2723d49b800008a5d784563014c39c2723a'
    '49b8000064a7b3b6e00d4c39c2723749b80000e8890423c78a4c39c2480f42c8'
    'eb2e48b9ffe30b5402000000eb2248b9ffe7764817000000eb1648b9ff0fa5d4'
    'e8000000eb0a48b9ff9f724e1809000048ffc148ba4b598638d6c56d344889f0'
    '48f7e248c1ea0b483b5730756d4869c2102700004829c6483b7710735d488b47'
    '08488d147648c1e2040fb644102a83f807735489c6ba0100000083ee06742ff7'
    'de40f6c601740aba0a00000083f805741d40f6c602740c486bd26483e60683fe'
    '02740b3c02770e4869d2102700004839ca480f42ca4889c859c3488d3d4f6c3e'
    '03ff15f92e4603488d3dd27d3e03ff15cc2b4603'
)
BODY_SHA256 = 'ef650a9a9f8474dde1e485185c784c8eef1490a3195387aa0626f58226139d5a'
BRANCHES = [
    (0xd, '0f8240010000', 2, 6, 0x230b4e3),
    (0x1f, '0f822e010000', 2, 6, 0x230b4e3),
    (0x31, '0f821c010000', 2, 6, 0x230b4e3),
    (0x43, '0f820a010000', 2, 6, 0x230b4e3),
    (0x55, '0f82f8000000', 2, 6, 0x230b4e3),
    (0x6d, '0f82e0000000', 2, 6, 0x230b4e3),
    (0x85, '0f82c8000000', 2, 6, 0x230b4e3),
    (0x9d, '0f82b0000000', 2, 6, 0x230b4e3),
    (0xb5, '0f8298000000', 2, 6, 0x230b4e3),
    (0xcd, '0f8680000000', 2, 6, 0x230b4e3),
    (0xe0, '7640', 1, 2, 0x230b4b2),
    (0xef, '723d', 1, 2, 0x230b4be),
    (0xfe, '723a', 1, 2, 0x230b4ca),
    (0x10d, '7237', 1, 2, 0x230b4d6),
    (0x120, 'eb2e', 1, 2, 0x230b4e0),
    (0x12c, 'eb22', 1, 2, 0x230b4e0),
    (0x138, 'eb16', 1, 2, 0x230b4e0),
    (0x144, 'eb0a', 1, 2, 0x230b4e0),
    (0x16b, '756d', 1, 2, 0x230b56a),
    (0x17b, '735d', 1, 2, 0x230b56a),
    (0x191, '7354', 1, 2, 0x230b577),
    (0x19d, '742f', 1, 2, 0x230b55e),
    (0x1a5, '740a', 1, 2, 0x230b541),
    (0x1af, '741d', 1, 2, 0x230b55e),
    (0x1b5, '740c', 1, 2, 0x230b553),
    (0x1c1, '740b', 1, 2, 0x230b55e),
    (0x1c5, '770e', 1, 2, 0x230b565),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x230b571, 0x576e470),
    (0x230b57e, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x230b56a, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x230b577, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = [0x21f8158, 0x21f82fa, 0x26b727c, 0x26e6c33, 0x26ec560, 0x26f7743, 0x270eafb, 0x27375f9, 0x2775d8c]
CALLER_FUNCTIONS = {'0x21f8158': ('0x21f7c40', '0x21f851f'), '0x21f82fa': ('0x21f7c40', '0x21f851f'), '0x26b727c': ('0x26b7110', '0x26b7309'), '0x26e6c33': ('0x26e6a30', '0x26e7f2f'), '0x26ec560': ('0x26ebdc0', '0x26eff10'), '0x26f7743': ('0x26f7280', '0x26f7ee8'), '0x270eafb': ('0x270e6a0', '0x270f1b1'), '0x27375f9': ('0x27371f0', '0x2738e41'), '0x2775d8c': ('0x27758c0', '0x277643c')}
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

