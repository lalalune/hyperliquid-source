#!/usr/bin/env python3
"""Authenticated node94 spot-meta-32815f0 binding (0x32815f0).

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

START, END = 0x32815f0, 0x3281767
FDE_VA = 0xde5ed4
FDE = bytes.fromhex(
    '3c000000c049100014b749027701000000420e10420e18420e20420e28410e30'
    '83068c058d048e038f0202b80e28420e20420e18420e10420e08410e30000000'
)
BODY = bytes.fromhex(
    '415741564155415453493bb0880100000f835401000089cb498b888001000048'
    '69f6e80000000fb64431492a4431480f8228010000b9010000000f858a000000'
    '4889d048f7e74989c64989d7ba640000004889c848f7e24989d54989c44c89f7'
    '4c89fe4889c24c89e9ff1549cb4e024889c14889d684db74294889c849f7e44c'
    '0fafe94901d54c0fafe64d01ec4929c64d19e731c04d09f70f95c04801c14883'
    'd6004885f60f94c048ba5c8fc2f5285c8f024839d10f92c220c20fb6c24889ca'
    '5b415c415d415e415fc30fb6f040f6c601740eb90a00000083fe010f845fffff'
    'ffa8027415486bc9644189f04183e0fe4183f8020f8446ffffffa80474184869'
    'c9102700004189f04183e0fc4183f8040f842affffffa80874184869c900e1f5'
    '054189f04183e0f84183f8080f840effffffa810742749b80000c16ff2862300'
    '4889c84889d149f7e070124889ca4889c183e6f083fe100f84e3feffff488d3d'
    '1c0b4702ff1516cd4e02488d3d8f0a4702ff1509cd4e02'
)
BODY_SHA256 = '6ccbf361d09ea34a9ec77632933be7a801acfd1a255f82532bc7de135367be77'
BRANCHES = [
    (0x10, '0f8354010000', 2, 6, 0x328175a),
    (0x2f, '0f8228010000', 2, 6, 0x328174d),
    (0x3a, '0f858a000000', 2, 6, 0x32816ba),
    (0x77, '7429', 1, 2, 0x3281692),
    (0xd1, '740e', 1, 2, 0x32816d1),
    (0xdb, '0f845fffffff', 2, 6, 0x3281630),
    (0xe3, '7415', 1, 2, 0x32816ea),
    (0xf4, '0f8446ffffff', 2, 6, 0x3281630),
    (0xfc, '7418', 1, 2, 0x3281706),
    (0x110, '0f842affffff', 2, 6, 0x3281630),
    (0x118, '7418', 1, 2, 0x3281722),
    (0x12c, '0f840effffff', 2, 6, 0x3281630),
    (0x134, '7427', 1, 2, 0x328174d),
    (0x149, '7012', 1, 2, 0x328174d),
    (0x157, '0f84e3feffff', 2, 6, 0x3281630),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3281659, 0x576e1a8),
    (0x3281754, 0x576e470),
    (0x3281761, 0x576e470),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x328174d, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x328175a, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x57738b0']
GOT_SITES = {'0x57738b0': ['0x21a36e2', '0x21a383f', '0x2711046', '0x27115bd', '0x27167bc', '0x2716d5d', '0x271722d', '0x271e0dc', '0x27286dc', '0x272c34a', '0x273a36d', '0x273a3b9', '0x3273dac', '0x3273ee0', '0x371b75a', '0x371fcf8', '0x37381d3', '0x3738504', '0x3738c7c', '0x3739417', '0x3739568', '0x373dd0f', '0x373df95', '0x373e082', '0x373e171', '0x394b7ba', '0x46f7874', '0x46f78c0', '0x46f8714', '0x46f8760', '0x4c22df2', '0x4c22f4f', '0x4d02656', '0x4d02c66', '0x4d031dd', '0x4d0381d', '0x4d0bba3', '0x4d0d473', '0x4d0da0d', '0x4d0ddcd', '0x4d0e28d', '0x4d0eabd', '0x4d1ff1c', '0x4d2066c', '0x4d30719', '0x4d31089', '0x4d37dda', '0x4d39075']}


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

