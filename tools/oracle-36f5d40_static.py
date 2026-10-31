#!/usr/bin/env python3
"""Authenticated node94 oracle-36f5d40 binding (0x36f5d40).

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

START, END = 0x36f5d40, 0x36f61d1
FDE_VA = 0xe4b618
FDE = bytes.fromhex(
    '4c00000004a1160020a78a029104000000410e10420e18420e20420e28420e30'
    '410e38470ee00183078c068d058e048f0386020324040e38410e30420e28420e'
    '20420e18420e10410e08410ee0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca8000000488b8424e00000004c8b60084d85e4'
    '0f84310100004c894c24104c8b58104531c94c89db4d89e2450fb7b222030000'
    '4589f541c1e50649c7c7ffffffff31ed4939ed742b4b3bb4fad00200000f97c0'
    '1c004883c54049ffc73c0174e30fb6c085c07423eb0d662e0f1f840000000000'
    '4d89f74883eb010f829e0300004f8b94fa28030000eba149837c2ad0000f95c0'
    '410f9ec14130d14484c80f84a700000089d548ba4b598638d6c56d344889f048'
    'f7e248c1ea0b4869d2102700004889f04829d04c8b51104c39d00f8379030000'
    '488b5108488d044048c1e005488b5c0220410fb79424220300004189d241c1e2'
    '0648c7c0ffffffff4531ed0f1f4400004d39ea742b493bb4c4d0020000410f97'
    'c14180d9004983c54048ffc04180f90174de410fb6d185d27425eb070f1f4000'
    '4889d04983eb010f82740100004d8ba4c428030000eb9a4531c9e9cc02000049'
    '89cf48897c241866430f10442cc066430f104c2cd066430f10542ce066430f10'
    '5c2cf0660f295c2460660f29542450660f294c2440660f29442430488d7c2478'
    '488d7424304889dab9020000004d89c64d89c1ff15dfe7070243837c2cc00074'
    '784885db0f88050100004f8b7c2cd04c0faffb0f80f60000004b8b4c2cc84d89'
    'fe49f7de4d0f48f74c89f84801c80f80e80000004885c0488b7c2418488b7424'
    '100f8e1201000066490f6ec6660f62052cdfb0fc660f5c0544cfb0fc660f28d8'
    '660f15d8f20f58d80f57c0f2480f2ac0f20f5ed8e9e40000004c893424488d7c'
    '2430488bb424e000000031d2b9010000004d89f9ff15ded10702807c2478000f'
    '85db010000488b4424304885c0488b7c2418488b7424107e3af20f1084249000'
    '00000f1405b7deb0fc660f5c05cfceb0fc660f28d8660f15d8f20f58d80f57c0'
    'f2480f2ac0f20f5ed84885db796fe9da000000660f57db4885db7961e9cc0000'
    '00660f57db488b742410e944010000488d3d92bfff01ff155484070248c1f83f'
    '48ba00000000000000804831c24901cf488d35c1bcff014c0f40fa31ffff154d'
    'd107024c89f84885c0488b7c2418488b7424100f8feefeffff660f57db4b0faf'
    '5c2cd070684b8b442cf04885c00f88390100004889c248f7da4084ed480f45d0'
    '4889d94829d17052660f57c04885c90f8f990000004885c00f84a10000006648'
    '0f6ec8660f620dd5ddb0fc660f5c0dedcdb0fc660f28d1660f15d1f20f58d1f2'
    '0f5ec2f20f5f05fd4eb1fceb7a488d3d3cbcff01ff15968307020f99c00fb6c0'
    '48b9ffffffffffffff7f4801c14829d3488d3501bcff01480f40d931ff660f29'
    '5c2420ff1587d00702660f285c2420488b742410488b7c24184b8b442cf04889'
    'd9660f57c04885c90f8e67ffffff0f57c0f2480f2ac14885c00f855ffffffff2'
    '0f1005814eb1fcf20f5f1d794eb1fcf20f59d88b46108947200f10060f114710'
    'f20f115f0841b9010000004c890f4881c4a80000005b415c415d415e415f5dc3'
    '488d3dd22deafc488d153abbff01be81000000ff15ff7e0702488d1510bbff01'
    '4889c74c89d6ff151c7e0702488d3da038eafc488d0d76c1ff014c8d051fbbff'
    '01488d542430be2b000000ff15777e0702'
)
BODY_SHA256 = '76f596cd4101ae5f3c56465ca95e203c8a9163395a732d48e6e5aeec0b57ae4c'
BRANCHES = [
    (0x20, '0f8431010000', 2, 6, 0x36f5e97),
    (0x53, '742b', 1, 2, 0x36f5dc0),
    (0x6b, '74e3', 1, 2, 0x36f5d90),
    (0x72, '7423', 1, 2, 0x36f5dd7),
    (0x74, 'eb0d', 1, 2, 0x36f5dc3),
    (0x87, '0f829e030000', 2, 6, 0x36f616b),
    (0x95, 'eba1', 1, 2, 0x36f5d78),
    (0xaa, '0f84a7000000', 2, 6, 0x36f5e97),
    (0xda, '0f8379030000', 2, 6, 0x36f6199),
    (0x113, '742b', 1, 2, 0x36f5e80),
    (0x130, '74de', 1, 2, 0x36f5e50),
    (0x138, '7425', 1, 2, 0x36f5e9f),
    (0x13a, 'eb07', 1, 2, 0x36f5e83),
    (0x147, '0f8274010000', 2, 6, 0x36f6001),
    (0x155, 'eb9a', 1, 2, 0x36f5e31),
    (0x15a, 'e9cc020000', 1, 5, 0x36f616b),
    (0x1bf, '7478', 1, 2, 0x36f5f79),
    (0x1c4, '0f8805010000', 2, 6, 0x36f600f),
    (0x1d3, '0f80f6000000', 2, 6, 0x36f600f),
    (0x1ee, '0f80e8000000', 2, 6, 0x36f601c),
    (0x201, '0f8e12010000', 2, 6, 0x36f6059),
    (0x234, 'e9e4000000', 1, 5, 0x36f605d),
    (0x25f, '0f85db010000', 2, 6, 0x36f6180),
    (0x277, '7e3a', 1, 2, 0x36f5ff3),
    (0x2ac, '796f', 1, 2, 0x36f605d),
    (0x2ae, 'e9da000000', 1, 5, 0x36f60cd),
    (0x2ba, '7961', 1, 2, 0x36f605d),
    (0x2bc, 'e9cc000000', 1, 5, 0x36f60cd),
    (0x2ca, 'e944010000', 1, 5, 0x36f6153),
    (0x313, '0f8feefeffff', 2, 6, 0x36f5f47),
    (0x323, '7068', 1, 2, 0x36f60cd),
    (0x32d, '0f8839010000', 2, 6, 0x36f61ac),
    (0x346, '7052', 1, 2, 0x36f60da),
    (0x34f, '0f8f99000000', 2, 6, 0x36f612e),
    (0x358, '0f84a1000000', 2, 6, 0x36f613f),
    (0x38b, 'eb7a', 1, 2, 0x36f6147),
    (0x3e8, '0f8e67ffffff', 2, 6, 0x36f6095),
    (0x3f9, '0f855fffffff', 2, 6, 0x36f609e),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x36f5ef3, 0x57746d8),
    (0x36f5f94, 0x5773178),
    (0x36f6016, 0x576e470),
    (0x36f603d, 0x5773190),
    (0x36f60d4, 0x576e470),
    (0x36f6103, 0x5773190),
    (0x36f6193, 0x576e098),
    (0x36f61a6, 0x576dfc8),
    (0x36f61cb, 0x576e048),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x36f600f, 0x56f1fa8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f706f736974696f6e2e7273'), 204, 57),
    (0x36f60cd, 0x56f1d10, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f757365725f7374617465732e7273'), 659, 10),
    (0x36f6199, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x3766cca, 0x3767514]
CALLER_FUNCTIONS = {'0x3766cca': ('0x3766bb0', '0x3766e58'), '0x3767514': ('0x3767460', '0x3767628')}
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

