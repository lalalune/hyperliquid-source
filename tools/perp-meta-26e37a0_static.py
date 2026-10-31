#!/usr/bin/env python3
"""Authenticated node94 perp-meta-26e37a0 binding (0x26e37a0).

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

START, END = 0x26e37a0, 0x26e3d34
FDE_VA = 0x10ecb1c
FDE = bytes.fromhex(
    '50000000f4ee12007c6c5f0194050000040ff992ff410e10420e18420e20420e'
    '28420e30410e38470eb00283078c068d058e048f03860203d1040e38410e3042'
    '0e28420e20420e18420e10410e08410eb0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecf80000004c89cd4c898424a000000048898c24'
    'b80000004989d44989ff0fb682a200000088442406488b828000000048898424'
    '90000000488b0a488b7a080fb6829000000088442407488b8288000000488984'
    '24980000004889b424c00000004c8bb6b000000049b84b598638d6c56d344c89'
    'f049f7e04889d3498b44247048898424b000000048c1eb0b498b442478488984'
    '24a8000000498bb424a80000004d8b6930b80100000048894424104c39eb4889'
    '4c241875654c89f049f7e048c1ea0b4869ca102700004c89f04829c8483b4510'
    '735b48897c24604889742470488b4d08488d044048c1e004488b740108488b7c'
    '01104885ff48897c240874494889742410ff1521a708034885c00f8409040000'
    '4889c7488b742410eb3048c7442408000000004885c97550e9ba00000048c744'
    '240800000000488b4c24184885c97538e9a2000000bf0100000048897c241048'
    '8b542408ff15d6a60803488b4c2418488b742470488b7c246049b84b598638d6'
    'c56d344885c9746f4885ff746a4c39eb0f8566030000488b4d104c89f049f7e0'
    '48c1ea0b4869c2102700004929c64939ce0f8345030000488b45084b8d147648'
    'c1e2040fb644102a66480f6ec7660f62050b05b2fd660f5c0523f5b1fd660f28'
    'c8660f15c8f20f58c8488d15f0e0cdfdf20f5e0cc2eb1b4c39eb0f85ed020000'
    '4869c3102700004929c6488b4d10660f57c94939ce0f83d2020000660f294c24'
    '70488b5d084f8d347649c1e604420fb644332a4883f8070f83ce020000b90600'
    '000029c1c1e103488d05a2d4cffdf20f1014010fb6442406413a8424b1000000'
    '488d053bddcffd488d0d2fddcffd480f44c848894c244848c744245005000000'
    '66480f6ec6660f62055304b2fd660f5c056bf4b1fd660f28c8660f15c8f20f58'
    'c8660f294c2460660f28c1f20f11942488000000f20f5ec2f20f118424e00000'
    '00488d4424484889442420488d051e39adff48894424284c8dac24e00000004c'
    '896c2430488b0525ff08034889442438488d359b18b0fd488dbc24c800000048'
    '8d542420ff1596a508034a8d04334883c02a0fb6004883f8070f83fb010000b9'
    '0600000029c1c1e103488d05c0d3cffdf20f100401f20f11842480000000498b'
    '442438498b4c2440488bb424b80000008b5610899424f0000000660f1006660f'
    '298424e0000000488d0cc8488944242048894c2428488b8424c0000000488944'
    '24304c896c243848896c2440488d7c2448488d742420e8c5cde9ff488d7c2420'
    '488bb424b0000000488b9424a8000000ff15aa0c0903660f28542460f20f5e94'
    '2480000000f20f108424900000000f14050b03b2fd660f5c0523f3b1fd660f28'
    'c8660f15c8f20f58c8f20f5e8c2488000000488b4c240849890f488b44241049'
    '89470849894f100fb644240641888790000000f2410f114f600f284c2470f241'
    '0f114f68488b8424a000000049894770488b842498000000498947780f108424'
    'c8000000410f114718488b8424d80000004989472841c6879100000001f2410f'
    '1197800000000f10442448410f114730488b44245849894740488b4424183401'
    '418887920000000fb6442407418887930000000f10442420410f114748488b44'
    '243049894758f2410f118f8800000041c687a500000005410fb68424a1000000'
    '418887a4000000410f10842491000000410f1187940000004c89f84881c4f800'
    '00005b415c415d415e415f5dc3488d3d2ce50003ff15d6a70803eb2b488d3d1d'
    'e50003ff15c7a70803eb1c488d3d9ef60003ff1598a40803eb0d488d3d8ff600'
    '03ff1589a408030f0bbf01000000488b742408ff15dfa208034889c3488d7c24'
    '48e8cafe0900eb09ff153aa408034889c3488bb424c80000004885f67417488b'
    'bc24d000000031d2ff1502a30803eb05eb004889c3488b7424084885f6488b7c'
    '2410740831d2ff15e4a208034889dfe8dcc3f702'
)
BODY_SHA256 = '9ccc1a0fafd10222d96ffacce777201542ba6550c4c0a3b401a70876e328535c'
BRANCHES = [
    (0xc3, '7565', 1, 2, 0x26e38ca),
    (0xe0, '735b', 1, 2, 0x26e38dd),
    (0x10a, '7449', 1, 2, 0x26e38f5),
    (0x11a, '0f8409040000', 2, 6, 0x26e3cc9),
    (0x128, 'eb30', 1, 2, 0x26e38fa),
    (0x136, '7550', 1, 2, 0x26e3928),
    (0x138, 'e9ba000000', 1, 5, 0x26e3997),
    (0x14e, '7538', 1, 2, 0x26e3928),
    (0x150, 'e9a2000000', 1, 5, 0x26e3997),
    (0x186, '746f', 1, 2, 0x26e3997),
    (0x18b, '746a', 1, 2, 0x26e3997),
    (0x190, '0f8566030000', 2, 6, 0x26e3c9c),
    (0x1b1, '0f8345030000', 2, 6, 0x26e3c9c),
    (0x1f5, 'eb1b', 1, 2, 0x26e39b2),
    (0x1fa, '0f85ed020000', 2, 6, 0x26e3c8d),
    (0x215, '0f83d2020000', 2, 6, 0x26e3c8d),
    (0x237, '0f83ce020000', 2, 6, 0x26e3cab),
    (0x319, '0f83fb010000', 2, 6, 0x26e3cba),
    (0x4fa, 'eb2b', 1, 2, 0x26e3cc7),
    (0x509, 'eb1c', 1, 2, 0x26e3cc7),
    (0x518, 'eb0d', 1, 2, 0x26e3cc7),
    (0x546, 'eb09', 1, 2, 0x26e3cf1),
    (0x55c, '7417', 1, 2, 0x26e3d15),
    (0x56e, 'eb05', 1, 2, 0x26e3d15),
    (0x570, 'eb00', 1, 2, 0x26e3d12),
    (0x582, '7408', 1, 2, 0x26e3d2c),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26e3b36, 0x2580900),
    (0x26e3ce1, 0x2783bb0),
    (0x26e3d2f, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26e38b1, 0x576dfd8),
    (0x26e3904, 0x576dfe0),
    (0x26e3aa4, 0x576e040),
    (0x26e3b50, 0x5774800),
    (0x26e3c94, 0x576e470),
    (0x26e3ca3, 0x576e470),
    (0x26e3cb2, 0x576e150),
    (0x26e3cc1, 0x576e150),
    (0x26e3cd3, 0x576dfb8),
    (0x26e3ce8, 0x576e128),
    (0x26e3d08, 0x576e010),
    (0x26e3d26, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26e3c8d, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x26e3c9c, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x26e3cab, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x26e3cba, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = [0x2565b8d, 0x2565ff9, 0x26df773, 0x26e2240, 0x26e2fdb, 0x2737c40, 0x273804a, 0x2775853]
CALLER_FUNCTIONS = {'0x2565b8d': ('0x2565b30', '0x2566415'), '0x2565ff9': ('0x2565b30', '0x2566415'), '0x26df773': ('0x26df430', '0x26e056a'), '0x26e2240': ('0x26e1d90', '0x26e242d'), '0x26e2fdb': ('0x26e2ac0', '0x26e314f'), '0x2737c40': ('0x27371f0', '0x2738e41'), '0x273804a': ('0x27371f0', '0x2738e41'), '0x2775853': ('0x27755e0', '0x27758b2')}
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

