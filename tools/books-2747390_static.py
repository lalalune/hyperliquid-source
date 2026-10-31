#!/usr/bin/env python3
"""Authenticated node94 books-2747390 binding (0x2747390).

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

START, END = 0x2747390, 0x2747b4b
FDE_VA = 0x10f025c
FDE = bytes.fromhex(
    '50000000342613002c716501bb070000048ffc92ff410e10420e18420e20420e'
    '28420e30410e38470ed00483078c068d058e048f03860203af050e38410e3042'
    '0e28420e20420e18420e10410e08410ed0040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec180200004889fb48898c24d8000000488b8688'
    '00000080be800000000066c70424fb000f84a90100004989cf4989d44989f645'
    '89c548894424684889e7e8c17703004d3bbe180200000f8313070000498d8680'
    '00000048898424d00000004d8d8e90000000498b8e100200004969d7e8000000'
    '488b441158488b4c1160498b96f8010000498bb60002000048c1e10331ff6690'
    '4839f90f8440010000488b2c384839f50f83c60600004989e849c1e0054883c7'
    '084a837c02080075d744896c2474418b4424108984247001000066410f100424'
    '660f29842460010000410fb686f2080000888424b000000048c7442410000000'
    '0048897424184c894c24604c890c24488d8424b00000004889442408488dbc24'
    '000100004889e6e894ea4601488b842400010000488b8c240801000031d24889'
    'c64885c00f95c27408488bb424100100004889142448c7442408000000004889'
    '44241048894c2418488954242048c744242800000000488944243048894c2438'
    '48897424404c89742448488d84246001000048894424504c8d6c24784889e64c'
    '89efe8390b0a00488db424d80000004c89efe839ea11004883bc248800000000'
    '744466c703df00488d05c087cafd4889430848c7431022000000e95503000066'
    'c703fb00e9cd03000066c703df00488d05bb87cafd4889430848c743101f0000'
    '00e9b00300000fb6c08d0c40ffc14889e74c89f64c89e2e884a5000066813c24'
    '86010f85d0020000498bb6903300004839f50f8354050000498b868833000048'
    '69cdd80000004c8d2408488d34084881c680000000488dbc24e00000004c89e2'
    'e8cb02c5ff4c8d2d0387cafd4883bc24e0000000000f8499000000488b8424e8'
    '00000048898424c80000004c89e7e84d8ff9ff4889c5488b7c24604c89feff15'
    '14cf020366480f6ec5f30f7e153fc8abfd660f62c2660f281d53b8abfd660f5c'
    'c3660f28c8660f15c8f20f58c866480f6ec0660f62c2660f5cc3660f28d0660f'
    '15d0f20f58d0f20f5ecaf20f580df62bacfd488d2db750acfdf20f1005d730ac'
    'fd660f2ec173174989edb820000000e993000000b81f000000e9890000004883'
    'bc24c800000000b81f00000074794c89e7e8aa8ef9ff4989c4488b7c24604c89'
    'feff1571ce020366490f6ec4f30f7e159cc7abfd660f62c2660f281db0b7abfd'
    '660f5cc3660f28c8660f15c8f20f58c866480f6ec0660f62c2660f5cc3660f28'
    'd0660f15d0f20f58d0f20f5ecaf20f580d532bacfd660f2e0d432dacfd4989ed'
    'b820000000731266c703df004c896b0848894310e97b010000418b4668898424'
    '08010000498b46604889842400010000440fb64424744889e7488d8c24000100'
    '004c8b6424604c89e64c89faff157ed4020366813c2486010f85fa0000004c89'
    'e7488b7424684c89faff1569d402034883f8010f85b20100004981c6003a0000'
    '488dbc24000100004c89f6488b9424d00000004c89f9ff1544d4020383bc2400'
    '010000010f859a0000004c8bbc2408010000488b8c2410010000f20f10842418'
    '010000f20f108c24200100004889e74c89fe4c89e2ff1505c60203833c24010f'
    '85e0020000488b4424484889842410020000660f10442408660f104c2418660f'
    '10542428660f105c2438660f299c2400020000660f299424f0010000660f298c'
    '24e0010000660f298424d00100004889e7488d8c24d00100004c89f64c89fae8'
    '4c3fc50066c7038601488d7c2478e88d591600e9be0000000f104424500f1143'
    '500f104424400f114340660f100424660f104c2410660f10542420660f105c24'
    '30660f115b30660f115320660f114b10660f1103488b4c24784885c9743d488b'
    '942480000000488b84248800000048c74424080000000048894c241048895424'
    '1848c74424280000000048894c24304889542438b901000000eb0431c931c048'
    '890c2448894c242048894424404c8db424000100004989e70f1f840000000000'
    '4c89f74c89fee8e53b12004883bc24000100000075ea4889d84881c418020000'
    '5b415c415d415e415f5dc34c89e7488b742468ff15afd202034889c74889d64c'
    '89f2e8b9ee0300660f57c9660f298c24b0000000c78424c00000000000000048'
    '8b44246848898424f00000004c89bc24f80000004889e7ff1573d202030fb704'
    '243d860100000f85d0000000660f10442404660f11842492000000660f298424'
    'c0010000488dbc2400010000488d9424b0000000488d8c24f00000004c8d8424'
    'c00100004c89f6e814090000488dbc2460010000488db42400010000e82fef03'
    '000fb78424600100003d860100000f8485fdffff0fb78c246601000066894b06'
    '8b8c2462010000894b02488b8c24680100000f108424800100000f1143200f10'
    '8424900100000f1143300f108424a00100000f1143400f108424b00100000f11'
    '4350660f10842470010000660f11431066890348894b08e938feffff0fb74c24'
    '1266898c24a00000000f104424020f298424900000000f104424500f1143500f'
    '104424440f1143440f104424340f1143340f104424240f1143240f104424140f'
    '1143140fb78c24a000000066894b12660f28842490000000660f114302668903'
    'e9cffdffff66c7038601e9c5fdffff488d3deaa6fa02ff1564690203488d15c5'
    'a4fa024889efff15ac640203488d153d39f7024889efff159c6402030f0beb00'
    '4889c3488d7c2478e8d35616004889dfe8cb85f102ff15dd650203'
)
BODY_SHA256 = '90cc624261e8354cd4e8960ded6cc224ac61870d2124a6b6f87172a457f1dc57'
BRANCHES = [
    (0x30, '0f84a9010000', 2, 6, 0x274756f),
    (0x56, '0f8313070000', 2, 6, 0x2747aff),
    (0xa3, '0f8440010000', 2, 6, 0x2747579),
    (0xb0, '0f83c6060000', 2, 6, 0x2747b0c),
    (0xc7, '75d7', 1, 2, 0x2747430),
    (0x147, '7408', 1, 2, 0x27474e1),
    (0x1c0, '7444', 1, 2, 0x2747596),
    (0x1da, 'e955030000', 1, 5, 0x27478c4),
    (0x1e4, 'e9cd030000', 1, 5, 0x2747946),
    (0x201, 'e9b0030000', 1, 5, 0x2747946),
    (0x222, '0f85d0020000', 2, 6, 0x2747888),
    (0x232, '0f8354050000', 2, 6, 0x2747b1c),
    (0x275, '0f8499000000', 2, 6, 0x27476a4),
    (0x305, '7317', 1, 2, 0x27476ae),
    (0x30f, 'e993000000', 1, 5, 0x2747737),
    (0x319, 'e989000000', 1, 5, 0x2747737),
    (0x32c, '7479', 1, 2, 0x2747737),
    (0x3a5, '7312', 1, 2, 0x2747749),
    (0x3b4, 'e97b010000', 1, 5, 0x27478c4),
    (0x3f8, '0f85fa000000', 2, 6, 0x2747888),
    (0x413, '0f85b2010000', 2, 6, 0x274795b),
    (0x444, '0f859a000000', 2, 6, 0x2747874),
    (0x47f, '0f85e0020000', 2, 6, 0x2747af5),
    (0x4f3, 'e9be000000', 1, 5, 0x2747946),
    (0x53c, '743d', 1, 2, 0x274790b),
    (0x579, 'eb04', 1, 2, 0x274790f),
    (0x5b4, '75ea', 1, 2, 0x2747930),
    (0x626, '0f85d0000000', 2, 6, 0x2747a8c),
    (0x68e, '0f8485fdffff', 2, 6, 0x27477a9),
    (0x6f7, 'e938feffff', 1, 5, 0x27478c4),
    (0x760, 'e9cffdffff', 1, 5, 0x27478c4),
    (0x76a, 'e9c5fdffff', 1, 5, 0x27478c4),
    (0x79e, 'eb00', 1, 2, 0x2747b30),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x27473da, 0x277eba0),
    (0x27474b7, 0x3bb5f50),
    (0x2747532, 0x27e8070),
    (0x2747542, 0x2865f80),
    (0x27475a7, 0x2751b30),
    (0x27475f0, 0x23978c0),
    (0x274761e, 0x26e0570),
    (0x27476c1, 0x26e0570),
    (0x274786f, 0x339b7c0),
    (0x274787e, 0x28ad210),
    (0x2747936, 0x286b520),
    (0x2747972, 0x2786830),
    (0x27479f7, 0x2748310),
    (0x2747a0c, 0x2786940),
    (0x2747b38, 0x28ad210),
    (0x2747b40, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x274762e, 0x5774548),
    (0x27476d1, 0x5774548),
    (0x274777c, 0x5774c00),
    (0x2747799, 0x5774c08),
    (0x27477c6, 0x5774c10),
    (0x2747805, 0x5773e10),
    (0x2747963, 0x5774c18),
    (0x27479a7, 0x5774c20),
    (0x2747b06, 0x576e470),
    (0x2747b16, 0x576dfc8),
    (0x2747b26, 0x576dfc8),
    (0x2747b45, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2747aff, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2747b0c, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x2747b1c, 0x56bb460, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = [0x2358581, 0x23e8237]
CALLER_FUNCTIONS = {'0x2358581': ('0x2355f40', '0x235e836'), '0x23e8237': ('0x23e7d10', '0x23e863d')}
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

