#!/usr/bin/env python3
"""Authenticated node94 spot-meta-26e10b0 binding (0x26e10b0).

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

START, END = 0x26e10b0, 0x26e16ef
FDE_VA = 0x10ec924
FDE = bytes.fromhex(
    '50000000fcec120084475f013f060000044bf992ff410e10420e18420e20420e'
    '28420e30410e38470ea00283078c068d058e048f03860203f1040e38410e3042'
    '0e28420e20420e18420e10410e08410ea0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece800000048897424504c8bbeb0000000488bb1'
    '700100004939f70f834f0500004989cc4989d64889fb0fb682c2000000884424'
    '04488b82a000000048898424a80000000fb682b000000088442407488b82a800'
    '000048898424b8000000488b82900000004889442458488b8298000000488984'
    '24c0000000488b82d800000048898424b00000000fb682f40000008844240548'
    '8b82c80000004889442418488b82d000000048898424c80000000fb682f50000'
    '0088442406488b81680100004d89fd49c1e5054889c54a8b1428488d7c242048'
    '89ceff15302709030fb64c24284883f902733bb80a00000048f76424200f806d'
    '0400004801c848c7c1ffffffff4989c74c0f42f94c0f43f84981ff001f0afa72'
    '434981c700e1f5054c0f42f9eb3d4c897c24604d85ff0f84d10300004981ff00'
    'e1f505732b488d05048fb2fd4889442420488b0578d508034889442428488d44'
    '2460eb3b4981c700e1f5054c897c24604981c7001f0afa4c89bc248000000048'
    '8d05168eb2fd4889442420488b053ed508034889442428488d84248000000048'
    '89442430488b0535ce08034889442438488d356bfdaffd488d7c2468488d5424'
    '20ff15c9cd0803488b44246848894424104c8b7c2470488b4424784889442448'
    '488b7424184c01ed488b45084d8bac24880100004c39e80f8355030000488b55'
    '004c39ea0f83480300004889ac2498000000498bac24800100004869c0e80000'
    '000fb64c05494869c2e80000000fb644054838c10f825203000028c10fb6c948'
    '8d159afbcffd4885f6743866480f6ec6660f6205782bb2fd660f5c05901bb2fd'
    '660f28c8660f15c8f20f58c8488d355d07cefdf20f5e0cc6660f298c24d00000'
    '00eb0d660f57c0660f298424d00000004c897c2418f20f1004caf20f118424a0'
    '000000837c2458027331b8030000004889442408bf03000000ff1569cc080348'
    '85c00f84d30200004989c7c640024166c7004e2fb803000000eb38b809000000'
    '4889442408bf09000000ff1538cc08034885c00f84a20200004989c748b85472'
    '69676765726549890741c6470864b8090000004889442408488b7c2450498d86'
    'e0000000498b4e58498b56608b701089b42490000000660f1000660f29842480'
    '000000488d04d148894c2420488944242848897c2430488d8424800000004889'
    '4424384c89642440488d7c2468488d742420e8798ee9ff488d7c2420488b7424'
    '58488b9424c0000000ff15c1330903488b8c24c80000004885c9744f488b8424'
    '98000000488b004c39e80f83b10100004869c0e80000000fb644054866480f6e'
    'c9660f620d072ab2fd660f5c0d1f1ab2fd660f28c1660f15c1f20f58c1488d0d'
    'ec05cefdf20f5e04c1eb04660f57c0f20f108c24a80000000f140dd129b2fd66'
    '0f5c0de919b2fd660f28d1660f15d1f20f58d1f20f5e9424a0000000488b4424'
    '10488903488b44241848894308488b442448488943100fb64424048883900000'
    '00f20f1153600f288c24d0000000f20f114b68488b8424b00000004889437048'
    '8b8424b800000048894378488b442408488943184c897b2048894328c6839100'
    '00000048c78380000000000000000f104c24680f114b30488b44247848894340'
    '0fb64424058883920000000fb64424078883930000000f104c24200f114b4848'
    '8b44243048894358f20f1183880000000fb64424068883a5000000410fb686c1'
    '0000008883a4000000410f1086b10000000f1183940000004889d84881c4e800'
    '00005b415c415d415e415f5dc3b8090000004889442448bf09000000ff1506ca'
    '08034885c00f84870000004989c70fb605b381edfd41884708488b05a081edfd'
    '498907b8090000004889442410e98efcffff488d3de70b0103ff1561ce0803eb'
    '4f488d3dd80b0103ff1552ce0803eb4048c7c0ffffffffe987fbffff488d153d'
    '3603034c89ffff158cc90803488d3d150c0103ff1507cb0803eb15bf01000000'
    '488b7424084c8b7c2418ff1558c908030f0bbf01000000be09000000ff1546c9'
    '08034889c34c8b742410eb294889c34c8b742410eb294889c3488b7424204885'
    'f64c8b742410740d488b7c242831d2ff156bc90803488d7c2468e801250a004c'
    '89ff488b74240831d2ff1551c908034c8b7c2418eb0eff155cca08034889c34c'
    '8b7424104d85f6740e4c89ff4c89f631d2ff1529c908034889dfe821eaf702'
)
BODY_SHA256 = 'b1026e10cd2d563681d89300eb0537ce839315ea9bf4e615b207c0cfdc89bf90'
BRANCHES = [
    (0x27, '0f834f050000', 2, 6, 0x26e162c),
    (0xf1, '733b', 1, 2, 0x26e11de),
    (0xfd, '0f806d040000', 2, 6, 0x26e1620),
    (0x11f, '7243', 1, 2, 0x26e1214),
    (0x12c, 'eb3d', 1, 2, 0x26e121b),
    (0x136, '0f84d1030000', 2, 6, 0x26e15bd),
    (0x143, '732b', 1, 2, 0x26e1220),
    (0x162, 'eb3b', 1, 2, 0x26e124f),
    (0x1f7, '0f8355030000', 2, 6, 0x26e1602),
    (0x204, '0f8348030000', 2, 6, 0x26e1602),
    (0x234, '0f8252030000', 2, 6, 0x26e163c),
    (0x249, '7438', 1, 2, 0x26e1333),
    (0x281, 'eb0d', 1, 2, 0x26e1340),
    (0x2a8, '7331', 1, 2, 0x26e138b),
    (0x2c2, '0f84d3020000', 2, 6, 0x26e164b),
    (0x2d9, 'eb38', 1, 2, 0x26e13c3),
    (0x2f3, '0f84a2020000', 2, 6, 0x26e164b),
    (0x39a, '744f', 1, 2, 0x26e149b),
    (0x3aa, '0f83b1010000', 2, 6, 0x26e1611),
    (0x3e9, 'eb04', 1, 2, 0x26e149f),
    (0x525, '0f8487000000', 2, 6, 0x26e1662),
    (0x54d, 'e98efcffff', 1, 5, 0x26e1290),
    (0x55f, 'eb4f', 1, 2, 0x26e1660),
    (0x56e, 'eb40', 1, 2, 0x26e1660),
    (0x577, 'e987fbffff', 1, 5, 0x26e11b3),
    (0x599, 'eb15', 1, 2, 0x26e1660),
    (0x5ca, 'eb29', 1, 2, 0x26e16a5),
    (0x5d4, 'eb29', 1, 2, 0x26e16af),
    (0x5e6, '740d', 1, 2, 0x26e16a5),
    (0x614, 'eb0e', 1, 2, 0x26e16d4),
    (0x627, '740e', 1, 2, 0x26e16e7),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26e1422, 0x257a2a0),
    (0x26e16aa, 0x2783bb0),
    (0x26e16ea, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26e1192, 0x57738c8),
    (0x26e1271, 0x576e040),
    (0x26e1369, 0x576dfd8),
    (0x26e139a, 0x576dfd8),
    (0x26e1439, 0x5774800),
    (0x26e15cc, 0x576dfd8),
    (0x26e1609, 0x576e470),
    (0x26e1618, 0x576e470),
    (0x26e1636, 0x576dfc8),
    (0x26e1643, 0x576e150),
    (0x26e165a, 0x576dfb8),
    (0x26e166c, 0x576dfb8),
    (0x26e169f, 0x576e010),
    (0x26e16b9, 0x576e010),
    (0x26e16c6, 0x576e128),
    (0x26e16e1, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26e1602, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26e1611, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26e162c, 0x5714c70, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x26e163c, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x232d4a3, 0x256c9cf, 0x256cf89, 0x26dea1d, 0x26e19d7, 0x26eabb2, 0x277529b]
CALLER_FUNCTIONS = {'0x232d4a3': ('0x232d1b0', '0x232d585'), '0x256c9cf': ('0x256c8d0', '0x256d1b5'), '0x256cf89': ('0x256c8d0', '0x256d1b5'), '0x26dea1d': ('0x26de3d0', '0x26df425'), '0x26e19d7': ('0x26e16f0', '0x26e1d8d'), '0x26eabb2': ('0x26e81c0', '0x26ebdc0'), '0x277529b': ('0x2774fd0', '0x27752a2')}
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

