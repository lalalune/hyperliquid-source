#!/usr/bin/env python3
"""Authenticated node94 spot-meta-42fbcb0 binding (0x42fbcb0).

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

START, END = 0x42fbcb0, 0x42fc2e8
FDE_VA = 0x122d560
FDE = bytes.fromhex(
    '5000000038f9260048e70c0338060000042ba98fff410e10420e18420e20420e'
    '28420e30410e38470ea00283078c068d058e048f03860203ea040e38410e3042'
    '0e28420e20420e18420e10410e08410ea0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece800000048897424504c8bbeb0000000488bb1'
    '700100004939f70f83480500004989cc4989d64889fb0fb682c2000000884424'
    '04488b82a000000048898424a80000000fb682b000000088442407488b82a800'
    '000048898424b8000000488b82900000004889442458488b8298000000488984'
    '24c0000000488b82d800000048898424b00000000fb682f40000008844240548'
    '8b82c80000004889442418488b82d000000048898424c80000000fb682f50000'
    '0088442406488b81680100004d89fd49c1e5054889c54a8b1428488d7c242048'
    '89ceff15307b47010fb64c24284883f902733bb80a00000048f76424200f8066'
    '0400004801c848c7c1ffffffff4989c74c0f42f94c0f43f84981ff001f0afa72'
    '434981c700e1f5054c0f42f9eb3d4c897c24604d85ff0f84ca0300004981ff00'
    'e1f505732b488d0504e3f0fb4889442420488b05782947014889442428488d44'
    '2460eb3b4981c700e1f5054c897c24604981c7001f0afa4c89bc248000000048'
    '8d0516e2f0fb4889442420488b053e2947014889442428488d84248000000048'
    '89442430488b05352247014889442438488d356b51eefb488d7c2468488d5424'
    '20ff15c9214701488b44246848894424104c8b7c2470488b4424784889442448'
    '4c01ed488b45084d8bac24880100004c39e80f8353030000488b55004c39ea0f'
    '83460300004889ac2498000000498bac24800100004869c0e80000000fb64c05'
    '494869c2e80000000fb644054838c10f825003000028c10fb6c9488d357fb53f'
    'fc488b5424184885d2743166480f6ec2660f6205787ff0fb660f5c05906ff0fb'
    '660f28c8660f15c8f20f58c8f20f5e0cc6660f298c24d0000000eb0d660f57c0'
    '660f298424d00000004c897c2418f20f1004cef20f118424a0000000837c2458'
    '027331b8030000004889442408bf03000000ff15702047014885c00f84d30200'
    '004989c7c640024166c7004e2fb803000000eb38b8090000004889442408bf09'
    '000000ff153f2047014885c00f84a20200004989c748b8547269676765726549'
    '890741c6470864b8090000004889442408488b7c2450498d86e0000000498b4e'
    '58498b56608b701089b42490000000660f1000660f29842480000000488d04d1'
    '48894c2420488944242848897c2430488d84248000000048894424384c896424'
    '40488d7c2468488d742420e8e0ef5700488d7c2420488b742458488b9424c000'
    '0000ff15c8874701488b8c24c80000004885c9744f488b842498000000488b00'
    '4c39e80f83b10100004869c0e800000066480f6ec9660f620d137ef0fb0fb644'
    '0548660f5c0d266ef0fb660f28c1660f15c1f20f58c1488d0de3b33ffcf20f5e'
    '04c1eb04660f57c0f20f108c24a80000000f140dd87df0fb660f5c0df06df0fb'
    '660f28d1660f15d1f20f58d1f20f5e9424a0000000488b442410488903488b44'
    '241848894308488b442448488943100fb6442404888390000000f20f1153600f'
    '288c24d0000000f20f114b68488b8424b000000048894370488b8424b8000000'
    '48894378488b442408488943184c897b2048894328c683910000000048c78380'
    '000000000000000f104c24680f114b30488b442478488943400fb64424058883'
    '920000000fb64424078883930000000f104c24200f114b48488b442430488943'
    '58f20f1183880000000fb64424068883a5000000410fb686c10000008883a400'
    '0000410f1086b10000000f1183940000004889d84881c4e80000005b415c415d'
    '415e415f5dc3b8090000004889442448bf09000000ff150d1e47014885c00f84'
    '870000004989c70fb605bad52bfc41884708488b05a7d52bfc498907b8090000'
    '004889442410e995fcffff488d3dee5f3f01ff1568224701eb4f488d3ddf5f3f'
    '01ff1559224701eb4048c7c0ffffffffe98efbffff488d15448a41014c89ffff'
    '15931d4701488d3d1c603f01ff150e1f4701eb15bf01000000488b7424084c8b'
    '7c2418ff155f1d47010f0bbf01000000be09000000ff154d1d47014889c34c8b'
    '742410eb294889c34c8b742410eb294889c3488b7424204885f64c8b74241074'
    '0d488b7c242831d2ff15721d4701488d7c2468e8e83805004c89ff488b742408'
    '31d2ff15581d47014c8b7c2418eb0eff15631e47014889c34c8b7424104d85f6'
    '740e4c89ff4c89f631d2ff15301d47014889dfe8283e3601'
)
BODY_SHA256 = 'e702715f7d715f01a73e5a8984070268474ab62eb4704fe59d303c867b2b55de'
BRANCHES = [
    (0x27, '0f8348050000', 2, 6, 0x42fc225),
    (0xf1, '733b', 1, 2, 0x42fbdde),
    (0xfd, '0f8066040000', 2, 6, 0x42fc219),
    (0x11f, '7243', 1, 2, 0x42fbe14),
    (0x12c, 'eb3d', 1, 2, 0x42fbe1b),
    (0x136, '0f84ca030000', 2, 6, 0x42fc1b6),
    (0x143, '732b', 1, 2, 0x42fbe20),
    (0x162, 'eb3b', 1, 2, 0x42fbe4f),
    (0x1f2, '0f8353030000', 2, 6, 0x42fc1fb),
    (0x1ff, '0f8346030000', 2, 6, 0x42fc1fb),
    (0x22f, '0f8250030000', 2, 6, 0x42fc235),
    (0x249, '7431', 1, 2, 0x42fbf2c),
    (0x27a, 'eb0d', 1, 2, 0x42fbf39),
    (0x2a1, '7331', 1, 2, 0x42fbf84),
    (0x2bb, '0f84d3020000', 2, 6, 0x42fc244),
    (0x2d2, 'eb38', 1, 2, 0x42fbfbc),
    (0x2ec, '0f84a2020000', 2, 6, 0x42fc244),
    (0x393, '744f', 1, 2, 0x42fc094),
    (0x3a3, '0f83b1010000', 2, 6, 0x42fc20a),
    (0x3e2, 'eb04', 1, 2, 0x42fc098),
    (0x51e, '0f8487000000', 2, 6, 0x42fc25b),
    (0x546, 'e995fcffff', 1, 5, 0x42fbe90),
    (0x558, 'eb4f', 1, 2, 0x42fc259),
    (0x567, 'eb40', 1, 2, 0x42fc259),
    (0x570, 'e98efbffff', 1, 5, 0x42fbdb3),
    (0x592, 'eb15', 1, 2, 0x42fc259),
    (0x5c3, 'eb29', 1, 2, 0x42fc29e),
    (0x5cd, 'eb29', 1, 2, 0x42fc2a8),
    (0x5df, '740d', 1, 2, 0x42fc29e),
    (0x60d, 'eb0e', 1, 2, 0x42fc2cd),
    (0x620, '740e', 1, 2, 0x42fc2e0),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x42fc01b, 0x487b000),
    (0x42fc2a3, 0x434fb90),
    (0x42fc2e3, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x42fbd92, 0x57738c8),
    (0x42fbe71, 0x576e040),
    (0x42fbf62, 0x576dfd8),
    (0x42fbf93, 0x576dfd8),
    (0x42fc032, 0x5774800),
    (0x42fc1c5, 0x576dfd8),
    (0x42fc202, 0x576e470),
    (0x42fc211, 0x576e470),
    (0x42fc22f, 0x576dfc8),
    (0x42fc23c, 0x576e150),
    (0x42fc253, 0x576dfb8),
    (0x42fc265, 0x576dfb8),
    (0x42fc298, 0x576e010),
    (0x42fc2b2, 0x576e010),
    (0x42fc2bf, 0x576e128),
    (0x42fc2da, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x42fc1fb, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x42fc20a, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x42fc225, 0x5714c70, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x42fc235, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x42f7e2c, 0x42f8ddc, 0x42fec57, 0x430ffed, 0x431b3dd, 0x433918b]
CALLER_FUNCTIONS = {'0x42f7e2c': ('0x42f7890', '0x42f8834'), '0x42f8ddc': ('0x42f8840', '0x42f97e4'), '0x42fec57': ('0x42fe970', '0x42ff00d'), '0x430ffed': ('0x430d610', '0x4311140'), '0x431b3dd': ('0x4318a00', '0x431c530'), '0x433918b': ('0x4338ec0', '0x4339192')}
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

