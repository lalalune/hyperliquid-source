#!/usr/bin/env python3
"""Authenticated node94 spot-meta-26e3150 binding (0x26e3150).

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

START, END = 0x26e3150, 0x26e3799
FDE_VA = 0x10ecac8
FDE = bytes.fromhex(
    '50000000a0ee120080665f0149060000040bf992ff410e10420e18420e20420e'
    '28420e30410e38470ec00283078c068d058e048f0386020333050e38410e3042'
    '0e28420e20420e18420e10410e08410ec0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec080100004c898424d800000048898c24e00000'
    '004889b424e80000004c8bbeb0000000498bb1700100004939f70f8348050000'
    '4c89cd4989d64889fb0fb682a200000088442406488b828000000048898424b8'
    '000000488b024889442450488b420848894424400fb682900000008844240748'
    '8b828800000048898424c0000000488b427048898424d0000000488b42784889'
    '8424c8000000488b82a800000048898424b00000004d8ba1680100004d89fd49'
    'c1e5054b8b142c488d7c24184c89ceff15a30609030fb64c24204883f9024c89'
    '7c2448733bb80a00000048f76424180f80870400004801c848c7c2ffffffff48'
    '89c1480f42ca480f43c84881f9001f0afa72464881c100e1f505480f42caeb40'
    '4c897c24704d85ff0f842d0100004c89f94981ff00e1f505732b488d056f6eb2'
    'fd4889442418488b05e3b408034889442420488d442470eb3b4881c100e1f505'
    '48894c24704881c1001f0afa48898c2490000000488d05816db2fd4889442418'
    '488b05a9b408034889442420488d8424900000004889442428488b05a0ad0803'
    '4889442430488d35d6dcaffd488d7c2458488d542418ff1534ad0803488b4424'
    '584889442410488b4424604889442408488b7c2468488b7424504d01ec4885f6'
    '0f84c2000000498b04244c8b4424404d85c00f84b4000000483b85880100000f'
    '8368030000488b8d800100004869d0e80000000fb64c114866490f6ec0660f62'
    '050b0bb2fd660f5c0523fbb1fd660f28c8660f15c8f20f58c8488d15f0e6cdfd'
    'f20f5e0cca498b4c24084c8bad880100004c39e9726fe9f4020000b809000000'
    '4889442410bf09000000ff1518ac08034885c00f843d0300000fb60dc863edfd'
    '884808488b0db663edfd4889442408488908bf09000000488b7424504d01ec48'
    '85f60f853effffff498b0424660f57c9498b4c24084c8bad880100004c39e90f'
    '838a0200004c39e80f8381020000660f298c24f000000048897c24404c8bbd80'
    '0100004869c9e8000000410fb64c0f494869c0e8000000412a4c07480f829602'
    '0000498db6a80000000fb6c1488d0d2ddacffdf20f1004c1f20f118424a80000'
    '000fb64c2406488dbc24900000004889ea4c8b442448e8b50dc5ff498b442408'
    '4c39e80f8315020000498b0c244c39e90f83080200004869c0e8000000410fb6'
    '4407494869c9e8000000412a440f480f82320200000fb6c0488d0dc1d9cffdf2'
    '0f1004c1f20f11442448498b4638498b4e40488bb424e00000008b5610899424'
    '80000000660f1006660f29442470488d0cc8488944241848894c2420488b8424'
    'e80000004889442428488d442470488944243048896c2438488d7c2458488d74'
    '2418e8696de9ff4c8b7c2450488d7c2418488bb424d0000000488b9424c80000'
    '004c8b6424104c8b6c2408ff159f120903f20f108424b0000000f20f100d0e09'
    'b2fd0f14c1660f281523f9b1fd660f5cc2660f28d8660f15d8f20f58d8f20f5e'
    '5c2448f20f108424b80000000f14c1660f5cc2660f28c8660f15c8f20f58c8f2'
    '0f5e8c24a80000004c89234c896b08488b442440488943100fb6442406888390'
    '000000f20f114b600f288c24f0000000f20f114b68488b8424d8000000488943'
    '70488b8424c0000000488943780f108424900000000f114318488b8424a00000'
    '0048894328c6839100000001f20f119b800000000f104424580f114330488b44'
    '2468488943404180f7014488bb920000000fb64424078883930000000f104424'
    '180f114348488b44242848894358f20f118b88000000c683a500000005410fb6'
    '86a10000008883a4000000410f1086910000000f1183940000004889d84881c4'
    '080100005b415c415d415e415f5dc3488d3d4aeb0003ff15c4ad0803eb56488d'
    '3d3beb0003ff15b5ad0803eb47488d3d2ceb0003ff15a6ad0803eb3848c7c0ff'
    'ffffffe96dfbffff488d15911503034c89ffff15e0a80803488d3d69eb0003ff'
    '155baa0803eb0d488d3d5aeb0003ff154caa08030f0bbf01000000be09000000'
    'ff15a2a808034889c3488d7c2458e88d040a00eb31ff15fda908034889c34c8b'
    '7424104d85f64c8b7c240874544c89ff4c89f631d2ff15c5a808034889dfe8bd'
    'c9f7024889c34c8b7424104c8b7c2408488bb424900000004885f6741f488bbc'
    '249800000031d2ff1593a80803eb0d4889c34c8b7424104c8b7c24084d85f675'
    'ac4889dfe877c9f702'
)
BODY_SHA256 = 'f6c5eeaf9e6a903cdd85397c19007878aa4d7030220662e386f350b4e21dbed3'
BRANCHES = [
    (0x3a, '0f8348050000', 2, 6, 0x26e36d8),
    (0xe3, '733b', 1, 2, 0x26e3270),
    (0xef, '0f8087040000', 2, 6, 0x26e36cc),
    (0x111, '7246', 1, 2, 0x26e32a9),
    (0x11e, 'eb40', 1, 2, 0x26e32b0),
    (0x128, '0f842d010000', 2, 6, 0x26e33ab),
    (0x138, '732b', 1, 2, 0x26e32b5),
    (0x157, 'eb3b', 1, 2, 0x26e32e4),
    (0x1e0, '0f84c2000000', 2, 6, 0x26e33f8),
    (0x1f2, '0f84b4000000', 2, 6, 0x26e33fc),
    (0x1ff, '0f8368030000', 2, 6, 0x26e36bd),
    (0x254, '726f', 1, 2, 0x26e3415),
    (0x256, 'e9f4020000', 1, 5, 0x26e369f),
    (0x273, '0f843d030000', 2, 6, 0x26e3706),
    (0x2a2, '0f853effffff', 2, 6, 0x26e3336),
    (0x2bf, '0f838a020000', 2, 6, 0x26e369f),
    (0x2c8, '0f8381020000', 2, 6, 0x26e369f),
    (0x2fc, '0f8296020000', 2, 6, 0x26e36e8),
    (0x343, '0f8315020000', 2, 6, 0x26e36ae),
    (0x350, '0f8308020000', 2, 6, 0x26e36ae),
    (0x36f, '0f8232020000', 2, 6, 0x26e36f7),
    (0x55c, 'eb56', 1, 2, 0x26e3704),
    (0x56b, 'eb47', 1, 2, 0x26e3704),
    (0x57a, 'eb38', 1, 2, 0x26e3704),
    (0x583, 'e96dfbffff', 1, 5, 0x26e3245),
    (0x5a5, 'eb0d', 1, 2, 0x26e3704),
    (0x5d3, 'eb31', 1, 2, 0x26e3756),
    (0x5eb, '7454', 1, 2, 0x26e3791),
    (0x61b, '741f', 1, 2, 0x26e378c),
    (0x62d, 'eb0d', 1, 2, 0x26e378c),
    (0x63f, '75ac', 1, 2, 0x26e373d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26e3486, 0x2334240),
    (0x26e3532, 0x257a2a0),
    (0x26e371e, 0x2783bb0),
    (0x26e374e, 0x5660110),
    (0x26e3794, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26e321f, 0x57738c8),
    (0x26e3306, 0x576e040),
    (0x26e33ba, 0x576dfd8),
    (0x26e355b, 0x5774800),
    (0x26e36a6, 0x576e470),
    (0x26e36b5, 0x576e470),
    (0x26e36c4, 0x576e470),
    (0x26e36e2, 0x576dfc8),
    (0x26e36ef, 0x576e150),
    (0x26e36fe, 0x576e150),
    (0x26e3710, 0x576dfb8),
    (0x26e3725, 0x576e128),
    (0x26e3745, 0x576e010),
    (0x26e3777, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26e369f, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26e36ae, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26e36bd, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26e36d8, 0x5714c70, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x26e36e8, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
    (0x26e36f7, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x256c92d, 0x256cd99, 0x26de6dc, 0x26e1ba0, 0x26e294b, 0x2775243]
CALLER_FUNCTIONS = {'0x256c92d': ('0x256c8d0', '0x256d1b5'), '0x256cd99': ('0x256c8d0', '0x256d1b5'), '0x26de6dc': ('0x26de3d0', '0x26df425'), '0x26e1ba0': ('0x26e16f0', '0x26e1d8d'), '0x26e294b': ('0x26e2430', '0x26e2abf'), '0x2775243': ('0x2774fd0', '0x27752a2')}
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

