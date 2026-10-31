#!/usr/bin/env python3
"""Authenticated node94 spot-meta-257c010 binding (0x257c010).

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

START, END = 0x257c010, 0x257c5ca
FDE_VA = 0x10cd0a4
FDE = bytes.fromhex(
    '500000007cf4100064ef4a01ba05000004f3a093ff410e10420e18420e20420e'
    '28420e30410e38440e900183078c068d058e048f038602032b050e38410e3042'
    '0e28420e20420e18420e10410e08410e90010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec584889f54989fd4889f7e8f43e26004885c074'
    '7c488b7548488b0e4885c97463488b76084c8b200fb779624189f841c1e00348'
    'c7c0ffffffff662e0f1f8400000000004d85c0742b4c3b64c110410f97c14180'
    'd90048ffc04983c0f84180f90174e1410fb6f985ff750ceb410f1f8000000000'
    '4889f84883ee017207488b4cc168eba44889efe8783e26004885c0758449c745'
    '000000000049c745080800000049c7451000000000e9780400004c8b7550488b'
    '1a4c89f74c89e6ff15bb701f034d3ba6880100000f83790400004c896c242049'
    '8b86800100004969cce80000000fb6440849488d0dff8900fef20f1004c1f20f'
    '110424bf40000000ff15ba1e1f034885c00f846704000066480f6ec3660f6205'
    '4c7dc8fd660f5c05646dc8fd660f28c8660f15c8f20f58c8f20f5e0c244c8920'
    'f20f11480848c744240804000000488944241048c744241801000000488b5d40'
    '4885db0f84a9030000488b55004c8b6d08488b4d10488b7d184c8b7d48488b75'
    '504889742430be010000004c897c2428eb4b66666666662e0f1f840000000000'
    '4889f148c1e10448892c08660f28442440f20f1144080848ffc64889742418b2'
    '01b900000000488b5c24384885db4c8b7c2428488b3c240f8435030000f6c201'
    '0f84890300004d85ed7425410fb795ba0000004839d70f83c40000004d89eb48'
    '89fae9de000000660f1f8400000000004885ff74384889fa4989cd4883e20774'
    '3131c9666666662e0f1f8400000000004d8badc000000048ffc14839ca75f148'
    '89fa4829ca4883ff087315eb514989cdeb4c4889fa4883ff0872430f1f440000'
    '498b8dc0000000488b89c0000000488b89c0000000488b89c0000000488b89c0'
    '000000488b89c0000000488b89c00000004c8ba9c00000004883c2f875c231ff'
    '31c9410fb795ba0000004839d70f8249ffffff666666662e0f1f840000000000'
    '4d8b5d004d85db0f849302000048ffc1410fb795b80000004d89dd66413b93ba'
    '00000073db4885c90f84a20000004d8d0cd34981c1c80000004889cf4883e707'
    '0f84fa0100004531c00f1f80000000004d8b294d8d8dc000000049ffc04c39c7'
    '75ee4889cf4c29c74883f90872436690498b09488b89c0000000488b89c00000'
    '00488b89c0000000488b89c0000000488b89c0000000488b89c00000004c8ba9'
    'c00000004d8d8dc00000004883c7f875bf48c704240000000048ffcb498b0f48'
    '85c97526e9570100000f1f8000000000488d4a0148890c244d89dd48ffcb498b'
    '0f4885c90f84360100004d8b7708498b6cd308440fb741624589c141c1e10348'
    'c7c7ffffffff662e0f1f8400000000004d85c9743b483b6cf910410f97c24180'
    'da0048ffc74983c1f84180fa0174e1450fb6c24585c074384983ee01731fe9dd'
    '000000666666662e0f1f8400000000004c89c74983ee010f82c3000000488b4c'
    'f968eb8f6666662e0f1f8400000000004989f448895c24384889c34d8b7cd360'
    '4c8b7424304c89f74889eeff15376d1f03493bae880100000f83e60000004889'
    'd8498b96800100004869cde80000000fb6540a4966490f6ec7660f6205ef79c8'
    'fd660f5c05076ac8fd660f28c8660f15c8f20f58c8488d0d5c8600fef20f5e0c'
    'd1660f294c24404c89e64c3b6424080f85ebfcffffba01000000b90800000041'
    'b810000000488d7c2408e891ebf9ff488b4424104c89e6e9c4fcffff0f1f4000'
    'b201b9000000004885db488b3c240f85e9fcffffeb1c662e0f1f840000000000'
    '4889cf4883f9080f8264feffffe91efeffff488b4424184c8b6c242049894510'
    '488b44240849894500488b442410498945084c89e84883c4585b415c415d415e'
    '415f5dc3488d3d955c1703ff150f1f1f03eb29488d3d865c1703ff15001f1f03'
    '488d3dc98f1403ff15f31e1f03eb0d488d3d6a721403ff15e41e1f030f0bbf08'
    '000000be40000000ff151a1a1f03eb04eb020f0b4889c3488b7424084885f674'
    '11488b7c241048c1e60431d2ff154e1a1f034889dfe8463b0e03'
)
BODY_SHA256 = 'c390a3b526157bf02f8008f9ca40f0e38bb28b475ba21e2bfa063f22c2828d34'
BRANCHES = [
    (0x1f, '747c', 1, 2, 0x257c0ad),
    (0x2b, '7463', 1, 2, 0x257c0a0),
    (0x53, '742b', 1, 2, 0x257c090),
    (0x6d, '74e1', 1, 2, 0x257c060),
    (0x75, '750c', 1, 2, 0x257c093),
    (0x77, 'eb41', 1, 2, 0x257c0ca),
    (0x87, '7207', 1, 2, 0x257c0a0),
    (0x8e, 'eba4', 1, 2, 0x257c044),
    (0x9b, '7584', 1, 2, 0x257c031),
    (0xb5, 'e978040000', 1, 5, 0x257c542),
    (0xd4, '0f8379040000', 2, 6, 0x257c563),
    (0x111, '0f8467040000', 2, 6, 0x257c58e),
    (0x163, '0f84a9030000', 2, 6, 0x257c522),
    (0x190, 'eb4b', 1, 2, 0x257c1ed),
    (0x1d7, '0f8435030000', 2, 6, 0x257c522),
    (0x1e0, '0f8489030000', 2, 6, 0x257c57f),
    (0x1e9, '7425', 1, 2, 0x257c220),
    (0x1f6, '0f83c4000000', 2, 6, 0x257c2d0),
    (0x202, 'e9de000000', 1, 5, 0x257c2f5),
    (0x213, '7438', 1, 2, 0x257c25d),
    (0x21f, '7431', 1, 2, 0x257c262),
    (0x23d, '75f1', 1, 2, 0x257c240),
    (0x249, '7315', 1, 2, 0x257c270),
    (0x24b, 'eb51', 1, 2, 0x257c2ae),
    (0x250, 'eb4c', 1, 2, 0x257c2ae),
    (0x259, '7243', 1, 2, 0x257c2ae),
    (0x29c, '75c2', 1, 2, 0x257c270),
    (0x2ad, '0f8249ffffff', 2, 6, 0x257c20c),
    (0x2c7, '0f8493020000', 2, 6, 0x257c570),
    (0x2e3, '73db', 1, 2, 0x257c2d0),
    (0x2e8, '0f84a2000000', 2, 6, 0x257c3a0),
    (0x300, '0f84fa010000', 2, 6, 0x257c510),
    (0x320, '75ee', 1, 2, 0x257c320),
    (0x32c, '7243', 1, 2, 0x257c381),
    (0x36f, '75bf', 1, 2, 0x257c340),
    (0x382, '7526', 1, 2, 0x257c3ba),
    (0x384, 'e957010000', 1, 5, 0x257c4f0),
    (0x3a4, '0f8436010000', 2, 6, 0x257c4f0),
    (0x3d3, '743b', 1, 2, 0x257c420),
    (0x3ed, '74e1', 1, 2, 0x257c3e0),
    (0x3f6, '7438', 1, 2, 0x257c440),
    (0x3fc, '731f', 1, 2, 0x257c42d),
    (0x3fe, 'e9dd000000', 1, 5, 0x257c4f0),
    (0x417, '0f82c3000000', 2, 6, 0x257c4f0),
    (0x422, 'eb8f', 1, 2, 0x257c3c3),
    (0x458, '0f83e6000000', 2, 6, 0x257c554),
    (0x4af, '0f85ebfcffff', 2, 6, 0x257c1b0),
    (0x4d7, 'e9c4fcffff', 1, 5, 0x257c1b0),
    (0x4ee, '0f85e9fcffff', 2, 6, 0x257c1ed),
    (0x4f4, 'eb1c', 1, 2, 0x257c522),
    (0x507, '0f8264feffff', 2, 6, 0x257c381),
    (0x50d, 'e91efeffff', 1, 5, 0x257c340),
    (0x551, 'eb29', 1, 2, 0x257c58c),
    (0x56d, 'eb0d', 1, 2, 0x257c58c),
    (0x58e, 'eb04', 1, 2, 0x257c5a4),
    (0x590, 'eb02', 1, 2, 0x257c5a4),
    (0x59f, '7411', 1, 2, 0x257c5c2),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x257c027, 0x27dff20),
    (0x257c0a3, 0x27dff20),
    (0x257c4da, 0x251b070),
    (0x257c5c5, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x257c0d7, 0x5773198),
    (0x257c118, 0x576dfd8),
    (0x257c45b, 0x5773198),
    (0x257c55b, 0x576e470),
    (0x257c56a, 0x576e470),
    (0x257c577, 0x576e470),
    (0x257c586, 0x576e470),
    (0x257c598, 0x576dfb8),
    (0x257c5bc, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x257c554, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x257c563, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x257c570, 0x56c5540, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x257c57f, 0x56c37f0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = [0x27ef101]
CALLER_FUNCTIONS = {'0x27ef101': ('0x27ef0b0', '0x27ef2cf')}
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

