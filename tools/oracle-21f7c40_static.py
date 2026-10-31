#!/usr/bin/env python3
"""Authenticated node94 oracle-21f7c40 binding (0x21f7c40).

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

START, END = 0x21f7c40, 0x21f851f
FDE_VA = 0x108fdf0
FDE = bytes.fromhex(
    '50000000c8210d00487e1601df08000004df5294ff410e10420e18420e20420e'
    '28420e30410e38470e900383078c068d058e048f03860203cd020e38410e3042'
    '0e28420e20420e18420e10410e08410e90030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec580100004889cd48899424d00000004989f748'
    '89fb8b7620450fb677354d8b6710498b47184889442460450fb66f36488d91b8'
    '0500004881c190000000488d7c2468ff15bbbc57030fb74424683d8601000075'
    '11807c247000746b66c7036300e9620200000fb74c246e66894b068b4c246a89'
    '4b020f10842480000000f30f6f8c24900000000f109424a00000000f109c24b0'
    '0000000f114318f30f7f4b280f1153380f115b48488b8c24c000000048894b58'
    'f30f6f442470668903f30f7f4308e90102000044886c24154488742417498d4f'
    '24488b442478410f10070f29842400010000f30f6f01f30f7f8424280100000f'
    'b64910888c243801000048b94b598638d6c56d34488944241848f7e14989d549'
    'c1ed0b4c3badc80500000f83490700000fb6842428010000884424140fb68424'
    '0001000088442412488b84240101000048898424e00000000fb6842409010000'
    '884424114889ac24f8000000488badc00500004d69f5f002000066c744246841'
    '01488d7c2468e8c51618014e3b6c35304c8b4424180f85b90600004889e94969'
    'c5102700004d89c54929c54c01f14c3b69100f839c060000488b41084e8d1c6d'
    '000000004d01eb4c89da48c1e204440fb64c102a4183f9070f83c9060000418d'
    '410289c283e201488d34d248ffc6a802488bac24f8000000740e486bf66489c2'
    '83e20e83fa027422a80475084183f9067411eb694869f61027000083e00c83f8'
    '0474074869f600e1f5054c89e04809f048c1e82074124c89e031d248f7f64989'
    'c24c39e67611eb354489e031d2f7f64189c24c39e677264885d27521b2084428'
    'ca0fb6fa89fe83e6014c8d24f649ffc440f6c702750e488b442460eb1a66c703'
    '6500eb504d6be46489fe83e6fe83fe02488b4424607422f6c20475074585c975'
    '2eeb0f4d69e41027000083e7fc83ff0474074d69e400e1f5054889c24c09e248'
    'c1ea20742431d249f7f44885d2742466c70366004889d84881c4580100005b41'
    '5c415d415e415f5dc331d241f7f44885d275dc4c899c24f00000004889442458'
    '4c899424d8000000498d570a0fb644241288442420488b8424e0000000488944'
    '24210fb6442411884424298b028944242a48899424e80000000fb74204668944'
    '242e488d7c2468488d7424204c89c24989cee8496313000fb74424683d860100'
    '000f8513010000488b44247048898424c80000000fb6442478884424160fb644'
    '2479884424130fb744247e8b4c247a894c2448668944244c488b8c24d0000000'
    '8b411089442430f30f6f01660f7f44242048892c24440fb64c2415488d7c2468'
    '488d5424204c897424504c89f6488b4c24184c8b442458e8842e4d0066817c24'
    '6886010f8521040000f6442414017420660fefc0f30f6f8c2429010000660f74'
    'c8660fd7c13dffff00000f842b010000488b7c24184889eee853314d00488b7c'
    '2450488b77704939f50f8385040000488b4768488b8c24f000000048c1e1054c'
    '8b6c0820807c2413024c8bb424d8000000488b9424c80000000f85a50000004d'
    '89e880fa04488b7424180f85fa00000066c7038100e95afeffff0fb74c246e66'
    '894b068b4c246a894b02488b4c24700fb75424788b74247a897424400fb77424'
    '7e6689742444488bb424c0000000488973580f108424b00000000f1143480f10'
    '8424a00000000f1143380f108424900000000f114328f30f6f842480000000f3'
    '0f7f43180fb7742444668973168b74244089731266890348894b0866895310e9'
    'd0fdffff48b80080c6a47e8d03004839c2488b7424187745e833321100488bb4'
    '24c80000004889c14809f048c1e82074144889f031d248f7f1eb1066c7038000'
    'e98ffdffff89f031d2f7f14989f04885d2488b742418488b7c2450740d4881fe'
    '0f270000774689f0eb544c3b6424600f87300100004d39f54d0f46ee4d39e84d'
    '0f47e84c89e848f76424580f90c148ba99999999999999194839d00f97c008c8'
    '742f66c7036900e928fdffffb8ffffffff4881fe5f5af4050f861701000048b9'
    'feffffffffffff7f4883c10be94d010000488b8c24d00000008b411089442479'
    'f30f6f01f30f7f442469c6442468010fb644241288442420488b8424e0000000'
    '48894424210fb644241188442429488b8c24e80000008b018944242a0fb74104'
    '668944242e4889f2488d742468488d4c24204d89c5ff15fdb657034d89e8488b'
    '7c2450488b742418a80174594889d14c89f048f7642458701448bafeffffffff'
    'ffff7f4839d077054839c8763866480f6ec1660f6205c6bb00fe660f5c05deab'
    '00fe660f28c8660f15c8f20f58c8f20f5e0d8a2b01fe66c7036800f20f114b08'
    'e92ffcffff48b80080c6a47e8d03004939c6773d4d89c54c89f2e89130110048'
    '89c14c09f048c1e82074154c89f031d248f7f1eb1281c6a0860100e986feffff'
    '4489f031d2f7f14885d2488b742418743e4881fe0f270000770489f0eb12b8ff'
    'ffffff4881fe5f5af4050f865101000048b9feffffffffffff7f4883c1024889'
    '4b0866c703c400894304e9a5fbffff4889efe8e97656003c0274120fb64c2411'
    '80f1020a4c24120f851f010000f30f7e8580390000488d7c2468488b7424504c'
    '8b7424184c89f2488b8c24d0000000488bac24d80000004989e84d89e9ff15bd'
    'b5570366817c24688601757e4983c7250fb654241780f20131c04c3b6424600f'
    '96c00fb74c244c66894b268b4c2448894b22f3410f6f07f30f7f433b48894308'
    '488b44245848894310488b8424c8000000488943180fb64424168843200fb644'
    '241388432148896b284c8973308853380fb64424158843390fb644241488433a'
    '66c7038601e9cafaffff0f108424b80000000f1143500f108424a80000000f11'
    '4340f30f6f442468f30f6f4c24780f109424880000000f109c24980000000f11'
    '5b300f115320f30f7f4b10f30f7f03e980faffff488d3d259d4f03ff15cf5f57'
    '0381c6a0860100e98efeffff66c7037400884302e95bfaffff66c74424684101'
    '488d3db23b39fe488d0d421a4f034c8d050b164f03488d542468be2b000000ff'
    '15635b57030f0b488d3d62ae4f03ff155c5c5703488d1515564a034c89efff15'
    'c45a57034889c3488d7c2468e87f0f18014889dfe8f77b4603ff15095c5703'
)
BODY_SHA256 = '464d4ab1738e3af8f221194af4e9a3d2dfc73f916b3ea4161d8baf050dd41e93'
BRANCHES = [
    (0x5f, '7511', 1, 2, 0x21f7cb2),
    (0x66, '746b', 1, 2, 0x21f7d13),
    (0x6d, 'e962020000', 1, 5, 0x21f7f14),
    (0xce, 'e901020000', 1, 5, 0x21f7f14),
    (0x12a, '0f8349070000', 2, 6, 0x21f84b9),
    (0x195, '0f85b9060000', 2, 6, 0x21f8494),
    (0x1b2, '0f839c060000', 2, 6, 0x21f8494),
    (0x1d8, '0f83c9060000', 2, 6, 0x21f84e7),
    (0x1f8, '740e', 1, 2, 0x21f7e48),
    (0x206, '7422', 1, 2, 0x21f7e6a),
    (0x20a, '7508', 1, 2, 0x21f7e54),
    (0x210, '7411', 1, 2, 0x21f7e63),
    (0x212, 'eb69', 1, 2, 0x21f7ebd),
    (0x221, '7407', 1, 2, 0x21f7e6a),
    (0x234, '7412', 1, 2, 0x21f7e88),
    (0x244, '7611', 1, 2, 0x21f7e97),
    (0x246, 'eb35', 1, 2, 0x21f7ebd),
    (0x255, '7726', 1, 2, 0x21f7ebd),
    (0x25a, '7521', 1, 2, 0x21f7ebd),
    (0x274, '750e', 1, 2, 0x21f7ec4),
    (0x27b, 'eb1a', 1, 2, 0x21f7ed7),
    (0x282, 'eb50', 1, 2, 0x21f7f14),
    (0x295, '7422', 1, 2, 0x21f7ef9),
    (0x29a, '7507', 1, 2, 0x21f7ee3),
    (0x29f, '752e', 1, 2, 0x21f7f0f),
    (0x2a1, 'eb0f', 1, 2, 0x21f7ef2),
    (0x2b0, '7407', 1, 2, 0x21f7ef9),
    (0x2c3, '7424', 1, 2, 0x21f7f29),
    (0x2cd, '7424', 1, 2, 0x21f7f33),
    (0x2f1, '75dc', 1, 2, 0x21f7f0f),
    (0x361, '0f8513010000', 2, 6, 0x21f80ba),
    (0x3e3, '0f8521040000', 2, 6, 0x21f844a),
    (0x3ee, '7420', 1, 2, 0x21f8050),
    (0x40a, '0f842b010000', 2, 6, 0x21f817b),
    (0x429, '0f8385040000', 2, 6, 0x21f84f4),
    (0x459, '0f85a5000000', 2, 6, 0x21f8144),
    (0x46a, '0f85fa000000', 2, 6, 0x21f81aa),
    (0x475, 'e95afeffff', 1, 5, 0x21f7f14),
    (0x4ff, 'e9d0fdffff', 1, 5, 0x21f7f14),
    (0x516, '7745', 1, 2, 0x21f819d),
    (0x52f, '7414', 1, 2, 0x21f8185),
    (0x539, 'eb10', 1, 2, 0x21f818b),
    (0x540, 'e98ffdffff', 1, 5, 0x21f7f14),
    (0x55b, '740d', 1, 2, 0x21f81aa),
    (0x564, '7746', 1, 2, 0x21f81ec),
    (0x568, 'eb54', 1, 2, 0x21f81fe),
    (0x56f, '0f8730010000', 2, 6, 0x21f82e5),
    (0x5a0, '742f', 1, 2, 0x21f8211),
    (0x5a7, 'e928fdffff', 1, 5, 0x21f7f14),
    (0x5b8, '0f8617010000', 2, 6, 0x21f8315),
    (0x5cc, 'e94d010000', 1, 5, 0x21f835e),
    (0x64a, '7459', 1, 2, 0x21f82e5),
    (0x657, '7014', 1, 2, 0x21f82ad),
    (0x666, '7705', 1, 2, 0x21f82ad),
    (0x66b, '7638', 1, 2, 0x21f82e5),
    (0x6a0, 'e92ffcffff', 1, 5, 0x21f7f14),
    (0x6b2, '773d', 1, 2, 0x21f8331),
    (0x6c9, '7415', 1, 2, 0x21f8320),
    (0x6d3, 'eb12', 1, 2, 0x21f8327),
    (0x6db, 'e986feffff', 1, 5, 0x21f81a6),
    (0x6ef, '743e', 1, 2, 0x21f836f),
    (0x6f8, '7704', 1, 2, 0x21f833e),
    (0x6fc, 'eb12', 1, 2, 0x21f8350),
    (0x70a, '0f8651010000', 2, 6, 0x21f84a1),
    (0x72a, 'e9a5fbffff', 1, 5, 0x21f7f14),
    (0x739, '7412', 1, 2, 0x21f838d),
    (0x747, '0f851f010000', 2, 6, 0x21f84ac),
    (0x78a, '757e', 1, 2, 0x21f844a),
    (0x805, 'e9cafaffff', 1, 5, 0x21f7f14),
    (0x84f, 'e980faffff', 1, 5, 0x21f7f14),
    (0x867, 'e98efeffff', 1, 5, 0x21f833a),
    (0x874, 'e95bfaffff', 1, 5, 0x21f7f14),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x21f7dc6, 0x3379490),
    (0x21f7f92, 0x232e2e0),
    (0x21f8017, 0x26caea0),
    (0x21f8058, 0x26cb1b0),
    (0x21f8158, 0x230b390),
    (0x21f82fa, 0x230b390),
    (0x21f8372, 0x275fa60),
    (0x21f850c, 0x3379490),
    (0x21f8514, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x21f7c8f, 0x5773950),
    (0x21f8275, 0x5773978),
    (0x21f83bd, 0x5773980),
    (0x21f849b, 0x576e470),
    (0x21f84df, 0x576e048),
    (0x21f84ee, 0x576e150),
    (0x21f84fe, 0x576dfc8),
    (0x21f8519, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x21f8494, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x21f84e7, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x21f84f4, 0x569db10, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x1ea3554, 0x271c57b]
CALLER_FUNCTIONS = {'0x1ea3554': ('0x1ea3140', '0x1ea3f55'), '0x271c57b': ('0x271c490', '0x271dfdb')}
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

