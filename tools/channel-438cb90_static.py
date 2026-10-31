#!/usr/bin/env python3
"""Authenticated node94 channel-438cb90 binding (0x438cb90).

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

START, END = 0x438cb90, 0x438d2a7
FDE_VA = 0x1237aa0
FDE = bytes.fromhex(
    '50000000789e2700e85015031707000004efcf8fff410e10420e18420e20420e'
    '28420e30410e38470ea00c83078c068d058e048f0386020387060e38410e3042'
    '0e28420e20420e18420e10410e08410ea00c0000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece80500004889fb4c8b3ebf01000000e84f6cb5'
    '004989c689d54c8b2b498b45384889442410418b45408944240c80bba8020000'
    '004c89e80f858e000000c683a8020000014c89b4242803000089ac2430030000'
    '488b44241048898424c00100008b44240c898424c8010000488d7c2458488db4'
    '2428030000488d9424c0010000e80e6bb500b800ca9a3b48f76424608b4c2468'
    '4801c84883d20031c948f7daba000000004819d24809c2807c245800480f45d1'
    '498b4530f048015058488b03488b4030f048ff4018488b0331c9488748104839'
    '8ba00200007324498b4530f048ff40204889c8482b83a00200000f82b4020000'
    '498b5530f048014260eb094885c90f8415010000498b4530f048ff40284889c8'
    '48c1e80949bc535a9ba02fb8440049f7e448c1ea0b488b4424104801d00f804b'
    '0200004869d200ca9a3b4829d1034c240c81f900ca9a3b720f48ffc00f802c02'
    '000081c1003665c44c89b4242803000089ac243003000048898424c001000089'
    '8c24c8010000488d7c2458488db42428030000488d9424c0010000e8006ab500'
    'b800ca9a3b48f76424608b4c24684801c84883d20031f648f7dab90000000048'
    '19c94809c1807c245800480f45ce4889c848c1e80949f7e448c1ea0b498b4530'
    '483b90a000000075214869d200ca9a3b4889ce4829d639b0a8000000760eba80'
    '000000be48000000eb0c72f2ba88000000be40000000f048ff0430f048010c10'
    '498b4530f048014868488b2bb90100000031c0f0480fb14d284883f802743548'
    '85c00f858d000000488b4d18498b074885c9742c498b7f084839c1752748397d'
    '20752131c9b801000000f0480fb14d287541eb61498b07498b7f08ff5010eb55'
    '498b7f08ff104989c44989d6488b45184885c07407488b7d20ff50184c896518'
    '4c89752031c9b801000000f0480fb14d287422488b4518488b7d2048c7451800'
    '0000004885c00f84db00000031c948874d28ff50084c8d7308488b034883c010'
    '488d0df1f7380148894c24284889442430488d44242848894424384889442440'
    '48c744244800000000bf01000000e85d69b5000fb6b398020000488d0d1f2b36'
    'fc486334b14801ce48894424208954241cffe648c783a800000000000000e9c8'
    '0100004c8d63500fb67350488d0dfe2a36fc486334b14801ceffe6488b7328e9'
    'd3000000488d6b480fb64348488d0ded2a36fc486304814801c8ffe0488b7338'
    'e9c2000000488b7340e9bd000000488d3d351544fc488d15f4613c01be280000'
    '00ff1531153e01488d3dbadb2e01ff152c153e01488d3d3df73801ff15ff113e'
    '01488d3d68013901ff15da203e01488d3d5b013901ff15d5203e01488d3d5e1e'
    '3901ff15c0203e01eb2b488d3d4f1e3901ff15b9203e01eb1c488d3d30193901'
    'ff15a2203e01eb0d488d3d21193901ff159b203e010f0b4c8965184c89752048'
    '89c7e859312d014989c7e9b10200004989c7e9ae020000488973304889733848'
    '8d6b48c643480048897340488d7c2458488d542438e8967d1c004c8b7c245849'
    '83ff0c0f94c000c0fec08845004983ff0c0f84a8000000488d742460488dbc24'
    '28030000ba60010000ff15c10f3e014183ff0b0f8490000000488b4330488b40'
    '08f048ff48104c8da42488040000488db42428030000488b2d930f3e01ba6001'
    '00004c89e7ffd5c6435001488dbc24c8010000ba600100004c89e6ffd54c89bc'
    '24c0010000488dbbb00000000fb69399020000488d4b584c8d83a8000000488d'
    'b424c0010000e87517fdff4c8973284c8d6350c64350004c89f6e918ffffff41'
    'c604240340b503eb2541c60424014c89f7e84a58fcff488dbbb0000000e88ee1'
    'fbff488d7b5840b501e892e1faff4088ab98020000bf01000000e81167b50049'
    '89c64189d4488984242803000089942430030000488b44241048898424c00100'
    '008b44240c898424c8010000488d7c2458488db42428030000488d9424c00100'
    '00e8fa65b500b800ca9a3b48f76424608b4c24684801c84883d20031ed48f7da'
    'b9000000004819c94809c1807c245800480f45cd48898ba00200004c89b42428'
    '0300004489a42430030000488b44242048898424c00100008b44241c898424c8'
    '010000488d7c2458488db42428030000488d9424c0010000e88365b500807c24'
    '5800b80000000075098b6c2468488b442460498b7530483b869000000075153b'
    'ae98000000730fbf7000000041b830000000eb0d72f1bf7800000041b8380000'
    '004183ff0c0f94c1ba00ca9a3b48f7e24189e94901c14883d20031c048f7da48'
    '19c04c09c8f04aff0406f04801043e89c84881c4e80500005b415c415d415e41'
    '5f5dc34989c7c68398020000024c89ffe8cb2e2d014989c7eb0f4989c7488dbb'
    'b0000000e807e0fbff488d7b58e80ee0faffeb2e4989c7eb0c4989c7c6450002'
    '41c60424024c89f7e89356fcff488dbbb0000000e8d7dffbff488d7b58e8dedf'
    'faffc68398020000024c89ffe86f2e2d01ff15810e3e01'
)
BODY_SHA256 = '4251099ae6df4cc2f68b68fd0745e3814eff9b28823893c658ff2625e721bdb2'
BRANCHES = [
    (0x44, '0f858e000000', 2, 6, 0x438cc68),
    (0xe5, '7324', 1, 2, 0x438cc9b),
    (0xfa, '0f82b4020000', 2, 6, 0x438cf44),
    (0x109, 'eb09', 1, 2, 0x438cca4),
    (0x10e, '0f8415010000', 2, 6, 0x438cdb9),
    (0x13d, '0f804b020000', 2, 6, 0x438cf1e),
    (0x157, '720f', 1, 2, 0x438ccf8),
    (0x15c, '0f802c020000', 2, 6, 0x438cf1e),
    (0x1e7, '7521', 1, 2, 0x438cd9a),
    (0x1fc, '760e', 1, 2, 0x438cd9c),
    (0x208, 'eb0c', 1, 2, 0x438cda6),
    (0x20a, '72f2', 1, 2, 0x438cd8e),
    (0x23d, '7435', 1, 2, 0x438ce04),
    (0x242, '0f858d000000', 2, 6, 0x438ce65),
    (0x252, '742c', 1, 2, 0x438ce10),
    (0x25b, '7527', 1, 2, 0x438ce14),
    (0x261, '7521', 1, 2, 0x438ce14),
    (0x270, '7541', 1, 2, 0x438ce43),
    (0x272, 'eb61', 1, 2, 0x438ce65),
    (0x27e, 'eb55', 1, 2, 0x438ce65),
    (0x293, '7407', 1, 2, 0x438ce2c),
    (0x2b1, '7422', 1, 2, 0x438ce65),
    (0x2c6, '0f84db000000', 2, 6, 0x438cf37),
    (0x331, 'ffe6', 1, 2, 0x438cea9),
    (0x33e, 'e9c8010000', 1, 5, 0x438d09b),
    (0x359, 'ffe6', 1, 2, 0x438ced1),
    (0x35f, 'e9d3000000', 1, 5, 0x438cfc7),
    (0x37a, 'ffe0', 1, 2, 0x438ceec),
    (0x380, 'e9c2000000', 1, 5, 0x438cfd7),
    (0x389, 'e9bd000000', 1, 5, 0x438cfdb),
    (0x3e8, 'eb2b', 1, 2, 0x438cfa5),
    (0x3f7, 'eb1c', 1, 2, 0x438cfa5),
    (0x406, 'eb0d', 1, 2, 0x438cfa5),
    (0x42a, 'e9b1020000', 1, 5, 0x438d270),
    (0x432, 'e9ae020000', 1, 5, 0x438d275),
    (0x471, '0f84a8000000', 2, 6, 0x438d0af),
    (0x493, '0f8490000000', 2, 6, 0x438d0b9),
    (0x51a, 'e918ffffff', 1, 5, 0x438cfc7),
    (0x527, 'eb25', 1, 2, 0x438d0de),
    (0x627, '7509', 1, 2, 0x438d1c2),
    (0x63d, '7515', 1, 2, 0x438d1e4),
    (0x645, '730f', 1, 2, 0x438d1e6),
    (0x652, 'eb0d', 1, 2, 0x438d1f1),
    (0x654, '72f1', 1, 2, 0x438d1d7),
    (0x6b8, 'eb0f', 1, 2, 0x438d259),
    (0x6d2, 'eb2e', 1, 2, 0x438d292),
    (0x6d7, 'eb0c', 1, 2, 0x438d275),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x438cbac, 0x4ee3800),
    (0x438cc1d, 0x4ee3730),
    (0x438cd2b, 0x4ee3730),
    (0x438ce9e, 0x4ee3800),
    (0x438cfb2, 0x5660110),
    (0x438cfe5, 0x4554d80),
    (0x438d096, 0x435e810),
    (0x438d0c1, 0x4352910),
    (0x438d0cd, 0x434b260),
    (0x438d0d9, 0x433b270),
    (0x438d0ea, 0x4ee3800),
    (0x438d131, 0x4ee3730),
    (0x438d1a8, 0x4ee3730),
    (0x438d240, 0x5660110),
    (0x438d254, 0x434b260),
    (0x438d25d, 0x433b270),
    (0x438d278, 0x4352910),
    (0x438d284, 0x434b260),
    (0x438d28d, 0x433b270),
    (0x438d29c, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x438cf31, 0x576e468),
    (0x438cf3e, 0x576e470),
    (0x438cf4b, 0x576e150),
    (0x438cf58, 0x576f038),
    (0x438cf65, 0x576f040),
    (0x438cf72, 0x576f038),
    (0x438cf81, 0x576f040),
    (0x438cf90, 0x576f038),
    (0x438cf9f, 0x576f040),
    (0x438d019, 0x576dfe0),
    (0x438d2a1, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x438cf25, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x438cf37, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x438cf44, 0x571c688, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
]
CALLERS = [0x4b65304]
CALLER_FUNCTIONS = {'0x4b65304': ('0x4b65270', '0x4b653f6')}
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

