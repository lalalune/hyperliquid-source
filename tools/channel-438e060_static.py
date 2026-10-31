#!/usr/bin/env python3
"""Authenticated node94 channel-438e060 binding (0x438e060).

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

START, END = 0x438e060, 0x438e8d2
FDE_VA = 0x1237bf0
FDE = bytes.fromhex(
    '50000000c89f27006864150372080000044bcf8fff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f038602037e070e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004889fb4c8b26bf01000000e87f57b5'
    '004989c689d54c8b3b498b47384889442460418b47408944241c80bb20010000'
    '004c89f87579c68320010000014c893424896c2408488b44246048894424708b'
    '44241c89442478488d7c24384889e6488d542470e85756b500b800ca9a3b48f7'
    '6424408b4c24484801c84883d20031c948f7daba000000004819d24809c2807c'
    '243800480f45d1498b4730f048015058488b03488b4030f048ff4018488b0331'
    'c94887481048398b180100007324498b4730f048ff40204889c8482b83180100'
    '000f82b2020000498b5730f048014260eb094885c90f8400010000498b4730f0'
    '48ff40284889c848c1e80949bd535a9ba02fb8440049f7e548c1ea0b488b4424'
    '604801d00f80490200004869d200ca9a3b4829d1034c241c81f900ca9a3b720f'
    '48ffc00f802a02000081c1003665c44c893424896c24084889442470894c2478'
    '488d7c24384889e6488d542470e85e55b500b800ca9a3b48f76424408b4c2448'
    '4801c84883d20031f648f7dab9000000004819c94809c1807c243800480f45ce'
    '4889c848c1e80949f7e548c1ea0b498b4730483b90a000000075214869d200ca'
    '9a3b4889ce4829d639b0a8000000760eba80000000be48000000eb0c72f2ba88'
    '000000be40000000f048ff0430f048010c10498b4730f0480148684c8b2bb901'
    '00000031c0f0490fb14d284883f80274374885c00f8592000000498b4d18498b'
    '04244885c9742f498b7c24084839c1752a49397d20752431c9b801000000f049'
    '0fb14d287544eb64498b0424498b7c2408ff5010eb56498b7c2408ff104989c4'
    '4989d6498b45184885c07407498b7d20ff50184d8965184d89752031c9b80100'
    '0000f0490fb14d287422498b4518498b7d2049c74518000000004885c00f84e9'
    '00000031c949874d28ff50084c8d7308488b034883c010488d0d4ae338014889'
    '8c24a800000048898424b0000000488d8424a800000048894424704889442478'
    '48c784248000000000000000bf01000000e8aa54b50048898424900000008954'
    '246c0fb64369488d0d931636fc486304814801c8ffe04c8da3980000000fb683'
    '98000000488d0d891636fc486304814801c8ffe0488b7370e9ed0100004c8dab'
    '900000000fb68390000000488d0d721636fc486304814801c8ffe0488bb38000'
    '0000e9dc010000488bb388000000e9d7010000488d3d800044fc488d153f4d3c'
    '01be28000000ff157c003e01488d3d05c72e01ff1577003e01488d3d88e23801'
    'ff154afd3d01488d3df3eb3801ff152d0c3e01488d3de6eb3801ff15180c3e01'
    '488d3da9093901ff150b0c3e01eb2b488d3d9a093901ff15040c3e01eb1c488d'
    '3d7b043901ff15ed0b3e01eb0d488d3d6c043901ff15e60b3e010f0b4d896518'
    '4d8975204889c7e8a41c2d014989c7e9360400004989c7e9330400004989c780'
    'bb10010000030f85f603000080bb08010000030f85e9030000488dbb90000000'
    'e80babfbffe9d803000080bb1001000003751580bb0801000003750c488dbb90'
    '000000e8e8aafbffc6436800488b6b48488b7370f048ff45104c8d63404c8b6b'
    '40498b85c00100000f1f840000000000a8010f85ac0100004883f8fe0f844703'
    '0000488d4802f0490fb18dc001000075df498dbd80000000e803867b00498b85'
    '100100006666662e0f1f8400000000004889c14883c902f0490fb18d10010000'
    '75ee4885c0752a498b8500010000498bbd0801000049c7850001000000000000'
    'f04983a510010000fd4885c07403ff5008c64368004c8973704c8da398000000'
    'c68398000000004c89f6488973784889b3800000004c8dab90000000c6839000'
    '0000004889b388000000488d7c2438488d542470e837631c000fb64424388d0c'
    '00fec141884d0084c00f852b0200008b4424400f104424440f2904248b4c2454'
    '894c241085c00f841d020000488b4b78488b4908f048ff49108b4c2410894c24'
    '300f2804240f29442420c68398000000018943280f284424200f11432c8b4424'
    '3089433c488b432848898424980000008b4330898424a0000000c6436801488b'
    '4338488943704889e7ff1551023e018b44240889442440488b04244889442438'
    'c744244800000000488dbc2498000000488d742438ff1545023e01f20f114378'
    'c6831001000000488d7b78488d742470e88b77faff84c00f840dfeffff41b601'
    'b004eb344889742438f048ff0e750b488d7c2438ff154e493e01f048ff4d10c6'
    '4368004c89f7e875d1faff4c89e7e8ad30fcffb0014531f6884369bf01000000'
    'e81b51b5004989c44189d5488944242089542428488b442460488904248b4424'
    '1c89442408488d7c2438488d7424204889e2e81950b500b800ca9a3b48f76424'
    '408b4c24484801c84883d20031ed48f7dab9000000004819c94809c1807c2438'
    '00480f45cd48898b180100004c8964242044896c2428488b8424900000004889'
    '04248b44246c89442408488d7c2438488d7424204889e2e8b44fb500807c2438'
    '00b80000000075098b6c2448488b442440498b4f30483b819000000075143ba9'
    '98000000730ebe70000000bf30000000eb0c72f2be78000000bf38000000ba00'
    'ca9a3b48f7e24189e84901c04883d20031c048f7da4819c04c09c0f048ff0439'
    'f0480104314489f04881c4b80000005b415c415d415e415f5dc341c604240341'
    'b601b003e9cffeffff8b442410894424300f2804240f29442420c68398000000'
    '01c74328000000000f284424200f11432c8b44243089433c4c89f7e800d0faff'
    '4c8d6340e982feffffff15c10e3e014989c7488d7b40e8252ffcffeb63eb2049'
    '89c74c89e7e8162ffcffeb544989c7c64369024c89ffe895182d01eb02eb0049'
    '89c7807b68007414488b4370f048ff08750a488d7b70ff156c473e01c6436800'
    'eb0d4989c741c645000241c60424024c89f7e889cffaff488d7b40e8c02efcff'
    'c64369024c89ffe844182d01ff1556f83d01'
)
BODY_SHA256 = 'a5ae2eb4ccdc2e68c34b2de147bc212c19762bcd70001853c62943a072630252'
BRANCHES = [
    (0x44, '7579', 1, 2, 0x438e11f),
    (0xcc, '7324', 1, 2, 0x438e152),
    (0xe1, '0f82b2020000', 2, 6, 0x438e3f9),
    (0xf0, 'eb09', 1, 2, 0x438e15b),
    (0xf5, '0f8400010000', 2, 6, 0x438e25b),
    (0x124, '0f8049020000', 2, 6, 0x438e3d3),
    (0x13e, '720f', 1, 2, 0x438e1af),
    (0x143, '0f802a020000', 2, 6, 0x438e3d3),
    (0x1b9, '7521', 1, 2, 0x438e23c),
    (0x1ce, '760e', 1, 2, 0x438e23e),
    (0x1da, 'eb0c', 1, 2, 0x438e248),
    (0x1dc, '72f2', 1, 2, 0x438e230),
    (0x20f, '7437', 1, 2, 0x438e2a8),
    (0x214, '0f8592000000', 2, 6, 0x438e30c),
    (0x225, '742f', 1, 2, 0x438e2b6),
    (0x22f, '752a', 1, 2, 0x438e2bb),
    (0x235, '7524', 1, 2, 0x438e2bb),
    (0x244, '7544', 1, 2, 0x438e2ea),
    (0x246, 'eb64', 1, 2, 0x438e30c),
    (0x254, 'eb56', 1, 2, 0x438e30c),
    (0x26a, '7407', 1, 2, 0x438e2d3),
    (0x288, '7422', 1, 2, 0x438e30c),
    (0x29d, '0f84e9000000', 2, 6, 0x438e3ec),
    (0x314, 'ffe0', 1, 2, 0x438e356),
    (0x332, 'ffe0', 1, 2, 0x438e374),
    (0x338, 'e9ed010000', 1, 5, 0x438e58a),
    (0x359, 'ffe0', 1, 2, 0x438e39b),
    (0x362, 'e9dc010000', 1, 5, 0x438e5a3),
    (0x36e, 'e9d7010000', 1, 5, 0x438e5aa),
    (0x3cd, 'eb2b', 1, 2, 0x438e45a),
    (0x3dc, 'eb1c', 1, 2, 0x438e45a),
    (0x3eb, 'eb0d', 1, 2, 0x438e45a),
    (0x40f, 'e936040000', 1, 5, 0x438e8aa),
    (0x417, 'e933040000', 1, 5, 0x438e8af),
    (0x426, '0f85f6030000', 2, 6, 0x438e882),
    (0x433, '0f85e9030000', 2, 6, 0x438e882),
    (0x445, 'e9d8030000', 1, 5, 0x438e882),
    (0x451, '7515', 1, 2, 0x438e4c8),
    (0x45a, '750c', 1, 2, 0x438e4c8),
    (0x492, '0f85ac010000', 2, 6, 0x438e6a4),
    (0x49c, '0f8447030000', 2, 6, 0x438e849),
    (0x4af, '75df', 1, 2, 0x438e4f0),
    (0x4e0, '75ee', 1, 2, 0x438e530),
    (0x4e5, '752a', 1, 2, 0x438e571),
    (0x50c, '7403', 1, 2, 0x438e571),
    (0x569, '0f852b020000', 2, 6, 0x438e7fa),
    (0x586, '0f841d020000', 2, 6, 0x438e809),
    (0x637, '0f840dfeffff', 2, 6, 0x438e4aa),
    (0x642, 'eb34', 1, 2, 0x438e6d8),
    (0x64d, '750b', 1, 2, 0x438e6ba),
    (0x726, '7509', 1, 2, 0x438e791),
    (0x73c, '7514', 1, 2, 0x438e7b2),
    (0x744, '730e', 1, 2, 0x438e7b4),
    (0x750, 'eb0c', 1, 2, 0x438e7be),
    (0x752, '72f2', 1, 2, 0x438e7a6),
    (0x7a4, 'e9cffeffff', 1, 5, 0x438e6d8),
    (0x7e4, 'e982feffff', 1, 5, 0x438e6cb),
    (0x7fb, 'eb63', 1, 2, 0x438e8c0),
    (0x7fd, 'eb20', 1, 2, 0x438e87f),
    (0x80a, 'eb54', 1, 2, 0x438e8c0),
    (0x81b, 'eb02', 1, 2, 0x438e87f),
    (0x81d, 'eb00', 1, 2, 0x438e87f),
    (0x826, '7414', 1, 2, 0x438e89c),
    (0x830, '750a', 1, 2, 0x438e89c),
    (0x840, 'eb0d', 1, 2, 0x438e8af),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x438e07c, 0x4ee3800),
    (0x438e0d4, 0x4ee3730),
    (0x438e1cd, 0x4ee3730),
    (0x438e351, 0x4ee3800),
    (0x438e467, 0x5660110),
    (0x438e4a0, 0x4348fb0),
    (0x438e4c3, 0x4348fb0),
    (0x438e518, 0x4b46b20),
    (0x438e5b4, 0x45548f0),
    (0x438e690, 0x4335e20),
    (0x438e6c6, 0x433b840),
    (0x438e6ce, 0x4351780),
    (0x438e6e0, 0x4ee3800),
    (0x438e712, 0x4ee3730),
    (0x438e777, 0x4ee3730),
    (0x438e83b, 0x433b840),
    (0x438e856, 0x4351780),
    (0x438e865, 0x4351780),
    (0x438e876, 0x5660110),
    (0x438e8b2, 0x433b840),
    (0x438e8bb, 0x4351780),
    (0x438e8c7, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x438e3e6, 0x576e468),
    (0x438e3f3, 0x576e470),
    (0x438e400, 0x576e150),
    (0x438e40d, 0x576f040),
    (0x438e41a, 0x576f038),
    (0x438e427, 0x576f038),
    (0x438e436, 0x576f040),
    (0x438e445, 0x576f038),
    (0x438e454, 0x576f040),
    (0x438e649, 0x576e8a0),
    (0x438e675, 0x576e8c0),
    (0x438e6b4, 0x5773008),
    (0x438e849, 0x576f710),
    (0x438e896, 0x5773008),
    (0x438e8cc, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x438e3da, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x438e3ec, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x438e3f9, 0x571c688, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
]
CALLERS = [0x4b62a94]
CALLER_FUNCTIONS = {'0x4b62a94': ('0x4b62a00', '0x4b62b86')}
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

