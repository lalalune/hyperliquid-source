#!/usr/bin/env python3
"""Authenticated node94 channel-4399360 binding (0x4399360).

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

START, END = 0x4399360, 0x4399e76
FDE_VA = 0x12382b8
FDE = bytes.fromhex(
    '5000000090a62700a0101603160b000004afd18fff410e10420e18420e20420e'
    '28420e30410e38470e800483078c068d058e048f03860203cf090e38410e3042'
    '0e28420e20420e18420e10410e08410e80040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc80100004889fb4c8b26bf01000000e87fa4b4'
    '004989c689d54c8b3b498b47384889442410418b47408944240c80bbd0000000'
    '004c89f80f8588000000c683d0000000014c89742420896c2428488b44241048'
    '894424588b44240c89442460488dbc2490000000488d742420488d542458e84d'
    'a3b400b800ca9a3b48f7a424980000008b8c24a00000004801c84883d20031c9'
    '48f7daba000000004819d24809c280bc249000000000480f45d1498b4730f048'
    '015058488b03488b4030f048ff4018488b0331c94887481048398bc800000073'
    '24498b4730f048ff40204889c8482b83c80000000f82cd020000498b5730f048'
    '014260eb094885c90f840f010000498b4730f048ff40284889c848c1e80949bd'
    '535a9ba02fb8440049f7e548c1ea0b488b4424104801d00f80640200004869d2'
    '00ca9a3b4829d1034c240c81f900ca9a3b720f48ffc00f804502000081c10036'
    '65c44c89742420896c24284889442458894c2460488dbc2490000000488d7424'
    '20488d542458e845a2b400b800ca9a3b48f7a424980000008b8c24a000000048'
    '01c84883d20031f648f7dab9000000004819c94809c180bc249000000000480f'
    '45ce4889c848c1e80949f7e548c1ea0b498b4730483b90a000000075214869d2'
    '00ca9a3b4889ce4829d639b0a8000000760eba80000000be48000000eb0c72f2'
    'ba88000000be40000000f048ff0430f048010c10498b4730f0480148684c8b2b'
    'b90100000031c0f0490fb14d284883f80274374885c00f8592000000498b4d18'
    '498b04244885c9742f498b7c24084839c1752a49397d20752431c9b801000000'
    'f0490fb14d287544eb64498b0424498b7c2408ff5010eb56498b7c2408ff1049'
    '89c44989d6498b45184885c07407498b7d20ff50184d8965184d89752031c9b8'
    '01000000f0490fb14d287422498b4518498b7d2049c74518000000004885c00f'
    '84f500000031c949874d28ff50084c8d7308488b034883c010488d0d28303801'
    '48898c24600100004889842468010000488d84246001000048898424a8010000'
    '48898424b001000048c78424b801000000000000bf01000000e882a1b4004889'
    '8424580100008954241c0fb683c4000000488d0dc46435fc486304814801c8ff'
    'e04c8da3a80000000fb683a8000000488d0db66435fc486304814801c8ffe048'
    '8bb380000000e9eb000000488daba00000000fb683a0000000488d0d9c6435fc'
    '486304814801c8ffe0488bb390000000e9dd000000488bb398000000e9d80000'
    '00488d3d524d43fc488d15119a3b01be28000000ff154e4d3d01488d3dd7132e'
    '01ff15494d3d01488d3d5a2f3801ff151c4a3d01488d3dfd393801ff15f7583d'
    '01488d3df0393801ff15f2583d01488d3d7b563801ff15dd583d01e9fb050000'
    '488d3d69563801ff15d3583d01e9e9050000488d3d47513801ff15b9583d01e9'
    'd7050000488d3d35513801ff15af583d01e9c50500004d8965184d8975204889'
    'c7e86a692c014989c7e9680600004989c7e9770600004889b3880000004889b3'
    '90000000488daba0000000c683a0000000004889b398000000488dbc24900000'
    '00488d9424a8010000e8d2b71b00440fb6ac24900000004180fd030f94c000c0'
    'fec08845004180fd030f8439030000488b8424c0000000488944244f0f108424'
    '910000000f108c24a10000000f109424b10000000f295424400f294c24300f29'
    '4424204180fd020f8408030000488b8388000000488b4008f048ff4810488b44'
    '244f488984244f0100000f284424200f284c24300f285424400f299424400100'
    '000f298c24300100000f29842420010000c683a800000001488b84244f010000'
    '488984249f0100000f288424200100000f288c24300100000f28942440010000'
    '0f299424900100000f298424700100000f298c248001000044886c24580f1144'
    '24590f114c24690f288424900100000f11442479488b84249f01000048898424'
    '880000004c8b6b284d8d6510b10131c0f0410fb04d100f85410400004983c518'
    '488d05f77935fc488984249000000048c784249800000011000000488d442458'
    '48898424a0000000488d7c2420488d9424900000004c89eee8930d370031c9b0'
    '01f0410fb00c240f850304000048c78424900000000100000048c78424980000'
    '000100000048b82b0000000000008048898424a000000048c784241001000000'
    '000000bf88000000ff152a463d014885c00f84940300004989c4488db4249000'
    '0000ba880000004889c7ff1510463d01f049ff04240f8e800300004c89642420'
    '488d7b30488b84248800000048898424c00000000f104424580f104c24680f10'
    '5424780f299424b00000000f298c24a00000000f298424900000004c89a424c8'
    '000000488d1526373801488db42490000000e8291c4200488b4b28f048ff010f'
    '8e16030000488b4358f048ff80c8010000f048ff000f8e00030000488b5360f0'
    '48ff020f8ef2020000488b73684c89a424f800000048898c24c80000000f1044'
    '24580f104c24680f105424780f298424900000000f298c24a00000000f299424'
    'b0000000488b8c248800000048898c24c000000048898424d000000048899424'
    'd80000004889b424e00000000f1043700f118424e80000000f1083b00000000f'
    '118424080100008b83c000000089842418010000c684241c01000000488d3565'
    '363801488dbc2490000000e86051fdff4889c7b984000000b8cc000000f0480f'
    'b10f7407488b4710ff50204c89b3800000004c8da3a8000000c683a800000000'
    '4c89f6e96efcffff41c604240340b503e9aa000000488b44244f488984244f01'
    '00000f284424200f284c24300f285424400f299424400100000f298c24300100'
    '000f2984242001000041c60424010f288424200100000f288c24300100000f28'
    '9424400100000f298424700100000f298c24800100000f29942490010000488b'
    '84244f010000488984249f0100004c89f7e87aa5fbff488b4328f048ff08750a'
    '488d7b28ff15a6933d01488d7b30e8ad4efaff488d7b5840b501e8718afbff40'
    '88abc4000000bf01000000e8f09bb4004989c64189d448894424208954242848'
    '8b44241048894424588b44240c89442460488dbc2490000000488d742420488d'
    '542458e8e89ab400b800ca9a3b48f7a424980000008b8c24a00000004801c848'
    '83d20031ed48f7dab9000000004819c94809c180bc249000000000480f45cd48'
    '898bc80000004c897424204489642428488b84245801000048894424588b4424'
    '1c89442460488dbc2490000000488d742420488d542458e8749ab40080bc2490'
    '00000000b800000000750f8bac24a0000000488b842498000000498b7730483b'
    '869000000075153bae98000000730fbf7000000041b830000000eb0d72f1bf78'
    '00000041b8380000004180fd030f94c1ba00ca9a3b48f7e24189e94901c14883'
    'd20031c048f7da4819c04c09c8f04aff0406f04801043e89c84881c4c8010000'
    '5b415c415d415e415f5dc3bf08000000be88000000ff15c5423d010f0b4c89e7'
    'ba00ca9a3bff15c5513d01e9acfbffff4c89e731f6ff15bd513d01e9edfbffff'
    '4989c7e9a50000004989c7e99d0000004989c7eb2e4989c7c683c4000000024c'
    '89ffe869632c014989c7eb204989c7488b4328f048ff08750a488d7b28ff15cd'
    '913d01488d7b30e8d44cfaff488d7b58e89b88fbffe9810000004989c7eb4e49'
    '89c7488d7c2420e8245efaffeb3f4989c7eb3a4989c731c9b001f0410fb00c24'
    '742b4c89e731f6ff152b513d01eb1e4989c7c645000241c6042402eb104989c7'
    '488dbc2490000000e8f3ab19004c89f7e81ba3fbff488b4328f048ff08750a48'
    '8d7b28ff1547913d01488d7b30e84e4cfaff488d7b58e81588fbffc683c40000'
    '00024c89ffe8a6622c01ff15b8423d01ff15b2423d01'
)
BODY_SHA256 = '18171352df0938f074aceb5a48f2a7e4f1ed4395498fba4b874455812db593f6'
BRANCHES = [
    (0x44, '0f8588000000', 2, 6, 0x4399432),
    (0xdf, '7324', 1, 2, 0x4399465),
    (0xf4, '0f82cd020000', 2, 6, 0x4399727),
    (0x103, 'eb09', 1, 2, 0x439946e),
    (0x108, '0f840f010000', 2, 6, 0x439957d),
    (0x137, '0f8064020000', 2, 6, 0x4399701),
    (0x151, '720f', 1, 2, 0x43994c2),
    (0x156, '0f8045020000', 2, 6, 0x4399701),
    (0x1db, '7521', 1, 2, 0x439955e),
    (0x1f0, '760e', 1, 2, 0x4399560),
    (0x1fc, 'eb0c', 1, 2, 0x439956a),
    (0x1fe, '72f2', 1, 2, 0x4399552),
    (0x231, '7437', 1, 2, 0x43995ca),
    (0x236, '0f8592000000', 2, 6, 0x439962e),
    (0x247, '742f', 1, 2, 0x43995d8),
    (0x251, '752a', 1, 2, 0x43995dd),
    (0x257, '7524', 1, 2, 0x43995dd),
    (0x266, '7544', 1, 2, 0x439960c),
    (0x268, 'eb64', 1, 2, 0x439962e),
    (0x276, 'eb56', 1, 2, 0x439962e),
    (0x28c, '7407', 1, 2, 0x43995f5),
    (0x2aa, '7422', 1, 2, 0x439962e),
    (0x2bf, '0f84f5000000', 2, 6, 0x439971a),
    (0x33f, 'ffe0', 1, 2, 0x4399681),
    (0x35d, 'ffe0', 1, 2, 0x439969f),
    (0x366, 'e9eb000000', 1, 5, 0x43997b6),
    (0x387, 'ffe0', 1, 2, 0x43996c9),
    (0x390, 'e9dd000000', 1, 5, 0x43997d2),
    (0x39c, 'e9d8000000', 1, 5, 0x43997d9),
    (0x3fb, 'e9fb050000', 1, 5, 0x4399d5b),
    (0x40d, 'e9e9050000', 1, 5, 0x4399d5b),
    (0x41f, 'e9d7050000', 1, 5, 0x4399d5b),
    (0x431, 'e9c5050000', 1, 5, 0x4399d5b),
    (0x449, 'e968060000', 1, 5, 0x4399e16),
    (0x451, 'e977060000', 1, 5, 0x4399e2d),
    (0x4a9, '0f8439030000', 2, 6, 0x4399b48),
    (0x4e7, '0f8408030000', 2, 6, 0x4399b55),
    (0x5b6, '0f8541040000', 2, 6, 0x4399d5d),
    (0x607, '0f8503040000', 2, 6, 0x4399d70),
    (0x651, '0f8494030000', 2, 6, 0x4399d4b),
    (0x675, '0f8e80030000', 2, 6, 0x4399d5b),
    (0x6df, '0f8e16030000', 2, 6, 0x4399d5b),
    (0x6f5, '0f8e00030000', 2, 6, 0x4399d5b),
    (0x703, '0f8ef2020000', 2, 6, 0x4399d5b),
    (0x7c2, '7407', 1, 2, 0x4399b2b),
    (0x7e3, 'e96efcffff', 1, 5, 0x43997b6),
    (0x7f0, 'e9aa000000', 1, 5, 0x4399bff),
    (0x87e, '750a', 1, 2, 0x4399bea),
    (0x969, '750f', 1, 2, 0x4399cda),
    (0x985, '7515', 1, 2, 0x4399cfc),
    (0x98d, '730f', 1, 2, 0x4399cfe),
    (0x99a, 'eb0d', 1, 2, 0x4399d09),
    (0x99c, '72f1', 1, 2, 0x4399cef),
    (0xa0b, 'e9acfbffff', 1, 5, 0x439991c),
    (0xa1b, 'e9edfbffff', 1, 5, 0x439996d),
    (0xa23, 'e9a5000000', 1, 5, 0x4399e2d),
    (0xa2b, 'e99d000000', 1, 5, 0x4399e2d),
    (0xa33, 'eb2e', 1, 2, 0x4399dc3),
    (0xa4a, 'eb20', 1, 2, 0x4399dcc),
    (0xa57, '750a', 1, 2, 0x4399dc3),
    (0xa75, 'e981000000', 1, 5, 0x4399e5b),
    (0xa7d, 'eb4e', 1, 2, 0x4399e2d),
    (0xa8c, 'eb3f', 1, 2, 0x4399e2d),
    (0xa91, 'eb3a', 1, 2, 0x4399e2d),
    (0xaa0, '742b', 1, 2, 0x4399e2d),
    (0xaad, 'eb1e', 1, 2, 0x4399e2d),
    (0xabb, 'eb10', 1, 2, 0x4399e2d),
    (0xadd, '750a', 1, 2, 0x4399e49),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x439937c, 0x4ee3800),
    (0x43993de, 0x4ee3730),
    (0x43994e6, 0x4ee3730),
    (0x4399679, 0x4ee3800),
    (0x43997a1, 0x5660110),
    (0x43997e9, 0x4554fc0),
    (0x4399958, 0x470a6f0),
    (0x4399a32, 0x47bb660),
    (0x4399b0b, 0x436ec70),
    (0x4399bd1, 0x4354150),
    (0x4399bee, 0x433eaa0),
    (0x4399bfa, 0x4352670),
    (0x4399c0b, 0x4ee3800),
    (0x4399c43, 0x4ee3730),
    (0x4399cb7, 0x4ee3730),
    (0x4399da2, 0x5660110),
    (0x4399dc7, 0x433eaa0),
    (0x4399dd0, 0x4352670),
    (0x4399de7, 0x433fc10),
    (0x4399e28, 0x4534a20),
    (0x4399e30, 0x4354150),
    (0x4399e4d, 0x433eaa0),
    (0x4399e56, 0x4352670),
    (0x4399e65, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4399714, 0x576e468),
    (0x4399721, 0x576e470),
    (0x439972e, 0x576e150),
    (0x439973b, 0x576f038),
    (0x4399748, 0x576f040),
    (0x4399755, 0x576f038),
    (0x4399767, 0x576f040),
    (0x4399779, 0x576f038),
    (0x439978b, 0x576f040),
    (0x43999a8, 0x576dfd8),
    (0x43999ca, 0x576dfe0),
    (0x4399be4, 0x5772f90),
    (0x4399d55, 0x576e020),
    (0x4399d65, 0x576ef30),
    (0x4399d75, 0x576ef38),
    (0x4399dbd, 0x5772f90),
    (0x4399e07, 0x576ef38),
    (0x4399e43, 0x5772f90),
    (0x4399e6a, 0x576e128),
    (0x4399e70, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4399708, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x439971a, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x4399727, 0x571c688, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
]
CALLERS = [0x4b60324]
CALLER_FUNCTIONS = {'0x4b60324': ('0x4b60290', '0x4b60416')}
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

