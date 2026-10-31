#!/usr/bin/env python3
"""Authenticated node94 hour-13cdfc0 binding (0x13cdfc0).

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

START, END = 0x13cdfc0, 0x13cea45
FDE_VA = 0xfc61a0
FDE = bytes.fromhex(
    '5000000078850000187e4000850a000004bf9195ff410e10420e18420e20420e'
    '28420e30410e38470ee00483078c068d058e048f0386020370070e38410e3042'
    '0e28420e20420e18420e10410e08410ee0040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec280200004189f64889fb4c8daf800000008b87'
    '8000000083f8020f84e80000004c896c247885c075308bb38c00000083feff0f'
    '8427020000bfa8010000ba0900000031c94531c031c0ff15240a3a044883f8ff'
    '0f84200200008b056ccb3a0485c00f850e0800008bbb90000000c78390000000'
    'ffffffff83ffff7406ff15b9063a04488dbc24a80000004c89eee881aeb10380'
    'bc24a800000000746c488b8424b000000089c183e10383f901755a4c89ed4c8d'
    '78ff4c8b60ff4c8b6807498b45004885c074054c89e7ffd0498b75084885f674'
    '21498b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89e7ff154eff'
    '3904be180000004c89ff31d2ff153eff39044989ed488d7c244cff15c0073a04'
    '448b64244c488d839c000000443ba39c000000740848c74378000000008b4c24'
    '54894808488b4c244c4889084c8dbc24a80000004c89ffff1583073a044889e7'
    '4c89fe31d2ff151d093a048b3c2485ff0f8416060000be01000000ff156f073a'
    '0485c00f84170100004c896c247089042448c7442404000000004c8dac24a800'
    '00004c89efff1535073a0448b8010000001601000048898424b8000000488d05'
    '128de4fe48898424c000000048c78424c80000002c0000004989e74c89ff4c89'
    'eeff1519073a048b05ebc93a0485c00f85c4000000f20f104b7080bba8000000'
    '010f850b010000660f2ec80f8601010000f20f5805a7c6e3fef20f1143688b05'
    'b4c93a0485c00f84eb000000488d058dc93a04488904244c89bc24a800000048'
    '8d3d92c93a04488d0d5bbd29044c8d053cbd2904488d9424a8000000be010000'
    '00ff1591063a04e9ab0000008bbb88000000be09000000ff1513083a0483f8ff'
    '0f85e0fdffffff158c063a048b3048c1e6204883ce02488d7c2478e8f0070000'
    '488d3d2abae4fe488d1512c82904be22000000ff15ef013a04488d0500c93a04'
    '488904244c89bc24a8000000488d3d05c93a04488d0dcebc29044c8d05afbc29'
    '04488d9424a8000000be01000000f20f11442430ff15fe053a04f20f10442430'
    'f20f104b7080bba8000000010f84f5fefffff20f114b684c8dbc24a80000004c'
    '89ffff15b8053a044889e74c89fe31d2ff1552073a048b042485c00f844b0400'
    '00c644243800894424204c8b3d17063a04418b475085c00f85480400004983c7'
    '184c89bc24a8000000488d05b060070048898424b0000000488d6c24384889ac'
    '24b8000000488b050c073a0448898424c0000000488d44242048898424c80000'
    '00488b05f8063a0448898424d0000000488d35436be2fe488d7c2458488d9424'
    'a8000000ff15b6fc39044c8b6c24604c8b7c24684c89ef4c89feff15c8063a04'
    '4885c00f85f503000048b800000000b60100004889442438c744244000000000'
    '66c74424440000c644244201c6442444014889ac24800000004981ff7f010000'
    '0f87ed030000488dac24a80000004889ef4c89ee4c89faff15e3fb390442c684'
    '3ca80000000049ffc74889e74889ee4c89faff15d8043a04833c24017516488d'
    '05233f38044889442428c744242001000000eb14488b742408488d7c2420488d'
    '542438e8a80ab103837c2420010f84d10400008b4424248944243048895c2438'
    '488d4318488944242041fece8b0526c73a044180fe020f839500000085c00f85'
    '1a0400008b4424503d00100e000f83640300003d905f01000f838603000089c0'
    'b9c5b3a291480fafc848c1e92b488b7358488b4360488dbc24a80000004489e2'
    'ff50284c8ba424b00000004c8bac24b80000004d85ed0f84c1000000498d6c24'
    '104c8b3d28fb3904eb13660f1f4400004883c52849ffcd0f84a0000000488b75'
    'f84885f674ea488b7d0031d241ffd7ebdf85c00f85c80300008b4424503dff0f'
    '0e000f87cf0200003d8f5f01000f87f102000089c0b9c5b3a291480fafc848c1'
    'e92b488b7358488b4360488dbc24a80000004489e2ff50284c8ba424b0000000'
    '4c8bac24b80000004d85ed7430498d6c24104c8b3d97fa3904eb0e0f1f440000'
    '4883c52849ffcd7414488b75f84885f674ee488b7d0031d241ffd7ebe3488b84'
    '24a80000004885c0741348c1e003488d34804c89e731d2ff1553fa3904488b73'
    '08488b5310488dbc24a8000000ff159d023a044489742448488b43284885c074'
    '384c8b6b2048c1e0034c8d3c4031ed4c8da424a80000004c8b357a023a046690'
    '498b742d08498b542d104c89e741ffd64883c5184939ef75e783bc2400010000'
    '03750d8bbc2404010000ff15d8003a04c7842400010000030000008b44243089'
    '8424040100004889e7488db424a800000031d2b901000000e8937eb1038b6c24'
    '484c8b742470833c24010f84eb0200008b442404488b4c2408660f1044241089'
    '84248c00000048898c2490000000660f11842498000000488dbc24a8000000e8'
    'cc49000041833e0274448bbb8c00000083ffff7406ff154d003a048bbb900000'
    '0083ffff7406ff153c003a048bbb9400000083ffff7406ff152b003a048bbb98'
    '00000083ffff7406ff151a003a040f1084248c0000000f108c2498000000410f'
    '114e0c410f11064080fd027316488b437848ffc048c7c1ffffffff480f45c848'
    '894b78488b7424584885f6740d488b7c246031d2ff15d6f839044881c4280200'
    '005b415c415d415e415f5dc3488d3d82b5e4fe488d1556c32904be2b000000ff'
    '1503fd39044c893c244889e048898424a8000000498d7f50488d0da9b729044c'
    '8d05cab72904488d9424a8000000be01000000ff151f013a04e97ffbffff4889'
    '8424a8000000488d3df087e4fe488d0da48729044c8d05a5852904488d9424a8'
    '000000be2b000000ff157af83904e99c0100004c8d05e606b103488d7c242048'
    '8d8c24800000004c89ee4c89fae8be7ab103e951fcffff488d3dacb5e4fe488d'
    '0d3bc429044c8d05bcc22904488d9424a8000000be2b000000ff1529f83904e9'
    '4b010000488d3dfe86e4fe488d15a6852904be1c000000ff15cbf83904e92d01'
    '0000488d0537c33a04488904244889e048898424a8000000488d3d39c33a0448'
    '8d0d02b729044c8d05e3b62904488d9424a8000000be01000000ff1538003a04'
    '8bbb90000000c78390000000ffffffff83ffff0f85b0f7ffffe9b1f7ffff488d'
    '05dbc23a04488904244889e048898424a8000000488d3dddc23a04488d0da6b6'
    '29044c8d0587b62904488d9424a8000000be01000000ff15dcff3904e9a3fbff'
    'ff488d0598c23a04488904244889e048898424a8000000488d3d9ac23a04488d'
    '0d63b629044c8d0544b62904488d9424a8000000be01000000ff1599ff3904e9'
    'f5fbffff488b44242848898424a8000000488d3db685e4fe488d0df98529044c'
    '8d0532842904488d9424a8000000be16000000ff15eff63904eb14488b542408'
    '488d7c2438488d742420e8f10100000f0b4889c3498b75084885f67421498b45'
    '10f3480fbcc831d24839f00f47d14883f8110f43d14c89e7ff1572f63904be18'
    '0000004c89ffe98a0000004889c3488dbc248c000000e875450000eb694889c3'
    '488dbc24a8000000e8d3450000eb57ff1553f739044889c331edeb0b4889c3eb'
    '454889c340b501488dbc24a8000000e87c4600004084ed7523eb2bff1527f739'
    '044889c3488bbc24a8000000488b07ff10eb13ff150ff739044889c38b7c2430'
    'ff15e2fc3904488b7424584885f6740d488b7c246031d2ff15d3f539044889df'
    'e8cb162904'
)
BODY_SHA256 = '5690f29d4d83c2f8edb173c2afd6dc8bd174df166e534dcae2c88e01cb5d9a9d'
BRANCHES = [
    (0x27, '0f84e8000000', 2, 6, 0x13ce0d5),
    (0x34, '7530', 1, 2, 0x13ce026),
    (0x3f, '0f8427020000', 2, 6, 0x13ce22c),
    (0x60, '0f8420020000', 2, 6, 0x13ce246),
    (0x6e, '0f850e080000', 2, 6, 0x13ce842),
    (0x87, '7406', 1, 2, 0x13ce04f),
    (0xa7, '746c', 1, 2, 0x13ce0d5),
    (0xb9, '755a', 1, 2, 0x13ce0d5),
    (0xd1, '7405', 1, 2, 0x13ce098),
    (0xdf, '7421', 1, 2, 0x13ce0c2),
    (0x133, '7408', 1, 2, 0x13ce0fd),
    (0x170, '0f8416060000', 2, 6, 0x13ce74c),
    (0x183, '0f8417010000', 2, 6, 0x13ce260),
    (0x1ef, '0f85c4000000', 2, 6, 0x13ce279),
    (0x201, '0f850b010000', 2, 6, 0x13ce2d2),
    (0x20b, '0f8601010000', 2, 6, 0x13ce2d2),
    (0x226, '0f84eb000000', 2, 6, 0x13ce2d7),
    (0x267, 'e9ab000000', 1, 5, 0x13ce2d7),
    (0x280, '0f85e0fdffff', 2, 6, 0x13ce026),
    (0x30c, '0f84f5feffff', 2, 6, 0x13ce1c7),
    (0x33b, '0f844b040000', 2, 6, 0x13ce74c),
    (0x357, '0f8548040000', 2, 6, 0x13ce765),
    (0x3e3, '0f85f5030000', 2, 6, 0x13ce79e),
    (0x420, '0f87ed030000', 2, 6, 0x13ce7d3),
    (0x45c, '7516', 1, 2, 0x13ce434),
    (0x472, 'eb14', 1, 2, 0x13ce448),
    (0x48d, '0f84d1040000', 2, 6, 0x13ce924),
    (0x4b6, '0f8395000000', 2, 6, 0x13ce511),
    (0x4be, '0f851a040000', 2, 6, 0x13ce89e),
    (0x4cd, '0f8364030000', 2, 6, 0x13ce7f7),
    (0x4d8, '0f8386030000', 2, 6, 0x13ce824),
    (0x516, '0f84c1000000', 2, 6, 0x13ce59d),
    (0x528, 'eb13', 1, 2, 0x13ce4fd),
    (0x537, '0f84a0000000', 2, 6, 0x13ce59d),
    (0x544, '74ea', 1, 2, 0x13ce4f0),
    (0x54f, 'ebdf', 1, 2, 0x13ce4f0),
    (0x553, '0f85c8030000', 2, 6, 0x13ce8e1),
    (0x562, '0f87cf020000', 2, 6, 0x13ce7f7),
    (0x56d, '0f87f1020000', 2, 6, 0x13ce824),
    (0x5ab, '7430', 1, 2, 0x13ce59d),
    (0x5b9, 'eb0e', 1, 2, 0x13ce589),
    (0x5c7, '7414', 1, 2, 0x13ce59d),
    (0x5d0, '74ee', 1, 2, 0x13ce580),
    (0x5db, 'ebe3', 1, 2, 0x13ce580),
    (0x5e8, '7413', 1, 2, 0x13ce5bd),
    (0x61f, '7438', 1, 2, 0x13ce619),
    (0x657, '75e7', 1, 2, 0x13ce600),
    (0x661, '750d', 1, 2, 0x13ce630),
    (0x6aa, '0f84eb020000', 2, 6, 0x13ce95b),
    (0x6e8, '7444', 1, 2, 0x13ce6ee),
    (0x6f3, '7406', 1, 2, 0x13ce6bb),
    (0x704, '7406', 1, 2, 0x13ce6cc),
    (0x715, '7406', 1, 2, 0x13ce6dd),
    (0x726, '7406', 1, 2, 0x13ce6ee),
    (0x74b, '7316', 1, 2, 0x13ce723),
    (0x76b, '740d', 1, 2, 0x13ce73a),
    (0x7d9, 'e97ffbffff', 1, 5, 0x13ce31d),
    (0x80e, 'e99c010000', 1, 5, 0x13ce96f),
    (0x832, 'e951fcffff', 1, 5, 0x13ce448),
    (0x85f, 'e94b010000', 1, 5, 0x13ce96f),
    (0x87d, 'e92d010000', 1, 5, 0x13ce96f),
    (0x8d3, '0f85b0f7ffff', 2, 6, 0x13ce049),
    (0x8d9, 'e9b1f7ffff', 1, 5, 0x13ce04f),
    (0x91c, 'e9a3fbffff', 1, 5, 0x13ce484),
    (0x95f, 'e9f5fbffff', 1, 5, 0x13ce519),
    (0x999, 'eb14', 1, 2, 0x13ce96f),
    (0x9bb, '7421', 1, 2, 0x13ce99e),
    (0x9e6, 'e98a000000', 1, 5, 0x13cea35),
    (0x9fb, 'eb69', 1, 2, 0x13cea26),
    (0xa0d, 'eb57', 1, 2, 0x13cea26),
    (0xa1a, 'eb0b', 1, 2, 0x13ce9e7),
    (0xa1f, 'eb45', 1, 2, 0x13cea26),
    (0xa37, '7523', 1, 2, 0x13cea1c),
    (0xa39, 'eb2b', 1, 2, 0x13cea26),
    (0xa51, 'eb13', 1, 2, 0x13cea26),
    (0xa6e, '740d', 1, 2, 0x13cea3d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x13ce05a, 0x4ee8ee0),
    (0x13ce25b, 0x13cea50),
    (0x13ce443, 0x4edeef0),
    (0x13ce658, 0x4ee64f0),
    (0x13ce69f, 0x13d3070),
    (0x13ce7ed, 0x4ee62b0),
    (0x13ce96a, 0x13ceb60),
    (0x13ce9b6, 0x13d2f30),
    (0x13ce9c8, 0x13d2fa0),
    (0x13ce9ef, 0x13d3070),
    (0x13cea40, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x13ce016, 0x576ea40),
    (0x13ce049, 0x576e708),
    (0x13ce0bc, 0x576e010),
    (0x13ce0cc, 0x576e010),
    (0x13ce0da, 0x576e8a0),
    (0x13ce117, 0x576e8a0),
    (0x13ce125, 0x576ea48),
    (0x13ce13b, 0x576e8b0),
    (0x13ce165, 0x576e8a0),
    (0x13ce1a1, 0x576e8c0),
    (0x13ce221, 0x576e8b8),
    (0x13ce237, 0x576ea50),
    (0x13ce246, 0x576e8d8),
    (0x13ce273, 0x576e468),
    (0x13ce2b4, 0x576e8b8),
    (0x13ce2e2, 0x576e8a0),
    (0x13ce2f0, 0x576ea48),
    (0x13ce384, 0x576e040),
    (0x13ce39a, 0x576ea68),
    (0x13ce3f7, 0x576dfe0),
    (0x13ce412, 0x576e8f0),
    (0x13ce5b7, 0x576e010),
    (0x13ce5cd, 0x576e870),
    (0x13ce62a, 0x576e708),
    (0x13ce6b5, 0x576e708),
    (0x13ce6c6, 0x576e708),
    (0x13ce6d7, 0x576e708),
    (0x13ce6e8, 0x576e708),
    (0x13ce734, 0x576e010),
    (0x13ce75f, 0x576e468),
    (0x13ce793, 0x576e8b8),
    (0x13ce7c8, 0x576e048),
    (0x13ce819, 0x576e048),
    (0x13ce837, 0x576e108),
    (0x13ce87a, 0x576e8b8),
    (0x13ce8d6, 0x576e8b8),
    (0x13ce919, 0x576e8b8),
    (0x13ce953, 0x576e048),
    (0x13ce998, 0x576e010),
    (0x13ce9cf, 0x576e128),
    (0x13ce9fb, 0x576e128),
    (0x13cea13, 0x576e128),
    (0x13cea20, 0x576e708),
    (0x13cea37, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x13ce267, 0x566aa80, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f646174652f6d6f642e7273'), 1909, 38),
    (0x13ce753, 0x566aab0, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6461746574696d652f6d6f642e7273'), 579, 14),
    (0x13ce82b, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
]
CALLERS = [0x13cece2, 0x13ced4a, 0x13cff31]
CALLER_FUNCTIONS = {'0x13cece2': ('0x13cec80', '0x13d0892'), '0x13ced4a': ('0x13cec80', '0x13d0892'), '0x13cff31': ('0x13cec80', '0x13d0892')}
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

