#!/usr/bin/env python3
"""Authenticated node94 channel-4391840 binding (0x4391840).

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

START, END = 0x4391840, 0x4392387
FDE_VA = 0x1237cf0
FDE = bytes.fromhex(
    '50000000c8a02700489b1503470b000004e3d18fff410e10420e18420e20420e'
    '28420e30410e38470ed00583078c068d058e048f03860203ff090e38410e3042'
    '0e28420e20420e18420e10410e08410ed0050000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec980200004889fb4c8b3ebf01000000e89f1fb5'
    '004989c689d54c8b23498b4424384889442430418b4424408944240c80bb1801'
    '0000004c89e00f8592000000c68318010000014c89742410896c2418488b4424'
    '3048898424800000008b44240c89842488000000488dbc2460010000488d7424'
    '10488d942480000000e8621eb500b800ca9a3b48f7a424680100008b8c247001'
    '00004801c84883d20031c948f7daba000000004819d24809c280bc2460010000'
    '00480f45d1498b442430f048015058488b03488b4030f048ff4018488b0331c9'
    '4887481048398b100100007326498b442430f048ff40204889c8482b83100100'
    '000f82ef020000498b542430f048014260eb094885c90f84200100004d89e549'
    '8b442430f048ff40284889c848c1e80949bc535a9ba02fb8440049f7e448c1ea'
    '0b488b4424304801d00f80810200004869d200ca9a3b4829d1034c240c81f900'
    'ca9a3b720f48ffc00f806202000081c1003665c44c89742410896c2418488984'
    '2480000000898c2488000000488dbc2460010000488d742410488d9424800000'
    '00e84a1db500b800ca9a3b48f7a424680100008b8c24700100004801c84883d2'
    '0031f648f7dab9000000004819c94809c180bc246001000000480f45ce4889c8'
    '48c1e80949f7e448c1ea0b4d89ec498b4530483b90a000000075214869d200ca'
    '9a3b4889ce4829d639b0a8000000760eba80000000be48000000eb0c72f2ba88'
    '000000be40000000f048ff0430f048010c10498b442430f0480148684c896424'
    '584c8b23b90100000031c0f0490fb14c24284883f80274384885c00f85990000'
    '00498b4c2418498b074885c9742e498b7f084839c1752949397c2420752231c9'
    'b801000000f0490fb14c24287546eb6a498b07498b7f08ff5010eb5e498b7f08'
    'ff104989c74989d6498b4424184885c07408498b7c2420ff50184d897c24184d'
    '8974242031c9b801000000f0490fb14c24287426498b442418498b7c242049c7'
    '442418000000004885c00f84f900000031c949874c2428ff5008488d43084889'
    '44243849be0000000000000080488b034883c010488d0d0dab380148894c2470'
    '4889442478488d4424704889842450020000488984245802000048c784246002'
    '000000000000bf01000000e8701cb50048894424508954244c0fb68308010000'
    '488d0d85df35fc486304814801c8ffe04c8dab000100000fb68300010000488d'
    '0d77df35fc486304814801c8ffe0488bb3d8000000e9ed000000488dabf80000'
    '000fb683f8000000488d0d5ddf35fc486304814801c8ffe0488bb3e8000000e9'
    'df000000488bb3f0000000e9da000000488d3d43c843fc488d1502153c01be28'
    '000000ff153fc83d01488d3dc88e2e01ff153ac83d01488d3d4baa3801ff150d'
    'c53d01488d3d8eb43801ff15e8d33d01488d3d81b43801ff15e3d33d01488d3d'
    '6cd13801ff15ced33d01e91d060000488d3d5ad13801ff15c4d33d01e90b0600'
    '00488d3d38cc3801ff15aad33d01e9f9050000488d3d26cc3801ff15a0d33d01'
    'e9e70500004d897c24184d897424204889c7e859e42c014989c6e92c06000049'
    '89c6e9780600004889b3e00000004889b3e8000000488dabf8000000c683f800'
    '0000004889b3f0000000488dbc2460010000488d942450020000e861191c004c'
    '8ba424600100004d8d7e014d39fc0f94c000c0fec08845004d39fc0f84950300'
    '004c89f14d39f40f84930300004989ce4c8bbc2468010000488bac2470010000'
    '488b83e0000000488b4008f048ff4810c6830001000001488d7c2464ff153ecb'
    '3d01bf28000000ff156bc23d014885c00f84eb0400004989c548c70001000000'
    '48c74008010000004c8960104c8978184889682048894424400f57c00f294424'
    '200f294424100f298424400100000f298424300100000f298424200100000f29'
    '8424100100000f298424000100000f298424f00000000f298424e00000000f29'
    '8424d00000000f298424c00000000f298424b00000000f298424a00000000f29'
    '8424900000000f2984248000000048c78424500100008800000066c784245801'
    '00000100488dbc24800000004c89fe4889eaff15a0c33d014c8dbc2460010000'
    '488db42480000000bae00000004c89ffff158ac13d01488d742410ba20000000'
    '4c89ffff1577c33d010f284424100f284c24200f298424700200000f298c2480'
    '020000488b7b284883c7104c8dbbd0000000c70424010000004c8d0564f335fc'
    '488d94247002000041b9190000004889fe4c89f9e8b74d1900498b0748ffc048'
    'c7c1ffffffff480f45c849890ff049ff45000f8eb40300004c8b6360f049ff44'
    '24104c8b7b58498b87c00100000f1f00a8010f858b0000004883f8fe0f845903'
    '0000488d4802f0490fb18fc001000075df48c7842480000000000000004c89ac'
    '2488000000498dbf80000000488db42480000000e8d75b7b00498b8710010000'
    '4889c14883c902f0490fb18f1001000075ee4885c0755f498b8700010000498b'
    'bf0801000049c7870001000000000000f04983a710010000fd4885c07438ff50'
    '08eb33488dbc246801000048c7842468010000000000004c89ac247001000048'
    'c784246001000001000000e8d03b3a00f049ff4c24104c8b7c24404c897c2410'
    '8b44246c89842488000000488b4424644889842480000000488db42484000000'
    '488dbc246001000031d2b9801d2c04ff15b3c83d01488b84246801000048b900'
    '0000004057ffff4801c148ba81aefeff7faefeff4839d10f8256020000f20f10'
    '8424600100000f298424400200008bbc248000000048b9572951cea0c8451848'
    'f7e94889d648c1ee3f48c1ea0d01d6ff155bc83d0185c00f8416020000488dbb'
    '80000000898424600100000f288424400200000f138424640100004c89bc2470'
    '010000488d1536653a01488db42460010000e829924200488b7424384889b3d8'
    '0000004c8dab00010000c6830001000000e911fcffff41c645000340b503eb3b'
    '41c6450001488b7c2438e8a1f7fbff488b4328f048ff08750a488d7b28ff15b5'
    '0f3e01488d7b30e88491faff488dbb8000000040b501e825f9fbff4088ab0801'
    '0000bf01000000e8f416b5004989c689d5488944241089542418488b44243048'
    '898424800000008b44240c89842488000000488dbc2460010000488d74241048'
    '8d942480000000e8e415b500b800ca9a3b48f7a424680100008b8c2470010000'
    '4801c84883d2004531ed48f7dab9000000004819c94809c180bc246001000000'
    '490f45cd48898b100100004c89742410896c2418488b44245048898424800000'
    '008b44244c89842488000000488dbc2460010000488d742410488d9424800000'
    '00e86a15b50080bc246001000000b8000000007510448bac2470010000488b84'
    '2468010000488b4c2458488b7130483b86900000007516443bae98000000730f'
    'bf7000000041b830000000eb0d72f1bf7800000041b8380000004d39fc0f94c1'
    'ba00ca9a3b48f7e24589e94901c14883d20031c048f7da4819c04c09c8f04aff'
    '0406f04801043e89c84881c4980200005b415c415d415e415f5dc3ff15afd43d'
    '01bf08000000be28000000ff15afbd3d01eb19488d3da57de8fb488d15978c2d'
    '01be26000000ff15dcc13d010f0b4989c6eb2e4989c6c68308010000024c89f7'
    'e86bde2c014989c6eb204989c6488b4328f048ff08750a488d7b28ff15d70d3e'
    '01488d7b30e8a68ffaff488dbb80000000e84af7fbffe9970000004989c6eb5f'
    'eb1aeb454989c6c645000241c6450002eb4d4989c64c8b6c2440eb034989c6f0'
    '49ff4d007539488d7c2440ff15f70c3e01eb2c4989c6f049ff0f7523488d7c24'
    '10ff15e10c3e01eb164989c64d85e4740e4c89ff4c89e631d2ff15d1bc3d0148'
    '8b7c2438e827f5fbff488b4328f048ff08750a488d7b28ff153b0d3e01488d7b'
    '30e80a8ffaff488dbb80000000e8aef6fbffc68308010000024c89f7e88fdd2c'
    '01ff15a1bd3d01'
)
BODY_SHA256 = '3b6d468b14fffad7f99335dc8cef522a20c2490d0fb5dc016035757ebd1580e7'
BRANCHES = [
    (0x46, '0f8592000000', 2, 6, 0x439191e),
    (0xeb, '7326', 1, 2, 0x4391953),
    (0x101, '0f82ef020000', 2, 6, 0x4391c36),
    (0x111, 'eb09', 1, 2, 0x439195c),
    (0x116, '0f8420010000', 2, 6, 0x4391a7c),
    (0x149, '0f8081020000', 2, 6, 0x4391c10),
    (0x163, '720f', 1, 2, 0x43919b4),
    (0x168, '0f8062020000', 2, 6, 0x4391c10),
    (0x1f9, '7521', 1, 2, 0x4391a5c),
    (0x20e, '760e', 1, 2, 0x4391a5e),
    (0x21a, 'eb0c', 1, 2, 0x4391a68),
    (0x21c, '72f2', 1, 2, 0x4391a50),
    (0x256, '7438', 1, 2, 0x4391ad0),
    (0x25b, '0f8599000000', 2, 6, 0x4391b3a),
    (0x26c, '742e', 1, 2, 0x4391adc),
    (0x275, '7529', 1, 2, 0x4391ae0),
    (0x27c, '7522', 1, 2, 0x4391ae0),
    (0x28c, '7546', 1, 2, 0x4391b14),
    (0x28e, 'eb6a', 1, 2, 0x4391b3a),
    (0x29a, 'eb5e', 1, 2, 0x4391b3a),
    (0x2b0, '7408', 1, 2, 0x4391afa),
    (0x2d2, '7426', 1, 2, 0x4391b3a),
    (0x2ea, '0f84f9000000', 2, 6, 0x4391c29),
    (0x36e, 'ffe0', 1, 2, 0x4391b90),
    (0x38c, 'ffe0', 1, 2, 0x4391bae),
    (0x395, 'e9ed000000', 1, 5, 0x4391cc7),
    (0x3b6, 'ffe0', 1, 2, 0x4391bd8),
    (0x3bf, 'e9df000000', 1, 5, 0x4391ce3),
    (0x3cb, 'e9da000000', 1, 5, 0x4391cea),
    (0x42a, 'e91d060000', 1, 5, 0x439228c),
    (0x43c, 'e90b060000', 1, 5, 0x439228c),
    (0x44e, 'e9f9050000', 1, 5, 0x439228c),
    (0x460, 'e9e7050000', 1, 5, 0x439228c),
    (0x47a, 'e92c060000', 1, 5, 0x43922eb),
    (0x482, 'e978060000', 1, 5, 0x439233f),
    (0x4db, '0f8495030000', 2, 6, 0x43920b6),
    (0x4e7, '0f8493030000', 2, 6, 0x43920c0),
    (0x530, '0f84eb040000', 2, 6, 0x4392261),
    (0x692, '0f8eb4030000', 2, 6, 0x439228c),
    (0x6b2, '0f858b000000', 2, 6, 0x4391f83),
    (0x6bc, '0f8459030000', 2, 6, 0x439225b),
    (0x6cf, '75df', 1, 2, 0x4391ef0),
    (0x710, '75ee', 1, 2, 0x4391f40),
    (0x715, '755f', 1, 2, 0x4391fb6),
    (0x73c, '7438', 1, 2, 0x4391fb6),
    (0x741, 'eb33', 1, 2, 0x4391fb6),
    (0x7d7, '0f8256020000', 2, 6, 0x4392273),
    (0x817, '0f8416020000', 2, 6, 0x4392273),
    (0x871, 'e911fcffff', 1, 5, 0x4391cc7),
    (0x87e, 'eb3b', 1, 2, 0x43920fb),
    (0x897, '750a', 1, 2, 0x43920e3),
    (0x993, '7510', 1, 2, 0x43921e5),
    (0x9b5, '7516', 1, 2, 0x439220d),
    (0x9be, '730f', 1, 2, 0x439220f),
    (0x9cb, 'eb0d', 1, 2, 0x439221a),
    (0x9cd, '72f1', 1, 2, 0x4392200),
    (0xa31, 'eb19', 1, 2, 0x439228c),
    (0xa51, 'eb2e', 1, 2, 0x43922c1),
    (0xa68, 'eb20', 1, 2, 0x43922ca),
    (0xa75, '750a', 1, 2, 0x43922c1),
    (0xa96, 'e997000000', 1, 5, 0x4392372),
    (0xa9e, 'eb5f', 1, 2, 0x439233f),
    (0xaa0, 'eb1a', 1, 2, 0x43922fc),
    (0xaa2, 'eb45', 1, 2, 0x4392329),
    (0xab0, 'eb4d', 1, 2, 0x439233f),
    (0xaba, 'eb03', 1, 2, 0x43922ff),
    (0xac4, '7539', 1, 2, 0x439233f),
    (0xad1, 'eb2c', 1, 2, 0x439233f),
    (0xada, '7523', 1, 2, 0x439233f),
    (0xae7, 'eb16', 1, 2, 0x439233f),
    (0xaef, '740e', 1, 2, 0x439233f),
    (0xb11, '750a', 1, 2, 0x439235d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x439185c, 0x4ee3800),
    (0x43918c9, 0x4ee3730),
    (0x43919e1, 0x4ee3730),
    (0x4391b8b, 0x4ee3800),
    (0x4391cb2, 0x5660110),
    (0x4391cfa, 0x4553660),
    (0x4391eb4, 0x4526c70),
    (0x4391f34, 0x4b47b10),
    (0x4391fab, 0x4735b80),
    (0x4392092, 0x47bb2c0),
    (0x43920ca, 0x4351870),
    (0x43920e7, 0x433b270),
    (0x43920f6, 0x4351a20),
    (0x4392107, 0x4ee3800),
    (0x4392147, 0x4ee3730),
    (0x43921c1, 0x4ee3730),
    (0x43922a0, 0x5660110),
    (0x43922c5, 0x433b270),
    (0x43922d1, 0x4351a20),
    (0x4392344, 0x4351870),
    (0x4392361, 0x433b270),
    (0x439236d, 0x4351a20),
    (0x439237c, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4391c23, 0x576e468),
    (0x4391c30, 0x576e470),
    (0x4391c3d, 0x576e150),
    (0x4391c4a, 0x576f038),
    (0x4391c57, 0x576f040),
    (0x4391c64, 0x576f038),
    (0x4391c76, 0x576f040),
    (0x4391c88, 0x576f038),
    (0x4391c9a, 0x576f040),
    (0x4391d5c, 0x576e8a0),
    (0x4391d67, 0x576dfd8),
    (0x4391e32, 0x576e1d8),
    (0x4391e50, 0x576dfe0),
    (0x4391e63, 0x576e1e0),
    (0x4391fef, 0x576e8a8),
    (0x439204f, 0x576e8b0),
    (0x43920dd, 0x5773098),
    (0x439225b, 0x576f710),
    (0x439226b, 0x576e020),
    (0x4392286, 0x576e468),
    (0x43922bb, 0x5773098),
    (0x439230b, 0x5773008),
    (0x4392321, 0x5773008),
    (0x4392339, 0x576e010),
    (0x4392357, 0x5773098),
    (0x4392381, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4391c17, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x4391c29, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x4391c36, 0x571c688, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
    (0x439227a, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x4b64da4]
CALLER_FUNCTIONS = {'0x4b64da4': ('0x4b64d10', '0x4b64e96')}
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

