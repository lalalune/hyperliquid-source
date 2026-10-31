#!/usr/bin/env python3
"""Authenticated node94 channel-4399e80 binding (0x4399e80).

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

START, END = 0x4399e80, 0x439a8af
FDE_VA = 0x123830c
FDE = bytes.fromhex(
    '50000000e4a627006c1b16032f0a000004fbd18fff410e10420e18420e20420e'
    '28420e30410e38470e800a83078c068d058e048f038602038f080e38410e3042'
    '0e28420e20420e18420e10410e08410e800a0000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc80400004889fb4c8b26bf01000000e85f99b4'
    '004989c689d54c8b3b498b47384889442410418b47408944240c80bba8000000'
    '004c89f80f858e000000c683a8000000014c89b4245803000089ac2460030000'
    '488b44241048898424e80100008b44240c898424f0010000488d7c2468488db4'
    '2458030000488d9424e8010000e81e98b400b800ca9a3b48f76424708b4c2478'
    '4801c84883d20031c948f7daba000000004819d24809c2807c246800480f45d1'
    '498b4730f048015058488b03488b4030f048ff4018488b0331c9488748104839'
    '8ba00000007324498b4730f048ff40204889c8482b83a00000000f82af020000'
    '498b5730f048014260eb094885c90f8415010000498b4730f048ff40284889c8'
    '48c1e80949bd535a9ba02fb8440049f7e548c1ea0b488b4424104801d00f8046'
    '0200004869d200ca9a3b4829d1034c240c81f900ca9a3b720f48ffc00f802702'
    '000081c1003665c44c89b4245803000089ac246003000048898424e801000089'
    '8c24f0010000488d7c2468488db42458030000488d9424e8010000e81097b400'
    'b800ca9a3b48f76424708b4c24784801c84883d20031f648f7dab90000000048'
    '19c94809c1807c246800480f45ce4889c848c1e80949f7e548c1ea0b498b4730'
    '483b90a000000075214869d200ca9a3b4889ce4829d639b0a8000000760eba80'
    '000000be48000000eb0c72f2ba88000000be40000000f048ff0430f048010c10'
    '498b4730f0480148684c8b2bb90100000031c0f0490fb14d284883f802743748'
    '85c00f8592000000498b4d18498b04244885c9742f498b7c24084839c1752a49'
    '397d20752431c9b801000000f0490fb14d287544eb64498b0424498b7c2408ff'
    '5010eb56498b7c2408ff104989c44989d6498b45184885c07407498b7d20ff50'
    '184d8965184d89752031c9b801000000f0490fb14d287422498b4518498b7d20'
    '49c74518000000004885c00f84d100000031c949874d28ff50084c8d7308488b'
    '034883c010488d0dfc24380148894c24384889442440488d4424384889442448'
    '488944245048c744245800000000bf01000000e86896b4004889442428895424'
    '1c0fb6839c000000488d0ddd5935fc486304814801c8ffe04c8dab800000000f'
    'b68380000000488d0dcf5935fc486304814801c8ffe0488b7b58e9df00000048'
    '8d6b780fb64378488d0dbe5935fc486304814801c8ffe0488b7b68e9ce000000'
    '488b7b70e9c9000000488d3d4a4243fc488d15098f3b01be28000000ff154642'
    '3d01488d3dcf082e01ff1541423d01488d3d52243801ff15143f3d01488d3dad'
    '2e3801ff15ef4d3d01488d3da02e3801ff15ea4d3d01488d3d734b3801ff15d5'
    '4d3d01e9d9040000488d3d614b3801ff15cb4d3d01e9c7040000488d3d3f4638'
    '01ff15b14d3d01e9b5040000488d3d2d463801ff15a74d3d01e9a30400004d89'
    '65184d8975204889c7e8625e2c014989c7e9730500004989c7e9b70500004889'
    '7b6048897b68488d6b78c643780048897b70488d742448e854af1b0024018d0c'
    '00fec1884d0084c00f844902000041c645000341bd0100000041f6c5010f855b'
    '0200004d85e40f84a60200004c89642420f049ff04240f8e250400008b839800'
    '0000898424e00100000f1083880000000f118424d001000048c7442468030000'
    '004c89642470488dbc24f8010000488d0dc86e35fc488d74246841b81d000000'
    '31d2e809b37d0048c78424e80100000100000048c78424f001000001000000bf'
    '28000000ff154e3c3d014885c00f849e0300004989c5488b8424080200004989'
    '4520660f108424e8010000660f108c24f801000066410f114d1066410f114500'
    '4c896c2430488d7c2468e811e7faff488b7b28488d7710440fb68fb005000048'
    '81c7d8020000488d0d4d6e35fc41b8140000004c89eae865b018004c8dab8800'
    '0000f20f58c1660f2e05aa06e7fb7633488b2d11453d018b455085c00f852103'
    '00000fb6454883f81f7718b900603c800fa3c1730e8b055d073e0185c00f853c'
    '030000418b4510898424c0040000410f1045000f118424b0040000488b6b38f0'
    '48ff4510488dbc24e8010000488db42458030000ba6c010000ff15613b3d014c'
    '8b6b30498b85c0010000660f1f440000a8010f85cb0000004883f8fe0f848902'
    '0000488d4802f0490fb18dc001000075df48c7442468020000004c8964247048'
    '8d7c2478488db424e8010000ba6c010000ff15093b3d01498dbd80000000488d'
    '742468e808d27a00498b8510010000904889c14883c902f0490fb18d10010000'
    '75ee4885c00f858d000000498b8500010000498bbd0801000049c78500010000'
    '00000000f04983a510010000fd4885c07466ff5008eb614989d44885d2740d48'
    '8b4360488b4008f048ff481041c64500014531ed41f6c5010f84a5fdffff40b5'
    '03eb77488d7c2478488db424e8010000ba6c010000ff15653a3d0148c7442468'
    '020000004c89642470488d7c2468e8bd6d3900f048ff4d104c8973584c8dab80'
    '000000c68380000000004c89f7e90cfdffff4c89f7e8c670fbff488b4328f048'
    'ff08750a488d7b28ff15c28a3d01488d7b3040b501e89680fbff4088ab9c0000'
    '00bf01000000e81592b4004989c64189d4488984245803000089942460030000'
    '488b44241048898424e80100008b44240c898424f0010000488d7c2468488db4'
    '2458030000488d9424e8010000e8fe90b400b800ca9a3b48f76424708b4c2478'
    '4801c84883d20031ed48f7dab9000000004819c94809c1807c246800480f45cd'
    '48898ba00000004c89b424580300004489a42460030000488b44242848898424'
    'e80100008b44241c898424f0010000488d7c2468488db42458030000488d9424'
    'e8010000e88790b400807c246800b80000000075098b6c2478488b442470498b'
    '4f30483b819000000075143ba998000000730ebe70000000bf30000000eb0c72'
    'f2be78000000bf38000000ba00ca9a3b48f7e24189e84901c04883d20031c048'
    'f7da4819c0f048ff04394c09c0f0480104314180e5014489e84881c4c8040000'
    '5b415c415d415e415f5dc3ff15df4f3d01bf08000000be28000000ff15df383d'
    '010f0b4889ac24e8010000488d8424e80100004889442468488d7d50488d0dad'
    '0a2e014c8d05ce0a2e01488d542468be01000000ff153e413d01e9a3fcffff48'
    '8d05fa033e0148898424e8010000488d8424e80100004889442468488d3df603'
    '3e01488d0dbff72c014c8d05a0f72c01488d542468be01000000ff15f8403d01'
    'e97efcffff4989c7eb294989c7c6839c000000024c89ffe834592c014989c748'
    '8b4328f048ff08750a488d7b28ff159d883d01488d7b30e8747efbffe9990000'
    '004989c7f049ff4d007554488d7c2430ff15f2873d01eb474989c7eb424989c7'
    'eb334989c7c645000241c6450002eb454989c7eb404989c7488bb424f8010000'
    '4885f67410488bbc240002000031d2ff15bb373d01488d7c2468e881e2faff48'
    '8b442420f048ff08750b488d7c2420ff1593873d014c89f7e8036efbff488b43'
    '28f048ff08750a488d7b28ff15ff873d01488d7b30e8d67dfbffc6839c000000'
    '024c89ffe867582c01ff1579383d01'
)
BODY_SHA256 = 'f1672d6b52cfca7a51059d74621d4bafc36b3425da3beb6bf06793b25cbb89e6'
BRANCHES = [
    (0x44, '0f858e000000', 2, 6, 0x4399f58),
    (0xe5, '7324', 1, 2, 0x4399f8b),
    (0xfa, '0f82af020000', 2, 6, 0x439a22f),
    (0x109, 'eb09', 1, 2, 0x4399f94),
    (0x10e, '0f8415010000', 2, 6, 0x439a0a9),
    (0x13d, '0f8046020000', 2, 6, 0x439a209),
    (0x157, '720f', 1, 2, 0x4399fe8),
    (0x15c, '0f8027020000', 2, 6, 0x439a209),
    (0x1e7, '7521', 1, 2, 0x439a08a),
    (0x1fc, '760e', 1, 2, 0x439a08c),
    (0x208, 'eb0c', 1, 2, 0x439a096),
    (0x20a, '72f2', 1, 2, 0x439a07e),
    (0x23d, '7437', 1, 2, 0x439a0f6),
    (0x242, '0f8592000000', 2, 6, 0x439a15a),
    (0x253, '742f', 1, 2, 0x439a104),
    (0x25d, '752a', 1, 2, 0x439a109),
    (0x263, '7524', 1, 2, 0x439a109),
    (0x272, '7544', 1, 2, 0x439a138),
    (0x274, 'eb64', 1, 2, 0x439a15a),
    (0x282, 'eb56', 1, 2, 0x439a15a),
    (0x298, '7407', 1, 2, 0x439a121),
    (0x2b6, '7422', 1, 2, 0x439a15a),
    (0x2cb, '0f84d1000000', 2, 6, 0x439a222),
    (0x336, 'ffe0', 1, 2, 0x439a198),
    (0x354, 'ffe0', 1, 2, 0x439a1b6),
    (0x35a, 'e9df000000', 1, 5, 0x439a2be),
    (0x375, 'ffe0', 1, 2, 0x439a1d7),
    (0x37b, 'e9ce000000', 1, 5, 0x439a2ce),
    (0x384, 'e9c9000000', 1, 5, 0x439a2d2),
    (0x3e3, 'e9d9040000', 1, 5, 0x439a741),
    (0x3f5, 'e9c7040000', 1, 5, 0x439a741),
    (0x407, 'e9b5040000', 1, 5, 0x439a741),
    (0x419, 'e9a3040000', 1, 5, 0x439a741),
    (0x431, 'e973050000', 1, 5, 0x439a829),
    (0x439, 'e9b7050000', 1, 5, 0x439a875),
    (0x468, '0f8449020000', 2, 6, 0x439a537),
    (0x47d, '0f855b020000', 2, 6, 0x439a55e),
    (0x486, '0f84a6020000', 2, 6, 0x439a5b2),
    (0x496, '0f8e25040000', 2, 6, 0x439a741),
    (0x50d, '0f849e030000', 2, 6, 0x439a731),
    (0x58e, '7633', 1, 2, 0x439a443),
    (0x59c, '0f8521030000', 2, 6, 0x439a743),
    (0x5a9, '7718', 1, 2, 0x439a443),
    (0x5b3, '730e', 1, 2, 0x439a443),
    (0x5bd, '0f853c030000', 2, 6, 0x439a77f),
    (0x612, '0f85cb000000', 2, 6, 0x439a563),
    (0x61c, '0f8489020000', 2, 6, 0x439a72b),
    (0x62f, '75df', 1, 2, 0x439a490),
    (0x680, '75ee', 1, 2, 0x439a4f0),
    (0x685, '0f858d000000', 2, 6, 0x439a598),
    (0x6b0, '7466', 1, 2, 0x439a598),
    (0x6b5, 'eb61', 1, 2, 0x439a598),
    (0x6bd, '740d', 1, 2, 0x439a54c),
    (0x6d8, '0f84a5fdffff', 2, 6, 0x439a303),
    (0x6e1, 'eb77', 1, 2, 0x439a5da),
    (0x72d, 'e90cfdffff', 1, 5, 0x439a2be),
    (0x742, '750a', 1, 2, 0x439a5ce),
    (0x833, '7509', 1, 2, 0x439a6be),
    (0x849, '7514', 1, 2, 0x439a6df),
    (0x851, '730e', 1, 2, 0x439a6e1),
    (0x85d, 'eb0c', 1, 2, 0x439a6eb),
    (0x85f, '72f2', 1, 2, 0x439a6d3),
    (0x8fa, 'e9a3fcffff', 1, 5, 0x439a422),
    (0x940, 'e97efcffff', 1, 5, 0x439a443),
    (0x948, 'eb29', 1, 2, 0x439a7f3),
    (0x967, '750a', 1, 2, 0x439a7f3),
    (0x97c, 'e999000000', 1, 5, 0x439a89a),
    (0x989, '7554', 1, 2, 0x439a85f),
    (0x996, 'eb47', 1, 2, 0x439a85f),
    (0x99b, 'eb42', 1, 2, 0x439a85f),
    (0x9a0, 'eb33', 1, 2, 0x439a855),
    (0x9ae, 'eb45', 1, 2, 0x439a875),
    (0x9b3, 'eb40', 1, 2, 0x439a875),
    (0x9c3, '7410', 1, 2, 0x439a855),
    (0x9e8, '750b', 1, 2, 0x439a875),
    (0xa05, '750a', 1, 2, 0x439a891),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4399e9c, 0x4ee3800),
    (0x4399f0d, 0x4ee3730),
    (0x439a01b, 0x4ee3730),
    (0x439a193, 0x4ee3800),
    (0x439a2a9, 0x5660110),
    (0x439a2d7, 0x4555230),
    (0x439a362, 0x4b75670),
    (0x439a3ca, 0x4348ae0),
    (0x439a3f6, 0x4525460),
    (0x439a4e3, 0x4b476f0),
    (0x439a58e, 0x4731350),
    (0x439a5b5, 0x4351680),
    (0x439a5d5, 0x4352670),
    (0x439a5e6, 0x4ee3800),
    (0x439a62d, 0x4ee3730),
    (0x439a6a4, 0x4ee3730),
    (0x439a7d7, 0x5660110),
    (0x439a7f7, 0x4352670),
    (0x439a85a, 0x4348ae0),
    (0x439a878, 0x4351680),
    (0x439a895, 0x4352670),
    (0x439a8a4, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x439a21c, 0x576e468),
    (0x439a229, 0x576e470),
    (0x439a236, 0x576e150),
    (0x439a243, 0x576f038),
    (0x439a250, 0x576f040),
    (0x439a25d, 0x576f038),
    (0x439a26f, 0x576f040),
    (0x439a281, 0x576f038),
    (0x439a293, 0x576f040),
    (0x439a384, 0x576dfd8),
    (0x439a479, 0x576dfe0),
    (0x439a4d1, 0x576dfe0),
    (0x439a575, 0x576dfe0),
    (0x439a5c8, 0x5773090),
    (0x439a72b, 0x576f710),
    (0x439a73b, 0x576e020),
    (0x439a774, 0x576e8b8),
    (0x439a7ba, 0x576e8b8),
    (0x439a7ed, 0x5773090),
    (0x439a810, 0x5773008),
    (0x439a84f, 0x576e010),
    (0x439a86f, 0x5773008),
    (0x439a88b, 0x5773090),
    (0x439a8a9, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x439a210, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x439a222, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x439a22f, 0x571c688, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
]
CALLERS = [0x4b620f4]
CALLER_FUNCTIONS = {'0x4b620f4': ('0x4b62060', '0x4b621e6')}
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

