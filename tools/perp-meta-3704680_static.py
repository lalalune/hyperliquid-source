#!/usr/bin/env python3
"""Authenticated node94 perp-meta-3704680 binding (0x3704680).

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

START, END = 0x3704680, 0x37052a1
FDE_VA = 0x11a4f00
FDE = bytes.fromhex(
    '50000000d8721e0078f75502210c000004a77c90ff410e10420e18420e20420e'
    '28420e30410e38470ee00383078c068d058e048f038602030f0b0e38410e3042'
    '0e28420e20420e18420e10410e08410ee0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca801000089cd4989d648b94b598638d6c56d34'
    '4889d048f7e148c1ea0b483b56300f85090b00004869ca102700004c89f04829'
    'c8483b46100f83f20a00004889bc244801000049bd0000000000000080488b4e'
    '08488d044048c1e0048b5c0118896c011883fb3248897424300f82880000004c'
    '8b66384d85e40f84be0a0000488b442430488b4040410fb794249e020000486b'
    'fa3848c7c1ffffffff31f60f1f4400004989f84901f07438413b9c8c74020000'
    '410f97c04180d8004883c6c848ffc14180f80174db410fb6d085d27516e96101'
    '000066666666662e0f1f8400000000004889d14883e8010f824d0a00004d8ba4'
    'cca0020000eb8e4c8b7e5048c704240000000048c744241000000000885c2458'
    '48c74424500000000048c744244000000000488dbc24a80000004889e6488d4c'
    '244031d2e88747c9fff30f6f0424f30f7f842428010000488b44241048898424'
    '3801000048c78424100100000000000048c78424180100000100000048c78424'
    '20010000000000004c89bc24400100004c8da4241001000083fd320f83c20000'
    '0089e8488b4c24304c8b695048c704240000000048c744241000000000884424'
    '5848c74424500000000048c7442440000000004c8dbc24a80000004889e6488d'
    '4c24404c89ff31d2e8e346c9fff30f6f0424f30f7f8424c0000000488b442410'
    '48898424d000000048c78424a80000000000000048c78424b000000001000000'
    '48c78424b8000000000000004c89ac24d800000049bd0000000000000080e9bb'
    '0000004929f44983c4d04c89a424180100004c89ac241001000083fd320f823e'
    'ffffff488b4424304c8b78384d85ff0f84e2080000488b442430488b4040410f'
    'b7979e020000486bfa3848c7c1ffffffff31f6666666662e0f1f840000000000'
    '4989f84901f07428413bac8f74020000410f97c04180d8004883c6c848ffc141'
    '80f80174db410fb6d085d27506eb18904889d14883e8010f827a0800004d8bbc'
    'cfa0020000eb974929f74983c7d04c89bc24b00000004c89ac24a80000004c89'
    'ff4c89e6e897efc2ff48c74424400000000048c7442450000000000fb6d0488d'
    '7c244089dee82637c9ff488b44245048898424f0000000f30f6f442440488b94'
    '24a8000000488b8c24b00000004c39ea488db424a80000004889f0480f44c166'
    '0f7f8424e0000000488b4018c744243c030000004885c0488b5c24300f849e00'
    '00004c39ea480f45ce488b49204885c9747c4889ca4883e2070f848c07000031'
    'f66666666666662e0f1f840000000000488b80c801000048ffc64839f275f148'
    '89ca4829f24883f90872430f1f440000488b80c8010000488b80c8010000488b'
    '80c8010000488b80c8010000488b80c8010000488b80c8010000488b80c80100'
    '00488b80c80100004883c2f875c26683b8c20100000074080fb640188944243c'
    '488b83f8000000488b8b000100004801c148ffc1660f6f00660fd7d0f7d26689'
    '54245848894424404883c010488944244848894c2450488b8310010000488944'
    '24604889e7488d742440e8a1d74a0089ac248c000000488b0424488b4c240831'
    'd24889c64885c00f95c27405488b742410488dbbf80000004889bc2468010000'
    '488954244048c744244800000000488944245048894c2458488954246048c744'
    '246800000000488944247048894c24784889b42480000000488d837001000048'
    '89842458010000488d83280100004889842450010000488d8388010000488984'
    '2460010000488d835801000048898424000100006666662e0f1f840000000000'
    '4889e7488d742440e8d3d2caff488b04244885c00f8432040000488b4c241048'
    '8d0c89f30f6f4488088b448818898424a0000000660f7f842490000000894424'
    '10660f7f0424488bbc24680100004889e6e84a1de9ff4889c3488b40084c8b63'
    '204c89e14885c00f8432030000488d4b2048898c24080100004989df4983c708'
    '488b4b100fb7b02203000089f7c1e70348c7c2ffffffff660f1f840000000000'
    '4885ff743b4c3bb4d0d0020000410f97c04180d80048ffc24883c7f84180f801'
    '74de410fb6f085f674364883e901731de9f202000066662e0f1f840000000000'
    '4889f24883e9010f82da020000488b84d028030000eb8d660f1f840000000000'
    '8b8424a000000089442410660f6f842490000000660f7f0424488bbc24600100'
    '004889e6e8c768c9ff4c89b42470010000498b074885c00f84a3000000488b4b'
    '10488b5424300fb7b02203000089f7c1e70349c7c1ffffffff0f1f8000000000'
    '4885ff743b4e3bb4c8d0020000410f97c04180d80049ffc14883c7f84180f801'
    '74de410fb6f085f674364883e901731de97202000066662e0f1f840000000000'
    '4989f14883e9010f825a0200004a8b84c828030000eb8f660f1f840000000000'
    '488944240848894c24104c894c24184c897c242048c7042400000000eb196690'
    '4c893c244c8974240848c744241000000000488b5424304889e7488db4247001'
    '0000e87986cbff4989c74989c5498b5f10418b6f048b4c243c39e989e80f42c1'
    '41894704418b4738488b8c24e00000004885c90f84b7000000488b9424e80000'
    '000fb779364189f841c1e00248c7c6ffffffff666666662e0f1f840000000000'
    '4d85c0743b3b44b10c410f97c14180d90048ffc64983c0fc4180f90174e2410f'
    'b6f985ff743a4883ea017321e9970100006666666666662e0f1f840000000000'
    '4889fe4883ea010f827b010000488b4cf148eb8d6666662e0f1f840000000000'
    '48894c240848895424104889742418488d8424e0000000488944242048c70424'
    '00000000eb23662e0f1f840000000000488d8c24e000000048890c2448c74424'
    '0800000000894424204983c738488b44243048898424780100004c89bc248001'
    '0000488d8424a800000048898424880100004889e7488db42478010000e83e87'
    'cbff803801750a8b84248c000000418907498b5510458b7d044c89f74889de48'
    '8b8c24080100004c8b842458010000e83c24ffff4439fd741b488bbc24500100'
    '00488db424900000004c89f24489f9e86c970000488b842408010000488b084d'
    '85e4742c4885c90f8553fcffff488bbc2400010000488db42490000000e87e80'
    'caffe939fcffff4c89e14d85e475d5904885c90f8427fcffff8b8424a0000000'
    '89442410660f6f842490000000660f7f0424488bbc24000100004889e6e8ee65'
    'c9ffe9f9fbffff488944241048c7442418000000004c894c24204c893c244c89'
    '742408e9cffdffff48894c240848c7442410000000004889742418488d8c24e0'
    '00000048890c24e9b9feffff4889e34c8d7424404c8bbc244801000049bc0000'
    '000000000080662e0f1f8400000000004889df4c89f6e865cecaff48833c2400'
    '75ee6641c7078601488dbc24e0000000e8db27cfff488bb424a80000004c39e6'
    '0f849c0000004885f67410488bbc24b000000031d2ff15b58f0602488b8c24c0'
    '0000004885c9743d488b9424c8000000488b8424d000000048c7442448000000'
    '0048894c2450488954245848c74424680000000048894c24704889542478b901'
    '000000eb0431c931c048894c244048894c246048898424800000004889e34c8d'
    '742440666666662e0f1f8400000000004889df4c89f6e80599caff48833c2400'
    '75ee488bb424100100004c39e60f84a30000004885f67410488bbc2418010000'
    '31d2ff15088f0602488b8c24280100004885c9743d488b942430010000488b84'
    '243801000048c74424480000000048894c2450488954245848c7442468000000'
    '0048894c24704889542478b901000000eb0431c931c048894c244048894c2460'
    '4889842480000000488d9c24a80000004c8d74244066662e0f1f840000000000'
    '4889df4c89f6e85598caff4883bc24a80000000075ea4c89f84881c4a8010000'
    '5b415c415d415e415f5dc34889ca4883f9080f8398f8ffffe9d1f8ffff488d3d'
    'fccffe01ff15a6920602488d3d07d0fe01ff1599920602488d3dfacffe01ff15'
    '8c9206020f0b4889c34889e7e8ff1ec7ffe98a000000ff152c8f06024889c348'
    '89e7e8e91ec7ffe981000000ff15168f0602eb1b4889c3488d7c2440e8ef25cf'
    'ffeb50eb054889c3eb494889c3eb514889c3eb324889c34c8db424900100004c'
    '8d7c24406666662e0f1f8400000000004c89f74c89fee825cccaff4883bc2490'
    '0100000075ea488dbc24e0000000e89d25cfff488dbc24a8000000e8c0090600'
    '488dbc2410010000e8b30906004889dfe87baef501ff158d8e0602ff15878e06'
    '02'
)
BODY_SHA256 = '159153119605486409b018eda035c9f9c6ce30f6f1787575761a2645af3c61d5'
BRANCHES = [
    (0x2e, '0f85090b0000', 2, 6, 0x37051bd),
    (0x45, '0f83f20a0000', 2, 6, 0x37051bd),
    (0x79, '0f8288000000', 2, 6, 0x3704787),
    (0x86, '0f84be0a0000', 2, 6, 0x37051ca),
    (0xb6, '7438', 1, 2, 0x3704770),
    (0xd3, '74db', 1, 2, 0x3704730),
    (0xdb, '7516', 1, 2, 0x3704773),
    (0xdd, 'e961010000', 1, 5, 0x37048c3),
    (0xf7, '0f824d0a0000', 2, 6, 0x37051ca),
    (0x105, 'eb8e', 1, 2, 0x3704715),
    (0x19b, '0f83c2000000', 2, 6, 0x37048e3),
    (0x23e, 'e9bb000000', 1, 5, 0x370497e),
    (0x25d, '0f823effffff', 2, 6, 0x3704821),
    (0x26f, '0f84e2080000', 2, 6, 0x37051d7),
    (0x2a6, '7428', 1, 2, 0x3704950),
    (0x2c3, '74db', 1, 2, 0x3704920),
    (0x2cb, '7506', 1, 2, 0x3704953),
    (0x2cd, 'eb18', 1, 2, 0x3704967),
    (0x2d7, '0f827a080000', 2, 6, 0x37051d7),
    (0x2e5, 'eb97', 1, 2, 0x37048fe),
    (0x37c, '0f849e000000', 2, 6, 0x3704aa0),
    (0x390, '747c', 1, 2, 0x3704a8e),
    (0x399, '0f848c070000', 2, 6, 0x37051ab),
    (0x3bd, '75f1', 1, 2, 0x3704a30),
    (0x3c9, '7243', 1, 2, 0x3704a8e),
    (0x40c, '75c2', 1, 2, 0x3704a50),
    (0x416, '7408', 1, 2, 0x3704aa0),
    (0x48a, '7405', 1, 2, 0x3704b11),
    (0x534, '0f8432040000', 2, 6, 0x3704fec),
    (0x587, '0f8432030000', 2, 6, 0x3704f3f),
    (0x5c3, '743b', 1, 2, 0x3704c80),
    (0x5e0, '74de', 1, 2, 0x3704c40),
    (0x5e8, '7436', 1, 2, 0x3704ca0),
    (0x5ee, '731d', 1, 2, 0x3704c8d),
    (0x5f0, 'e9f2020000', 1, 5, 0x3704f67),
    (0x607, '0f82da020000', 2, 6, 0x3704f67),
    (0x615, 'eb8d', 1, 2, 0x3704c24),
    (0x657, '0f84a3000000', 2, 6, 0x3704d80),
    (0x683, '743b', 1, 2, 0x3704d40),
    (0x6a0, '74de', 1, 2, 0x3704d00),
    (0x6a8, '7436', 1, 2, 0x3704d60),
    (0x6ae, '731d', 1, 2, 0x3704d4d),
    (0x6b0, 'e972020000', 1, 5, 0x3704fa7),
    (0x6c7, '0f825a020000', 2, 6, 0x3704fa7),
    (0x6d5, 'eb8f', 1, 2, 0x3704ce6),
    (0x6fc, 'eb19', 1, 2, 0x3704d97),
    (0x753, '0f84b7000000', 2, 6, 0x3704e90),
    (0x783, '743b', 1, 2, 0x3704e40),
    (0x79c, '74e2', 1, 2, 0x3704e00),
    (0x7a4, '743a', 1, 2, 0x3704e60),
    (0x7aa, '7321', 1, 2, 0x3704e4d),
    (0x7ac, 'e997010000', 1, 5, 0x3704fc8),
    (0x7c7, '0f827b010000', 2, 6, 0x3704fc8),
    (0x7d2, 'eb8d', 1, 2, 0x3704de1),
    (0x804, 'eb23', 1, 2, 0x3704ea9),
    (0x865, '750a', 1, 2, 0x3704ef1),
    (0x897, '741b', 1, 2, 0x3704f34),
    (0x8c2, '742c', 1, 2, 0x3704f70),
    (0x8c7, '0f8553fcffff', 2, 6, 0x3704ba0),
    (0x8e2, 'e939fcffff', 1, 5, 0x3704ba0),
    (0x8ed, '75d5', 1, 2, 0x3704f44),
    (0x8f3, '0f8427fcffff', 2, 6, 0x3704ba0),
    (0x922, 'e9f9fbffff', 1, 5, 0x3704ba0),
    (0x943, 'e9cffdffff', 1, 5, 0x3704d97),
    (0x967, 'e9b9feffff', 1, 5, 0x3704ea5),
    (0x9a0, '75ee', 1, 2, 0x3705010),
    (0x9c0, '0f849c000000', 2, 6, 0x37050e2),
    (0x9c9, '7410', 1, 2, 0x370505b),
    (0x9e6, '743d', 1, 2, 0x37050a5),
    (0xa23, 'eb04', 1, 2, 0x37050a9),
    (0xa60, '75ee', 1, 2, 0x37050d0),
    (0xa6d, '0f84a3000000', 2, 6, 0x3705196),
    (0xa76, '7410', 1, 2, 0x3705108),
    (0xa93, '743d', 1, 2, 0x3705152),
    (0xad0, 'eb04', 1, 2, 0x3705156),
    (0xb14, '75ea', 1, 2, 0x3705180),
    (0xb32, '0f8398f8ffff', 2, 6, 0x3704a50),
    (0xb38, 'e9d1f8ffff', 1, 5, 0x3704a8e),
    (0xb71, 'e98a000000', 1, 5, 0x3705280),
    (0xb87, 'e981000000', 1, 5, 0x370528d),
    (0xb92, 'eb1b', 1, 2, 0x370522f),
    (0xba1, 'eb50', 1, 2, 0x3705273),
    (0xba3, 'eb05', 1, 2, 0x370522a),
    (0xba8, 'eb49', 1, 2, 0x3705273),
    (0xbad, 'eb51', 1, 2, 0x3705280),
    (0xbb2, 'eb32', 1, 2, 0x3705266),
    (0xbe4, '75ea', 1, 2, 0x3705250),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x37047c4, 0x3398f50),
    (0x3704868, 0x3398f50),
    (0x3704984, 0x3333920),
    (0x37049a5, 0x33980d0),
    (0x3704aea, 0x3bb2290),
    (0x3704ba8, 0x33b1e80),
    (0x3704bf1, 0x3596940),
    (0x3704cc4, 0x339b590),
    (0x3704da2, 0x33bd420),
    (0x3704edd, 0x33bd620),
    (0x3704f0f, 0x36f7350),
    (0x3704f2f, 0x370e6a0),
    (0x3704f5d, 0x33acfe0),
    (0x3704f9d, 0x339b590),
    (0x3705016, 0x33b1e80),
    (0x3705030, 0x33f7810),
    (0x37050d6, 0x33ae9e0),
    (0x3705186, 0x33ae9e0),
    (0x37051ec, 0x33770f0),
    (0x3705202, 0x33770f0),
    (0x370521c, 0x33f7810),
    (0x3705256, 0x33b1e80),
    (0x370526e, 0x33f7810),
    (0x370527b, 0x3765c40),
    (0x3705288, 0x3765c40),
    (0x3705290, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3705055, 0x576e010),
    (0x3705102, 0x576e010),
    (0x37051c4, 0x576e470),
    (0x37051d1, 0x576e470),
    (0x37051de, 0x576e470),
    (0x37051f6, 0x576e128),
    (0x370520c, 0x576e128),
    (0x3705295, 0x576e128),
    (0x370529b, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37051bd, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x37051ca, 0x56f21d8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 279, 86),
    (0x37051d7, 0x56f21d8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 279, 86),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774b88']
GOT_SITES = {'0x5774b88': ['0x273c030', '0x4d4c48e']}


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

