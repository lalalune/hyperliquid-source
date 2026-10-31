#!/usr/bin/env python3
"""Authenticated node94 spot-meta-3baedf0 binding (0x3baedf0).

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

START, END = 0x3baedf0, 0x3baf8a7
FDE_VA = 0x11e063c
FDE = bytes.fromhex(
    '50000000142a2200ace79c02b70a0000041f0f90ff410e10420e18420e20420e'
    '28420e30410e38470ef00283078c068d058e048f03860203f1090e38410e3042'
    '0e28420e20420e18420e10410e08410ef0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec380100004989f7833e024889bc24a00000000f'
    '846c08000066662e0f1f8400000000004c89ffe8182376ff4885c00f84490800'
    '00807a2c0175e9498b4f484c8b204c3b61100f83d0090000488b41084969cce8'
    '00000080bc08d20000000074c34801c80fb688d3000000884c24108b88db0000'
    '00894c2437488b88d400000048894c24304c8bb0df000000488b1a48d1eb4883'
    'c2084989d531edbfc0000000ff1536f1bb014885c00f84110900004989c04c89'
    '284c896008488958100fb644241041884018488b442430498940198b44243741'
    '8940204d8970244188682c48c7442468040000004c8944247048c74424780100'
    '0000498b37498b6f08498b4f10498b47184889442418498b4740488944242049'
    '8b474848898424b0000000498b475048894424584d8b77584d8b6f60498b4768'
    '4889442410498b87900000004889442428498b87980000004889442460498b87'
    'a000000048898424b8000000b80100000048894424504883fe020f84d5020000'
    '4c8b5c24204d85db4c8b4c24104c8b5424580f84370200004889c8eb1e0f1f00'
    '40b601b800000000b900000000ba000000004d85db0f84a902000040f6c6010f'
    '84b50800004885ed7426488b5424180fb78d720200004839ca0f83c100000048'
    '89eb4889d1e9dc000000660f1f440000488b7424184885f674384889f14889c5'
    '4883e107743131d20f1f840000000000488bad7802000048ffc24839d175f148'
    '8b7424184889f04829d04883fe087310eb4c4889c5eb474889f04883fe08723e'
    '488b8d78020000488b8978020000488b8978020000488b8978020000488b8978'
    '020000488b8978020000488b8978020000488ba9780200004883c0f875c231d2'
    '31c00fb78d720200004839ca0f824dffffff66666666662e0f1f840000000000'
    '488b9d100200004885db0f84b207000048ffc00fb78d700200004889dd663b8b'
    '7202000073da4885c00f8491000000488d14cb4881c2800200004889c64883e6'
    '070f84d900000031ff0f1f8000000000488b2a488d957802000048ffc74839fe'
    '75ee4889c64829fe4883f80872436690488b02488b8078020000488b80780200'
    '00488b8078020000488b8078020000488b8078020000488b8078020000488ba8'
    '78020000488d95780200004883c6f875bf48c744241800000000eb100f1f4000'
    '488d410148894424184889dd49ffcb488d144948c1e204807c132c010f851efe'
    'ffff4c8ba4cb18020000488b8424b00000004c3b60100f83a8060000488b4008'
    '4969cce800000080bc08d2000000000f84ebfdffffeb1f660f1f840000000000'
    '4889c64883f8080f8343ffffffeb8231d2e98e0000004c895c24204801d34801'
    'c80fb688d3000000884c240f488b88df00000048898c24880000004c8b3b49d1'
    'ef4883c3088b88db000000894c2447488b80d40000004889442440b801000000'
    '488984249000000048c78424980000000000000048c784248000000000000000'
    '488b742450483b7424680f8498030000e9b2030000488b5424204c8b4c24104c'
    '8b54245848895424204c898424a80000004983fa02488b7c24284c8b4424600f'
    '84880500004885ff0f847f05000048898c2498000000eb290f1f840000000000'
    '488b7c24284c8b44246041b20141bd000000004885ff4c8b4c24100f844c0500'
    '0041f6c2010f84a60500004d85f67420410fb786da0400004939c10f83bf0000'
    '004c89f34c89c8e9d70000000f1f40004d85c974384c89c84d89ee4883e00774'
    '3131c9666666662e0f1f8400000000004d8bb6e004000048ffc14839c875f14c'
    '89c84829c84983f9087315eb514d89eeeb4c4c89c84983f90872430f1f440000'
    '498b8ee0040000488b89e0040000488b89e0040000488b89e0040000488b89e0'
    '040000488b89e0040000488b89e00400004c8bb1e00400004883c0f875c24531'
    'c94531ed410fb786da0400004939c10f824cffffff66662e0f1f840000000000'
    '498b1e4885db0f84a704000049ffc5410fb786d80400004989de663b83da0400'
    '0073dd4d85ed0f84a4000000488d0cc34881c1e80400004c89ea4883e2070f84'
    '8c01000031f6662e0f1f8400000000004c8b31498d8ee004000048ffc64839f2'
    '75ee4c89ea4829f24983fd0872436690488b09488b89e0040000488b89e00400'
    '00488b89e0040000488b89e0040000488b89e0040000488b89e00400004c8bb1'
    'e0040000498d8ee00400004883c2f875bf31c94c8b64c3084d3b60107228e9d2'
    '030000666666662e0f1f840000000000488d48014989de4c8b64c3084d3b6010'
    '0f83af03000048894c241048ffcf498b48084969d4e800000080bc11bc000000'
    '010f8503feffff48897c24284c6be8684a8d042b4805a00000004801d1440fb6'
    'b9d10000008b4824488d942410010000894a100f1040140f11028b4810894a24'
    '0f10000f114214488b8424b80000004889842408010000488dbc24e000000048'
    '8db42408010000ff15a351bc0183bc24e0000000010f8585fdffff488d8424e8'
    '0000000f10000f1048100f298c24d00000000f298424c0000000410fb6f74c89'
    'e7488d9424c0000000e832226dffa801488b7c24284c8b4424600f844afdffff'
    'eb2066666666662e0f1f8400000000004c89ea4983fd080f82d4feffffe98efe'
    'ffff4989d74c01eb4883c3604c89e0480fc84889842488000000c74424470000'
    '000048c744244000000000b0014889842480000000c644240f50b80200000048'
    '89842490000000b80100000048894424584531ed4c8b8424a8000000488b7424'
    '50483b742468751fba01000000b90800000041b830000000488d7c2468e80e74'
    '72ff4c8b442470488b442450488d044048c1e00449891c004d896400084d897c'
    '00100fb64c240f41884c0018488b4c244049894c00198b4c244741894c002048'
    '8b8c248800000049894c0024488b8c248000000041884c002c488b44245048ff'
    'c04889442478488b8c2498000000488bb4249000000048894424504883fe020f'
    '85fbf8ffffe9cbfbffff49c7070200000041837f50020f84400100004d8d7750'
    '4c89f7e8a81876ff4885c00f842b010000488dac2410010000eb160f1f440000'
    '4c89f7e8881876ff4885c00f840b010000498b8f980000004c8b204c3b61100f'
    '8343010000488b41084969cce800000080bc08bc0000000175c6498bb7a00000'
    '00488d7a404989d54883c2544801c80fb698d10000008b42108945100f10020f'
    '1145008b47108945240f10070f1145144889b42408010000488dbc24e0000000'
    '488db42408010000ff15624fbc0183bc24e0000000010f8564ffffff488d8424'
    'e80000000f10000f1048100f298c24d00000000f298424c00000000fb6f34c89'
    'e7488d9424c0000000e8f21f6dffa8010f842affffff4889d34d89e6490fcec7'
    '4424370000000048c74424300000000040b501c644241050bfc0000000ff1525'
    'e8bb014885c00f85eff6ffffbf08000000bec0000000ff15ece7bb01488b8424'
    'a000000048c7000000000048c740080800000048c74010000000004881c43801'
    '00005b415c415d415e415f5dc3488b4c2478488b8424a0000000488948100f10'
    '4424680f1100ebd3488d3dd129b401ff154becbb01488d3dc429b401ff153eec'
    'bb01eb2b488d3db529b401ff152fecbb01eb1c488d3dcea7b301ff1520ecbb01'
    'eb0d488d3dbfa7b301ff1511ecbb010f0b488d3de0a7b301ebc2488d3dd7a7b3'
    '01ebc8eb08eb060f0b0f0beb004889c3488b4424684885c07415488b7c247048'
    'c1e004488d344031d2ff1571e7bb014889dfe86908ab01'
)
BODY_SHA256 = 'e038fa4b0baf74f0b202bab055587392f6d920bfc47a3ad84bfb9807dd94bc91'
BRANCHES = [
    (0x1f, '0f846c080000', 2, 6, 0x3baf681),
    (0x3b, '0f8449080000', 2, 6, 0x3baf67a),
    (0x45, '75e9', 1, 2, 0x3baee20),
    (0x52, '0f83d0090000', 2, 6, 0x3baf818),
    (0x6b, '74c3', 1, 2, 0x3baee20),
    (0xb5, '0f8411090000', 2, 6, 0x3baf7bc),
    (0x17a, '0f84d5020000', 2, 6, 0x3baf245),
    (0x192, '0f8437020000', 2, 6, 0x3baf1bf),
    (0x19b, 'eb1e', 1, 2, 0x3baefab),
    (0x1b5, '0f84a9020000', 2, 6, 0x3baf254),
    (0x1bf, '0f84b5080000', 2, 6, 0x3baf86a),
    (0x1c8, '7426', 1, 2, 0x3baefe0),
    (0x1d9, '0f83c1000000', 2, 6, 0x3baf090),
    (0x1e5, 'e9dc000000', 1, 5, 0x3baf0b6),
    (0x1f8, '7438', 1, 2, 0x3baf022),
    (0x204, '7431', 1, 2, 0x3baf027),
    (0x21d, '75f1', 1, 2, 0x3baf000),
    (0x22e, '7310', 1, 2, 0x3baf030),
    (0x230, 'eb4c', 1, 2, 0x3baf06e),
    (0x235, 'eb47', 1, 2, 0x3baf06e),
    (0x23e, '723e', 1, 2, 0x3baf06e),
    (0x27c, '75c2', 1, 2, 0x3baf030),
    (0x28c, '0f824dffffff', 2, 6, 0x3baefcf),
    (0x2aa, '0f84b2070000', 2, 6, 0x3baf852),
    (0x2c4, '73da', 1, 2, 0x3baf090),
    (0x2c9, '0f8491000000', 2, 6, 0x3baf150),
    (0x2e1, '0f84d9000000', 2, 6, 0x3baf1b0),
    (0x300, '75ee', 1, 2, 0x3baf0e0),
    (0x30c, '7243', 1, 2, 0x3baf141),
    (0x34f, '75bf', 1, 2, 0x3baf100),
    (0x35a, 'eb10', 1, 2, 0x3baf15c),
    (0x37c, '0f851efeffff', 2, 6, 0x3baef90),
    (0x396, '0f83a8060000', 2, 6, 0x3baf834),
    (0x3af, '0f84ebfdffff', 2, 6, 0x3baef90),
    (0x3b5, 'eb1f', 1, 2, 0x3baf1c6),
    (0x3c7, '0f8343ffffff', 2, 6, 0x3baf100),
    (0x3cd, 'eb82', 1, 2, 0x3baf141),
    (0x3d1, 'e98e000000', 1, 5, 0x3baf254),
    (0x44a, '0f8498030000', 2, 6, 0x3baf5d8),
    (0x450, 'e9b2030000', 1, 5, 0x3baf5f7),
    (0x47f, '0f8488050000', 2, 6, 0x3baf7fd),
    (0x488, '0f847f050000', 2, 6, 0x3baf7fd),
    (0x496, 'eb29', 1, 2, 0x3baf2b1),
    (0x4bb, '0f844c050000', 2, 6, 0x3baf7fd),
    (0x4c5, '0f84a6050000', 2, 6, 0x3baf861),
    (0x4ce, '7420', 1, 2, 0x3baf2e0),
    (0x4db, '0f83bf000000', 2, 6, 0x3baf390),
    (0x4e7, 'e9d7000000', 1, 5, 0x3baf3b3),
    (0x4f3, '7438', 1, 2, 0x3baf31d),
    (0x4ff, '7431', 1, 2, 0x3baf322),
    (0x51d, '75f1', 1, 2, 0x3baf300),
    (0x529, '7315', 1, 2, 0x3baf330),
    (0x52b, 'eb51', 1, 2, 0x3baf36e),
    (0x530, 'eb4c', 1, 2, 0x3baf36e),
    (0x539, '7243', 1, 2, 0x3baf36e),
    (0x57c, '75c2', 1, 2, 0x3baf330),
    (0x58f, '0f824cffffff', 2, 6, 0x3baf2d1),
    (0x5a6, '0f84a7040000', 2, 6, 0x3baf843),
    (0x5c1, '73dd', 1, 2, 0x3baf390),
    (0x5c6, '0f84a4000000', 2, 6, 0x3baf460),
    (0x5de, '0f848c010000', 2, 6, 0x3baf560),
    (0x600, '75ee', 1, 2, 0x3baf3e0),
    (0x60c, '7243', 1, 2, 0x3baf441),
    (0x64f, '75bf', 1, 2, 0x3baf400),
    (0x65c, '7228', 1, 2, 0x3baf476),
    (0x65e, 'e9d2030000', 1, 5, 0x3baf825),
    (0x680, '0f83af030000', 2, 6, 0x3baf825),
    (0x6a1, '0f8503feffff', 2, 6, 0x3baf29a),
    (0x715, '0f8585fdffff', 2, 6, 0x3baf290),
    (0x75a, '0f844afdffff', 2, 6, 0x3baf29a),
    (0x760, 'eb20', 1, 2, 0x3baf572),
    (0x777, '0f82d4feffff', 2, 6, 0x3baf441),
    (0x77d, 'e98efeffff', 1, 5, 0x3baf400),
    (0x7e6, '751f', 1, 2, 0x3baf5f7),
    (0x87f, '0f85fbf8ffff', 2, 6, 0x3baef70),
    (0x885, 'e9cbfbffff', 1, 5, 0x3baf245),
    (0x896, '0f8440010000', 2, 6, 0x3baf7cc),
    (0x8ab, '0f842b010000', 2, 6, 0x3baf7cc),
    (0x8b9, 'eb16', 1, 2, 0x3baf6c1),
    (0x8cb, '0f840b010000', 2, 6, 0x3baf7cc),
    (0x8df, '0f8343010000', 2, 6, 0x3baf818),
    (0x8f8, '75c6', 1, 2, 0x3baf6b0),
    (0x956, '0f8564ffffff', 2, 6, 0x3baf6b0),
    (0x990, '0f842affffff', 2, 6, 0x3baf6b0),
    (0x9c6, '0f85eff6ffff', 2, 6, 0x3baeeab),
    (0xa26, 'ebd3', 1, 2, 0x3baf7eb),
    (0xa42, 'eb2b', 1, 2, 0x3baf85f),
    (0xa51, 'eb1c', 1, 2, 0x3baf85f),
    (0xa60, 'eb0d', 1, 2, 0x3baf85f),
    (0xa78, 'ebc2', 1, 2, 0x3baf82c),
    (0xa81, 'ebc8', 1, 2, 0x3baf83b),
    (0xa83, 'eb08', 1, 2, 0x3baf87d),
    (0xa85, 'eb06', 1, 2, 0x3baf87d),
    (0xa8b, 'eb00', 1, 2, 0x3baf87d),
    (0xa98, '7415', 1, 2, 0x3baf89f),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3baee23, 0x3311140),
    (0x3baf539, 0x3281770),
    (0x3baf5ed, 0x32d6a00),
    (0x3baf693, 0x3310f40),
    (0x3baf6b3, 0x3310f40),
    (0x3baf779, 0x3281770),
    (0x3baf8a2, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3baee9c, 0x576dfd8),
    (0x3baf4f7, 0x57746a0),
    (0x3baf738, 0x57746a0),
    (0x3baf7ad, 0x576dfd8),
    (0x3baf7c6, 0x576dfb8),
    (0x3baf81f, 0x576e470),
    (0x3baf82c, 0x576e470),
    (0x3baf83b, 0x576e470),
    (0x3baf84a, 0x576e470),
    (0x3baf859, 0x576e470),
    (0x3baf899, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3baf818, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x3baf825, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x3baf834, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x3baf843, 0x56ea018, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 560, 47),
    (0x3baf852, 0x56ea018, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 560, 47),
]
CALLERS = [0x2763966, 0x2763ad2, 0x4d919c6, 0x4d91b32, 0x4d946f6, 0x4d94862]
CALLER_FUNCTIONS = {'0x2763966': ('0x2761b20', '0x27649f6'), '0x2763ad2': ('0x2761b20', '0x27649f6'), '0x4d919c6': ('0x4d8fce0', '0x4d92a0e'), '0x4d91b32': ('0x4d8fce0', '0x4d92a0e'), '0x4d946f6': ('0x4d92a10', '0x4d956ce'), '0x4d94862': ('0x4d92a10', '0x4d956ce')}
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

