#!/usr/bin/env python3
"""Authenticated node94 books-26f7ef0 binding (0x26f7ef0).

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

START, END = 0x26f7ef0, 0x26f8a3f
FDE_VA = 0x10ed270
FDE = bytes.fromhex(
    '5000000048f6120078ac60014f0b0000044ffb92ff410e10420e18420e20420e'
    '28420e30410e38470eb00283078c068d058e048f0386020339090e38410e3042'
    '0e28420e20420e18420e10410e08410eb0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecf800000048897424084883bf78330000000f84'
    'c60900004989d74889f8488b9f7033000066c74424204101488d7c2420488984'
    '2490000000e85615c800488b8424900000004883b8c8050000000f84b8090000'
    '4c8bb0c005000066c74424204101488d7c2420e82815c800488b4c24088b4110'
    '89442430f30f6f01660f7f442420488d7424204c89f7ff15d4c607034c89f948'
    '29c10f80d108000031c04885c9480f4fc148898424e80000000f8e8408000048'
    'c78424c80000000000000048c78424d00000000800000048c78424d800000000'
    '000000488b43104885c048899c24f00000000f84800400004c89b424e0000000'
    '4c8b73084869c0d80000004c01f04889442410eb2d4889cb4989ff4885dbbec8'
    '000000490f44f54c89ff31d2ffd566904981c6d80000004c3b7424100f84d303'
    '00004d8bbeb80000004d85ff74e24c893424498baec00000004d8da778030000'
    '410fb7875604000048894424188d0485000000004c8d348048c7c3ffffffff45'
    '31ed66666666662e0f1f8400000000004d39ee744b4b8d342cba14000000488b'
    '7c2408ff15ef63070348984885c00f98c10f9fc028c84983c51448ffc33c0174'
    'cf0fb6c085c074384c8b34244883ed017321e959ffffff660f1f840000000000'
    '488b5c24184c8b34244883ed010f823dffffff4d8bbcdf58040000e959ffffff'
    '4b8b44afd031c94889c24885c0400f95c64c8b342474054b8b54afe04b8b7caf'
    'd84088f148894c242048c744242800000000488944243048897c243848894c24'
    '4048c744244800000000488944245048897c245848895424604c897424684c8d'
    'a424980000004c89e7488d5c24204889dee85ad80e004c8d7c242841bd680000'
    '00488b2d985e0703488b84249800000031c94889c24885c0400f95c67408488b'
    '9424a8000000488bbc24a00000004088f14c8b442408418b701041897758f341'
    '0f6f00f3410f7f474848894c242048c744242800000000488944243048897c24'
    '3848894c244048c744244800000000488944245048897c245848895424604c89'
    '7424684c89b42488000000488dbc24c80000004889dee8e59ce6ff0f1f440000'
    '488b4424604885c00f840201000048ffc84889442460837c2420010f85690600'
    '0048837c2428000f8581000000488b442430488b4c24384885c9745a4889ca48'
    '83e2070f84ad00000031f60f1f440000488b406848ffc64839f275f44889ca48'
    '29f24883f908722e0f1f840000000000488b4068488b4068488b4068488b4068'
    '488b4068488b4068488b4068488b40684883c2f875da48c74424200100000048'
    '89442428660fefc0f3410f7f47084c89e74c89fee817e542ff4883bc24980000'
    '00000f846d050000488b8424a800000049894710f30f6f842498000000f3410f'
    '7f074883bc24b0000000000f850fffffffe91afdffff4889ca4883f9080f836d'
    'ffffffeb9166662e0f1f840000000000f6442420010f84f5fcffff488b7c2428'
    '488b4424304885ff74144889c1488b074885c00f8587000000e9b7fcffff488b'
    '4c24384885c9745e4889ca4883e2070f849500000031f6660f1f840000000000'
    '488b406848ffc64839f275f44889ca4829f24883f908722e0f1f840000000000'
    '488b4068488b4068488b4068488b4068488b4068488b4068488b4068488b4068'
    '4883c2f875da31c94889c7488b074885c00f843efcffff660f1f840000000000'
    '4989c7488d59014885c9bec8000000490f44f531d2ffd5498b074c89ff4889d9'
    '4885c075dbe911fcffff4889ca4883f908738debb1488b8424d0000000488904'
    '244c8bbc24d80000004c8bb424e00000004c89742420488b4424084889442428'
    '488d44242048898424980000004983ff0272314983ff150f83e9040000488d8c'
    '2498000000ba01000000488b3c244c89fee81aec1400eb0cb808000000488904'
    '244531ff488b7c24088b471089442430f30f6f07660f7f442420ff1598ad0703'
    '48c74424180000000084c00f85ed0000004983be40010000000f84df00000049'
    '8dbe48010000488d742420e8e0422a014889c648c1ee39498b8e28010000498b'
    '9630010000660f6ec6660f60c0f20f70c000660f70c044488d71b048c7442418'
    '00000000660f76c931ff4821d0f30f6f1401660f6fda660f74d866440fd7c345'
    '85c07452f3450fbcc84901c14921d149f7d94f8d0c8949c1e104f3420f6f1c0e'
    '660f6e64243066420f6e6c0e10660f745c2420660f74ec660fdbdd66440fd7d3'
    '4181faffff0000742b458d48ff664521c14589c875ae660f74d166440fd7c245'
    '85c0751a4801f84883c0104883c710e976ffffff4a8b4409f8488944241848c7'
    '8424980000000000000048c78424a00000000800000048c78424a80000000000'
    '0000488b8424c800000048894424104d85ff4c8b34240f841a02000041807e20'
    '020f840f0200004b8d04bf4d8d2cc649bf4b598638d6c56d344c89f50f1f4000'
    '488b4d084889c849f7e748c1ea0b4869c2102700004829c1488b8424f0000000'
    '483b48100f833d020000488b55184c69e1d80000004c0360084c89e7488b7424'
    '08488b8c24900000004c8d84249800000041b907000000e8045bfeff488d5d28'
    '84c00f857c0100004c89f849f7a424b000000048c1ea0b488b84249000000048'
    '3b90c80500000f83300200004c69e2f00200004c03a0c005000066c744242041'
    '01488d7c2420e8f50dc800488b7c24088b471089442430f30f6f07660f7f4424'
    '20ff1571ab070384c00f85f10000004983bc244001000000b8000000000f84e6'
    '000000498dbc2448010000488d742420e8bb402a014889c648c1ee39498b8c24'
    '28010000498b942430010000660f6ec6660f60c0f20f70c000660f70c044488d'
    '71b031ff4821d0f30f6f0c01660f6fd1660f74d066440fd7c24585c07452f345'
    '0fbcc84901c14921d149f7d94f8d0c8949c1e104f3420f6f140e660f6e5c2430'
    '66420f6e640e10660f74542420660f74e3660fdbd466440fd7d24181faffff00'
    '007441458d48ff664521c14589c875ae660f76d2660f74ca66440fd7c14585c0'
    '751e4801f84883c0104883c710e972ffffff66666666662e0f1f840000000000'
    '31c0eb054a8b4409f8488b4c24184829c1b800000000480f43c1483b8424e800'
    '000073124c39eb740d807d48024889dd0f850afeffff488b4424104885c07413'
    '48c1e003488d34804c89f731d2ff150d580703488b8424a80000004889442430'
    'f30f6f842498000000660f7f442420488d7c242031f6488b942490000000e8dd'
    '2de0ff4881c4f80000005b415c415d415e415f5dc3488d3ddcccfc02ff151e5c'
    '0703e9dd000000488d3d1a2cfc02ff150c5c0703e9cb0000000f99c10fb6c948'
    'baffffffffffffff7f4801ca4929c7488d3532ebfc024c0f40fa31ffff15fea8'
    '07034c89f9e9fef6ffff488d3dcfccfc02ff15c95b0703e98800000066c74424'
    '204101488d3dbf37e9fd488d0d4f16ff024c8d051812ff02488d542420be2b00'
    '0000ff1570570703eb5a66c74424204101488d3d9137e9fd488d0d2116ff024c'
    '8d053212ff02488d542420be2b000000ff1542570703eb2c66c7442420410148'
    '8d3d6337e9fd488d0df315ff024c8d05bc11ff02488d542420be2b000000ff15'
    '145707030f0b488d942498000000488b3c244c89feff1585bf0703e924fbffff'
    'e97d0000004889c3488d7c2420e82e0bc800e9c8000000ff15bb5707034889c3'
    '488d7c2420e8160bc800e9b0000000ff15a35707034889c3488d7c2420e8fe0a'
    'c8004c8b3424eb6dff158a570703eb624889c34c8db424980000004c8d7c2420'
    '4c89f74c89fee8652b17004883bc24980000000075eaeb0dff155a570703eb02'
    '0f0b4889c3488b8424c80000004885c0744d488bbc24d000000048c1e003488d'
    '348031d2ff15165607034889dfe80e77f6024889c3488b4424104885c0741348'
    'c1e003488d34804c89f731d2ff15ee550703488dbc2498000000e80118080048'
    '89dfe8d976f602ff15eb5607030f0b'
)
BODY_SHA256 = '00d5dd9695e7d180fbca07c03eee42b7871ba876a263e800ca0b80cd0e46d789'
BRANCHES = [
    (0x1e, '0f84c6090000', 2, 6, 0x26f88da),
    (0x5a, '0f84b8090000', 2, 6, 0x26f8908),
    (0xa2, '0f80d1080000', 2, 6, 0x26f8869),
    (0xb9, '0f8e84080000', 2, 6, 0x26f8833),
    (0xf2, '0f8480040000', 2, 6, 0x26f8468),
    (0x113, 'eb2d', 1, 2, 0x26f8032),
    (0x13c, '0f84d3030000', 2, 6, 0x26f8405),
    (0x14c, '74e2', 1, 2, 0x26f8020),
    (0x193, '744b', 1, 2, 0x26f80d0),
    (0x1bf, '74cf', 1, 2, 0x26f8080),
    (0x1c6, '7438', 1, 2, 0x26f80f0),
    (0x1d0, '7321', 1, 2, 0x26f80e3),
    (0x1d2, 'e959ffffff', 1, 5, 0x26f8020),
    (0x1ed, '0f823dffffff', 2, 6, 0x26f8020),
    (0x1fb, 'e959ffffff', 1, 5, 0x26f8049),
    (0x215, '7405', 1, 2, 0x26f810c),
    (0x29c, '7408', 1, 2, 0x26f8196),
    (0x328, '0f8402010000', 2, 6, 0x26f8320),
    (0x33b, '0f8569060000', 2, 6, 0x26f889a),
    (0x347, '0f8581000000', 2, 6, 0x26f82be),
    (0x35a, '745a', 1, 2, 0x26f82a6),
    (0x363, '0f84ad000000', 2, 6, 0x26f8306),
    (0x37a, '75f4', 1, 2, 0x26f8260),
    (0x386, '722e', 1, 2, 0x26f82a6),
    (0x3b4, '75da', 1, 2, 0x26f8280),
    (0x3e2, '0f846d050000', 2, 6, 0x26f8845),
    (0x40b, '0f850fffffff', 2, 6, 0x26f8210),
    (0x411, 'e91afdffff', 1, 5, 0x26f8020),
    (0x41d, '0f836dffffff', 2, 6, 0x26f8280),
    (0x423, 'eb91', 1, 2, 0x26f82a6),
    (0x435, '0f84f5fcffff', 2, 6, 0x26f8020),
    (0x448, '7414', 1, 2, 0x26f834e),
    (0x453, '0f8587000000', 2, 6, 0x26f83d0),
    (0x459, 'e9b7fcffff', 1, 5, 0x26f8005),
    (0x466, '745e', 1, 2, 0x26f83b6),
    (0x46f, '0f8495000000', 2, 6, 0x26f83fa),
    (0x48a, '75f4', 1, 2, 0x26f8370),
    (0x496, '722e', 1, 2, 0x26f83b6),
    (0x4c4, '75da', 1, 2, 0x26f8390),
    (0x4d1, '0f843efcffff', 2, 6, 0x26f8005),
    (0x503, '75db', 1, 2, 0x26f83d0),
    (0x505, 'e911fcffff', 1, 5, 0x26f800b),
    (0x511, '738d', 1, 2, 0x26f8390),
    (0x513, 'ebb1', 1, 2, 0x26f83b6),
    (0x551, '7231', 1, 2, 0x26f8474),
    (0x557, '0f83e9040000', 2, 6, 0x26f8936),
    (0x576, 'eb0c', 1, 2, 0x26f8474),
    (0x5ab, '0f85ed000000', 2, 6, 0x26f858e),
    (0x5b9, '0f84df000000', 2, 6, 0x26f858e),
    (0x622, '7452', 1, 2, 0x26f8566),
    (0x667, '742b', 1, 2, 0x26f8584),
    (0x674, '75ae', 1, 2, 0x26f8514),
    (0x682, '751a', 1, 2, 0x26f858e),
    (0x68f, 'e976ffffff', 1, 5, 0x26f84fa),
    (0x6d6, '0f841a020000', 2, 6, 0x26f87e6),
    (0x6e1, '0f840f020000', 2, 6, 0x26f87e6),
    (0x724, '0f833d020000', 2, 6, 0x26f8857),
    (0x762, '0f857c010000', 2, 6, 0x26f87d4),
    (0x786, '0f8330020000', 2, 6, 0x26f88ac),
    (0x7c9, '0f85f1000000', 2, 6, 0x26f87b0),
    (0x7dd, '0f84e6000000', 2, 6, 0x26f87b9),
    (0x83c, '7452', 1, 2, 0x26f8780),
    (0x881, '7441', 1, 2, 0x26f87b4),
    (0x88e, '75ae', 1, 2, 0x26f872e),
    (0x8a0, '751e', 1, 2, 0x26f87b0),
    (0x8ad, 'e972ffffff', 1, 5, 0x26f8714),
    (0x8c2, 'eb05', 1, 2, 0x26f87b9),
    (0x8e2, '7312', 1, 2, 0x26f87e6),
    (0x8e7, '740d', 1, 2, 0x26f87e6),
    (0x8f0, '0f850afeffff', 2, 6, 0x26f85f0),
    (0x8fe, '7413', 1, 2, 0x26f8803),
    (0x962, 'e9dd000000', 1, 5, 0x26f8934),
    (0x974, 'e9cb000000', 1, 5, 0x26f8934),
    (0x9a5, 'e9fef6ffff', 1, 5, 0x26f7f98),
    (0x9b7, 'e988000000', 1, 5, 0x26f8934),
    (0x9e8, 'eb5a', 1, 2, 0x26f8934),
    (0xa16, 'eb2c', 1, 2, 0x26f8934),
    (0xa5b, 'e924fbffff', 1, 5, 0x26f8474),
    (0xa60, 'e97d000000', 1, 5, 0x26f89d2),
    (0xa72, 'e9c8000000', 1, 5, 0x26f8a2f),
    (0xa8a, 'e9b0000000', 1, 5, 0x26f8a2f),
    (0xaa6, 'eb6d', 1, 2, 0x26f8a05),
    (0xaae, 'eb62', 1, 2, 0x26f8a02),
    (0xad4, '75ea', 1, 2, 0x26f89b0),
    (0xad6, 'eb0d', 1, 2, 0x26f89d5),
    (0xade, 'eb02', 1, 2, 0x26f89d2),
    (0xaf0, '744d', 1, 2, 0x26f8a2f),
    (0xb1d, '7413', 1, 2, 0x26f8a22),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26f7f35, 0x3379490),
    (0x26f7f63, 0x3379490),
    (0x26f8161, 0x27e59c0),
    (0x26f8206, 0x2561ef0),
    (0x26f82c4, 0x1b267e0),
    (0x26f8461, 0x2847080),
    (0x26f84bb, 0x399c7a0),
    (0x26f8647, 0x26de150),
    (0x26f8696, 0x3379490),
    (0x26f86e0, 0x399c7a0),
    (0x26f882e, 0x24fb610),
    (0x26f895d, 0x3379490),
    (0x26f8975, 0x3379490),
    (0x26f898d, 0x3379490),
    (0x26f89b6, 0x286b520),
    (0x26f89fd, 0x5660110),
    (0x26f8a2a, 0x277a230),
    (0x26f8a32, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26f7f86, 0x5774660),
    (0x26f8093, 0x576e488),
    (0x26f848a, 0x5773228),
    (0x26f86b1, 0x5773228),
    (0x26f87fd, 0x576e010),
    (0x26f884c, 0x576e470),
    (0x26f885e, 0x576e470),
    (0x26f888c, 0x5773190),
    (0x26f88a1, 0x576e470),
    (0x26f88d2, 0x576e048),
    (0x26f8900, 0x576e048),
    (0x26f892e, 0x576e048),
    (0x26f8945, 0x57748d0),
    (0x26f8967, 0x576e128),
    (0x26f897f, 0x576e128),
    (0x26f8998, 0x576e128),
    (0x26f89c8, 0x576e128),
    (0x26f89f4, 0x576e010),
    (0x26f8a1c, 0x576e010),
    (0x26f8a37, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26f8845, 0x56c5528, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 600, 48),
    (0x26f8857, 0x56bb478, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x26f889a, 0x56c5570, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 198, 39),
]
CALLERS = [0x2736a7d]
CALLER_FUNCTIONS = {'0x2736a7d': ('0x27362b0', '0x27371ee')}
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

