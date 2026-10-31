#!/usr/bin/env python3
"""Authenticated node94 books-270e6a0 binding (0x270e6a0).

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

START, END = 0x270e6a0, 0x270f1b1
FDE_VA = 0x10edc00
FDE = bytes.fromhex(
    'f0000000d8ff1200980a6201110b0000042f0193ff410e10420e18420e20420e'
    '28420e30410e38470ee00383078c068d058e048f038602712e0002682e0002b9'
    '2e00029d2e0002712e0002bb2e00542e0002982e00027a2e0003a3012e10440e'
    'e8035e0ef003490ee0037b2e0002962e10570ee803450ef003490ee0034c2e00'
    '027d2e0002672e00452e007a2e00672e00540e38410e30420e28420e20420e18'
    '420e10410e08410ee0032e00712e006d2e00752e00712e00712e006e2e006e2e'
    '00672e00502e004f2e00492e00552e00522e00492e004c2e00492e004f2e0062'
    '2e006e2e00522e004f2e00492e004a2e00482e00'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca80100004c8904244889d548897424084889fb'
    '83bfa83100000149bf4b598638d6c56d340f85bc0100004d89cef20f1083b031'
    '0000488d7c24104889ceff15c80806038b4424103b43600f9fc0751a8b442414'
    '3b43640f97c0750e8b436839442418760de97d01000084c00f85750100004889'
    'e849f7e748c1ea0b483b93c80500000f83400900004c8ba3c00500004c69eaf0'
    '02000066c74424104101488d7c2410e83cadc6004889e849f7e748c1ea0b4869'
    'c2102700004889ef4829c74b8b742c704839f70f832a0900004d01ec498b4c24'
    '68488d147f48c1e205488b34244889f048f7d8480f48c648f76411200f80e707'
    '000048b900000000000000804883c1fe4839c80f87d007000080bbf208000002'
    '48b900e40b540200000048ba00e8764817000000480f44d14839d00f82b20000'
    '008b05b1c3060385c00f85b3070000488b4c24088b4110894424200f10010f29'
    '442410488d7424104c89f7e8001014000f57c0f2480f2a0424f20f590547bfaf'
    'fd66480f7ec148b8ffffffffffffff7f4821c1660f57c948baffffffffffffef'
    '7f4839d17f2ef20f10156ac4affd660f2ed07710660f2e0594bfaffd7706660f'
    '28c8eb10f20f5fd0f20f100d80bfaffdf20f5dcaf2480f2cc9660f2e0d47baaf'
    'fd480f47c831c0660f2ec9480f4bc148890424833b017521488b4b08488b5328'
    '0fb6b3f2080000488dbc24800100004531c0e8f9932701eb16660f57c0660f29'
    '842490010000660f298424800100004889e849f7e748c1ea0b483b9378330000'
    '0f83020700004869c2102700004829c54c8ba37033000048899424e80000004c'
    '69ea380100004f8d342c66c74424104101488d7c2410e875abc6004b8d042c48'
    '83c01848894424284c8974243048c74424100000000048c74424180800000048'
    'c74424200000000048895c24384b3b6c2c100f83d30500004d8b6e084c69e5d8'
    '000000488b4424204889842400010000488b44241048898424f0000000488b44'
    '241848898424f8000000488b04244989c649f7de4c0f48f04b8bac25b0000000'
    '4889e849f7e748c1ea0b483b93c80500000f83620600004c69faf00200004c03'
    'bbc005000066c74424104101488d7c2410e8baaac6004d01e5498db580000000'
    '488d7c2410e8e689c8ff488b4c2410488b4424184885c90f94c24885c0400f94'
    'c64008d64889c24821ca4831c848d1e84801d00f94c14008f180f901752348b9'
    '0000000000000080488d410a488984243801000048898c2430010000e97f0200'
    '0031c948833c24000f99c166480f6ec8660f620d2854affd660f5c0d4044affd'
    '660f28c1660f15c1f20f58c1488d050da6affdf20f5904c8ff155a0c0603660f'
    '57c9f20f5fc1660f2e0522baaffd660f57d27416660f2e0574baaffd660f28d0'
    '7608f20f101566baaffdf2480f2cc24889c1660f28c2f20f5c0532bdaffdf248'
    '0f2cd048c1f93f4821ca4809c231c0660f2ed1480f43c2660f2e1539b7affd49'
    'c7c4ffffffff4c0f46e04983fc014983d4004c89ff4889ee4c89e2e890c8bfff'
    '4889c14c89e04809c848c1e8200f84fc0200004c89e031d248f7f148833c2400'
    '780e48ffc048c7c2ffffffff480f44c248f7e10f91c14883f8014883d00084c9'
    '0f84500400008b73608b4b648b53684189f141c1f90d418d79ff4531c04585c9'
    '7f2841b8010000004529c84d69c01f85eb5149c1e82741ffc04569c890010000'
    '4401cf4569c04fc5fdffc1ee0481e6ff0100004401c64469c7b505000041c1f8'
    '024863ff4869ff1f85eb514989f949c1e93f48c1ff254401cf29fec1ff024401'
    'c601fe81c6c506f5ff4863f64869f6805101004801ce89d14869c983de1b4348'
    'c1e9324869d6e80300004801ca31c94885d2480f4fca48833c240048c7442420'
    '0000000048c74424300000000048c74424400000000048c74424480800000066'
    '0f57c0660f1144245048c7442410010000004c8974241848c784248000000001'
    '000000488984249000000048898c249800000066c78424a000000001000f9984'
    '24b2000000488b442408660f1000660f118424c80000008b4010898424d80000'
    '00c68424dc0000000448c78424b8000000000000004883ec08488d8424f80000'
    '00488dbc2438010000488d5424184c89ee31c94989d950e804d1fdff4883c410'
    '8b05d2be060385c00f856f020000488b8424e8000000483b83c80500000f8364'
    '0300004c69e8f00200004c03abc005000066c7442410410140b501488d7c2410'
    '41b701e888a7c6004c8bb4243001000048b800000000000000804939c60f94c1'
    '0f84a1010000880c244c8ba424300100004c8bbc2438010000488b8c24400100'
    '00488bac2448010000488b8424500100004889842428010000488b8424580100'
    '004889442408660f28842480010000660f288c2490010000660f114c2421660f'
    '11442411c644241001498b7d68498b7570488d8424f00000004c8d4424104c89'
    'fa41b901000000506806000600e81e5ffeff4883c4104d85e474124969f43802'
    '00004c89ff31d2ff1543f205034885ed745448c74424180000000048896c2420'
    '488b842428010000488944242848c74424380000000048896c24404889442448'
    'b80100000040b501488b4c2408eb1e4489e031d2f7f148833c24000f8901fdff'
    'ffe90afdffff31c031c940b5014889442410488944243048894c24504531ff48'
    '8dbc2410010000488d742410e84fbf1500488b8424100100004885c074654c8d'
    'bc24100100004c8d6424104c8b2d9ef1050366666666662e0f1f840000000000'
    '488b8c2420010000488d0c49488b74c8084885f67415488d04c84883c008488b'
    '780848c1e60331d241ffd54c89ff4c89e6e8eabe1500488b8424100100004885'
    'c075bd0fb60c24488b8424000100004889442420660f288424f0000000660f29'
    '44241031ed488d7c24104189cf488bb424e80000004889dae813c7deff48b800'
    '000000000000804939c6750d488dbc2430010000e867de06004881c4a8010000'
    '5b415c415d415e415f5dc3488d3d46c5fa02ff1538f50503e964010000488d05'
    '3cbc06034889842410010000488d842410010000488944241040b501488d3d35'
    'bc0603488d0dfeaff5024c8d05dfaff502488d54241041b701be01000000ff15'
    '34f90503e945fdffff488d3de8e9fa02ff15daf4050348c7c0ffffffffe9a4fb'
    'ffff488d05d7bb06034889842430010000488d8424300100004889442410488d'
    '3dd3bb0603488d0d9caff5024c8d057daff502488d542410be01000000ff15d5'
    'f80503e907f8ffff66c74424104101488d3d83d0e7fd488d0d13affd024c8d05'
    '24abfd02488d542410be2b000000ff1534f00503e98800000066c74424104101'
    '488d3d52d0e7fd488d0de2aefd024c8d05abaafd02488d542410be2b000000ff'
    '1503f00503eb5a66c74424104101488d3d24d0e7fd488d0db4aefd024c8d0595'
    'aafd02488d542410be2b000000ff15d5ef0503eb2c66c74424104101488d3df6'
    'cfe7fd488d0d86aefd024c8d054faafd02488d542410be2b000000ff15a7ef05'
    '030f0b488d15fee0fa02ff1518ef05034889c3488d7c2410e8d3a3c600e9e100'
    '0000ff1560f005034889c3488dbc2430010000e8e8ab0600e9a40000004889c3'
    '488d7c2410e8a6a3c60040b50141b701eb36ff1530f005034889c3488d7c2410'
    'e88ba3c600eb7aff151bf005034889c3488d7c2410e876a3c600e984000000ff'
    '1503f005034889c348b80000000000000080483984243001000074334584ff74'
    '3b488dbc2430010000e872ab0600eb2c4889c3eb2c4889c340b50148b8000000'
    '000000008048398424300100007512488dbc2430010000e804dc06004084ed74'
    '22488dbc24f0000000e8a2b00600eb13ff1592ef05034889c3488d7c2410e81d'
    '40dfff4889dfe8650ff502ff1577ef0503'
)
BODY_SHA256 = 'd52ab62e8509a1d76e3944cd8ae493dbc5b875230b314940973fbe97cdcb6777'
BRANCHES = [
    (0x31, '0f85bc010000', 2, 6, 0x270e893),
    (0x5a, '751a', 1, 2, 0x270e716),
    (0x66, '750e', 1, 2, 0x270e716),
    (0x6f, '760d', 1, 2, 0x270e71e),
    (0x71, 'e97d010000', 1, 5, 0x270e893),
    (0x78, '0f8575010000', 2, 6, 0x270e893),
    (0x8f, '0f8340090000', 2, 6, 0x270f075),
    (0xd3, '0f832a090000', 2, 6, 0x270f0a3),
    (0xfc, '0f80e7070000', 2, 6, 0x270ef89),
    (0x113, '0f87d0070000', 2, 6, 0x270ef89),
    (0x13b, '0f82b2000000', 2, 6, 0x270e893),
    (0x149, '0f85b3070000', 2, 6, 0x270efa2),
    (0x1a4, '7f2e', 1, 2, 0x270e874),
    (0x1b2, '7710', 1, 2, 0x270e864),
    (0x1bc, '7706', 1, 2, 0x270e864),
    (0x1c2, 'eb10', 1, 2, 0x270e874),
    (0x1f6, '7521', 1, 2, 0x270e8b9),
    (0x217, 'eb16', 1, 2, 0x270e8cf),
    (0x240, '0f8302070000', 2, 6, 0x270efe8),
    (0x2b2, '0f83d3050000', 2, 6, 0x270ef2b),
    (0x311, '0f8362060000', 2, 6, 0x270f019),
    (0x37c, '7523', 1, 2, 0x270ea41),
    (0x39c, 'e97f020000', 1, 5, 0x270ecc0),
    (0x3f2, '7416', 1, 2, 0x270eaaa),
    (0x400, '7608', 1, 2, 0x270eaaa),
    (0x46d, '0f84fc020000', 2, 6, 0x270ee0f),
    (0x480, '780e', 1, 2, 0x270eb30),
    (0x4a0, '0f8450040000', 2, 6, 0x270ef96),
    (0x4c0, '7f28', 1, 2, 0x270eb8a),
    (0x628, '0f856f020000', 2, 6, 0x270ef3d),
    (0x63d, '0f8364030000', 2, 6, 0x270f047),
    (0x680, '0f84a1010000', 2, 6, 0x270eec7),
    (0x719, '7412', 1, 2, 0x270edcd),
    (0x730, '7454', 1, 2, 0x270ee26),
    (0x76d, 'eb1e', 1, 2, 0x270ee2d),
    (0x77b, '0f8901fdffff', 2, 6, 0x270eb22),
    (0x781, 'e90afdffff', 1, 5, 0x270eb30),
    (0x7bc, '7465', 1, 2, 0x270eec3),
    (0x7f4, '7415', 1, 2, 0x270eeab),
    (0x821, '75bd', 1, 2, 0x270ee80),
    (0x86a, '750d', 1, 2, 0x270ef19),
    (0x898, 'e964010000', 1, 5, 0x270f0a1),
    (0x8e4, 'e945fdffff', 1, 5, 0x270ecce),
    (0x8fd, 'e9a4fbffff', 1, 5, 0x270eb46),
    (0x943, 'e907f8ffff', 1, 5, 0x270e7ef),
    (0x974, 'e988000000', 1, 5, 0x270f0a1),
    (0x9a5, 'eb5a', 1, 2, 0x270f0a1),
    (0x9d3, 'eb2c', 1, 2, 0x270f0a1),
    (0xa1d, 'e9e1000000', 1, 5, 0x270f1a3),
    (0xa38, 'e9a4000000', 1, 5, 0x270f181),
    (0xa50, 'eb36', 1, 2, 0x270f128),
    (0xa65, 'eb7a', 1, 2, 0x270f181),
    (0xa7a, 'e984000000', 1, 5, 0x270f1a3),
    (0xa9a, '7433', 1, 2, 0x270f16f),
    (0xa9f, '743b', 1, 2, 0x270f17c),
    (0xaae, 'eb2c', 1, 2, 0x270f17c),
    (0xab3, 'eb2c', 1, 2, 0x270f181),
    (0xacd, '7512', 1, 2, 0x270f181),
    (0xadf, '7422', 1, 2, 0x270f1a3),
    (0xaee, 'eb13', 1, 2, 0x270f1a3),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x270e74f, 0x3379490),
    (0x270e80b, 0x284f810),
    (0x270e8b2, 0x3987cb0),
    (0x270e916, 0x3379490),
    (0x270e9d1, 0x3379490),
    (0x270e9e5, 0x23973d0),
    (0x270eafb, 0x230b390),
    (0x270ecb7, 0x26ebdc0),
    (0x270ed03, 0x3379490),
    (0x270edad, 0x26f4cd0),
    (0x270ee4c, 0x286ada0),
    (0x270eeb1, 0x286ada0),
    (0x270eef8, 0x24fb610),
    (0x270ef14, 0x277cd80),
    (0x270f0b8, 0x3379490),
    (0x270f0d3, 0x2779cc0),
    (0x270f0e5, 0x3379490),
    (0x270f100, 0x3379490),
    (0x270f115, 0x3379490),
    (0x270f149, 0x2779cc0),
    (0x270f177, 0x277cd80),
    (0x270f189, 0x277a230),
    (0x270f19e, 0x25031c0),
    (0x270f1a6, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x270e6ea, 0x576efb8),
    (0x270ea78, 0x576f6d8),
    (0x270edc7, 0x576e010),
    (0x270ef32, 0x576e470),
    (0x270ef7e, 0x576e8b8),
    (0x270ef90, 0x576e470),
    (0x270efdd, 0x576e8b8),
    (0x270f00e, 0x576e048),
    (0x270f03f, 0x576e048),
    (0x270f06d, 0x576e048),
    (0x270f09b, 0x576e048),
    (0x270f0aa, 0x576dfc8),
    (0x270f0c2, 0x576e128),
    (0x270f0f2, 0x576e128),
    (0x270f107, 0x576e128),
    (0x270f11f, 0x576e128),
    (0x270f190, 0x576e128),
    (0x270f1ab, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x270ef2b, 0x56bb478, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x270ef89, 0x56bd978, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f696d706c5f676c6f62616c2e7273'), 626, 100),
    (0x270f0a3, 0x56bd1a8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x270bb7f, 0x270c49f]
CALLER_FUNCTIONS = {'0x270bb7f': ('0x27078a0', '0x270e698'), '0x270c49f': ('0x27078a0', '0x270e698')}
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

