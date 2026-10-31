#!/usr/bin/env python3
"""Authenticated node94 hyperliquidity-3261c40 binding (0x3261c40).

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

START, END = 0x3261c40, 0x3262583
FDE_VA = 0x115b7d8
FDE = bytes.fromhex(
    '50000000b0db190060641002430900000437e191ff410e10420e18420e20420e'
    '28420e30410e38470eb00283078c068d058e048f038602030c010e38410e3042'
    '0e28420e20420e18420e10410e08410eb0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecf80000004c8b32488b5a084c8b62104c89a424'
    'c80000004c8b6a18488b422048898424d00000004981fda00f000076114c8d35'
    '692c32fdbd1e000000e9ac0000004d89e94929c17311bd220000004c8d35292c'
    '32fde9930000004c894c24304c8b7a28488b46104885c00f84ab000000488b56'
    '18440fb790c20100004589d341c1e30349c7c1ffffffff660f1f840000000000'
    '4d85db74284a3b9cc870010000400f97c54080dd0049ffc14983c3f84080fd01'
    '74de440fb6d54585d27415eb034d89d14883ea0172524a8b84c8c8010000eba1'
    '8b05728e5102bd1d0000004c8d35642932fd85c00f85d50400000f288424e000'
    '00000f11471866c707df004c89770848896f104889f84881c4f80000005b415c'
    '415d415e415f5dc34c89bc24c00000004c897424584c89442420488974242848'
    '893c24488bb1800100004839f30f8373070000488b81780100004889da48c1e2'
    '054c8b3c10488b44100848894424184c89bc24d8000000660f76c0660f7f4424'
    '60c7442470ffffffff488d74246048894c24104889cfff15941351024c8b4010'
    'b1014d85c00f848c0000004c8b4818488b3c24488b742428488b442420450fb7'
    '986a010000428d14dd000000004c8d345249c7c2ffffffff31ed660f1f440000'
    '4939ee74204f3b7cd0100f97c280da004883c51849ffc280fa0174e40fb6d285'
    'd27419eb034d89da4983e9010f82c90000004f8b84d070010000eba14d8b4c28'
    '4849837c2850000f94c14c89ca4c09ea7522e9b30000004531c9488b3c24488b'
    '742428488b4424204c89ca4c09ea0f849600000084c9742348837c241800742c'
    'ff15e2d55002bd2b0000004c8d35c92932fd488b3c24e97ffeffffbd25000000'
    '4c8d35df2932fde96efeffff4c894c2418488b442410488db888030000488db4'
    '24d8000000e8a62813004885c074184983fd0a0f83c2000000bd1d0000004c8d'
    '35382932fdebabff157bd55002bd210000004c8d35412932fdeb974531c94c89'
    'ca4c09ea0f856affffff49be00000000000000804531ff8b0d5b8c510285c90f'
    '85410500004883c610488b4c2458488948784c897424604c896c24680f288424'
    'e00000000f11442470488d7c2438488d4c24604889dae8054c1400488b442438'
    '48b902000000000000804839c87c1a4885c07415488b7c244048c1e003488d34'
    '4031d2ff1567c05002488b3c244c897f0866c7078601e998fdffff488b4c2410'
    '4883c11048894c24084489e983e1074489ea81e2f80f0000f20f10055087fafc'
    'f20f100d5088fafcf20f59c1f20f59c1f20f59c1f20f59c1f20f59c1f20f59c1'
    'f20f59c1f20f59c14883c2f875da4885c948898424b80000007409f20f59c148'
    'ffc975f7ff159e27510266480f7ec048b9ffffffffffffff7f4821c1660f57c9'
    '48b8ffffffffffffef7f660f57d24839c17f28660f57db660f2ed8770e660f2e'
    '05ab84fafc660f28d07610f20f5fd8f20f10159984fafcf20f5dd3f2480f2cc2'
    '4889c1660f28c2f20f5c056187fafcf2480f2cd048c1f93f4821ca4809c231c0'
    '660f2ed1480f43c2660f2e156881fafc48c7c1ffffffff480f46c84c89e049f7'
    'e5bd240000004c8d354c2732fd488b3c240f8063fcffff48be99999999999999'
    '194839f00f8750fcffff4881f940420f000f8743fcffff488b44245848f7e148'
    '89c10f90c04839f10f97c208c20f8527fcffff4c89e048f7e10f90c14839f00f'
    '97c008c80f8510fcffff4d85e40f84a8000000488b44243049f7e40f80e40300'
    '004989c6488b7c24084c89fe4c89f2ff1513265102a8010f848f000000483b54'
    '24180f8584000000488d7c24384889de488b5424584c89e14d89e84c8b4c2408'
    'e83b180000488b7424484885f60f849e0300004c8b6c2440498b4d104889c849'
    'f7e40f90c2f6d2483d40420f000f92c084c20f852a020000488d0476498b44c5'
    'f84839c10f858e0000004c8d35fd2532fdbd27000000e9130200004c8d35d124'
    '32fdbd1e000000e94efbffffff1596d25002488b7c24084c89fe4c89f2ff1565'
    '2551024c8d35eb2532fde9a3fcffff488d056a8951024889442438488d442438'
    '4889442460488d056c895102488d0d357d40024c8d05167d4002488d54246048'
    '89fb4889c7be01000000ff1568c650024889dfe9e2faffff488944247048c744'
    '247800ca9a3b48b800e8764817000000488984248000000048898c2488000000'
    '48c78424900000000000000048c784249800000080969800488b442410488b88'
    '90010000488b809801000048898424b00000004969c7e80000004801c84883c0'
    '3048898424a800000048c7442430000000004c8d355f2432fd31c0eb17b80100'
    '0000f644243001b10148894c24300f8520010000488d0440488d4c24704c8b24'
    'c14d85e40f840a010000bd1f00000048b90080c6a47e8d03004939cc0f87cc00'
    '0000488d4c2470488d04c1488b480848894c2410488b40104889442418488b7c'
    '24084889de4c89e2e8031049004889c14c09e048c1e820740a4c89e031d248f7'
    'f1eb074489e031d2f7f14885d2488b8424b80000007577488b384c89fe4c89e2'
    '488b4c2408e836f10100a8017417488b7c2410488b742418e86302000084c00f'
    '8538ffffff4c3bbc24b00000000f8363010000bd77000000488b8424a8000000'
    '48837810047512488b40088b003b05417afafc0f8404ffffff4c8d35772332fd'
    'eb0c4c8d35e82232fdbd3b000000488b4424384885c00f84b6faffff48c1e003'
    '488d34404c89ef31d2ff1501bc5002e99efaffff488d4424384889442460488d'
    '8424d00000004889442468488d8424c80000004889442470488d7c2460e84e01'
    '0000a8010f84860000004989d7483b9424c000000077794c8b742438488d4424'
    '48f30f6f00660f7f8424e0000000488b742428488b4424208b0d1a87510285c9'
    '0f84bffaffff488d05f38651024889442438488d4424384889442460488d3df5'
    '865102488d0dbe7a40024c8d059f7a4002488d542460be01000000ff15f7c350'
    '02488b742428488b442420e975faffffff15b2cf5002488b4424384885c07415'
    '488b7c244048c1e003488d344031d2ff151bbb5002bd2c0000004c8d350b2232'
    'fde9acf9ffff488d151bd347024889dfff15b2ba5002488d3dd3fc4802ff154d'
    'bf5002eb1949c7c6ffffffffe913fcffff488d3d28d34702ff1532bf50020f0b'
    '4889c34a8d0475000000004885c0742beb16eb02eb004889c34c8b7424384d85'
    'f674184c8b6c244049c1e6034b8d34764c89ef31d2ff1595ba50024889dfe88d'
    'db3f02'
)
BODY_SHA256 = '08c46c91618aeed2a5e35413d93e4ccf0c1fccd1ee51dae5765eb917ca22843f'
BRANCHES = [
    (0x3b, '7611', 1, 2, 0x3261c8e),
    (0x49, 'e9ac000000', 1, 5, 0x3261d3a),
    (0x54, '7311', 1, 2, 0x3261ca7),
    (0x62, 'e993000000', 1, 5, 0x3261d3a),
    (0x77, '0f84ab000000', 2, 6, 0x3261d68),
    (0xa3, '7428', 1, 2, 0x3261d0d),
    (0xc0, '74de', 1, 2, 0x3261ce0),
    (0xc9, '7415', 1, 2, 0x3261d20),
    (0xcb, 'eb03', 1, 2, 0x3261d10),
    (0xd4, '7252', 1, 2, 0x3261d68),
    (0xde, 'eba1', 1, 2, 0x3261cc1),
    (0xf4, '0f85d5040000', 2, 6, 0x326220f),
    (0x14d, '0f8373070000', 2, 6, 0x3262506),
    (0x1a5, '0f848c000000', 2, 6, 0x3261e77),
    (0x1e3, '7420', 1, 2, 0x3261e45),
    (0x1fa, '74e4', 1, 2, 0x3261e20),
    (0x201, '7419', 1, 2, 0x3261e5c),
    (0x203, 'eb03', 1, 2, 0x3261e48),
    (0x20c, '0f82c9000000', 2, 6, 0x3261f1b),
    (0x21a, 'eba1', 1, 2, 0x3261dfd),
    (0x230, '7522', 1, 2, 0x3261e94),
    (0x232, 'e9b3000000', 1, 5, 0x3261f2a),
    (0x24e, '0f8496000000', 2, 6, 0x3261f2a),
    (0x256, '7423', 1, 2, 0x3261ebb),
    (0x25e, '742c', 1, 2, 0x3261ecc),
    (0x276, 'e97ffeffff', 1, 5, 0x3261d3a),
    (0x287, 'e96efeffff', 1, 5, 0x3261d3a),
    (0x2ad, '7418', 1, 2, 0x3261f07),
    (0x2b3, '0f83c2000000', 2, 6, 0x3261fbb),
    (0x2c5, 'ebab', 1, 2, 0x3261eb2),
    (0x2d9, 'eb97', 1, 2, 0x3261eb2),
    (0x2e4, '0f856affffff', 2, 6, 0x3261e94),
    (0x2ff, '0f8541050000', 2, 6, 0x3262486),
    (0x34d, '7c1a', 1, 2, 0x3261fa9),
    (0x352, '7415', 1, 2, 0x3261fa9),
    (0x376, 'e998fdffff', 1, 5, 0x3261d53),
    (0x3cc, '75da', 1, 2, 0x3261fe8),
    (0x3d9, '7409', 1, 2, 0x3262024),
    (0x3e2, '75f7', 1, 2, 0x326201b),
    (0x411, '7f28', 1, 2, 0x326207b),
    (0x41b, '770e', 1, 2, 0x326206b),
    (0x429, '7610', 1, 2, 0x326207b),
    (0x491, '0f8063fcffff', 2, 6, 0x3261d3a),
    (0x4a4, '0f8750fcffff', 2, 6, 0x3261d3a),
    (0x4b1, '0f8743fcffff', 2, 6, 0x3261d3a),
    (0x4cd, '0f8527fcffff', 2, 6, 0x3261d3a),
    (0x4e4, '0f8510fcffff', 2, 6, 0x3261d3a),
    (0x4ed, '0f84a8000000', 2, 6, 0x32621db),
    (0x4fb, '0f80e4030000', 2, 6, 0x3262525),
    (0x517, '0f848f000000', 2, 6, 0x32621ec),
    (0x522, '0f8584000000', 2, 6, 0x32621ec),
    (0x54d, '0f849e030000', 2, 6, 0x3262531),
    (0x572, '0f852a020000', 2, 6, 0x32623e2),
    (0x584, '0f858e000000', 2, 6, 0x3262258),
    (0x596, 'e913020000', 1, 5, 0x32623ee),
    (0x5a7, 'e94efbffff', 1, 5, 0x3261d3a),
    (0x5ca, 'e9a3fcffff', 1, 5, 0x3261eb2),
    (0x613, 'e9e2faffff', 1, 5, 0x3261d3a),
    (0x69b, 'eb17', 1, 2, 0x32622f4),
    (0x6ae, '0f8520010000', 2, 6, 0x3262414),
    (0x6c4, '0f840a010000', 2, 6, 0x3262414),
    (0x6dc, '0f87cc000000', 2, 6, 0x32623ee),
    (0x717, '740a', 1, 2, 0x3262363),
    (0x721, 'eb07', 1, 2, 0x326236a),
    (0x735, '7577', 1, 2, 0x32623ee),
    (0x74c, '7417', 1, 2, 0x32623a5),
    (0x75f, '0f8538ffffff', 2, 6, 0x32622dd),
    (0x76d, '0f8363010000', 2, 6, 0x3262516),
    (0x785, '7512', 1, 2, 0x32623d9),
    (0x793, '0f8404ffffff', 2, 6, 0x32622dd),
    (0x7a0, 'eb0c', 1, 2, 0x32623ee),
    (0x7b6, '0f84b6faffff', 2, 6, 0x3261eb2),
    (0x7cf, 'e99efaffff', 1, 5, 0x3261eb2),
    (0x804, '0f8486000000', 2, 6, 0x32624d0),
    (0x815, '7779', 1, 2, 0x32624d0),
    (0x840, '0f84bffaffff', 2, 6, 0x3261f45),
    (0x88b, 'e975faffff', 1, 5, 0x3261f45),
    (0x89e, '7415', 1, 2, 0x32624f5),
    (0x8c1, 'e9acf9ffff', 1, 5, 0x3261eb2),
    (0x8e3, 'eb19', 1, 2, 0x326253e),
    (0x8ec, 'e913fcffff', 1, 5, 0x3262144),
    (0x90e, '742b', 1, 2, 0x326257b),
    (0x910, 'eb16', 1, 2, 0x3262568),
    (0x912, 'eb02', 1, 2, 0x3262556),
    (0x914, 'eb00', 1, 2, 0x3262556),
    (0x921, '7418', 1, 2, 0x326257b),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3261ee5, 0x3394790),
    (0x3261f76, 0x33a6b80),
    (0x3262180, 0x32639c0),
    (0x3262348, 0x36f3350),
    (0x3262385, 0x32814c0),
    (0x3262398, 0x3262600),
    (0x326243d, 0x3262590),
    (0x326257e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3261dd6, 0x5773170),
    (0x3261ea0, 0x576f488),
    (0x3261f07, 0x576f488),
    (0x3261fa3, 0x576e010),
    (0x3262024, 0x57747c8),
    (0x326214f, 0x5774768),
    (0x32621ec, 0x576f488),
    (0x32621fd, 0x5774768),
    (0x326224a, 0x576e8b8),
    (0x3262409, 0x576e010),
    (0x32624bb, 0x576e8b8),
    (0x32624d0, 0x576f488),
    (0x32624ef, 0x576e010),
    (0x3262510, 0x576dfc8),
    (0x326251d, 0x576e470),
    (0x3262538, 0x576e470),
    (0x3262575, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3262506, 0x56df828, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x3262516, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x3262531, 0x56df860, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f68797065726c69717569646974792e7273'), 355, 29),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774cd0']
GOT_SITES = {'0x5774cd0': ['0x274ffa2', '0x4d72d28', '0x4d737f8']}


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

