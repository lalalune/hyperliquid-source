#!/usr/bin/env python3
"""Authenticated node94 oracle-37098a0 binding (0x37098a0).

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

START, END = 0x37098a0, 0x370a3c1
FDE_VA = 0x11a5184
FDE = bytes.fromhex(
    '500000005c751e0014475602210b000004d77c90ff410e10420e18420e20420e'
    '28420e30410e38470ee00283078c068d058e048f03860203c1070e38410e3042'
    '0e28420e20420e18420e10410e08410ee0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec2801000044894c240c4989cc488954242849b9'
    '4b598638d6c56d344889c849f7e14889d348c1eb0b4585c07448483b5e300f85'
    '260a00004869c3102700004d89e54929c5488b4e104939cd0f830c0a0000488b'
    '46084a8d146d000000004c01ea48c1e204807c102800742f66c7074400e94607'
    '0000483b5e300f85de090000488b4e104c89e049f7e148c1ea0b4869c2102700'
    '004d89e54929c54939cd0f83ba090000448944241c48897c2420488b46084e8d'
    '346d000000004d01ee4c89b4242001000049c1e60448898424d8000000428b6c'
    '301883fd3248897424100f83b70000004c8b7e5048c78424c000000000000000'
    '48c78424d00000000000000040886c247848c74424700000000048c744246000'
    '000000488d7c2430488db424c0000000488d4c246031d2e874f5c8ff0f108424'
    'c00000000f118424f8000000488b8424d0000000488984240801000048c78424'
    'e00000000000000048c78424e80000000100000048c78424f000000000000000'
    '4c89bc24100100004c8dbc24e0000000498b4f18b8030000004885c90f85b800'
    '0000e9450100004c8b7e384d85ff0f84f4080000488b442410488b4040410fb7'
    '979e020000486bfa3848c7c1ffffffff31f666666666662e0f1f840000000000'
    '4989f84901f07428413bac8f74020000410f97c04180d8004883c6c848ffc141'
    '80f80174db410fb6d085d2741aeb04904889d14883e8010f828b0800004d8bbc'
    'cfa0020000eb964929f74983c7d04c89bc24e800000048b80000000000000080'
    '48898424e0000000498b4f18b8030000004885c90f8492000000498b57204885'
    'd2747b4889d64883e6070f84e502000031ff66666666662e0f1f840000000000'
    '488b89c801000048ffc74839fe75f14889d64829fe4883fa0872430f1f440000'
    '488b89c8010000488b89c8010000488b89c8010000488b89c8010000488b89c8'
    '010000488b89c8010000488b89c8010000488b89c80100004883c6f875c26683'
    'b9c20100000074040fb641183944240c7675488b44242066c700430083fd3148'
    '8b7c24200f87be040000488b8c24f80000004989ff4885c90f84be020000488b'
    '942400010000488b84240801000048c74424680000000048894c247048895424'
    '7848c78424880000000000000048898c24900000004889942498000000b90100'
    '0000e979020000488b442410488db8f80000004889bc2418010000488b742428'
    'e8cbbbfeff4c8b50084d85d20f849d0000004c01b424d80000004c8d5808488b'
    '4810410fb7b2220300004189f041c1e00648c7c2ffffffff31ff660f1f440000'
    '4939f8742b4d3ba4d2d0020000410f97c14180d9004883c74048ffc24180f901'
    '74de410fb6f185f67419eb070f1f40004889f24883e90172364d8b94d2280300'
    '00eb9f498b543ad04885d2744d41837c3ac0000f94c1324c241c0f84fb010000'
    '488b44242066c7004500e9cdfeffff488d7c24604c89e6488b542410e8ef624f'
    '00488b442410483b58300f85490600004c3b68100f833f060000488b4c24288b'
    '4110894424700f10010f29442460488d742460488bbc2418010000e820cce8ff'
    '4889c34c8b7020488b442410488db888010000488b4c24288b4110894424700f'
    '10010f29442460488d742460e83f18c9ff488d43084c89642430488b4b084885'
    'c90f84a00000004c8b5310488b5424100fb7b9220300004189f841c1e00348c7'
    'c6ffffffff66662e0f1f8400000000004d85c074274c3ba4f1d0020000410f97'
    'c14180d90048ffc64983c0f84180f90174de410fb6f985ff7419eb034889fe49'
    '83ea010f82f9030000488b8cf128030000eb9d48894c24684c89542470488974'
    '2478488984248000000048c744246000000000eb2a4889d64883fa080f833efd'
    'ffffe977fdffff48894424604c8964246848c744247000000000488b54241048'
    '8d7c2460488d742430e8f235cbff4883c320488b4c24104c8d8170010000488b'
    '50108b08448b780489683883f901750f807c241c007513c70001000000eb1180'
    '7c241c000f84b4000000c700000000008b4c240c894804e9b700000031c931c0'
    '48894c246048898c248000000048898424a0000000488d5c24304c8d74246090'
    '4889df4c89f6e8354bcaff48837c24300075ed4c89ffe9ad010000488b4c2410'
    '488b71704939f50f83880400004c89db4989c6418b443ac48944245c458b6c3a'
    'f8488b4168488b8c242001000048c1e105488b7408204c89ffff1599ba06020f'
    'b6c03944240c0f8671010000488b4c242066c7015000894104e97efcffffc700'
    '010000008b4c240c89480448c74008000000004c89e74889d64889d9e80fd4fe'
    'ff443b7c240c741d488b442410488db828010000488b7424284c89e28b4c240c'
    'e83b470000488b034d85f6741d4885c07547488b7c24104881c758010000488b'
    '742428e85830caffeb2f4885c0742a488b7c24104881c758010000488b4c2428'
    '8b4110894424700f10010f29442460488d742460e8d715c9ff488b44242066c7'
    '00860183fd310f8797000000488b8c24f80000004885c97446488b9424000100'
    '00488b84240801000048c74424680000000048894c2470488954247848c78424'
    '880000000000000048898c24900000004889942498000000b901000000eb0431'
    'c931c048894c246048898c248000000048898424a0000000488d5c24304c8d74'
    '246066666666662e0f1f8400000000004889df4c89f6e88549caff48837c2430'
    '0075ed488b7c24204889f84881c4280100005b415c415d415e415f5dc34c89f1'
    '4889de4439ed750e8b44245c3944240c0f8364fcffff488b19488d7c2430e84d'
    '37ceff498b462048894424484c89f64883c628488dbc24c0000000e85035ceff'
    '488b8424d000000048898424980000000f108424c00000000f11842488000000'
    '498b465048898424b0000000418b4658898424b800000048895c2460488d4424'
    '680f104424300f104c24400f114424680f114c2478410f1046400f118424a000'
    '00004c89a424c0000000488b4c24684885c9488b5c24100f84aa000000488b54'
    '24700fb7b9220300004189f841c1e00348c7c6ffffffff660f1f840000000000'
    '4d85c074274c3ba4f1d0020000410f97c14180d90048ffc64983c0f84180f901'
    '74de410fb6f985ff7419eb034889fe4883ea010f827e010000488b8cf1280300'
    '00eb9f48894c243848895424404889742448488944245048c744243000000000'
    'eb3848894c247048c7442478000000004889b4248000000048894424604c8964'
    '2468e938fcffff48894424304c8964243848c744244000000000488d7c243048'
    '8db424c00000004889dae81132cbff4883c3608b4c241c80f1018968388b5424'
    '0c895004440fb6f94439ed7427488b44241048890424488d7c24604c89fe4c89'
    'e2b9020000004989d9ff15a1a406024885c078408b44245c3944240c7327488b'
    '44241048890424488d7c24604c89fe4c89e2b9010000004989d9ff1570a40602'
    '4885c07866488d7c2460e8817a0500e966faffff488dbc24c0000000488bb424'
    'd8000000ff15263e0602488b8424d000000048894424460f108424c00000000f'
    '11442436488b54242066c7024f000f10442430488b44243e488b4c24460f1142'
    '024889421048894a18eb100fb644241c83f047488b4c2420668901488d7c2460'
    'e80b7a0500e992f8ffff488d3daf7efe01ff155941060248894c244048c74424'
    '4800000000488974245048894424304c89642438e9c1feffff488d3d807efe01'
    'ff152a410602eb1d488d3d897efe01ff151b410602488d155479fe014c89efff'
    '15633c06020f0b4889c3488d7c2430e8dc36cfffeb30ff15ac3d06024889c348'
    '8d7c2460e887790500eb1b4889c3488dbc24c0000000e855cdc6ffeb16ff1585'
    '3d06024889c3488dbc24e0000000e88db805004889dfe8555df501ff15673d06'
    '02'
)
BODY_SHA256 = '73da7c07d5d63895ea8a6b6596ba224a2a0fab018342e8733e6583bcd5a845a2'
BRANCHES = [
    (0x38, '7448', 1, 2, 0x3709922),
    (0x3e, '0f85260a0000', 2, 6, 0x370a30a),
    (0x58, '0f830c0a0000', 2, 6, 0x370a30a),
    (0x76, '742f', 1, 2, 0x3709947),
    (0x7d, 'e946070000', 1, 5, 0x370a068),
    (0x86, '0f85de090000', 2, 6, 0x370a30a),
    (0xaa, '0f83ba090000', 2, 6, 0x370a30a),
    (0xea, '0f83b7000000', 2, 6, 0x3709a47),
    (0x19c, '0f85b8000000', 2, 6, 0x3709afa),
    (0x1a2, 'e945010000', 1, 5, 0x3709b8c),
    (0x1ae, '0f84f4080000', 2, 6, 0x370a348),
    (0x1e6, '7428', 1, 2, 0x3709ab0),
    (0x203, '74db', 1, 2, 0x3709a80),
    (0x20b, '741a', 1, 2, 0x3709ac7),
    (0x20d, 'eb04', 1, 2, 0x3709ab3),
    (0x217, '0f828b080000', 2, 6, 0x370a348),
    (0x225, 'eb96', 1, 2, 0x3709a5d),
    (0x254, '0f8492000000', 2, 6, 0x3709b8c),
    (0x261, '747b', 1, 2, 0x3709b7e),
    (0x26a, '0f84e5020000', 2, 6, 0x3709df5),
    (0x28d, '75f1', 1, 2, 0x3709b20),
    (0x299, '7243', 1, 2, 0x3709b7e),
    (0x2dc, '75c2', 1, 2, 0x3709b40),
    (0x2e6, '7404', 1, 2, 0x3709b8c),
    (0x2f0, '7675', 1, 2, 0x3709c07),
    (0x304, '0f87be040000', 2, 6, 0x370a068),
    (0x318, '0f84be020000', 2, 6, 0x3709e7c),
    (0x362, 'e979020000', 1, 5, 0x3709e80),
    (0x38c, '0f849d000000', 2, 6, 0x3709ccf),
    (0x3c3, '742b', 1, 2, 0x3709c90),
    (0x3e0, '74de', 1, 2, 0x3709c60),
    (0x3e8, '7419', 1, 2, 0x3709ca3),
    (0x3ea, 'eb07', 1, 2, 0x3709c93),
    (0x3f7, '7236', 1, 2, 0x3709ccf),
    (0x401, 'eb9f', 1, 2, 0x3709c42),
    (0x40b, '744d', 1, 2, 0x3709cfa),
    (0x41a, '0f84fb010000', 2, 6, 0x3709ebb),
    (0x42a, 'e9cdfeffff', 1, 5, 0x3709b9c),
    (0x44a, '0f8549060000', 2, 6, 0x370a339),
    (0x454, '0f833f060000', 2, 6, 0x370a339),
    (0x4c1, '0f84a0000000', 2, 6, 0x3709e07),
    (0x4f3, '7427', 1, 2, 0x3709dbc),
    (0x510, '74de', 1, 2, 0x3709d90),
    (0x518, '7419', 1, 2, 0x3709dd3),
    (0x51a, 'eb03', 1, 2, 0x3709dbf),
    (0x523, '0f82f9030000', 2, 6, 0x370a1c2),
    (0x531, 'eb9d', 1, 2, 0x3709d70),
    (0x553, 'eb2a', 1, 2, 0x3709e1f),
    (0x55c, '0f833efdffff', 2, 6, 0x3709b40),
    (0x562, 'e977fdffff', 1, 5, 0x3709b7e),
    (0x5ae, '750f', 1, 2, 0x3709e5f),
    (0x5b5, '7513', 1, 2, 0x3709e6a),
    (0x5bd, 'eb11', 1, 2, 0x3709e70),
    (0x5c4, '0f84b4000000', 2, 6, 0x3709f1e),
    (0x5d7, 'e9b7000000', 1, 5, 0x3709f33),
    (0x611, '75ed', 1, 2, 0x3709ea0),
    (0x616, 'e9ad010000', 1, 5, 0x370a068),
    (0x627, '0f8388040000', 2, 6, 0x370a355),
    (0x666, '0f8671010000', 2, 6, 0x370a07d),
    (0x679, 'e97efcffff', 1, 5, 0x3709b9c),
    (0x6a6, '741d', 1, 2, 0x3709f65),
    (0x6cb, '741d', 1, 2, 0x3709f8a),
    (0x6d0, '7547', 1, 2, 0x3709fb9),
    (0x6e8, 'eb2f', 1, 2, 0x3709fb9),
    (0x6ed, '742a', 1, 2, 0x3709fb9),
    (0x726, '0f8797000000', 2, 6, 0x370a063),
    (0x737, '7446', 1, 2, 0x370a01f),
    (0x77d, 'eb04', 1, 2, 0x370a023),
    (0x7c1, '75ed', 1, 2, 0x370a050),
    (0x7e6, '750e', 1, 2, 0x370a096),
    (0x7f0, '0f8364fcffff', 2, 6, 0x3709cfa),
    (0x897, '0f84aa000000', 2, 6, 0x370a1e7),
    (0x8c3, '7427', 1, 2, 0x370a18c),
    (0x8e0, '74de', 1, 2, 0x370a160),
    (0x8e8, '7419', 1, 2, 0x370a1a3),
    (0x8ea, 'eb03', 1, 2, 0x370a18f),
    (0x8f3, '0f827e010000', 2, 6, 0x370a317),
    (0x901, 'eb9f', 1, 2, 0x370a142),
    (0x920, 'eb38', 1, 2, 0x370a1fa),
    (0x942, 'e938fcffff', 1, 5, 0x3709e1f),
    (0x98b, '7427', 1, 2, 0x370a254),
    (0x9b2, '7840', 1, 2, 0x370a294),
    (0x9bc, '7327', 1, 2, 0x370a285),
    (0x9e3, '7866', 1, 2, 0x370a2eb),
    (0x9ef, 'e966faffff', 1, 5, 0x3709cfa),
    (0xa49, 'eb10', 1, 2, 0x370a2fb),
    (0xa65, 'e992f8ffff', 1, 5, 0x3709b9c),
    (0xa94, 'e9c1feffff', 1, 5, 0x370a1fa),
    (0xaa6, 'eb1d', 1, 2, 0x370a365),
    (0xad4, 'eb30', 1, 2, 0x370a3a6),
    (0xae9, 'eb1b', 1, 2, 0x370a3a6),
    (0xafb, 'eb16', 1, 2, 0x370a3b3),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x37099d7, 0x3398f50),
    (0x3709c20, 0x36f57f0),
    (0x3709cdc, 0x3bfffd0),
    (0x3709d1b, 0x3596940),
    (0x3709d4c, 0x339b590),
    (0x3709e29, 0x33bd420),
    (0x3709ea6, 0x33ae9e0),
    (0x3709f3c, 0x36f7350),
    (0x3709f60, 0x370e6a0),
    (0x3709f83, 0x33acfe0),
    (0x3709fb4, 0x339b590),
    (0x370a056, 0x33ae9e0),
    (0x370a09e, 0x33ed7f0),
    (0x370a0bb, 0x33ed610),
    (0x370a20a, 0x33bd420),
    (0x370a28a, 0x3761d10),
    (0x370a300, 0x3761d10),
    (0x370a36f, 0x33fda50),
    (0x370a384, 0x3761d10),
    (0x370a396, 0x33770f0),
    (0x370a3ae, 0x3765c40),
    (0x370a3b6, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3709ef9, 0x5775998),
    (0x370a249, 0x57746f0),
    (0x370a27a, 0x57746f0),
    (0x370a2a4, 0x576e0d0),
    (0x370a311, 0x576e470),
    (0x370a340, 0x576e470),
    (0x370a34f, 0x576e470),
    (0x370a35f, 0x576dfc8),
    (0x370a376, 0x576e128),
    (0x370a39d, 0x576e128),
    (0x370a3bb, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x370a30a, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x370a339, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x370a348, 0x56f21d8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 279, 86),
    (0x370a355, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5773da8']
GOT_SITES = {'0x5773da8': ['0x27219be', '0x2721bb0', '0x2721e11', '0x4d26e30', '0x4d27022', '0x4d2728a', '0x4d27600', '0x4d277f2', '0x4d27a5a']}


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

