#!/usr/bin/env python3
"""Authenticated node94 books-42e0840 binding (0x42e0840).

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

START, END = 0x42e0840, 0x42e1314
FDE_VA = 0x122c5fc
FDE = bytes.fromhex(
    '50000000d4e926003c420b03d40a000004f7ac8fff410e10420e18420e20420e'
    '28420e30410e38470ee00483078c068d058e048f03860203630a0e38410e3042'
    '0e28420e20420e18420e10410e08410ee0040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec280200004c894424204989ca488b074c8b4710'
    '4885c00f95c14d85c0400f95c64020ce4080fe010f85330a0000488b7708498d'
    '8a8000000048898c24a0000000498d8a9000000048894c2418498d6a60488b4a'
    '0848898c24b0000000488b4a1048898c24b80000004531e44c895424084889ac'
    '24a8000000e9940000000f108424300100000f298424900000000f1084242001'
    '00000f29842480000000660f108424e0000000660f108c24f0000000660f1094'
    '2400010000660f109c2410010000660f295c2470660f29542460660f294c2450'
    '660f29442440488d7c2440e8003b06004c8b54240866662e0f1f840000000000'
    'b8000000004c8b8424d000000049ffc8488bb424c80000000f844f0900004d85'
    'e4741d410fb78c247a0300004839ce0f83ab0000004d89e64889f1e9c6000000'
    '4885f6747e4889f14989c44883e1070f842d06000031d2660f1f840000000000'
    '4d8ba4248003000048ffc24839d175f04889f04829d04883fe0872430f1f4000'
    '498b8c2480030000488b8980030000488b8980030000488b8980030000488b89'
    '80030000488b8980030000488b89800300004c8ba1800300004883c0f875c131'
    'f6eb0531f64989c431c0410fb78c247a0300004839ce0f8259ffffff0f1f4000'
    '4d8b34244d85f60f84ac08000048ffc0410fb78c24780300004d89f466413b8e'
    '7a03000073da4885c04c898424d00000000f84a9000000498d14ce4881c28803'
    '00004889c64883e6070f844105000031ff6666666666662e0f1f840000000000'
    '4c8b22498d94248003000048ffc74839fe75ed4889c64829fe4883f808724390'
    '488b02488b8080030000488b8080030000488b8080030000488b808003000048'
    '8b8080030000488b80800300004c8ba080030000498d9424800300004883c6f8'
    '75be31c0488d1cc9498b8cde90000000483b8c24b80000007227e9cd07000090'
    '488d41014d89f4488d1cc9498b8cde90000000483b8c24b80000000f83ab0700'
    '0048898424c8000000498b84de980000004889442410f2410f1084dea0000000'
    'f20f118424c00000004c69f9d8000000488bac24b000000048898c24d8000000'
    '4d8d2c2f660f28057460f2fb660f29442440c7442450fefefefe4c89ef488d74'
    '2440ba010000004c89d14c8b44242041b902000000e8962f0200498d342f4881'
    'c680000000488bac24a8000000488d7c24404d89ef4c89ea4c8bac24d8000000'
    'e8db6c72004c8b542408488b4424404885c00f8468fdffff498bb20002000049'
    '39f50f83000700004c89ea48c1e205498bbaf8010000498bb218020000488b4c'
    '17084839f10f83b4060000488b14174839f20f83a7060000498bb21002000048'
    '69c9e80000000fb64c0e494869d2e80000002a4c16480f82bc0600004d8d34de'
    '4983c66066480f6ec0660f62052f32f2fb660f5c054722f2fb660f28e8660f15'
    'e8f20f58e80fb6c1488d0d016841fcf20f5e2cc18b450889442430488b450048'
    '89442428498d5e2041837e2000f20f10059b9af2fb74738b4508898424e80000'
    '00488b450048898424e00000008b430889442448488b03488944244048b80100'
    '0000540000004889442450488d05938a2dfc488944245848c74424602b000000'
    '488dbc24e0000000488d742440660f29ac2440010000ff15c4db4801660f28ac'
    '24400100004c8b542408f2410f104e10660f2ec1776a8b442430894308488b44'
    '2428488903f20f101d039af2fb660f28d3f20f5ed1660f28cbf20f5cca660f28'
    'd5f20f59d066410f101e660f14c9660f59cb660f14d0660f58d166410f111649'
    '8b461848ffc048c7c1ffffffff480f44c149894618eb34660f1f840000000000'
    'f20f1005209bf2fbf20f5fc1660f57c966410f110ef2410f11461049c7461800'
    '00000041c7462000000000f2410f1046180f1405c830f2fb660f5c05e020f2fb'
    '660f28c8660f15c8f20f58c8f2410f104610660f2ec10f8764fbfffff2410f10'
    '4608f20f100d96a2f2fb660f2ec80f874cfbfffff2410f1016660f28ca660f57'
    'e4f20fc2cc01f20f101d3a96f2fbf20fc2da01660f55da660f54d9660f55ca66'
    '0f56cb660f2ee10f8713fbfffff20f5ec8660f28c5f20fc2c503660f28d0660f'
    '54d1f20f5dcd660f55c1660f56c2660f2e8424c00000000f87e3faffff488dbc'
    '24e0000000488b7424184c89eaff157d2349016681bc24e000000086010f8547'
    'faffff488b9c24e8000000488b7c24184c89ee4889dae8f55c9c004889c14889'
    'd84809c848c1e8200f84360100004889d831d248f7f14c8b44240848f7e10f80'
    '340100004889c34883fb014883d300498b7e30498bb0000200004839f70f8322'
    '040000498b80f801000048c1e7054c8b743808660f2805e55cf2fb660f294424'
    '40c7442450fefefefe488bbc24a0000000488d742440ff1554224901488b4810'
    '4885c90f84db000000488b40184c8b5424084c8b5c24100fb7b16a0100008d14'
    'f5000000004c8d045248c7c2ffffffff31ff66666666662e0f1f840000000000'
    '4939f8742b4c3b74d110410f97c14180d9004883c71848ffc24180f90174e141'
    '0fb6f185f6744deb0a0f1f80000000004889f24883e8010f8200030000488b8c'
    'd170010000eb90660f1f8400000000004889c64883f8080f83e3faffffe920fb'
    'ffff4889f04883fe080f83f1f9ffffe92bfaffff488b4439484939c30f875ef9'
    'ffffeb3589d831d2f7f14c8b44240848f7e10f81ccfeffff48c7c3ffffffffe9'
    'c3feffff31c04c8b5424084c8b5c24104939c30f8727f9ffff488b4424104889'
    'c14809d948c1e920740731d248f7f3eb0431d2f7f34c89fa418b7260418b4a64'
    '458b5a684189f141c1f90d418d79ff4531c04585c97f2841b8010000004529c8'
    '4d69c01f85eb5149c1e82741ffc04569c8900100004401cf4569c04fc5fdffc1'
    'ee0481e6ff0100004401c64469c7b505000041c1f8024863ff4869ff1f85eb51'
    '4989f949c1e93f48c1ff254401cf29fec1ff024401c601fe81c6c506f5ff4863'
    'f64869f6805101004801ce4489d94869c983de1b4348c1e9324869f6e8030000'
    '4801ce4885f6b900000000480f4ef148c7842458010000010000004889842460'
    '01000048c78424680100000000000048c78424780100000000000048c7842488'
    '0100000000000048c78424900100000800000048c78424c80100000000000048'
    '8d842498010000660f57c0660f110048899c24d80100004889b424e001000066'
    'c78424e80100000000c68424fa01000000660f2805675af2fb660f114078c780'
    '88000000fefefefec68424240200000048c784240002000000000000488d7c24'
    '40488db424580100004c89d14c8b442420e89a44ffff488b4424404889c148f7'
    'd90f8069f7ffff7314488b7c24484869f02802000031d2ff1533ce4801488b4c'
    '24584885c97449488b542460488b44246848c78424e80000000000000048898c'
    '24f000000048899424f800000048c78424080100000000000048898c24100100'
    '004889942418010000b901000000eb0431c931c048898c24e000000048898c24'
    '0001000048898424200100000f1f4000488d7c2428488db424e0000000e89e71'
    '6600488b4424284885c00f84c0f6ffff488b4c2438488d0c49488b74c8084885'
    'f674cd488d04c84883c008488b780848c1e60331d2ff1575cd4801ebb331c049'
    '39c30f8798f6ffffe96cfdffff4881c4280200005b415c415d415e415f5dc348'
    '8d3d2a0f4101ff15a4d14801488d3d65104601ff1597d14801488d3de0bf4301'
    'ff158ad148010f0b488d15e90c41014c89efff15d0cc4801488d3d590f4101ff'
    '154bce4801488d158cb74301ff15b6cc48010f0b'
)
BODY_SHA256 = '3992fed3d26c9d8814dddc63d6fa778553bf9a04f902fd8940b05158f19563a7'
BRANCHES = [
    (0x34, '0f85330a0000', 2, 6, 0x42e12ad),
    (0x85, 'e994000000', 1, 5, 0x42e095e),
    (0x118, '0f844f090000', 2, 6, 0x42e12ad),
    (0x121, '741d', 1, 2, 0x42e0980),
    (0x12f, '0f83ab000000', 2, 6, 0x42e0a20),
    (0x13b, 'e9c6000000', 1, 5, 0x42e0a46),
    (0x143, '747e', 1, 2, 0x42e0a03),
    (0x14f, '0f842d060000', 2, 6, 0x42e0fc2),
    (0x16e, '75f0', 1, 2, 0x42e09a0),
    (0x17a, '7243', 1, 2, 0x42e09ff),
    (0x1bd, '75c1', 1, 2, 0x42e09c0),
    (0x1c1, 'eb05', 1, 2, 0x42e0a08),
    (0x1d6, '0f8259ffffff', 2, 6, 0x42e0975),
    (0x1e7, '0f84ac080000', 2, 6, 0x42e12d9),
    (0x204, '73da', 1, 2, 0x42e0a20),
    (0x211, '0f84a9000000', 2, 6, 0x42e0b00),
    (0x229, '0f8441050000', 2, 6, 0x42e0fb0),
    (0x251, '75ed', 1, 2, 0x42e0a80),
    (0x25d, '7243', 1, 2, 0x42e0ae2),
    (0x2a0, '75be', 1, 2, 0x42e0aa0),
    (0x2b8, '7227', 1, 2, 0x42e0b21),
    (0x2ba, 'e9cd070000', 1, 5, 0x42e12cc),
    (0x2db, '0f83ab070000', 2, 6, 0x42e12cc),
    (0x392, '0f8468fdffff', 2, 6, 0x42e0940),
    (0x3a2, '0f8300070000', 2, 6, 0x42e12e8),
    (0x3c5, '0f83b4060000', 2, 6, 0x42e12bf),
    (0x3d2, '0f83a7060000', 2, 6, 0x42e12bf),
    (0x3f6, '0f82bc060000', 2, 6, 0x42e12f8),
    (0x455, '7473', 1, 2, 0x42e0d0a),
    (0x4d4, '776a', 1, 2, 0x42e0d80),
    (0x535, 'eb34', 1, 2, 0x42e0dab),
    (0x596, '0f8764fbffff', 2, 6, 0x42e0940),
    (0x5ae, '0f874cfbffff', 2, 6, 0x42e0940),
    (0x5e7, '0f8713fbffff', 2, 6, 0x42e0940),
    (0x617, '0f87e3faffff', 2, 6, 0x42e0940),
    (0x63d, '0f8547faffff', 2, 6, 0x42e08ca),
    (0x668, '0f8436010000', 2, 6, 0x42e0fe4),
    (0x67e, '0f8034010000', 2, 6, 0x42e0ff8),
    (0x69d, '0f8322040000', 2, 6, 0x42e1305),
    (0x6e3, '0f84db000000', 2, 6, 0x42e1004),
    (0x723, '742b', 1, 2, 0x42e0f90),
    (0x73d, '74e1', 1, 2, 0x42e0f60),
    (0x745, '744d', 1, 2, 0x42e0fd4),
    (0x747, 'eb0a', 1, 2, 0x42e0f93),
    (0x757, '0f8200030000', 2, 6, 0x42e129d),
    (0x765, 'eb90', 1, 2, 0x42e0f37),
    (0x777, '0f83e3faffff', 2, 6, 0x42e0aa0),
    (0x77d, 'e920fbffff', 1, 5, 0x42e0ae2),
    (0x789, '0f83f1f9ffff', 2, 6, 0x42e09c0),
    (0x78f, 'e92bfaffff', 1, 5, 0x42e09ff),
    (0x79c, '0f875ef9ffff', 2, 6, 0x42e0940),
    (0x7a2, 'eb35', 1, 2, 0x42e1019),
    (0x7b2, '0f81ccfeffff', 2, 6, 0x42e0ec4),
    (0x7bf, 'e9c3feffff', 1, 5, 0x42e0ec7),
    (0x7d3, '0f8727f9ffff', 2, 6, 0x42e0940),
    (0x7e8, '7407', 1, 2, 0x42e1031),
    (0x7ef, 'eb04', 1, 2, 0x42e1035),
    (0x815, '7f28', 1, 2, 0x42e107f),
    (0x981, '0f8069f7ffff', 2, 6, 0x42e0930),
    (0x987, '7314', 1, 2, 0x42e11dd),
    (0x9a5, '7449', 1, 2, 0x42e1230),
    (0x9ee, 'eb04', 1, 2, 0x42e1234),
    (0xa2a, '0f84c0f6ffff', 2, 6, 0x42e0930),
    (0xa41, '74cd', 1, 2, 0x42e1250),
    (0xa5b, 'ebb3', 1, 2, 0x42e1250),
    (0xa62, '0f8798f6ffff', 2, 6, 0x42e0940),
    (0xa68, 'e96cfdffff', 1, 5, 0x42e1019),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x42e092b, 0x4344430),
    (0x42e0b95, 0x4303b30),
    (0x42e0bc0, 0x4a078a0),
    (0x42e0e96, 0x4ca6b90),
    (0x42e11b1, 0x42d5650),
    (0x42e125d, 0x4948400),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x42e0cf6, 0x576e8c0),
    (0x42e0e6d, 0x57731f0),
    (0x42e0f16, 0x5773170),
    (0x42e11d7, 0x576e010),
    (0x42e1295, 0x576e010),
    (0x42e12c6, 0x576e470),
    (0x42e12d3, 0x576e470),
    (0x42e12e0, 0x576e470),
    (0x42e12f2, 0x576dfc8),
    (0x42e12ff, 0x576e150),
    (0x42e130c, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x42e12bf, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x42e12cc, 0x5742338, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x42e12d9, 0x571d2c0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 560, 47),
    (0x42e12e8, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x42e12f8, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
    (0x42e1305, 0x571ca98, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x4ce8281]
CALLER_FUNCTIONS = {'0x4ce8281': ('0x4ce8080', '0x4ce8306')}
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

