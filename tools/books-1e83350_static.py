#!/usr/bin/env python3
"""Authenticated node94 books-1e83350 binding (0x1e83350).

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

START, END = 0x1e83350, 0x1e83e1f
FDE_VA = 0x1050534
FDE = bytes.fromhex(
    '500000000c290900142ee300cf0a000004bb6b94ff410e10420e18420e20420e'
    '28420e30410e38470ee00483078c068d058e048f038602036b0a0e38410e3042'
    '0e28420e20420e18420e10410e08410ee0040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec280200004c894424204989ca488b074c8b4710'
    '4885c00f95c14d85c0400f95c64020ce4080fe010f853b0a0000488b7708498d'
    '8a8000000048898c24a0000000498d8a9000000048894c2418498d6a60488b4a'
    '0848898c24b0000000488b4a1048898c24b80000004531e44c895424084889ac'
    '24a8000000e9940000000f108424300100000f298424900000000f1084242001'
    '00000f29842480000000660f108424e0000000660f108c24f0000000660f1094'
    '2400010000660f109c2410010000660f295c2470660f29542460660f294c2450'
    '660f29442440488d7c2440e8b0a302004c8b54240866662e0f1f840000000000'
    'b8000000004c8b8424d000000049ffc8488bb424c80000000f84570900004d85'
    'e4741d410fb78c247a0300004839ce0f83bb0000004d89e64889f1e9d6000000'
    '4885f674394889f14989c44883e107743231d2666666662e0f1f840000000000'
    '4d8ba4248003000048ffc24839d175f04889f04829d04883fe087314eb514989'
    'c4eb4c4889f04883fe0872430f1f4000498b8c2480030000488b898003000048'
    '8b8980030000488b8980030000488b8980030000488b8980030000488b898003'
    '00004c8ba1800300004883c0f875c131c031f6410fb78c247a0300004839ce0f'
    '8250ffffff66662e0f1f8400000000004d8b34244d85f60f84a408000048ffc0'
    '410fb78c24780300004d89f466413b8e7a03000073da4885c04c898424d00000'
    '000f84a9000000498d14ce4881c2880300004889c64883e6070f845104000031'
    'ff6666666666662e0f1f8400000000004c8b22498d94248003000048ffc74839'
    'fe75ed4889c64829fe4883f808724390488b02488b8080030000488b80800300'
    '00488b8080030000488b8080030000488b8080030000488b80800300004c8ba0'
    '80030000498d9424800300004883c6f875be31c0488d1cc9498b8cde90000000'
    '483b8c24b80000007227e9c507000090488d41014d89f4488d1cc9498b8cde90'
    '000000483b8c24b80000000f83a307000048898424c8000000498b84de980000'
    '004889442410f2410f1084dea0000000f20f118424c00000004c69f9d8000000'
    '488bac24b000000048898c24d80000004d8d2c2f660f2805543538fe660f2944'
    '2440c7442450fefefefe4c89ef488d742440ba010000004c89d14c8b44242041'
    'b902000000e8860b8600498d342f4881c680000000488bac24a8000000488d7c'
    '24404d89ef4c89ea4c8bac24d8000000e8db4151004c8b542408488b44244048'
    '85c00f8458fdffff498bb2000200004939f50f83f80600004c89ea48c1e20549'
    '8bbaf8010000498bb218020000488b4c17084839f10f83ac060000488b141748'
    '39f20f839f060000498bb2100200004869c9e80000000fb64c0e494869d2e800'
    '00002a4c16480f82b40600004d8d34de4983c66066480f6ec0660f62050f0738'
    'fe660f5c0527f737fe660f28e8660f15e8f20f58e80fb6c1488d0d01d755fef2'
    '0f5e2cc18b450889442430488b45004889442428498d5e2041837e2000f20f10'
    '057b6f38fe74738b4508898424e8000000488b450048898424e00000008b4308'
    '89442448488b03488944244048b801000000540000004889442450488d05735f'
    '73fe488944245848c74424602b000000488dbc24e0000000488d742440660f29'
    'ac2440010000ff15a4b08e03660f28ac24400100004c8b542408f2410f104e10'
    '660f2ec1776a8b442430894308488b442428488903f20f101de36e38fe660f28'
    'd3f20f5ed1660f28cbf20f5cca660f28d5f20f59d066410f101e660f14c9660f'
    '59cb660f14d0660f58d166410f1116498b461848ffc048c7c1ffffffff480f44'
    'c149894618eb34660f1f840000000000f20f1005007038fef20f5fc1660f57c9'
    '66410f110ef2410f11461049c746180000000041c7462000000000f2410f1046'
    '180f1405a80538fe660f5c05c0f537fe660f28c8660f15c8f20f58c8f2410f10'
    '4610660f2ec10f8754fbfffff2410f104608f20f100d767738fe660f2ec80f87'
    '3cfbfffff2410f1016660f28ca660f57e4f20fc2cc01f20f101d1a6b38fef20f'
    'c2da01660f55da660f54d9660f55ca660f56cb660f2ee10f8703fbfffff20f5e'
    'c8660f28c5f20fc2c503660f28d0660f54d1f20f5dcd660f55c1660f56c2660f'
    '2e8424c00000000f87d3faffff488dbc24e0000000488b7424184c89eaff155d'
    'f88e036681bc24e000000086010f8537faffff488b9c24e8000000488b7c2418'
    '4c89ee4889dae8d57b48004889c14889d84809c848c1e82074284889d831d248'
    'f7f1eb246666662e0f1f8400000000004889c64883f8080f83d3fbffffe910fc'
    'ffff89d831d2f7f14c8b44240848f7e14889c30f91c04883fb014883d30084c0'
    '0f8487030000498b7e30498bb0000200004839f70f838e030000498b80f80100'
    '0048c1e7054c8b743808660f28059e3138fe660f29442440c7442450fefefefe'
    '488bbc24a0000000488d742440ff150df78e03488b48104885c90f8487000000'
    '488b40184c8b5424084c8b5c24100fb7b16a0100008d14f5000000004c8d0452'
    '48c7c2ffffffff31ff0f1f80000000004939f8742b4c3b74d110410f97c14180'
    'd9004883c71848ffc24180f90174e1410fb6f185f67420eb0a0f1f8000000000'
    '4889f24883e8010f82b0020000488b8cd170010000eb97488b4439484939c30f'
    '875bf9ffffeb1531c04c8b5424084c8b5c24104939c30f8744f9ffff488b4424'
    '104889c14809d948c1e920740731d248f7f3eb0431d2f7f34c89fa418b726041'
    '8b4a64458b5a684189f141c1f90d418d79ff4531c04585c97f2841b801000000'
    '4529c84d69c01f85eb5149c1e82741ffc04569c8900100004401cf4569c04fc5'
    'fdffc1ee0481e6ff0100004401c64469c7b505000041c1f8024863ff4869ff1f'
    '85eb514989f949c1e93f48c1ff254401cf29fec1ff024401c601fe81c6c506f5'
    'ff4863f64869f6805101004801ce4489d94869c983de1b4348c1e9324869f6e8'
    '0300004801ce4885f6b900000000480f4ef148c7842458010000010000004889'
    '84246001000048c78424680100000000000048c78424780100000000000048c7'
    '8424880100000000000048c78424900100000800000048c78424c80100000000'
    '0000488d842498010000660f57c0660f110048899c24d80100004889b424e001'
    '000066c78424e80100000000c68424fa01000000660f2805742f38fe660f1140'
    '78c78088000000fefefefec68424240200000048c78424000200000000000048'
    '8d7c2440488db424580100004c89d14c8b442420e8878a8400488b4424404889'
    'c148f7d90f8086f7ffff7314488b7c24484869f02802000031d2ff1540a38e03'
    '488b4c24584885c97449488b542460488b44246848c78424e800000000000000'
    '48898c24f000000048899424f800000048c78424080100000000000048898c24'
    '100100004889942418010000b901000000eb0431c931c048898c24e000000048'
    '898c2400010000488984242001000090488d7c2428488db424e0000000e84e70'
    '9e00488b4424284885c00f84e0f6ffff488b4c2438488d0c49488b74c8084885'
    'f674cd488d04c84883c008488b780848c1e60331d2ff1585a28e03ebb331c049'
    '39c30f87b8f6ffffe96ffdffff48c7c3ffffffff498b7e30498bb00002000048'
    '39f70f8272fcffff488d1549c58003ff1503a28e034881c4280200005b415c41'
    '5d415e415f5dc3488d3d12e48603ff158ca68e03488d3d8d768303ff157fa68e'
    '03488d3dd0c78003ff1572a68e030f0b488d15d1e186034c89efff15b8a18e03'
    '488d3d41e48603ff1533a38e030f0b'
)
BODY_SHA256 = 'd152df921a2e6009d0cef944d487f7542293fc3ff517d2da237e1e8e8fa2aa71'
BRANCHES = [
    (0x34, '0f853b0a0000', 2, 6, 0x1e83dc5),
    (0x85, 'e994000000', 1, 5, 0x1e8346e),
    (0x118, '0f8457090000', 2, 6, 0x1e83dc5),
    (0x121, '741d', 1, 2, 0x1e83490),
    (0x12f, '0f83bb000000', 2, 6, 0x1e83540),
    (0x13b, 'e9d6000000', 1, 5, 0x1e83566),
    (0x143, '7439', 1, 2, 0x1e834ce),
    (0x14f, '7432', 1, 2, 0x1e834d3),
    (0x16e, '75f0', 1, 2, 0x1e834b0),
    (0x17a, '7314', 1, 2, 0x1e834e0),
    (0x17c, 'eb51', 1, 2, 0x1e8351f),
    (0x181, 'eb4c', 1, 2, 0x1e8351f),
    (0x18a, '7243', 1, 2, 0x1e8351f),
    (0x1cd, '75c1', 1, 2, 0x1e834e0),
    (0x1df, '0f8250ffffff', 2, 6, 0x1e83485),
    (0x1f7, '0f84a4080000', 2, 6, 0x1e83df1),
    (0x214, '73da', 1, 2, 0x1e83540),
    (0x221, '0f84a9000000', 2, 6, 0x1e83620),
    (0x239, '0f8451040000', 2, 6, 0x1e839e0),
    (0x261, '75ed', 1, 2, 0x1e835a0),
    (0x26d, '7243', 1, 2, 0x1e83602),
    (0x2b0, '75be', 1, 2, 0x1e835c0),
    (0x2c8, '7227', 1, 2, 0x1e83641),
    (0x2ca, 'e9c5070000', 1, 5, 0x1e83de4),
    (0x2eb, '0f83a3070000', 2, 6, 0x1e83de4),
    (0x3a2, '0f8458fdffff', 2, 6, 0x1e83450),
    (0x3b2, '0f83f8060000', 2, 6, 0x1e83e00),
    (0x3d5, '0f83ac060000', 2, 6, 0x1e83dd7),
    (0x3e2, '0f839f060000', 2, 6, 0x1e83dd7),
    (0x406, '0f82b4060000', 2, 6, 0x1e83e10),
    (0x465, '7473', 1, 2, 0x1e8382a),
    (0x4e4, '776a', 1, 2, 0x1e838a0),
    (0x545, 'eb34', 1, 2, 0x1e838cb),
    (0x5a6, '0f8754fbffff', 2, 6, 0x1e83450),
    (0x5be, '0f873cfbffff', 2, 6, 0x1e83450),
    (0x5f7, '0f8703fbffff', 2, 6, 0x1e83450),
    (0x627, '0f87d3faffff', 2, 6, 0x1e83450),
    (0x64d, '0f8537faffff', 2, 6, 0x1e833da),
    (0x678, '7428', 1, 2, 0x1e839f2),
    (0x682, 'eb24', 1, 2, 0x1e839f8),
    (0x697, '0f83d3fbffff', 2, 6, 0x1e835c0),
    (0x69d, 'e910fcffff', 1, 5, 0x1e83602),
    (0x6c0, '0f8487030000', 2, 6, 0x1e83d9d),
    (0x6d4, '0f838e030000', 2, 6, 0x1e83db8),
    (0x71a, '0f8487000000', 2, 6, 0x1e83af7),
    (0x753, '742b', 1, 2, 0x1e83ad0),
    (0x76d, '74e1', 1, 2, 0x1e83aa0),
    (0x775, '7420', 1, 2, 0x1e83ae7),
    (0x777, 'eb0a', 1, 2, 0x1e83ad3),
    (0x787, '0f82b0020000', 2, 6, 0x1e83d8d),
    (0x795, 'eb97', 1, 2, 0x1e83a7e),
    (0x79f, '0f875bf9ffff', 2, 6, 0x1e83450),
    (0x7a5, 'eb15', 1, 2, 0x1e83b0c),
    (0x7b6, '0f8744f9ffff', 2, 6, 0x1e83450),
    (0x7cb, '7407', 1, 2, 0x1e83b24),
    (0x7d2, 'eb04', 1, 2, 0x1e83b28),
    (0x7f8, '7f28', 1, 2, 0x1e83b72),
    (0x964, '0f8086f7ffff', 2, 6, 0x1e83440),
    (0x96a, '7314', 1, 2, 0x1e83cd0),
    (0x988, '7449', 1, 2, 0x1e83d23),
    (0x9d1, 'eb04', 1, 2, 0x1e83d27),
    (0xa0a, '0f84e0f6ffff', 2, 6, 0x1e83440),
    (0xa21, '74cd', 1, 2, 0x1e83d40),
    (0xa3b, 'ebb3', 1, 2, 0x1e83d40),
    (0xa42, '0f87b8f6ffff', 2, 6, 0x1e83450),
    (0xa48, 'e96ffdffff', 1, 5, 0x1e83b0c),
    (0xa62, '0f8272fcffff', 2, 6, 0x1e83a2a),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x1e8343b, 0x1ead7f0),
    (0x1e836b5, 0x26e4240),
    (0x1e836e0, 0x23978c0),
    (0x1e839b6, 0x230b590),
    (0x1e83ca4, 0x26cc730),
    (0x1e83d4d, 0x286ada0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x1e83816, 0x576e8c0),
    (0x1e8398d, 0x57731f0),
    (0x1e83a5d, 0x5773170),
    (0x1e83cca, 0x576e010),
    (0x1e83d85, 0x576e010),
    (0x1e83dbf, 0x576dfc8),
    (0x1e83dde, 0x576e470),
    (0x1e83deb, 0x576e470),
    (0x1e83df8, 0x576e470),
    (0x1e83e0a, 0x576dfc8),
    (0x1e83e17, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x1e83db8, 0x5690308, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x1e83dd7, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x1e83de4, 0x56bb478, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x1e83df1, 0x56905c8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 560, 47),
    (0x1e83e00, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x1e83e10, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x26ff0f1]
CALLER_FUNCTIONS = {'0x26ff0f1': ('0x26fed00', '0x26ff186')}
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

