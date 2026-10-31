#!/usr/bin/env python3
"""Authenticated node94 books-37568b0 binding (0x37568b0).

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

START, END = 0x37568b0, 0x3757149
FDE_VA = 0x11a6a6c
FDE = bytes.fromhex(
    '50000000448e1e003cfe5a029908000004737690ff410e10420e18420e20420e'
    '28420e30410e38470ed00283078c068d058e048f0386020308080e38410e3042'
    '0e28420e20420e18420e10410e08410ed0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec1801000048897c2428f30f6f02660f7f8424e0'
    '0000008b4210898424f0000000660fefc966480f6ed0660f74c1660f74d1660f'
    'dbd0660fd7c23dffff00000f84b5070000f30f6f02660f6e4a10660f740d9e18'
    'abfc660f7405a6d3aafc660fdbc1660fd7c03dffff00000f8489070000f30f6f'
    '02660f6e4a10660f740d621babfc660f74059a02abfc660fdbc1660fd7c03dff'
    'ff00000f845d070000488b064889442418488b98b80300004885db4889542430'
    '0f84b10000004889342448894c2408488b4424184c8ba0c0030000488b2df67a'
    '0102488d73080fb783e600000048894424108d0485000000004c8d348049c7c7'
    'ffffffff6666662e0f1f8400000000004d85f674414c8d6e14ba14000000488b'
    '7c2430ffd548984885c00f98c10f9fc028c849ffc74983c6ec4c89ee3c0174d0'
    '0fb6c085c0488b4c2408488b34240f84b2060000eb0e4c8b7c2410488b4c2408'
    '488b34244983ec01720d4a8b9cfbe8000000e96bffffff48c744243800000000'
    '48c744244800000000488b41104889cf488b59204885c00f95c14885db0f95c2'
    '20ca80fa010f85dc050000488b4e0848894c2408488b4e1848898c24a8000000'
    '488b4e2048898c24a0000000488b6f18488b4e1048894c24104531ffeb156690'
    'b80000000048ffcb488b4c24300f84280500004d85ff7428410fb78f6a010000'
    '4839cd0f83c70000004c89f94889eae9df0000006666662e0f1f840000000000'
    '4885ed74384889e94989c74883e107743131d2666666662e0f1f840000000000'
    '4d8bbf7001000048ffc24839d175f14889e84829d04883fd087315eb514989c7'
    'eb4c4889e84883fd0872430f1f440000498b8f70010000488b8970010000488b'
    '8970010000488b8970010000488b8970010000488b8970010000488b89700100'
    '004c8bb9700100004883c0f875c231c031ed410fb78f6a0100004839cd0f8246'
    'ffffff666666662e0f1f840000000000498b0f4885c90f845405000048ffc041'
    '0fb797680100004989cf663b916a01000073dd4885c00f84a4000000488d34d1'
    '4881c6780100004889c74883e7070f845c0300004531c0660f1f840000000000'
    '4c8b3e498db77001000049ffc04c39c775ee4889c74c29c74883f80872436690'
    '488b06488b8070010000488b8070010000488b8070010000488b807001000048'
    '8b8070010000488b80700100004c8bb870010000498db7700100004883c7f875'
    'bf31ed4c8b6cd1084d85ed7528e94efeffff66666666662e0f1f840000000000'
    '488d6a014989cf4c8b6cd1084d85ed0f842bfeffff488b442418833801750f48'
    '8b4424184c3b68080f8412feffff488b4424084c3ba8880100000f8344040000'
    '4889c6488d0452488d04c14883c06048890424488b8e800100004d69e5e80000'
    '004a8b4421584a8b4c2160488b9668010000488bb67001000048c1e1034531c0'
    '4c39c10f84b7fdffff4a8b3c004839f70f83090400004989f949c1e1054983c0'
    '084a837c0a080075d7488b442410488b70104839f70f83f3030000488b400848'
    '69cfd8000000488d34084881c680000000488d7c2450e8451e4c00488b442450'
    '488b5424584885c00f94c14885d2400f94c64008ce4889d14821c14831c248d1'
    'ea4801ca0f94c04008f00f8530fdffff488b0424488b384c89ee488b4c2408e8'
    '4ca7b2ffa8010f8414fdffff488b4424084c3ba8880100000f83460300004889'
    'd7488b90800100004a8d0c22460fb6442249462a4422480f820c020000b80100'
    '00000f857a01000048898424b0000000b800e1f505488b9424a8000000803a02'
    '0f85e30000008b81b8000000898424d8000000488b89b000000048898c24d000'
    '0000898424c000000048898c24b8000000ba007512004989fc488d7c2450488d'
    'b424bc00000031c9ff158a7a0102488b44245848b9000000004057ffff4801c1'
    '48ba81aefeff7faefeff4839d10f82ca020000448b7424508b4c2454894c2424'
    '8bbc24b800000048b9572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01'
    'd6ff15397a010285c00f848e0200004c89e7488b8c24a000000039010f9dc075'
    '13443971040f93c0750a8b4424243941080f93c084c0b800ca9a3b48b900e876'
    '4817000000480f45c1488b0c24488b114885d20f84c7fbffff483b9424b00000'
    '000f83b9fbffff4839c70f87b0fbffff488b0424488b4008488d0c104839c10f'
    '92c04839d10f97c108c10f8590fbffff488d7c24384c89eee8c3aac4ffe97efb'
    'ffff66666666662e0f1f8400000000004889c74883f8080f83c3fcffffe9fffc'
    'ffff410fb6f040f6c601740eb80a00000083fe010f846efeffff41f6c0027412'
    '486bc06489f283e2fe83fa020f8456feffff41f6c00474154869c01027000089'
    'f283e2fc83fa040f843bfeffff41f6c00874154869c000e1f50589f283e2f883'
    'fa080f8420feffff41f6c010741b48ba0000c16ff286230048f7e2700c83e6f0'
    '83fe100f84fffdffff488d3db0b2f901ff15aa740102e95b01000048837c2448'
    '007464488b44244848894424780f104424380f114424688b411089442460f30f'
    '6f01660f7f442450488b442470488b4c242848894128488b44247848894130f3'
    '0f7f41088b442460894118488b4424644889411c8b44246c89412448c7010100'
    '0000e98b000000488b4424384885c07438488b4c244048c74424580000000048'
    '8944246048894c246848c744247800000000488984248000000048898c248800'
    '0000b801000000eb0231c04889442450488944247048c7842490000000000000'
    '004c8db424b80000004c8d7c245066904c89f74c89fee81530c6ff4883bc24b8'
    '0000000075ea488b44242848c700000000004881c4180100005b415c415d415e'
    '415f5dc3488d3d15b1f901e9e0feffff488d3d012ff901ff1583730102eb3748'
    '8d15e2aef901ff15cc6e0102eb28488d15a38cf801ff15bd6e0102eb19488d3d'
    '0b2facfc488d15fd3df101be26000000ff15427301020f0beb04eb020f0b4889'
    'c3488d7c2438e8e56bcaff4889dfe8cd8ff001ff15df6f0102'
)
BODY_SHA256 = '826044e0edd7910f833c1aa8f933cda37f3ed4ffe90a37bac6c66e82cb954beb'
BRANCHES = [
    (0x4b, '0f84b5070000', 2, 6, 0x37570b6),
    (0x77, '0f8489070000', 2, 6, 0x37570b6),
    (0xa3, '0f845d070000', 2, 6, 0x37570b6),
    (0xc0, '0f84b1000000', 2, 6, 0x3756a27),
    (0x113, '7441', 1, 2, 0x3756a06),
    (0x13e, '74d0', 1, 2, 0x37569c0),
    (0x14e, '0f84b2060000', 2, 6, 0x37570b6),
    (0x154, 'eb0e', 1, 2, 0x3756a14),
    (0x168, '720d', 1, 2, 0x3756a27),
    (0x172, 'e96bffffff', 1, 5, 0x3756992),
    (0x1a5, '0f85dc050000', 2, 6, 0x3757037),
    (0x1dc, 'eb15', 1, 2, 0x3756aa3),
    (0x1ed, '0f8428050000', 2, 6, 0x3756fcb),
    (0x1f6, '7428', 1, 2, 0x3756ad0),
    (0x203, '0f83c7000000', 2, 6, 0x3756b80),
    (0x20f, 'e9df000000', 1, 5, 0x3756ba3),
    (0x223, '7438', 1, 2, 0x3756b0d),
    (0x22f, '7431', 1, 2, 0x3756b12),
    (0x24d, '75f1', 1, 2, 0x3756af0),
    (0x259, '7315', 1, 2, 0x3756b20),
    (0x25b, 'eb51', 1, 2, 0x3756b5e),
    (0x260, 'eb4c', 1, 2, 0x3756b5e),
    (0x269, '7243', 1, 2, 0x3756b5e),
    (0x2ac, '75c2', 1, 2, 0x3756b20),
    (0x2bd, '0f8246ffffff', 2, 6, 0x3756ab9),
    (0x2d6, '0f8454050000', 2, 6, 0x37570e0),
    (0x2f1, '73dd', 1, 2, 0x3756b80),
    (0x2f6, '0f84a4000000', 2, 6, 0x3756c50),
    (0x30e, '0f845c030000', 2, 6, 0x3756f20),
    (0x330, '75ee', 1, 2, 0x3756bd0),
    (0x33c, '7243', 1, 2, 0x3756c31),
    (0x37f, '75bf', 1, 2, 0x3756bf0),
    (0x38b, '7528', 1, 2, 0x3756c65),
    (0x38d, 'e94efeffff', 1, 5, 0x3756a90),
    (0x3af, '0f842bfeffff', 2, 6, 0x3756a90),
    (0x3bd, '750f', 1, 2, 0x3756c7e),
    (0x3c8, '0f8412feffff', 2, 6, 0x3756a90),
    (0x3da, '0f8344040000', 2, 6, 0x37570d4),
    (0x423, '0f84b7fdffff', 2, 6, 0x3756a90),
    (0x430, '0f8309040000', 2, 6, 0x37570ef),
    (0x447, '75d7', 1, 2, 0x3756cd0),
    (0x455, '0f83f3030000', 2, 6, 0x37570fe),
    (0x4aa, '0f8530fdffff', 2, 6, 0x3756a90),
    (0x4c6, '0f8414fdffff', 2, 6, 0x3756a90),
    (0x4d8, '0f8346030000', 2, 6, 0x37570d4),
    (0x4f7, '0f820c020000', 2, 6, 0x3756fb9),
    (0x502, '0f857a010000', 2, 6, 0x3756f32),
    (0x520, '0f85e3000000', 2, 6, 0x3756eb9),
    (0x58d, '0f82ca020000', 2, 6, 0x375710d),
    (0x5c9, '0f848e020000', 2, 6, 0x375710d),
    (0x5df, '7513', 1, 2, 0x3756ea4),
    (0x5e8, '750a', 1, 2, 0x3756ea4),
    (0x613, '0f84c7fbffff', 2, 6, 0x3756a90),
    (0x621, '0f83b9fbffff', 2, 6, 0x3756a90),
    (0x62a, '0f87b0fbffff', 2, 6, 0x3756a90),
    (0x64a, '0f8590fbffff', 2, 6, 0x3756a90),
    (0x65d, 'e97efbffff', 1, 5, 0x3756a90),
    (0x677, '0f83c3fcffff', 2, 6, 0x3756bf0),
    (0x67d, 'e9fffcffff', 1, 5, 0x3756c31),
    (0x68a, '740e', 1, 2, 0x3756f4a),
    (0x694, '0f846efeffff', 2, 6, 0x3756db8),
    (0x69e, '7412', 1, 2, 0x3756f62),
    (0x6ac, '0f8456feffff', 2, 6, 0x3756db8),
    (0x6b6, '7415', 1, 2, 0x3756f7d),
    (0x6c7, '0f843bfeffff', 2, 6, 0x3756db8),
    (0x6d1, '7415', 1, 2, 0x3756f98),
    (0x6e2, '0f8420feffff', 2, 6, 0x3756db8),
    (0x6ec, '741b', 1, 2, 0x3756fb9),
    (0x6fb, '700c', 1, 2, 0x3756fb9),
    (0x703, '0f84fffdffff', 2, 6, 0x3756db8),
    (0x716, 'e95b010000', 1, 5, 0x3757126),
    (0x721, '7464', 1, 2, 0x3757037),
    (0x782, 'e98b000000', 1, 5, 0x37570c2),
    (0x78f, '7438', 1, 2, 0x3757079),
    (0x7c7, 'eb02', 1, 2, 0x375707b),
    (0x804, '75ea', 1, 2, 0x37570a0),
    (0x82b, 'e9e0feffff', 1, 5, 0x3756fc0),
    (0x83d, 'eb37', 1, 2, 0x3757126),
    (0x84c, 'eb28', 1, 2, 0x3757126),
    (0x85b, 'eb19', 1, 2, 0x3757126),
    (0x878, 'eb04', 1, 2, 0x375712e),
    (0x87a, 'eb02', 1, 2, 0x375712e),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3756d26, 0x3c18b70),
    (0x3756d6f, 0x32814c0),
    (0x3756f08, 0x33a19d0),
    (0x37570a6, 0x33ba0c0),
    (0x3757136, 0x33fdd20),
    (0x375713e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3756e18, 0x576e8a8),
    (0x3756e71, 0x576e8b0),
    (0x3756fc0, 0x576e470),
    (0x37570e7, 0x576e470),
    (0x37570f6, 0x576dfc8),
    (0x3757105, 0x576dfc8),
    (0x3757120, 0x576e468),
    (0x3757143, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3756fb9, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x37570d4, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x37570e0, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x37570ef, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x37570fe, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x3757114, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x3766752]
CALLER_FUNCTIONS = {'0x3766752': ('0x37666d0', '0x3766853')}
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

