#!/usr/bin/env python3
"""Authenticated node94 pdi-26f8d50 binding (0x26f8d50).

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

START, END = 0x26f8d50, 0x26f95c7
FDE_VA = 0x10ed2f0
FDE = bytes.fromhex(
    '50000000c8f6120058ba6001770800000487fb92ff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f0386020399060e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb800000048c74424180000000048c744242800'
    '0000004883bf78330000000f84370700004989f74889fb4c8bb77033000066c7'
    '4424384101488d7c2438e8f106c8004883bbc8050000000f84390700004c8ba3'
    'c005000066c74424384101488d7c2438e8cb06c800498b4610488d3cc5000000'
    '0048894424084885c04c89bc249800000048897c241074744d8b6e08ff15e651'
    '07034885c00f84190700004989c74983ed804531f6488d6c2438660f1f440000'
    '4889ef4c89eee855fd5101488b442438488b4c24404889ca4821c24889ce4831'
    'c648d1ee4801d64885c9480f44f14885c0480f44f04b8934f749ffc64981c5d8'
    '0000004c3974240875b6eb0641bf08000000488b4424084d8d2cc731f6488d05'
    '0443fc0248894424304d89fe4c89fd904c39ed0f84db0100004989f749ffc70f'
    '84c40500004d8b4424304c89c0b91027000048f7e10f80900500004889c14801'
    'f10f8296050000488b7d004885ff0f84dc0000004881f90f270000771389ceeb'
    '2f6666666666662e0f1f840000000000beffffffff4881f95f5af40577128db1'
    'a08601006666662e0f1f8400000000004889c848ba4b598638d6c56d3448f7e2'
    '48c1ea0b4c39c20f85fa0400004869c2102700004829c1493b4c24100f83e504'
    '0000498b442408488d0c4948c1e1040fb644082a4883f8070f831b0500004883'
    'c508b90600000029c166480f6ecf660f620d1aafb0fd660f5c0d329fb0fd660f'
    '28c1660f15c1f20f58c1c1e103488d050c7fcefdf20f5e0401488d7c2418e84d'
    '5e16004c89fee9e5feffff0f1f4400004889c848ba4b598638d6c56d3448f7e2'
    '48c1ea0b4869c2102700004889cf4829c7498b7424704839f70f83da04000049'
    '8b442468488d147f48c1e205488b7c1020498b8424700200004885c00f84d2fe'
    'ffff498b942478020000440fb748624589ca41c1e20348c7c6ffffffff0f1f00'
    '4d85d2743b483b4cf010410f97c34180db0048ffc64983c2f84180fb0174e145'
    '0fb6cb4585c90f8488feffff4883ea01731be97dfeffff660f1f840000000000'
    '4c89ce4883ea010f8267feffff488b44f068eb9648837c24080074104c89f748'
    '8b74241031d2ff15944f07034c8da390000000488bab883300004c69b3903300'
    '00d8000000488d05c423fc0248894424086666666666662e0f1f840000000000'
    '4d85f60f842e010000488db580000000488d7c2438e806e3c9ff488b4424384c'
    '8b7c24404885c00f94c14d85ff0f94c208ca4c89f94821c14931c749d1ef4901'
    'cf4c8badb00000000f94c008d03c017526488bb3903300004939f50f83760300'
    '004969fdd80000004803bb88330000e8acefb7004989c7bf010000004c89ee4c'
    '89e2e8693d5101488bb3000200004939f50f833403000049c1e505488b93f801'
    '0000488bb3180200004a8b4c2a084839f10f83c20200004a8b142a4839f20f83'
    'b5020000488bb3100200004869c9e80000000fb64c0e494869d2e80000002a4c'
    '16480f82020300004881c5d800000066490f6ecf660f620dd4acb0fd660f5c0d'
    'ec9cb0fd660f28c1660f15c1f20f58c10fb6c9488d15c67ccefdf20f5e04ca49'
    '81c628ffffff488d7c241889c6e8fe5b1600e9c9feffff488b442418488b4c24'
    '204889c24885c07405488b542428400f95c6400fb6f6488974243848c7442440'
    '00000000488944244848894c2450488974245848c74424600000000048894424'
    '6848894c247048895424784c8dbbb83100004c8da424a00000004c8d6c24384c'
    '8b3582b60703488bac249800000066904c89e74c89eee875651700488b8424a0'
    '0000004885c07433488b8c24b00000008b748860f20f1044c8088b4508898424'
    'a8000000488b450048898424a00000004c89ff4c89e241ffd6ebb54c8d7c2418'
    '4c8d64243866662e0f1f8400000000004c89ff4c89e6e81565170048837c2418'
    '0075ed0fb683f2080000884424188b55008b45048b4d084189d041c1f80d418d'
    '70ff31ff4585c07f25bf010000004429c74869ff1f85eb5148c1ef27ffc74469'
    'c7900100004401c669ff4fc5fdffc1ea0481e2ff01000001fa69feb5050000c1'
    'ff024863f64869f61f85eb514989f049c1e83f48c1fe254401c629f2c1fe0201'
    'fa01f281c2c506f5ff4863d24869d2805101004801c289c84869c083de1b4348'
    'c1e8324869cae80300004801c131c04885c9480f4fc1488b8bd83100004889c2'
    '4809ca48c1ea20746c31d248f7f1488b8be03100004839c87607488983e03100'
    '004839c8488d051deceafd488944243848c7442440190000000f2805a0cab0fd'
    '0f114424480f974424584881c328320000488d7c2438488d7424184889dae8cd'
    'a9c7004881c4b80000005b415c415d415e415f5dc331d2f7f1488b8be0310000'
    '4839c87795eb9a488d3da28dff02ff154c500703e9fb000000488d3dc08dff02'
    'ff153a500703e9e9000000488d3d2e4bfc02ff15684d0703e9d7000000488d05'
    '1c4bfc024889442430488b7c2430ff15b44c0703e9bb000000488d3de09eff02'
    'ff15da4c0703e9a9000000488d05568bff0248894424084c89ef488b542408ff'
    '15334b0703e98a000000488d3db78dff02ff15a94c0703eb7b488d15f83cfc02'
    'ff15124b0703eb6c66c74424384101488d3db32be9fd488d0d430aff024c8d05'
    '3c06ff02488d542438be2b000000ff15644b0703eb3e66c74424384101488d3d'
    '852be9fd488d0d150aff024c8d05de05ff02488d542438be2b000000ff15364b'
    '0703eb10bf08000000488b742410ff15944a07030f0b4889c3488d7c2438e85d'
    'ffc700eb7aff15ed4b07034889c3488d7c2438e848ffc700eb65ff15d84b0703'
    'eb3d4889c34c89ff488b742410eb48eb334889c34c8d7424184c8d7c24386690'
    '4c89f74c89fee86562170048837c24180075edeb34ff159d4b0703eb07eb0048'
    '89c3eb1b4889c3488b74241048837c240800740b4c89f731d2ff15614a070348'
    '8d7c2418e8f7141b004889dfe84f6bf602ff15614b0703'
)
BODY_SHA256 = '672988e34a3f24a6bfcdbbdcc05c712547e4c4ea1fef22ed7c75af8506011292'
BRANCHES = [
    (0x2b, '0f8437070000', 2, 6, 0x26f94b8),
    (0x57, '0f8439070000', 2, 6, 0x26f94e6),
    (0x96, '7474', 1, 2, 0x26f8e5c),
    (0xa5, '0f8419070000', 2, 6, 0x26f9514),
    (0x108, '75b6', 1, 2, 0x26f8e10),
    (0x10a, 'eb06', 1, 2, 0x26f8e62),
    (0x133, '0f84db010000', 2, 6, 0x26f9064),
    (0x13f, '0f84c4050000', 2, 6, 0x26f9459),
    (0x155, '0f8090050000', 2, 6, 0x26f943b),
    (0x161, '0f8296050000', 2, 6, 0x26f944d),
    (0x16e, '0f84dc000000', 2, 6, 0x26f8fa0),
    (0x17b, '7713', 1, 2, 0x26f8ee0),
    (0x17f, 'eb2f', 1, 2, 0x26f8f00),
    (0x19c, '7712', 1, 2, 0x26f8f00),
    (0x1c7, '0f85fa040000', 2, 6, 0x26f9417),
    (0x1dc, '0f83e5040000', 2, 6, 0x26f9417),
    (0x1f8, '0f831b050000', 2, 6, 0x26f9469),
    (0x246, 'e9e5feffff', 1, 5, 0x26f8e80),
    (0x279, '0f83da040000', 2, 6, 0x26f94a9),
    (0x29c, '0f84d2feffff', 2, 6, 0x26f8ec4),
    (0x2c3, '743b', 1, 2, 0x26f9050),
    (0x2dd, '74e1', 1, 2, 0x26f9010),
    (0x2e6, '0f8488feffff', 2, 6, 0x26f8ec4),
    (0x2f0, '731b', 1, 2, 0x26f905d),
    (0x2f2, 'e97dfeffff', 1, 5, 0x26f8ec4),
    (0x307, '0f8267feffff', 2, 6, 0x26f8ec4),
    (0x312, 'eb96', 1, 2, 0x26f8ffa),
    (0x31a, '7410', 1, 2, 0x26f907c),
    (0x363, '0f842e010000', 2, 6, 0x26f91e7),
    (0x3af, '7526', 1, 2, 0x26f9127),
    (0x3bb, '0f8376030000', 2, 6, 0x26f9487),
    (0x3f1, '0f8334030000', 2, 6, 0x26f947b),
    (0x411, '0f83c2020000', 2, 6, 0x26f9429),
    (0x41e, '0f83b5020000', 2, 6, 0x26f9429),
    (0x442, '0f8202030000', 2, 6, 0x26f949a),
    (0x492, 'e9c9feffff', 1, 5, 0x26f90b0),
    (0x4a7, '7405', 1, 2, 0x26f91fe),
    (0x526, '7433', 1, 2, 0x26f92ab),
    (0x559, 'ebb5', 1, 2, 0x26f9260),
    (0x581, '75ed', 1, 2, 0x26f92c0),
    (0x5a7, '7f25', 1, 2, 0x26f931e),
    (0x647, '746c', 1, 2, 0x26f9405),
    (0x658, '7607', 1, 2, 0x26f93b1),
    (0x6c3, '7795', 1, 2, 0x26f93aa),
    (0x6c5, 'eb9a', 1, 2, 0x26f93b1),
    (0x6d4, 'e9fb000000', 1, 5, 0x26f9524),
    (0x6e6, 'e9e9000000', 1, 5, 0x26f9524),
    (0x6f8, 'e9d7000000', 1, 5, 0x26f9524),
    (0x714, 'e9bb000000', 1, 5, 0x26f9524),
    (0x726, 'e9a9000000', 1, 5, 0x26f9524),
    (0x745, 'e98a000000', 1, 5, 0x26f9524),
    (0x757, 'eb7b', 1, 2, 0x26f9524),
    (0x766, 'eb6c', 1, 2, 0x26f9524),
    (0x794, 'eb3e', 1, 2, 0x26f9524),
    (0x7c2, 'eb10', 1, 2, 0x26f9524),
    (0x7e3, 'eb7a', 1, 2, 0x26f95af),
    (0x7f8, 'eb65', 1, 2, 0x26f95af),
    (0x800, 'eb3d', 1, 2, 0x26f958f),
    (0x80d, 'eb48', 1, 2, 0x26f95a7),
    (0x80f, 'eb33', 1, 2, 0x26f9594),
    (0x831, '75ed', 1, 2, 0x26f9570),
    (0x833, 'eb34', 1, 2, 0x26f95b9),
    (0x83b, 'eb07', 1, 2, 0x26f9594),
    (0x83d, 'eb00', 1, 2, 0x26f958f),
    (0x842, 'eb1b', 1, 2, 0x26f95af),
    (0x852, '740b', 1, 2, 0x26f95af),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26f8d9a, 0x3379490),
    (0x26f8dc0, 0x3379490),
    (0x26f8e16, 0x3c18b70),
    (0x26f8f8e, 0x285ede0),
    (0x26f90c5, 0x23973d0),
    (0x26f911f, 0x32780d0),
    (0x26f9132, 0x3c0cea0),
    (0x26f91dd, 0x285ede0),
    (0x26f9266, 0x286f7e0),
    (0x26f92c6, 0x286f7e0),
    (0x26f93ee, 0x3373dc0),
    (0x26f952e, 0x3379490),
    (0x26f9543, 0x3379490),
    (0x26f9576, 0x286f7e0),
    (0x26f95b4, 0x28aaab0),
    (0x26f95bc, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26f8dec, 0x576dfd8),
    (0x26f9076, 0x576e010),
    (0x26f941e, 0x576e470),
    (0x26f9430, 0x576e470),
    (0x26f9442, 0x576e1b0),
    (0x26f945e, 0x576e118),
    (0x26f9470, 0x576e150),
    (0x26f948f, 0x576dfc8),
    (0x26f94a1, 0x576e150),
    (0x26f94b0, 0x576dfc8),
    (0x26f94de, 0x576e048),
    (0x26f950c, 0x576e048),
    (0x26f951e, 0x576dfb8),
    (0x26f9535, 0x576e128),
    (0x26f954a, 0x576e128),
    (0x26f9585, 0x576e128),
    (0x26f95a9, 0x576e010),
    (0x26f95c1, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26f9417, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x26f9429, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26f9469, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x26f949a, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
    (0x26f94a9, 0x56bd1a8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x222a615]
CALLER_FUNCTIONS = {'0x222a615': ('0x22297c0', '0x222af3e')}
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

