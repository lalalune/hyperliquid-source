#!/usr/bin/env python3
"""Authenticated node94 impl-wei-375e4c0 binding (0x375e4c0).

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

START, END = 0x375e4c0, 0x375eea8
FDE_VA = 0x11a6d34
FDE = bytes.fromhex(
    '500000000c911e0084775b02e8090000045f7590ff410e10420e18420e20420e'
    '28420e30410e38470ec00383078c068d058e048f038602034d090e38410e3042'
    '0e28420e20420e18420e10410e08410ec0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec880100004c898424b000000048897c2410483b'
    '96880100000f83660900004989ce4989d74869c2e8000000488b898803000048'
    '85c90f84f2000000498b96900300004531db440fb781ba0000004589c141c1e1'
    '0348c7c7ffffffff0f1f8400000000004d85c9742b4c3b7cf910410f97c24180'
    'da0048ffc74983c1f84180fa0174e1450fb6c24585c0750beb19660f1f440000'
    '4c89c74883ea01720f488b8cf9c0000000eb9f4c8b5cf9604803868001000049'
    '8b96a00300004885d20f8485000000498bb6a803000031c9440fb782ba000000'
    '4589c141c1e10348c7c7ffffffff66904d85c9742b4c3b7cfa10410f97c24180'
    'da0048ffc74983c1f84180fa0174e1450fb6c24585c0750beb19660f1f440000'
    '4c89c74883ee01722d488b94fac0000000eba5488b4cfa60eb1c4531db480386'
    '80010000498b96a00300004885d20f857bffffff31c931d24c895c24304929cb'
    '4c0f42da4c899c24a000000048c74424180000000048c74424200800000048c7'
    '44242800000000488ba8900000004885ed741a488b98980000004c8ba0a00000'
    '00b8010000004889442408eb0c48c7442408000000004531e4c78424f0000000'
    '00000000660fefc0f30f6f0d9dafe3fcf30f7f8c24f4000000c7842404010000'
    '0000dead660f7f4424508b8424f000000089442460488b8424f4000000488944'
    '24648b8424fc0000008944246c488b84240001000048894424704c89bc24e000'
    '00004983be98000000004c89a424a80000000f84a3000000498dbea000000048'
    '8db424e0000000e894dd23004889c648c1ee39498b8e80000000498b96880000'
    '00660f6ec6660f60c0f20f70c000660f70c044488d71f031ff660f76c94821d0'
    'f30f6f1401660f6fda660f74d866440fd7c34585c07429f3450fbcc84901c149'
    '21d149c1e1044989f24d29ca4d3b3a742e458d48ff664521c14589c875d96690'
    '660f74d166440fd7c24585c0750d4801f84883c0104883c710eba231c0eb1f4c'
    '89f9480fc948c78424c000000000000000c78424c700000000000000b001488b'
    '54247048899424180100000f284424500f284c24600f118c24080100000f1184'
    '24f8000000c684246901000032488b9424c0000000488994246a0100008b9424'
    'c70000008994247101000048898c24750100004d397e080f94c14c89b4248001'
    '000041220e884c240648c78424e00000000100000048c78424e8000000000000'
    '0048c78424f000000002000000488b4c240848898c242001000048c784242801'
    '0000000000004889ac243001000048899c243801000048898c244001000048c7'
    '842448010000000000004889ac245001000048899c2458010000888424680100'
    '00b80100000048894424484531ed48896c243848c74424400000000048c78424'
    'b800000000000000eb36660f1f440000488b4424204c89f148c1e1058b942490'
    '000000895408100f288424800000000f1104084c8964081849ffc64c89742428'
    '48837c2448020f848600000048837c2408027459488b8424a80000004885c074'
    '4048ffc848898424a80000004889842460010000f6442408010f842e0500004d'
    '85ed0f84e6000000410fb785e60000004839c30f83870100004c89e8e9a30100'
    '0048c784242001000002000000f644244801740848837c244002757148c78424'
    'e000000002000000b80200000048894424080fb6842468010000488d4c24073c'
    '02742d88442407488d8424f80000000f1040710f298424800000008b80810000'
    '0089842490000000488d8c2468010000c60100b8020000004889442448807c24'
    '07010f8416020000e960030000488b4c2440488d048948ffc148898c24e80000'
    '00488d9424f80000000f1004820f294424508b44821089442460b80200000048'
    '8944240848894c2440e9b80100004885db743a4889d84883e0074c8b6c243874'
    '3331c9666666662e0f1f8400000000004d8bade800000048ffc14839c875f148'
    '89d84829c84883fb087315eb514c8b6c2438eb4a4889d84883fb0872410f1f00'
    '498b8de8000000488b89e8000000488b89e8000000488b89e8000000488b89e8'
    '000000488b89e8000000488b89e80000004c8ba9e80000004883c0f875c248c7'
    '8424200100000100000031db31ed410fb785e60000004839c30f827afeffff90'
    '498b45004885c00f847103000048ffc5410fb79de40000004989c5663b98e600'
    '000073dc4885ed0f8488000000488d0cd84881c1f00000004889ea4883e2070f'
    '841602000031f6660f1f8400000000004c8b29498d8de800000048ffc64839f2'
    '75ee4889ea4829f24883fd0872436690488b09488b89e8000000488b89e80000'
    '00488b89e8000000488b89e8000000488b89e8000000488b89e80000004c8ba9'
    'e8000000498d8de80000004883c2f875bf31c9eb07488d4b014989c5488d149b'
    '4c89ac242801000048c78424300100000000000048898c24380100000f104490'
    '088b449018894424600f29442450b801000000488944240831ed48c744243800'
    '0000004889cb8b442460898424900000000f284424500f29842480000000488b'
    'bc2480010000488db42480000000ff155c450102488b48104885c90f847f0000'
    '00488b40180fb7b16a0100008d14f5000000004c8d045248c7c2ffffffff31ff'
    '4939f8742b4c3b7cd110410f97c14180d9004883c71848ffc24180f90174e141'
    '0fb6f185f674294883e801730ceb31904889f24883e8017227488b8cd1700100'
    '00eba2666666662e0f1f8400000000004c8b643948807c240600750eeb666690'
    '4531e4807c240600745a8b842490000000898424d00000000f28842480000000'
    '0f298424c0000000488d7c2450488bb424b0000000488d9424c0000000ff1535'
    '6201024c036424500f823b0100004c036424580f82300100004c036424600f82'
    '250100004d85e40f84f3fbffff4c01a424b80000000f820e0100004c8b742428'
    '4c3b7424180f85a5fbffff488d7c2418ff15925f0102e995fbffff4889ea4883'
    'fd080f8249feffffe903feffff31db488b8424a0000000482b8424b800000048'
    '0f43d84983ff01753a48b8ff7f35c69edbffff488b4c24304839c14c8b7c2410'
    '0f87a800000048b80080ca39612400004801c148894c2430807c240600751031'
    'c0eb3b4c8b7c2410807c24060074f031c0488b8c24b0000000807960004c8b71'
    '68490f45c64829c3731431db488d35bd0ff80131ffff15b54301024c89f0488b'
    '4c242849894f180f10442418410f114708488b4c243049894f20488b8c24a000'
    '000049894f2849895f30498947386641c70786014c89f84881c4880100005b41'
    '5c415d415e415f5dc34c8b7c24106641c707be00488b7424184885f674d6488b'
    '7c242048c1e60531d2ff15c1f10002ebc3488d3d9833f901ff1512f60002488d'
    '3d83b1f801ff1505f60002eb0d488d3dac9cf801ff15f6f500020f0beb02eb00'
    '4889c3488b7424184885f67411488b7c242048c1e60531d2ff1572f100024889'
    'dfe86a12f0010f0b'
)
BODY_SHA256 = '90715d33e5a04e3ef172ab967349904a721c4e8c1bf0d8f85f5223df261c2b38'
BRANCHES = [
    (0x25, '0f8366090000', 2, 6, 0x375ee51),
    (0x42, '0f84f2000000', 2, 6, 0x375e5fa),
    (0x73, '742b', 1, 2, 0x375e560),
    (0x8d, '74e1', 1, 2, 0x375e530),
    (0x96, '750b', 1, 2, 0x375e563),
    (0x98, 'eb19', 1, 2, 0x375e573),
    (0xa7, '720f', 1, 2, 0x375e578),
    (0xb1, 'eb9f', 1, 2, 0x375e512),
    (0xc9, '0f8485000000', 2, 6, 0x375e614),
    (0xf3, '742b', 1, 2, 0x375e5e0),
    (0x10d, '74e1', 1, 2, 0x375e5b0),
    (0x116, '750b', 1, 2, 0x375e5e3),
    (0x118, 'eb19', 1, 2, 0x375e5f3),
    (0x127, '722d', 1, 2, 0x375e616),
    (0x131, 'eba5', 1, 2, 0x375e598),
    (0x138, 'eb1c', 1, 2, 0x375e616),
    (0x14e, '0f857bffffff', 2, 6, 0x375e58f),
    (0x191, '741a', 1, 2, 0x375e66d),
    (0x1ab, 'eb0c', 1, 2, 0x375e679),
    (0x232, '0f84a3000000', 2, 6, 0x375e79b),
    (0x295, '7429', 1, 2, 0x375e780),
    (0x2af, '742e', 1, 2, 0x375e79f),
    (0x2bc, '75d9', 1, 2, 0x375e757),
    (0x2cc, '750d', 1, 2, 0x375e79b),
    (0x2d9, 'eba2', 1, 2, 0x375e73d),
    (0x2dd, 'eb1f', 1, 2, 0x375e7be),
    (0x408, 'eb36', 1, 2, 0x375e900),
    (0x446, '0f8486000000', 2, 6, 0x375e992),
    (0x452, '7459', 1, 2, 0x375e96d),
    (0x45f, '7440', 1, 2, 0x375e961),
    (0x479, '0f842e050000', 2, 6, 0x375ee6d),
    (0x482, '0f84e6000000', 2, 6, 0x375ea2e),
    (0x493, '0f8387010000', 2, 6, 0x375eae0),
    (0x49c, 'e9a3010000', 1, 5, 0x375eb04),
    (0x4b2, '7408', 1, 2, 0x375e97c),
    (0x4ba, '7571', 1, 2, 0x375e9ed),
    (0x4e1, '742d', 1, 2, 0x375e9d0),
    (0x522, '0f8416020000', 2, 6, 0x375ebfe),
    (0x528, 'e960030000', 1, 5, 0x375ed4d),
    (0x569, 'e9b8010000', 1, 5, 0x375ebe6),
    (0x571, '743a', 1, 2, 0x375ea6d),
    (0x57f, '7433', 1, 2, 0x375ea74),
    (0x59d, '75f1', 1, 2, 0x375ea50),
    (0x5a9, '7315', 1, 2, 0x375ea80),
    (0x5ab, 'eb51', 1, 2, 0x375eabe),
    (0x5b2, 'eb4a', 1, 2, 0x375eabe),
    (0x5bb, '7241', 1, 2, 0x375eabe),
    (0x5fc, '75c2', 1, 2, 0x375ea80),
    (0x619, '0f827afeffff', 2, 6, 0x375e959),
    (0x627, '0f8471030000', 2, 6, 0x375ee5e),
    (0x642, '73dc', 1, 2, 0x375eae0),
    (0x647, '0f8488000000', 2, 6, 0x375eb95),
    (0x65f, '0f8416020000', 2, 6, 0x375ed3b),
    (0x680, '75ee', 1, 2, 0x375eb30),
    (0x68c, '7243', 1, 2, 0x375eb91),
    (0x6cf, '75bf', 1, 2, 0x375eb50),
    (0x6d3, 'eb07', 1, 2, 0x375eb9c),
    (0x75b, '0f847f000000', 2, 6, 0x375eca0),
    (0x783, '742b', 1, 2, 0x375ec70),
    (0x79d, '74e1', 1, 2, 0x375ec40),
    (0x7a5, '7429', 1, 2, 0x375ec90),
    (0x7ab, '730c', 1, 2, 0x375ec79),
    (0x7ad, 'eb31', 1, 2, 0x375eca0),
    (0x7b7, '7227', 1, 2, 0x375eca0),
    (0x7c1, 'eba2', 1, 2, 0x375ec25),
    (0x7da, '750e', 1, 2, 0x375ecaa),
    (0x7dc, 'eb66', 1, 2, 0x375ed04),
    (0x7e8, '745a', 1, 2, 0x375ed04),
    (0x828, '0f823b010000', 2, 6, 0x375ee29),
    (0x833, '0f8230010000', 2, 6, 0x375ee29),
    (0x83e, '0f8225010000', 2, 6, 0x375ee29),
    (0x847, '0f84f3fbffff', 2, 6, 0x375e900),
    (0x855, '0f820e010000', 2, 6, 0x375ee29),
    (0x865, '0f85a5fbffff', 2, 6, 0x375e8d0),
    (0x876, 'e995fbffff', 1, 5, 0x375e8d0),
    (0x882, '0f8249feffff', 2, 6, 0x375eb91),
    (0x888, 'e903feffff', 1, 5, 0x375eb50),
    (0x8a7, '753a', 1, 2, 0x375eda3),
    (0x8c0, '0f87a8000000', 2, 6, 0x375ee2e),
    (0x8dd, '7510', 1, 2, 0x375edaf),
    (0x8e1, 'eb3b', 1, 2, 0x375edde),
    (0x8ed, '74f0', 1, 2, 0x375ed9f),
    (0x908, '7314', 1, 2, 0x375edde),
    (0x97c, '74d6', 1, 2, 0x375ee14),
    (0x98f, 'ebc3', 1, 2, 0x375ee14),
    (0x9ab, 'eb0d', 1, 2, 0x375ee7a),
    (0x9bc, 'eb02', 1, 2, 0x375ee80),
    (0x9be, 'eb00', 1, 2, 0x375ee80),
    (0x9cb, '7411', 1, 2, 0x375ee9e),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x375e707, 0x399c4a0),
    (0x375eea1, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x375ec0e, 0x5773170),
    (0x375ecdd, 0x5774f18),
    (0x375ed30, 0x5774cc8),
    (0x375edd5, 0x5773190),
    (0x375ee49, 0x576e010),
    (0x375ee58, 0x576e470),
    (0x375ee65, 0x576e470),
    (0x375ee74, 0x576e470),
    (0x375ee98, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x375ee51, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x375ee5e, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x375ee6d, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5773330']
GOT_SITES = {'0x5773330': ['0x1f68cc5', '0x3249026', '0x47ba911', '0x47bad61']}


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

