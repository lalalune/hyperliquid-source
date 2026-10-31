#!/usr/bin/env python3
"""Authenticated node94 clearinghouse-3707000 binding (0x3707000).

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

START, END = 0x3707000, 0x3707902
FDE_VA = 0x11a504c
FDE = bytes.fromhex(
    '5000000024741e00ac1f560202090000049b7c90ff410e10420e18420e20420e'
    '28420e30410e38470eb00383078c068d058e048f038602032e010e38410e3042'
    '0e28420e20420e18420e10410e08410eb0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec780100004d89c54989cc4989d74989f648897c'
    '24084889f74889d6ff1532d606024889c3418b471089442420f3410f6f07660f'
    '7f4424104983be10010000000f84dc000000498daef8000000498dbe18010000'
    '4c89fee8385729004889c648c1ee39498b8ef8000000498b9600010000660f6e'
    'c6660f60c0f20f70c000660f70c044488d718831ff660f76c94821d0f30f6f14'
    '01660f6fda660f74d866440fd7c34585c0745df3450fbcc84901c14921d149f7'
    'd94d6bc978f3420f6f1c0e660f6e64242066420f6e6c0e10660f745c2410660f'
    '74ec660fdbdd66440fd7cb4181f9ffff00007456458d48ff664521c14589c875'
    'b26666666666662e0f1f840000000000660f74d166440fd7c24585c075104801'
    'f84883c0104883c710e96bffffff488b44240866c70048004881c4780100005b'
    '415c415d415e415f5dc34d85ed745948b94b598638d6c56d344c89e048f7e148'
    'c1ea0b493b56300f85760600004869ca102700004c89e04829c8493b46100f83'
    '5f0600004d85ed792b498b4e08488d044048c1e004807c0128027518488b4424'
    '0866c7004e00eb90488b44240866c7004900eb844939dd7e0f488b44240866c7'
    '004b00e970ffffff418b471089442420f3410f6f07660f7f442410488d742410'
    '4889efe858f7e8ff4889c5488b4020488b5d00488d4d0848837d180048898424'
    '9000000048894c2478744a488b314885f60f84d9050000488b5510488d7c2410'
    'e83b46ceff488b4520488944242848837d3800743e488b75284885f60f84bb05'
    '0000488b5530488dbc24a0000000e86dc3cdffeb3648c74424100000000048c7'
    '44242000000000488944242848837d380075c248c78424a00000000000000048'
    'c78424b000000000000000498dbe88010000488b8424b0000000488984245001'
    '0000488b8424a00000004889842440010000488b8424a8000000488984244801'
    '0000488b455048898424680100008b45588984247001000048899c2418010000'
    '0f10442410f30f6f4c24200f11842420010000f30f7f8c24300100000f104540'
    '0f11842458010000418b471089442420f3410f6f07660f7f442410488d742410'
    'e86b42c9ff418b471089842410010000f3410f6f07660f7f8424000100004c89'
    'a424980000004c8b4c2478498b014885c00f847b000000488b4d100fb7b02203'
    '000089f7c1e70348c7c2ffffffff66904885ff74274c3ba4d0d0020000410f97'
    'c04180d80048ffc24883c7f84180f80174de410fb6f085f67419eb034889f248'
    '83e9010f82f6030000488b84d028030000eba8488944241848894c2420488954'
    '24284c894c243048c744241000000000eb134c894c24104c8964241848c74424'
    '2000000000488d7c2410488db424980000004c89f2e82660cbff488b4810448b'
    '500448898c24880000004885c9488944247844899424840000000f8493000000'
    '8338010f8596000000488d8424200100004c89a424a0000000488b8c24200100'
    '004885c90f84a0000000488b9424280100000fb7b9220300004189f841c1e003'
    '48c7c6ffffffff660f1f8400000000004d85c074274c3ba4f1d0020000410f97'
    'c14180d90048ffc64983c0f84180f90174de410fb6f985ff7431eb034889fe48'
    '83ea010f8218030000488b8cf128030000eb9f66b84a004531ede9f000000066'
    'b84d004531ede9e400000048894c241848895424204889742428488944243048'
    'c744241000000000eb1348894424104c8964241848c744242000000000488d7c'
    '2410488db424a00000004c89f2e80e5fcbff8338010f85f1020000488b48084c'
    '01e90f80ff02000048894808488b8424180100004c29e80f80f6020000488984'
    '24180100004d85ed79344d8d4e60450fb686ed0200004c893424488dbc241801'
    '0000be010000004c89e2b904000000ff157bd106024885c00f8815020000488b'
    '4c2478488b41084c01e80f80af02000048894108488b5d004889d84c29e80f80'
    'a70200004889450066b8860141b5014883c5204d8d8670010000668944241048'
    '8b442478488b50108b58044c89e7488bb424880000004889e9e872fdfeff399c'
    '24840000007419498dbe28010000488db424000100004c89e289d9e8a0700000'
    '0f104424600f298424f00000000f104424500f298424e0000000f30f6f442410'
    'f30f6f4c2420f30f6f542430f30f6f5c2440660f7f9c24d0000000660f7f9424'
    'c0000000660f7f8c24b0000000660f7f8424a0000000488b8c24200100004885'
    'c9743d488b942428010000488b84243001000048c74424180000000048894c24'
    '20488954242848c74424380000000048894c24404889542448b901000000eb04'
    '31c931c04c8da4244001000048894c241048894c24304889442450488d9c2400'
    '0100004c8d6c24100f1f8400000000004889df4c89eee825d0caff4883bc2400'
    '0100000075ea4c89e7e802b7ceff488b45004883bc24900000000074194885c0'
    '75404981c6580100004c89f74c89fee8cc58caffeb2c4885c074274981c65801'
    '0000418b471089442420f3410f6f07660f7f442410488d7424104c89f7e84e3e'
    'c9ff0f288424f0000000488b4424080f1140500f288424e00000000f1140400f'
    '288424a00000000f288c24b00000000f289424c00000000f289c24d00000000f'
    '1158300f1150200f1148100f1100e9a5f9ffff66b84c004531ede910feffff48'
    '8944242048c74424280000000048895424304c894c24104c89642418e924fcff'
    'ff48894c242048c744242800000000488974243048894424104c89642418e91a'
    'fdffff488d3dd6a9fe01ff15806c0602488d3d5932fe01ff15736c0602488d3d'
    '4c32fe01ff15666c0602eb19488d3d8617e9fc488d15cea6fe01be28000000ff'
    '15e36806020f0b66b8be004531ede97cfdffff4531ed66b8bf00e970fdffff45'
    '31ed66b8be00e964fdffff488d35a6a4fe0131ffff1536b9060231c04c39eb0f'
    '99c048b9ffffffffffffff7f4801c14c29eb480f40d94889d8e926fdffff4889'
    'c36681bc24a000000086017467488dbc24a0000000e876ac0500eb58ff158668'
    '06024889c34584ed7528488d7c2410e85cac0500eb1cff156c6806024889c34c'
    '89e7e829b5ceffeb2bff15596806024889c3488dbc2418010000e831a40500eb'
    '13ff15416806024889c3488d7c2410e85c61cfff4889dfe81488f501ff152668'
    '0602'
)
BODY_SHA256 = '0b52dd57f200034efd8942e488e5c59ac379bee95d77167ab278d474efd3d535'
BRANCHES = [
    (0x4c, '0f84dc000000', 2, 6, 0x370712e),
    (0xb1, '745d', 1, 2, 0x3707110),
    (0xf2, '7456', 1, 2, 0x370714a),
    (0xff, '75b2', 1, 2, 0x37070b3),
    (0x11c, '7510', 1, 2, 0x370712e),
    (0x129, 'e96bffffff', 1, 5, 0x3707099),
    (0x14d, '7459', 1, 2, 0x37071a8),
    (0x167, '0f8576060000', 2, 6, 0x37077e3),
    (0x17e, '0f835f060000', 2, 6, 0x37077e3),
    (0x187, '792b', 1, 2, 0x37071b4),
    (0x19a, '7518', 1, 2, 0x37071b4),
    (0x1a6, 'eb90', 1, 2, 0x3707138),
    (0x1b2, 'eb84', 1, 2, 0x3707138),
    (0x1b7, '7e0f', 1, 2, 0x37071c8),
    (0x1c3, 'e970ffffff', 1, 5, 0x3707138),
    (0x209, '744a', 1, 2, 0x3707255),
    (0x211, '0f84d9050000', 2, 6, 0x37077f0),
    (0x233, '743e', 1, 2, 0x3707273),
    (0x23c, '0f84bb050000', 2, 6, 0x37077fd),
    (0x253, 'eb36', 1, 2, 0x370728b),
    (0x271, '75c2', 1, 2, 0x3707235),
    (0x351, '0f847b000000', 2, 6, 0x37073d2),
    (0x373, '7427', 1, 2, 0x370739c),
    (0x390, '74de', 1, 2, 0x3707370),
    (0x398, '7419', 1, 2, 0x37073b3),
    (0x39a, 'eb03', 1, 2, 0x370739f),
    (0x3a3, '0f82f6030000', 2, 6, 0x370779f),
    (0x3b1, 'eba8', 1, 2, 0x370735b),
    (0x3d0, 'eb13', 1, 2, 0x37073e5),
    (0x41a, '0f8493000000', 2, 6, 0x37074b3),
    (0x423, '0f8596000000', 2, 6, 0x37074bf),
    (0x444, '0f84a0000000', 2, 6, 0x37074ea),
    (0x473, '7427', 1, 2, 0x370749c),
    (0x490, '74de', 1, 2, 0x3707470),
    (0x498, '7431', 1, 2, 0x37074cb),
    (0x49a, 'eb03', 1, 2, 0x370749f),
    (0x4a3, '0f8218030000', 2, 6, 0x37077c1),
    (0x4b1, 'eb9f', 1, 2, 0x3707452),
    (0x4ba, 'e9f0000000', 1, 5, 0x37075af),
    (0x4c6, 'e9e4000000', 1, 5, 0x37075af),
    (0x4e8, 'eb13', 1, 2, 0x37074fd),
    (0x515, '0f85f1020000', 2, 6, 0x370780c),
    (0x522, '0f80ff020000', 2, 6, 0x3707827),
    (0x537, '0f80f6020000', 2, 6, 0x3707833),
    (0x548, '7934', 1, 2, 0x370757e),
    (0x578, '0f8815020000', 2, 6, 0x3707793),
    (0x58a, '0f80af020000', 2, 6, 0x370783f),
    (0x59e, '0f80a7020000', 2, 6, 0x370784b),
    (0x5e5, '7419', 1, 2, 0x3707600),
    (0x661, '743d', 1, 2, 0x37076a0),
    (0x69e, 'eb04', 1, 2, 0x37076a4),
    (0x6e4, '75ea', 1, 2, 0x37076d0),
    (0x6fb, '7419', 1, 2, 0x3707716),
    (0x700, '7540', 1, 2, 0x3707742),
    (0x714, 'eb2c', 1, 2, 0x3707742),
    (0x719, '7427', 1, 2, 0x3707742),
    (0x78e, 'e9a5f9ffff', 1, 5, 0x3707138),
    (0x79a, 'e910feffff', 1, 5, 0x37075af),
    (0x7bc, 'e924fcffff', 1, 5, 0x37073e5),
    (0x7de, 'e91afdffff', 1, 5, 0x37074fd),
    (0x80a, 'eb19', 1, 2, 0x3707825),
    (0x82e, 'e97cfdffff', 1, 5, 0x37075af),
    (0x83a, 'e970fdffff', 1, 5, 0x37075af),
    (0x846, 'e964fdffff', 1, 5, 0x37075af),
    (0x879, 'e926fdffff', 1, 5, 0x37075a4),
    (0x88b, '7467', 1, 2, 0x37078f4),
    (0x89a, 'eb58', 1, 2, 0x37078f4),
    (0x8a8, '7528', 1, 2, 0x37078d2),
    (0x8b4, 'eb1c', 1, 2, 0x37078d2),
    (0x8c7, 'eb2b', 1, 2, 0x37078f4),
    (0x8df, 'eb13', 1, 2, 0x37078f4),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3707063, 0x399c7a0),
    (0x37071e3, 0x3596940),
    (0x3707220, 0x33eb860),
    (0x370724e, 0x33e35c0),
    (0x3707320, 0x339b590),
    (0x37073f5, 0x33bd420),
    (0x370750d, 0x33bd420),
    (0x37075d9, 0x36f7350),
    (0x37075fb, 0x370e6a0),
    (0x37076d6, 0x33b4700),
    (0x37076e9, 0x33f2df0),
    (0x370770f, 0x33acfe0),
    (0x370773d, 0x339b590),
    (0x3707895, 0x3762510),
    (0x37078af, 0x3762510),
    (0x37078c2, 0x33f2df0),
    (0x37078da, 0x3761d10),
    (0x37078ef, 0x33fda50),
    (0x37078f7, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3707028, 0x5774660),
    (0x370756f, 0x57746f0),
    (0x37077ea, 0x576e470),
    (0x37077f7, 0x576e470),
    (0x3707804, 0x576e470),
    (0x370781f, 0x576e108),
    (0x3707854, 0x5773190),
    (0x370789c, 0x576e128),
    (0x37078b6, 0x576e128),
    (0x37078c9, 0x576e128),
    (0x37078e1, 0x576e128),
    (0x37078fc, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37077e3, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x37077f0, 0x56eaa50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6d61702e7273'), 306, 46),
    (0x37077fd, 0x56eaa50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6d61702e7273'), 306, 46),
    (0x3707813, 0x56f1ee8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f636c656172696e67686f7573652e7273'), 1299, 29),
]
CALLERS = [0x2722159, 0x2722347, 0x272259b, 0x3709794, 0x4d27dbb, 0x4d27fa9, 0x4d28204, 0x4d2855b, 0x4d28749, 0x4d289a4]
CALLER_FUNCTIONS = {'0x2722159': ('0x2722010', '0x272278e'), '0x2722347': ('0x2722010', '0x272278e'), '0x272259b': ('0x2722010', '0x272278e'), '0x3709794': ('0x3709560', '0x3709894'), '0x4d27dbb': ('0x4d27c60', '0x4d283f7'), '0x4d27fa9': ('0x4d27c60', '0x4d283f7'), '0x4d28204': ('0x4d27c60', '0x4d283f7'), '0x4d2855b': ('0x4d28400', '0x4d28b97'), '0x4d28749': ('0x4d28400', '0x4d28b97'), '0x4d289a4': ('0x4d28400', '0x4d28b97')}
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

