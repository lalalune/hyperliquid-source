#!/usr/bin/env python3
"""Authenticated node94 vault-epoch-body binding (0x39582c0).

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

START, END = 0x39582c0, 0x3958b57
FDE_VA = 0x11c768c
FDE = bytes.fromhex(
    '50000000649a20002c0c79029708000004a31190ff410e10420e18420e20420e'
    '28420e30410e38470ed00183078c068d058e048f0386020313070e38410e3042'
    '0e28420e20420e18420e10410e08410ed0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec980000004c898c24880000004c898424800000'
    '0048894c245848895424404989f548897c2438488bbc24e00000004881c68400'
    '00004889742478e874dbffff4989c4498b4d0048898c24900000004883f9020f'
    '82610200004d8b4d08498b5d184d85c90f95c14885db0f95c220ca80fa010f85'
    '42020000498b6d104531f64c8d7c2410f6c1010f84ef0700004d85f67422410f'
    'b78ee60000004839cd0f83c10000004c89f14889eae9d9000000660f1f440000'
    '4885ed74384889e94d89ce4883e107743131d2666666662e0f1f840000000000'
    '4d8bb6e800000048ffc24839d175f14889ee4829d64883fd087315eb514d89ce'
    'eb4c4889ee4883fd0872430f1f440000498b8ee8000000488b89e8000000488b'
    '89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e80000'
    '004c8bb1e80000004883c6f875c24531c931ed410fb78ee60000004839cd0f82'
    '4bffffff6666662e0f1f840000000000498b0e4885c90f84fd05000049ffc141'
    '0fb796e40000004989ce663b91e600000073dd4d85c90f8494000000488d34d1'
    '4881c6f00000004c89cf4883e7070f84cc0000004531c0660f1f840000000000'
    '4c8b36498db6e800000049ffc04c39c775ee4c89cf4c29c74983f90872436690'
    '488b06488b80e8000000488b80e8000000488b80e8000000488b80e800000048'
    '8b80e8000000488b80e80000004c8bb0e8000000498db6e80000004883c7f875'
    'bf31edeb1266662e0f1f840000000000488d6a014989ce488d04928b54811889'
    '5424200f104481080f29442410488bbc24e00000004c89fee863d9ffff4c89e1'
    '4801c170294989ccb10141b90000000048ffcb0f8517feffffeb4b0f1f440000'
    '4c89cf4983f9087298e952ffffff48c1f93f48be00000000000000804831f149'
    '01c44c0f40e131ff488d357954db01ff151bace101b10141b90000000048ffcb'
    '0f85cafdffff4d85e40f8ec7000000498b6d504885ed488b5c24380f84820100'
    '004c896424684c896c2470498b45584889442430488b1dcd5ee101488db51802'
    '00000fb785f60200004c8d75d048894424608d0485000000004c8d248049c7c5'
    'ffffffff6666662e0f1f8400000000004d85e4743b4c8d7e14ba14000000488b'
    '7c2440ffd348984885c00f98c10f9fc028c84983c63049ffc54983c4ec4c89fe'
    '3c0174cc0fb6c085c0750aeb370f1f004c8b6c2460488b4424304883e8010f82'
    '5602000048894424304a8bacedf8020000e965ffffff66b80a00488b5c2438e9'
    '730300004c8bac24900000004183fd01488b5c24384c8b7c2470744c418b462c'
    '89442418498b46244889442410f2410f1047704889e7488d742410ff151769e1'
    '01488b8c24880000008b013b04240f9cc075798b41043b4424040f92c0756d8b'
    '41083b44240872684c89ff488bb424e0000000488b542440ff1562dbe101f241'
    '0f102e488b6c2468f2480f2ae5660f28ccf20f5e0d67278bfcf6442458017439'
    'f20f100578298bfc660f2ec1488b8c24800000007646488d3de352db01ff154d'
    '5de10166b80b00e9ab02000084c0749866b80c00e99e020000f20f10053f298b'
    'fc660f2ec10f87e10200008b0d4724e20185c90f852c0300004889c166480f6e'
    'c1660f620517b78afc660f5c052fa78afc660f28d8660f15d8f20f58d8f20f5e'
    '1ddb268bfcf20f5ed9660f2edd0f87b7000000f20f10052d288bfc660f2ec30f'
    '87a50000004839c166b80d000f8725020000488b8424e0000000488b38488b44'
    '2440f30f6f00f3410f6f8f98000000660f74c8660f6e401066410f6e97a80000'
    '00660f74d0660fdbd1660fd7c23dffff0000746df20f59e366480f7ee148b8ff'
    'ffffffffffff7f4821c1660f57c048baffffffffffffef7f4839d10f8ff50000'
    '00f20f100d8f248bfc660f2ecc0f87d3000000660f2e25b51f8bfc0f87c50000'
    '00660f28c4e9cc0000008b054823e20185c00f85f001000066b80e00e9760100'
    '00f20f5cebf20f1005c31e8bfcf20f5cc3f20f5905471c8bfcf20f100d47278b'
    'fcf20f58cd660f2ec1761dff15f76be10166b80f00e93d010000488b5c243866'
    'b80b00e92f0100000f57e4f2480f2ae5f20f59ec66480f7ee948b8ffffffffff'
    'ffff7f4821c1660f57c048baffffffffffffef7f4839d10f8f22010000f20f10'
    '0dd3238bfc660f2ecd0f8700010000660f2e2df91e8bfc0f87f2000000660f28'
    'c5e9f9000000f20f5fccf20f1005de1e8bfcf20f5dc1f2480f2cc8660f2e05a5'
    '198bfc480f47c84531f6660f2ec04c0f4bf1488b8c24d0000000f6c101741a48'
    '89e94c29f10f80ac01000066b81001483b8c24d80000007c7e4183fd01750431'
    'c0eb5e660f295c2440488b4c24788b411089442420660f1001660f2944241048'
    '8d742410ff15d6bce1014939c67e19660f285c2440660f28c3f20f5f05c71d8b'
    'fcb801000000eb194180bfae00000000660f285c244074a7b801000000660f28'
    'c348894308f20f1143104c897318f20f115b2066b886016689034889d84881c4'
    '980000005b415c415d415e415f5dc3f20f5fcdf20f1005f51d8bfcf20f5dc1f2'
    '480f2cc8660f2e05bc188bfc480f47c831c0660f2ec0480f4bc1483d00e1f505'
    '66b810000f8dcafdffffebab488d3de54fdb01ff15375ae101488d3da815d901'
    'ff152a5ae1010f0b488d053121e201488904244889e04889442410488d3d3621'
    'e201488d0dff14d1014c8d05e014d101488d542410be01000000ff15385ee101'
    'e9d3fdffff488d0df420e20148890c244889e148894c2410488d3df920e20148'
    '8d0dc214d1014c8d05a314d101488d542410be010000004989de4889c3f20f11'
    '642430f20f116c2460f20f114c2458ff15e35de101f20f104c2458f20f106c24'
    '60f20f10642430488b6c24684889d84c89f3e962fcffff0f99c10fb6c94801c1'
    '4c29f5488d357e4edb01480f40e94989dc4889fb31ff660f295c2440ff156ea6'
    'e101660f285c24404889df4c89e34889e966b81001483b8c24d80000000f8d16'
    'feffffe98ffeffff488d3dd1ffd801ff151b59e1010f0b'
)
BODY_SHA256 = 'f1c2bf29084c7ea86c3425e9d6575e8edc90bcea1d5fa3e90faf9932a6facaf9'
BRANCHES = [
    (0x5f, '0f8261020000', 2, 6, 0x3958586),
    (0x7e, '0f8542020000', 2, 6, 0x3958586),
    (0x93, '0f84ef070000', 2, 6, 0x3958b48),
    (0x9c, '7422', 1, 2, 0x3958380),
    (0xa9, '0f83c1000000', 2, 6, 0x3958430),
    (0xb5, 'e9d9000000', 1, 5, 0x3958453),
    (0xc3, '7438', 1, 2, 0x39583bd),
    (0xcf, '7431', 1, 2, 0x39583c2),
    (0xed, '75f1', 1, 2, 0x39583a0),
    (0xf9, '7315', 1, 2, 0x39583d0),
    (0xfb, 'eb51', 1, 2, 0x395840e),
    (0x100, 'eb4c', 1, 2, 0x395840e),
    (0x109, '7243', 1, 2, 0x395840e),
    (0x14c, '75c2', 1, 2, 0x39583d0),
    (0x15e, '0f824bffffff', 2, 6, 0x395836f),
    (0x176, '0f84fd050000', 2, 6, 0x3958a39),
    (0x191, '73dd', 1, 2, 0x3958430),
    (0x196, '0f8494000000', 2, 6, 0x39584f0),
    (0x1ae, '0f84cc000000', 2, 6, 0x3958540),
    (0x1d0, '75ee', 1, 2, 0x3958480),
    (0x1dc, '7243', 1, 2, 0x39584e1),
    (0x21f, '75bf', 1, 2, 0x39584a0),
    (0x223, 'eb12', 1, 2, 0x39584f7),
    (0x263, '7029', 1, 2, 0x395854e),
    (0x273, '0f8517feffff', 2, 6, 0x3958350),
    (0x279, 'eb4b', 1, 2, 0x3958586),
    (0x287, '7298', 1, 2, 0x39584e1),
    (0x289, 'e952ffffff', 1, 5, 0x39584a0),
    (0x2c0, '0f85cafdffff', 2, 6, 0x3958350),
    (0x2c9, '0f8ec7000000', 2, 6, 0x3958656),
    (0x2db, '0f8482010000', 2, 6, 0x3958723),
    (0x333, '743b', 1, 2, 0x3958630),
    (0x362, '74cc', 1, 2, 0x39585f0),
    (0x369, '750a', 1, 2, 0x3958635),
    (0x36b, 'eb37', 1, 2, 0x3958664),
    (0x37e, '0f8256020000', 2, 6, 0x395889a),
    (0x391, 'e965ffffff', 1, 5, 0x39585bb),
    (0x39f, 'e973030000', 1, 5, 0x39589d7),
    (0x3ba, '744c', 1, 2, 0x39586c8),
    (0x3f1, '7579', 1, 2, 0x395872c),
    (0x3fd, '756d', 1, 2, 0x395872c),
    (0x406, '7268', 1, 2, 0x3958730),
    (0x43e, '7439', 1, 2, 0x3958739),
    (0x454, '7646', 1, 2, 0x395875c),
    (0x467, 'e9ab020000', 1, 5, 0x39589d7),
    (0x46e, '7498', 1, 2, 0x39586c8),
    (0x474, 'e99e020000', 1, 5, 0x39589d7),
    (0x485, '0f87e1020000', 2, 6, 0x3958a2c),
    (0x493, '0f852c030000', 2, 6, 0x3958a85),
    (0x4cd, '0f87b7000000', 2, 6, 0x395884a),
    (0x4df, '0f87a5000000', 2, 6, 0x395884a),
    (0x4ec, '0f8725020000', 2, 6, 0x39589d7),
    (0x532, '746d', 1, 2, 0x3958861),
    (0x55b, '0f8ff5000000', 2, 6, 0x3958916),
    (0x56d, '0f87d3000000', 2, 6, 0x3958906),
    (0x57b, '0f87c5000000', 2, 6, 0x3958906),
    (0x585, 'e9cc000000', 1, 5, 0x3958916),
    (0x592, '0f85f0010000', 2, 6, 0x3958a48),
    (0x59c, 'e976010000', 1, 5, 0x39589d7),
    (0x5c9, '761d', 1, 2, 0x39588a8),
    (0x5d5, 'e93d010000', 1, 5, 0x39589d7),
    (0x5e3, 'e92f010000', 1, 5, 0x39589d7),
    (0x617, '0f8f22010000', 2, 6, 0x39589ff),
    (0x629, '0f8700010000', 2, 6, 0x39589ef),
    (0x637, '0f87f2000000', 2, 6, 0x39589ef),
    (0x641, 'e9f9000000', 1, 5, 0x39589ff),
    (0x67d, '741a', 1, 2, 0x3958959),
    (0x685, '0f80ac010000', 2, 6, 0x3958af7),
    (0x697, '7c7e', 1, 2, 0x39589d7),
    (0x69d, '7504', 1, 2, 0x3958963),
    (0x6a1, 'eb5e', 1, 2, 0x39589c1),
    (0x6cd, '7e19', 1, 2, 0x39589a8),
    (0x6e6, 'eb19', 1, 2, 0x39589c1),
    (0x6f6, '74a7', 1, 2, 0x395895f),
    (0x764, '0f8dcafdffff', 2, 6, 0x39587f4),
    (0x76a, 'ebab', 1, 2, 0x39589d7),
    (0x7c0, 'e9d3fdffff', 1, 5, 0x3958858),
    (0x832, 'e962fcffff', 1, 5, 0x3958759),
    (0x87d, '0f8d16feffff', 2, 6, 0x3958959),
    (0x883, 'e98ffeffff', 1, 5, 0x39589d7),
]
DIRECT_CALLS = [
    (0x3958307, 0x3955e80),
    (0x3958518, 0x3955e80),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x395856f, 0x5773190),
    (0x395869b, 0x576efb8),
    (0x39586d8, 0x5776240),
    (0x395871d, 0x576e470),
    (0x395888b, 0x576f488),
    (0x3958984, 0x5774660),
    (0x3958a33, 0x576e470),
    (0x3958a40, 0x576e470),
    (0x3958a7a, 0x576e8b8),
    (0x3958acf, 0x576e8b8),
    (0x3958b1c, 0x5773190),
    (0x3958b4f, 0x576e470),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3958716, 0x570da00, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f7661756c742f6d6f642e7273'), 626, 71),
    (0x3958a2c, 0x570da18, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f7661756c742f6d6f642e7273'), 621, 93),
    (0x3958a39, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3958b48, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774b50']
GOT_SITES = {'0x5774b50': '0x4d46888'}


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

