#!/usr/bin/env python3
"""Authenticated node94 spot-meta-2748d70 binding (0x2748d70).

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

START, END = 0x2748d70, 0x2749873
FDE_VA = 0xd819e0
FDE = bytes.fromhex(
    '4c000000cc040a0088739c01030b000000410e10420e18420e20420e28420e30'
    '410e38470e900683078c068d058e048f03860203be010e38410e30420e28420e'
    '20420e18420e10410e08410e90060000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecd80200004c8b8e680400004d85c90f84670100'
    '004c8d96680400004c8b9e70040000450fb77162498d414f4589f741c1e70348'
    'c7c3ffffffff662e0f1f8400000000004d85ff742b493b4cd910400f97c54080'
    'dd004883c01548ffc34983c7f84080fd0174dd400fb6ed85ed741ceb060f1f00'
    '4c89f34983eb010f82fb0000004d8b8cd950010000eb984c898c24800200004c'
    '899c248802000048899c24900200004c899424980200000f10000f2944244044'
    '8b481044894c2450440fb64814448b501044899424b0010000f30f6f00660f7f'
    '8424a00100004c8b9e10020000488b9e180200004885db74664c69f3e8000000'
    '4d8dbbbd0000004c8d15aa0ae5fdeb104981c7e80000004981c618ffffff743f'
    '41f647ff0174e9f3410f6f0766410f6e4f10660f6e9424b0010000660f748424'
    'a0010000660f74d1660fdbc2660fd7e881fdffff000075b8b827000000eb5948'
    '39d90f835b0900004c69f9e80000004380bc3bbc0000000074284c8d155e0ae5'
    'fdb818000000eb3066c707df00488d057a6fcafd4889470848c747101c000000'
    'eb234180c1ed4180f9eb732e4c8d15440ae5fdb83000000066c707df004c8957'
    '08488947104889f84881c4d80200005b415c415d415e415f5dc34d8b084d85c9'
    '0f84de000000488954241048894c240848893c244183f9010f85510100008b48'
    '10894c24300f10000f294424204889f34881c6e00b00008b4810898c24d00000'
    '000f10000f298424c0000000488dbc24a0010000488d9424c0000000e8ff7f08'
    '014883bc24a0010000000f84da020000488db3f01d00008b442430898424d001'
    '00000f284424200f298424c00100000f57c00f298424a00100000f298424b001'
    '0000488dbc24c0000000488d9424a0010000e8c981080180bc24c0000000000f'
    '84d60200000f108424c8000000f30f6f8c24d8000000660f7f8c2490000000e9'
    'c2020000498b400849b8cccccccccccccc0c4c39c00f83400200004c0fbdc041'
    '83f03841c1e8034d89c14983f11f483d80000000bb17000000490f43d9448d4b'
    'bf44884c2461c64424629448c744247700000000c644247f000f10020f114424'
    '638b5210895424734989cd4989f44889fd4885c00f8403050000483d80000000'
    '0f83fe04000088442477e925050000660fefc0660f7f842480010000660f7f84'
    '2470010000660f7f842460010000660f7f842450010000660f7f842440010000'
    '660f7f842430010000660f7f842420010000660f7f842410010000660f7f8424'
    '00010000660f7f8424f0000000660f7f8424e0000000660f7f8424d000000066'
    '0f7f8424c000000048c78424900100008800000066c78424980100000100488d'
    '05de6ccafd4c8da424c0000000ba120000004c89e74889f34889c6ff15675002'
    '034c8db424a0010000bae00000004c89f74c89e6ff15564e0203488d742420ba'
    '200000004c89f7ff15435002034c8b6c24384c8b6424304c8b742420488b6c24'
    '2848895c2418488db3e00b00008b442450898424d00000000f284424400f2984'
    '24c0000000488dbc24a0010000488d9424c0000000e8c67d08014883bc24a001'
    '0000000f84c7000000490fce480fcd490fcc490fcd488b442418488db0f01d00'
    '008b442450898424d00100000f284424400f118424c00100004c89ac24a00100'
    '004c89a424a80100004889ac24b00100004c89b424b8010000488dbc24c00000'
    '00488d9424a0010000e8727f080180bc24c0000000000f84df0100000f108424'
    'c8000000f30f6f8c24d8000000660f7f8c24b0000000e9cb01000066c7073f01'
    'b908000000e96c0400000f57c00f298424900000000f29842480000000488b3c'
    '244889d8488b4c24084c8b642410eb4f0f57c00f298424b00000000f298424a0'
    '000000488b3c24488b442418488b4c24084c8b642410e9860100000f57c00f29'
    '8424900000000f29842480000000488b3c24488b4c24084c8b6424104889d841'
    '0fb654240e48c1e228410fb674240f48c1e6204809d6410fb6542410c1e21848'
    '09f2410fb6742411c1e6104809d6410fb6542412c1e208450fb64424134909f0'
    '4909d0410fb674240d48c1e630410fb654240c48c1e2384809f24c01c2410fb6'
    '74240648c1e628450fb644240749c1e0204909f0410fb6742408c1e6184c09c6'
    '450fb644240941c1e0104909f0410fb674240ac1e608450fb64c240b4d09c149'
    '09f1410fb674240548c1e630450fb644240449c1e0384909f04d01c8418b3424'
    '0fce48899424a00100004c898424a80100004889b424b001000048c78424b801'
    '000000000000f30f6f8424a0010000f30f6f8c24b0010000660f748c24900000'
    '00660f74842480000000660fdbc1660fd7d081faffff00000f84ea02000066c7'
    '07df00488d05c169cafd4889470848c7471038000000e9eafaffff0f57c00f29'
    '8424b00000000f298424a0000000488b3c24488b4c24084c8b642410488b4424'
    '18410fb654240e48c1e228410fb674240f48c1e6204809d6410fb6542410c1e2'
    '184809f2410fb6742411c1e6104809d6410fb6542412c1e208450fb644241349'
    '09f04909d0410fb674240d48c1e630410fb654240c48c1e2384809f24c01c241'
    '0fb674240648c1e628450fb644240749c1e0204909f0410fb6742408c1e6184c'
    '09c6450fb644240941c1e0104909f0410fb674240ac1e608450fb64c240b4d09'
    'c14909f1410fb674240548c1e630450fb644240449c1e0384909f04d01c8418b'
    '34240fce48899424a00100004c898424a80100004889b424b001000048c78424'
    'b801000000000000f30f6f8424a0010000f30f6f8c24b0010000660f748c24b0'
    '000000660f748424a0000000660fdbc1660fd7d081faffff00000f8488010000'
    '66c707df00488d05a968cafd4889470848c7471039000000e988f9ffffc64424'
    '7780eb30480fc848898424a0010000ba080000004c29c28d42804a8d34044881'
    'c6a001000088442477488d7c2478ff15fc4902030f57c00f298424800100000f'
    '298424700100000f298424600100000f298424500100000f298424400100000f'
    '298424300100000f298424200100000f298424100100000f298424000100000f'
    '298424f00000000f298424e00000000f298424d00000000f298424c000000048'
    'c78424900100008800000066c784249801000001004c8db424c0000000488d74'
    '24614c89f74889daff155a4b0203488d9c24a0010000bae00000004889df4c89'
    'f6ff1549490203488d742420ba200000004889dfff15364b0203f30f6f44242c'
    '660f7f8424a00200008b44243c898424b0020000660f6e4c245066480f6ed066'
    '0f74442440660f74d1660fdbc2660fd7c03dffff000074274889ef66c74500df'
    '00488d056766cafd48894508b89c000000b9100000004889040fe926f8ffff48'
    '89ef4c89e04c89e9483b88180200000f831b0100004889fb4c03b810020000c6'
    '44242000488dbc24a0010000488db42480020000488d542420e812ae3dff0f10'
    '8424a00100000f108c24b00100000f298c24d00000000f298424c0000000488b'
    '84249802000048ff4810807c242001753e488b384885ff0f84c0000000488b48'
    '084885c90f84c0000000488b975001000048891048ffc94889480848c7020000'
    '0000beb001000031d2ff15514802030f288424c00000000f288c24d00000000f'
    '298c24b00100000f298424a00100000f108424a80100000f298424c000000048'
    '8b8424b501000048898424cd00000041c687bc000000010f288424c000000041'
    '0f1187bd000000488b8424cd000000498987ca0000004889df66c7038601e902'
    'f7ffff488d3db689fa02ff15304c0203488d3dc189fa02ff15234c0203488d3d'
    'bcbcf702ff15164c0203488d3d37a5c6fd488d1548ecf302be21000000ff1595'
    '480203'
)
BODY_SHA256 = '23a532a344be9c68b3f240d12181cf1bd1d5b40ece36044b581a7ceeed9f5b25'
BRANCHES = [
    (0x1b, '0f8467010000', 2, 6, 0x2748ef8),
    (0x53, '742b', 1, 2, 0x2748df0),
    (0x71, '74dd', 1, 2, 0x2748dc0),
    (0x79, '741c', 1, 2, 0x2748e07),
    (0x7b, 'eb06', 1, 2, 0x2748df3),
    (0x87, '0f82fb000000', 2, 6, 0x2748ef8),
    (0x95, 'eb98', 1, 2, 0x2748d9f),
    (0xf7, '7466', 1, 2, 0x2748ecf),
    (0x10e, 'eb10', 1, 2, 0x2748e90),
    (0x11e, '743f', 1, 2, 0x2748ecf),
    (0x125, '74e9', 1, 2, 0x2748e80),
    (0x156, '75b8', 1, 2, 0x2748e80),
    (0x15d, 'eb59', 1, 2, 0x2748f28),
    (0x162, '0f835b090000', 2, 6, 0x2749833),
    (0x178, '7428', 1, 2, 0x2748f12),
    (0x186, 'eb30', 1, 2, 0x2748f28),
    (0x1a0, 'eb23', 1, 2, 0x2748f35),
    (0x1aa, '732e', 1, 2, 0x2748f4a),
    (0x1e0, '0f84de000000', 2, 6, 0x2749034),
    (0x1f8, '0f8551010000', 2, 6, 0x27490bf),
    (0x24a, '0f84da020000', 2, 6, 0x274929a),
    (0x29f, '0f84d6020000', 2, 6, 0x27492eb),
    (0x2bf, 'e9c2020000', 1, 5, 0x27492f6),
    (0x2d5, '0f8340020000', 2, 6, 0x274928b),
    (0x334, '0f8403050000', 2, 6, 0x27495ad),
    (0x340, '0f83fe040000', 2, 6, 0x27495b4),
    (0x34a, 'e925050000', 1, 5, 0x27495e4),
    (0x483, '0f84c7000000', 2, 6, 0x27492c0),
    (0x4f6, '0f84df010000', 2, 6, 0x274944b),
    (0x516, 'e9cb010000', 1, 5, 0x2749456),
    (0x525, 'e96c040000', 1, 5, 0x2749706),
    (0x54e, 'eb4f', 1, 2, 0x274930f),
    (0x576, 'e986010000', 1, 5, 0x2749471),
    (0x6b8, '0f84ea020000', 2, 6, 0x2749718),
    (0x6d6, 'e9eafaffff', 1, 5, 0x2748f35),
    (0x81a, '0f8488010000', 2, 6, 0x2749718),
    (0x838, 'e988f9ffff', 1, 5, 0x2748f35),
    (0x842, 'eb30', 1, 2, 0x27495e4),
    (0x976, '7427', 1, 2, 0x274970f),
    (0x99a, 'e926f8ffff', 1, 5, 0x2748f35),
    (0x9af, '0f831b010000', 2, 6, 0x2749840),
    (0xa0f, '753e', 1, 2, 0x27497bf),
    (0xa17, '0f84c0000000', 2, 6, 0x274984d),
    (0xa24, '0f84c0000000', 2, 6, 0x274985a),
    (0xabe, 'e902f7ffff', 1, 5, 0x2748f35),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2748fac, 0x37d0fb0),
    (0x2749002, 0x37d11d0),
    (0x27491e5, 0x37d0fb0),
    (0x2749259, 0x37d11d0),
    (0x2749749, 0x1b24560),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x274916b, 0x576e1d8),
    (0x2749184, 0x576dfe0),
    (0x2749197, 0x576e1e0),
    (0x27495de, 0x576dfe0),
    (0x2749678, 0x576e1d8),
    (0x2749691, 0x576dfe0),
    (0x27496a4, 0x576e1e0),
    (0x27497b9, 0x576e010),
    (0x274983a, 0x576e470),
    (0x2749847, 0x576e470),
    (0x2749854, 0x576e470),
    (0x274986d, 0x576e108),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2749833, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2749840, 0x56f2208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 119, 37),
    (0x274984d, 0x56c5510, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6d61702f656e7472792e7273'), 614, 42),
    (0x2749861, 0x56884b0, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e6f64652e7273'), 618, 9),
]
CALLERS = [0x22ce111]
CALLER_FUNCTIONS = {'0x22ce111': ('0x22ce0d0', '0x22ce178')}
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

