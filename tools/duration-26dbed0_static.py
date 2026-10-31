#!/usr/bin/env python3
"""Authenticated node94 duration-26dbed0 binding (0x26dbed0).

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

START, END = 0x26dbed0, 0x26dc77f
FDE_VA = 0x10ec580
FDE = bytes.fromhex(
    '5000000058e9120048f95e01af0800000463fa92ff410e10420e18420e20420e'
    '28420e30410e38470ed00783078c068d058e048f038602035c080e38410e3042'
    '0e28420e20420e18420e10410e08410ed0070000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec980300004c894424684889742410488d471848'
    '894424404c8b6f184d85ed488954243848894c243048897c24180f84d5000000'
    '488b472048894424284c8b2568250903410fb785ee01000048894424208d0485'
    '000000004c8d348049f7de41bf1000000048c7c5ffffffffbb100100000f1f00'
    '498d041e483d1001000074444a8d342bba14000000488b7c241041ffd4489848'
    '85c00f98c10f9fc028c84983c7e848ffc54883c3143c0174c70fb6c085c07436'
    'eb1366666666662e0f1f840000000000488b6c2420488b4424284883e8010f82'
    'df06000048894424284d8bacedf0010000e95affffff4d29fd4c8b7c24384c8b'
    '642430498b5d004885db0f85c7000000e9510700004989cc4989d74531ed488b'
    '542410488b02488b4a088b52108954240848890c24488b4c244048898c243001'
    '00004c89ac243801000048c7842440010000000000004889ac24480100004889'
    '842450010000488b042448898424580100008b442408898424600100008b4424'
    '0c8984246401000048c74424500000000048c744246000000000488d7c247048'
    '8db42430010000488d542450e8ffd91900488b442470488b8c2480000000488d'
    '0c494c8d2cc84983c508498b5d004885db0f848f060000498b45080fb7938204'
    '000089d1c1e105488d344948c7c1ffffffff4531ed66662e0f1f840000000000'
    '4c39ee742b4c3bbccb30040000400f97c74080df004983c56048ffc14080ff01'
    '74de400fb6d785d2741deb070f1f40004889d14883e8010f8229060000488b9c'
    'cb88040000eb94428b442be8894424584a8b4c2be048894c2450894424784889'
    '4c2470488d742474488dbc2430010000ba1e00000031c9ff155b270903488b84'
    '243801000048b9000000004057ffff4801c148ba81aefeff7faefeff4839d10f'
    '82d3050000448bb424300100008bac24340100008b7c247048b9572951cea0c8'
    '451848f7e94889d648c1ee3f48c1ea0d01d6ff150827090385c00f8498050000'
    '8904244489742404896c2408498d4c246048894c2448413b4424600f9cc07516'
    '453b7424640f92c0750c413b6c2468720de9cd00000084c00f84c5000000488b'
    '4c24488b410889442478488b0148894424708b44240889842438010000488b04'
    '24488984243001000048b801000000540000004889842440010000488d0533d5'
    'edfd488984244801000048c78424500100002b000000488d7c2470488db42430'
    '010000ff1567260903660f57c9660f2ec10f823b040000f20f5e0531dfb2fdff'
    '1553850903660f57c9660f2ec10f8238040000f20f590515dfb2fd488dbc2430'
    '0100004889e6ff151c2d09038b84243801000089442408488b84243001000048'
    '8904244a8d042b4883c0e08b4c2408894808488b0c244889084a8b4c2bd848ff'
    'c148c7c0ffffffff480f45c14a8b4c2bc84a89442bd84a3b4c2ba80f83c80000'
    '00f2420f104c2bb0660f57c0660f2ec80f829c030000f20f5e0deae8b2fd6648'
    '0f7ec948baffffffffffffff7f4821ca48b9ffffffffffffef7f4839ca7f2a66'
    '0f57d2660f2ed17710660f2e0dcfe1b2fd7706660f28c1eb10f20f5fd1f20f10'
    '05bbe1b2fdf20f5dc2f2480f2cc84889ca48c1fa3f660f28c8f20f5c0d7fe4b2'
    'fdf2480f2cf14821d64809ce31c9660f57c9660f2ec1480f43ce660f2e0586de'
    'b2fd48c7c2ffffffff480f47ca4885c90f882e0300004801c948ffc1480f44ca'
    '4839c80f8632030000488b4c24108b4110898424800000000f10010f29442470'
    '4c897c2450488b442440488b084885c90f84d0000000488b442418488b402048'
    '89442420488d6c24704c8b2588200903488db1100100000fb781ee0100004889'
    '4c2428488d59f048894424188d0485000000004c8d3c8049c7c6ffffffff6690'
    '4d85ff743b4c8d6e14ba140000004889ef41ffd448984885c00f98c10f9fc028'
    'c84883c31849ffc64983c7ec4c89ee3c0174cd0fb6c085c0742deb090f1f4000'
    '4c8b742418488b4424204883e801488b4c2428723148894424204a8b8cf1f001'
    '0000e969ffffff488dbc2430010000488d5424504889dee8e4c2180080bc2452'
    '01000002751c66c7842430010000ce00488dbc2430010000e8d3260a00e96402'
    '00000fb7ac24300100000f108424320100000f298424d00000000f1084244201'
    '00000f298424e00000000f108424520100000f298424f00000000f1084246201'
    '00000f298424000100000f108424720100000f298424100100000f1084248001'
    '00000f1184241e01000048837b1000488b5c24384c8b742430752f488dbc2430'
    '010000488d542470488b742440e8feba18004883bc243001000000740d488dbc'
    '2438010000e8062b1d0066896c24700f288424d00000000f288c24e00000000f'
    '289424f00000000f289c24000100000f114424720f118c24820000000f119424'
    '920000000f119c24a20000000f288424100100000f118424b20000000f108424'
    '1e0100000f118424c00000004981c690000000488dbc2438010000488d742470'
    '4c89f2e8584ec3ff488b4c24108b4110898424cc0100000f10010f118424bc01'
    '000048b80200000000000080488984249001000048899c24a8010000488b4c24'
    '48488b0148898424b00100008b4108898424b801000048c78424300100000400'
    '00004c8b742468498b5e10493b1e75094c89f7ff15e77609034869fb68020000'
    '49037e08488db42430010000ba68020000ff155919090348ffc349895e10e9a3'
    '0000004c8b7c24384c8b642430e94cf9ffff488d3db0d8b3fd488d1548e7f802'
    'be1e000000ff154d1a0903488d3dafd6b3fd488d158fe4f802be1c000000ff15'
    '341a090348c7c1ffffffff48ffc1480f44ca4839c80f87cefcffff8b44240889'
    '842440010000488b04244889842438010000488b4424100f10000f1184244401'
    '00008b4010898424540100004c89bc2430010000488db42430010000488b7c24'
    '18e8aa380c004881c4980300005b415c415d415e415f5dc3488d3dd0d8b3fd48'
    '8d15c2e7f802be26000000ff15071d09034889c3488dbc2430010000e83fe509'
    '004889dfe89739f802ff15a9190903'
)
BODY_SHA256 = 'fbe11be9a7c70e251249b74a1519182b2aac9551dfe8fb0576ad467a6e606a02'
BRANCHES = [
    (0x3a, '0f84d5000000', 2, 6, 0x26dbfe5),
    (0x8a, '7444', 1, 2, 0x26dbfa0),
    (0xb7, '74c7', 1, 2, 0x26dbf50),
    (0xbe, '7436', 1, 2, 0x26dbfc6),
    (0xc0, 'eb13', 1, 2, 0x26dbfa5),
    (0xde, '0f82df060000', 2, 6, 0x26dc693),
    (0xf1, 'e95affffff', 1, 5, 0x26dbf20),
    (0x10a, '0f85c7000000', 2, 6, 0x26dc0a7),
    (0x110, 'e951070000', 1, 5, 0x26dc736),
    (0x1d1, '0f848f060000', 2, 6, 0x26dc736),
    (0x203, '742b', 1, 2, 0x26dc100),
    (0x220, '74de', 1, 2, 0x26dc0d0),
    (0x228, '741d', 1, 2, 0x26dc117),
    (0x22a, 'eb07', 1, 2, 0x26dc103),
    (0x237, '0f8229060000', 2, 6, 0x26dc736),
    (0x245, 'eb94', 1, 2, 0x26dc0ab),
    (0x29f, '0f82d3050000', 2, 6, 0x26dc748),
    (0x2da, '0f8498050000', 2, 6, 0x26dc748),
    (0x2fe, '7516', 1, 2, 0x26dc1e6),
    (0x308, '750c', 1, 2, 0x26dc1e6),
    (0x30f, '720d', 1, 2, 0x26dc1ee),
    (0x311, 'e9cd000000', 1, 5, 0x26dc2b3),
    (0x318, '0f84c5000000', 2, 6, 0x26dc2b3),
    (0x391, '0f823b040000', 2, 6, 0x26dc6a2),
    (0x3ad, '0f8238040000', 2, 6, 0x26dc6bb),
    (0x41b, '0f83c8000000', 2, 6, 0x26dc3b9),
    (0x430, '0f829c030000', 2, 6, 0x26dc6a2),
    (0x45d, '7f2a', 1, 2, 0x26dc359),
    (0x467, '7710', 1, 2, 0x26dc349),
    (0x471, '7706', 1, 2, 0x26dc349),
    (0x477, 'eb10', 1, 2, 0x26dc359),
    (0x4d0, '0f882e030000', 2, 6, 0x26dc6d4),
    (0x4e3, '0f8632030000', 2, 6, 0x26dc6eb),
    (0x510, '0f84d0000000', 2, 6, 0x26dc4b6),
    (0x563, '743b', 1, 2, 0x26dc470),
    (0x591, '74cd', 1, 2, 0x26dc430),
    (0x598, '742d', 1, 2, 0x26dc497),
    (0x59a, 'eb09', 1, 2, 0x26dc475),
    (0x5b3, '7231', 1, 2, 0x26dc4b6),
    (0x5c2, 'e969ffffff', 1, 5, 0x26dc400),
    (0x5e4, '751c', 1, 2, 0x26dc4d2),
    (0x5fd, 'e964020000', 1, 5, 0x26dc736),
    (0x679, '752f', 1, 2, 0x26dc57a),
    (0x69b, '740d', 1, 2, 0x26dc57a),
    (0x78e, '7509', 1, 2, 0x26dc669),
    (0x7be, 'e9a3000000', 1, 5, 0x26dc736),
    (0x7cd, 'e94cf9ffff', 1, 5, 0x26dbfee),
    (0x815, '0f87cefcffff', 2, 6, 0x26dc3b9),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26dc07c, 0x2879a80),
    (0x26dc4a7, 0x2868790),
    (0x26dc4c8, 0x277eba0),
    (0x26dc55d, 0x2868060),
    (0x26dc575, 0x28af080),
    (0x26dc5f3, 0x2311450),
    (0x26dc731, 0x279ffe0),
    (0x26dc76c, 0x277acb0),
    (0x26dc774, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26dc147, 0x576e8a8),
    (0x26dc1a2, 0x576e8b0),
    (0x26dc253, 0x576e8c0),
    (0x26dc26f, 0x57747c8),
    (0x26dc296, 0x576efb8),
    (0x26dc663, 0x5773d50),
    (0x26dc681, 0x576dfe0),
    (0x26dc6b5, 0x576e108),
    (0x26dc6ce, 0x576e108),
    (0x26dc75b, 0x576e468),
    (0x26dc779, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26dc6a9, 0x566adf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 89, 13),
    (0x26dc6c2, 0x566ab58, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 112, 13),
    (0x26dc74f, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x26fb3df, 0x27747aa]
CALLER_FUNCTIONS = {'0x26fb3df': ('0x26f9b70', '0x26fb746'), '0x27747aa': ('0x2773d60', '0x27747d9')}
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

