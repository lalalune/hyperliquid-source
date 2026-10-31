#!/usr/bin/env python3
"""Authenticated node94 hour-220bed0 binding (0x220bed0).

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

START, END = 0x220bed0, 0x220c477
FDE_VA = 0x1090254
FDE = bytes.fromhex(
    'c00000002c260d0074bc1701a705000004bb5194ff410e10420e18420e20420e'
    '28410e30470e800283068c058e048f03860202772e00562e005c2e0002702e00'
    '5a2e004b2e005e2e00782e00692e004f2e007a2e00662e00682e007d2e00029b'
    '2e00622e10570e8802420e9002490e80026c2e004c2e005d2e005f0e30410e28'
    '420e20420e18420e10410e08410e80022e006a2e005e2e00652e00592e00682e'
    '00024f2e004d2e00752e004b2e00492e004c2e00582e00482e00552e00492e00'
    '482e0000'
)
BODY = bytes.fromhex(
    '55415741564154534881ecd00000004889fb4c8b772883bf900b000001753b48'
    '8b83980b00004c39f00f825304000048b9917efb3a70ce88d2490fafce48c1c9'
    '0448bacc10c7bab88d06004839d172314c39f07431e91e02000048b8917efb3a'
    '70ce88d2490fafc648c1c80448b9cc10c7bab88d06004839c80f83f9010000eb'
    '1b4c39f07516488d157db51cfe488dbc2498000000b906000000eb14488d156d'
    'e4fffd488dbc2498000000b9080000004889dee8d8ceffff488d7c2410ff150d'
    '2956038b4424143d00100e000f83720300003d905f01000f838c0300003d1f1c'
    '00000f86010100004c8b3d69295603418b475085c00f85a00300004983c7184c'
    '897c2410488d05c57960014889442418488d05917b4e034889442420488d053d'
    '0c5e014889442428488d3516dcfefd4c8d7c2458488d5424104c89ffff152e20'
    '5603488d7c2410ff15832856034989e4488d7424104c89e731d2ff15182a5603'
    '8b3c2485ff0f8466030000beffffffffff156a28560385c00f84680300008904'
    '244c897c2410488d05e31d0a0048894424184c89642420488b05f22956034889'
    '442428488d3514d3fdfd488dbc24b8000000488d542410ff15b31f5603488b74'
    '24584885f6740d488b7c246031d2ff156c1f56030fb6bbf2080000488db424b8'
    '000000ff15df2856034c8b7b104c8b63288b436889442448488b436048894424'
    '40488d7c244c0f1083900b00000f29842480000000ff15b52756034c897c2430'
    '4c896424380f288424800000000f2944241048c744242000000000488d3d661b'
    '4903488d156f1b4903488d742410e83d1f3a0083bbe83a000002741c488db340'
    '3b0000488d7c2410488d8c24980000004c89f2e8087f6500488b83d8260000f0'
    '48ff000f8ea20200004c8bb3d82600000fb6ab9d3b00004c89342440886c2408'
    '488d7c2474ff15252756038b4424743b83903b00000f85930000008b4424783d'
    'ff0f0e000f87320100003d905f01000f83510100008b8b943b000081f900100e'
    '000f831501000081f9905f01000f833301000089c0bac5b3a291480fafd048c1'
    'ea2b89c8b9c5b3a291480fafc848c1e92b0fb6c269c0ab000000c1e80969c9ab'
    '0000000fb7c9c1e9094c8b342438c87518f049ff0e0f85b10000004889e7ff15'
    '5c6e5603e9a30000000fb66c240848b800000000000000804889442458400fb6'
    'c5488d7c2410488d74245831d24531c04531c9504156e895a8d7ff4883c4104c'
    '8b7c2410488b4424184d85ff0f846f010000488b7c24204c897c24104c8d7424'
    '18488944241848897c2420ff1527325603f049ff0f750b488d7c2410ff151e32'
    '56034881c3903b0000488b442418f048ff0875094c89f7ff15736d56038b4424'
    '7c894308488b4424744889034881c4d00000005b415c415e415f5dc3488d3dd7'
    'da00fe488d0d66e945034c8d05e7e74503488d542458be2b000000ff15571d56'
    '03e905010000488d3d2cac00fe488d15d4aa4503be1c000000ff15f91d5603e9'
    'e7000000488d3d8fda00fe488d0d1ee945034c8d059fe74503488d542458be2b'
    '000000ff150f1d5603488d3de9ab00fe488d1591aa4503be1c000000ff15b61d'
    '5603488d3dbfb01cfe488d1550184903be3e000000ff159d1d56034c897c2458'
    '488d4424584889442410498d7f50488d0d83784e034c8d0564784e03488d5424'
    '10be01000000ff151c255603e92afcffff488d1508e74503be2b000000488d3d'
    '21d900feeb13488d15dbe64503be22000000488d3dead800feff1599205603eb'
    '2a4889442410488d3d03b11cfe488d0dec1f49034c8d05b5184903488d542410'
    'be16000000ff154d1c56030f0b4889c3488b442418f048ff08755e4c89f7ff15'
    '0c6c5603eb53ff150c1d56034889c3488d7c2410e8b7000400eb3eff15f71c56'
    '034889c3488b7424584885f6742b488b7c246031d2ff15c51b56034889dfe8bd'
    '3c45034889c3488b0424f048ff0875094889e7ff15076c56034889dfe89f3c45'
    '03ff15b11c5603'
)
BODY_SHA256 = '5d012f851027ae4d6b1adedb7bd494d4de7301c0dcb8d115903d3c1ed02dd897'
BRANCHES = [
    (0x1d, '753b', 1, 2, 0x220bf2a),
    (0x29, '0f8253040000', 2, 6, 0x220c352),
    (0x4e, '7231', 1, 2, 0x220bf51),
    (0x53, '7431', 1, 2, 0x220bf56),
    (0x55, 'e91e020000', 1, 5, 0x220c148),
    (0x79, '0f83f9010000', 2, 6, 0x220c148),
    (0x7f, 'eb1b', 1, 2, 0x220bf6c),
    (0x84, '7516', 1, 2, 0x220bf6c),
    (0x9a, 'eb14', 1, 2, 0x220bf80),
    (0xcc, '0f8372030000', 2, 6, 0x220c314),
    (0xd7, '0f838c030000', 2, 6, 0x220c339),
    (0xe2, '0f8601010000', 2, 6, 0x220c0b9),
    (0xf5, '0f85a0030000', 2, 6, 0x220c36b),
    (0x165, '0f8466030000', 2, 6, 0x220c3a1),
    (0x178, '0f8468030000', 2, 6, 0x220c3b6),
    (0x1c5, '740d', 1, 2, 0x220c0a4),
    (0x25a, '741c', 1, 2, 0x220c148),
    (0x283, '0f8ea2020000', 2, 6, 0x220c3fb),
    (0x2b5, '0f8593000000', 2, 6, 0x220c21e),
    (0x2c4, '0f8732010000', 2, 6, 0x220c2cc),
    (0x2cf, '0f8351010000', 2, 6, 0x220c2f6),
    (0x2e1, '0f8315010000', 2, 6, 0x220c2cc),
    (0x2ed, '0f8333010000', 2, 6, 0x220c2f6),
    (0x32f, '7518', 1, 2, 0x220c219),
    (0x335, '0f85b1000000', 2, 6, 0x220c2bc),
    (0x344, 'e9a3000000', 1, 5, 0x220c2bc),
    (0x38c, '0f846f010000', 2, 6, 0x220c3d1),
    (0x3b5, '750b', 1, 2, 0x220c292),
    (0x3d2, '7509', 1, 2, 0x220c2ad),
    (0x421, 'e905010000', 1, 5, 0x220c3fb),
    (0x43f, 'e9e7000000', 1, 5, 0x220c3fb),
    (0x4cc, 'e92afcffff', 1, 5, 0x220bfcb),
    (0x4e4, 'eb13', 1, 2, 0x220c3c9),
    (0x4ff, 'eb2a', 1, 2, 0x220c3fb),
    (0x539, '755e', 1, 2, 0x220c469),
    (0x544, 'eb53', 1, 2, 0x220c469),
    (0x559, 'eb3e', 1, 2, 0x220c469),
    (0x56c, '742b', 1, 2, 0x220c469),
    (0x58e, '7509', 1, 2, 0x220c469),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x220bf83, 0x2208e60),
    (0x220c11e, 0x25ae060),
    (0x220c143, 0x2864050),
    (0x220c246, 0x1f86ae0),
    (0x220c424, 0x224c4e0),
    (0x220c44e, 0x5660110),
    (0x220c46c, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x220bf8d, 0x576e8a0),
    (0x220c00c, 0x576e040),
    (0x220c017, 0x576e8a0),
    (0x220c02a, 0x576ea48),
    (0x220c040, 0x576e8b0),
    (0x220c087, 0x576e040),
    (0x220c09e, 0x576e010),
    (0x220c0b3, 0x576e998),
    (0x220c0e5, 0x576e8a0),
    (0x220c175, 0x576e8a0),
    (0x220c20e, 0x5773070),
    (0x220c27b, 0x576f4a8),
    (0x220c28c, 0x576f4b0),
    (0x220c2a7, 0x5773020),
    (0x220c2eb, 0x576e048),
    (0x220c309, 0x576e108),
    (0x220c333, 0x576e048),
    (0x220c34c, 0x576e108),
    (0x220c365, 0x576e108),
    (0x220c396, 0x576e8b8),
    (0x220c3c9, 0x576e468),
    (0x220c3f5, 0x576e048),
    (0x220c40e, 0x5773020),
    (0x220c416, 0x576e128),
    (0x220c42b, 0x576e128),
    (0x220c445, 0x576e010),
    (0x220c463, 0x5773070),
    (0x220c471, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x220c2fd, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x220c340, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x220c359, 0x569dbb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f65786368616e67652e7273'), 601, 17),
    (0x220c3b6, 0x566aa98, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f646174652f6d6f642e7273'), 2061, 38),
]
CALLERS = [0x220b708, 0x22b5502]
CALLER_FUNCTIONS = {'0x220b708': ('0x2209d40', '0x220becb'), '0x22b5502': ('0x22b47c0', '0x22b649a')}
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

