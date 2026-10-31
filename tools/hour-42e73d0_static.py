#!/usr/bin/env python3
"""Authenticated node94 hour-42e73d0 binding (0x42e73d0).

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

START, END = 0x42e73d0, 0x42e797d
FDE_VA = 0x122c74c
FDE = bytes.fromhex(
    'bc00000024eb26007cac0b03ad05000004afad8fff410e10420e18420e20420e'
    '28410e30470e800283068c058e048f03860202912e00502e0002702e005a2e00'
    '4b2e005e2e00782e00692e004f2e007a2e00662e00682e007d2e00029b2e0075'
    '2e10520e8802420e9002490e80026c2e004c2e005d2e005f0e30410e28420e20'
    '420e18420e10410e08410e80022e006a2e005e2e00652e00592e00682e00024f'
    '2e004d2e00752e004b2e00492e004c2e00582e00482e00552e00492e00482e00'
)
BODY = bytes.fromhex(
    '55415741564154534881ecd00000004889fb4c8b772883bf1016000001753b48'
    '8b83181600004c39f00f825904000048b9917efb3a70ce88d2490fafce48c1c9'
    '0448bacc10c7bab88d06004839d172314c39f07431e91602000048b8917efb3a'
    '70ce88d2490fafc648c1c80448b9cc10c7bab88d06004839c80f83f1010000eb'
    '134c39f0750e488d15c49040fcb906000000eb0c488d15752ff2fbb908000000'
    '488dbc24b00000004889dee8e0651800488d7c2410ff15157448018b4424143d'
    '00100e000f83800300003d905f01000f839a0300003d1f1c00000f8601010000'
    '4c8b3d71744801418b475085c00f85ae0300004983c7184c897c2410488d05cd'
    'c452ff4889442418488d0599c640014889442420488d05455750ff4889442428'
    '488d351e27f1fb4c8d7c2458488d5424104c89ffff15366b4801488d7c2410ff'
    '158b7348014989e4488d7424104c89e731d2ff15207548018b3c2485ff0f8474'
    '030000beffffffffff157273480185c00f84760300008904244c897c2410488d'
    '05dba6090048894424184c89642420488b05fa7448014889442428488d351c1e'
    'f0fb488dbc2498000000488d542410ff15bb6a4801488b7424584885f6740d48'
    '8b7c246031d2ff15746a48010fb6bb72130000488db42498000000ff15e77348'
    '014c8b7b104c8b63288b436889442448488b43604889442440488d7c244c0f10'
    '83101600000f29842480000000ff15bd7248014c897c24304c896424380f2884'
    '24800000000f2944241048c744242000000000488d3de6524301488d15ef5243'
    '01488d742410e82570800083bb6845000002741c488db3c0450000488d7c2410'
    '488d8c24b00000004c89f2e8c0cc6400488b8358310000f048ff000f8eb00200'
    '004c8bb3583100000fb6ab1d4600004c89342440886c2408488d7c2474ff152d'
    '7248018b4424743b83104600000f85930000008b4424783dff0f0e000f874001'
    '00003d905f01000f835f0100008b8b1446000081f900100e000f832301000081'
    'f9905f01000f834101000089c0bac5b3a291480fafd048c1ea2b89c8b9c5b3a2'
    '91480fafc848c1e92b0fb6c269c0ab000000c1e80969c9ab0000000fb7c9c1e9'
    '094c8b342438c87518f049ff0e0f85bf0000004889e7ff1564b94801e9b10000'
    '000fb66c2408488d74242048b80000000000000080488944242048c744241000'
    '000000c644243800400fb6c5488d7c245831d24531c04531c9504156e8ff8e04'
    '004883c4104c8b7c2458488b4424604d85ff0f846f010000488b7c24684c897c'
    '24104c8d742418488944241848897c2420ff15217d4801f049ff0f750b488d7c'
    '2410ff15187d48014881c310460000488b442418f048ff0875094c89f7ff156d'
    'b848018b44247c894308488b4424744889034881c4d00000005b415c415e415f'
    '5dc3488d3dd125f3fb488d0d603438014c8d05e1323801488d542458be2b0000'
    '00ff1551684801e905010000488d3d26f7f2fb488d15cef53701be1c000000ff'
    '15f3684801e9e7000000488d3d8925f3fb488d0d183438014c8d059932380148'
    '8d542458be2b000000ff1509684801488d3de3f6f2fb488d158bf53701be1c00'
    '0000ff15b0684801488d3d10d340fc488d15ca854301be3e000000ff15976848'
    '014c897c2458488d4424584889442410498d7f50488d0d7dc340014c8d055ec3'
    '4001488d542410be01000000ff1516704801e91cfcffff488d1502323801be2b'
    '000000488d3d1b24f3fbeb13488d15d5313801be22000000488d3de423f3fbff'
    '15936b4801eb2a4889442410488d3d448c40fc488d0dfe5343014c8d05275043'
    '01488d542410be16000000ff15476748010f0b4889c3488b442418f048ff0875'
    '5e4c89f7ff1506b74801eb53ff15066848014889c3488d7c2410e8d1f10500eb'
    '3eff15f16748014889c3488b7424584885f6742b488b7c246031d2ff15bf6648'
    '014889dfe8b78737014889c3488b0424f048ff0875094889e7ff1501b7480148'
    '89dfe899873701ff15ab674801'
)
BODY_SHA256 = '65392f8ad976017d9d1d2f09f53732261e2e08319a466328023e14747714ed9a'
BRANCHES = [
    (0x1d, '753b', 1, 2, 0x42e742a),
    (0x29, '0f8259040000', 2, 6, 0x42e7858),
    (0x4e, '7231', 1, 2, 0x42e7451),
    (0x53, '7431', 1, 2, 0x42e7456),
    (0x55, 'e916020000', 1, 5, 0x42e7640),
    (0x79, '0f83f1010000', 2, 6, 0x42e7640),
    (0x7f, 'eb13', 1, 2, 0x42e7464),
    (0x84, '750e', 1, 2, 0x42e7464),
    (0x92, 'eb0c', 1, 2, 0x42e7470),
    (0xc4, '0f8380030000', 2, 6, 0x42e781a),
    (0xcf, '0f839a030000', 2, 6, 0x42e783f),
    (0xda, '0f8601010000', 2, 6, 0x42e75b1),
    (0xed, '0f85ae030000', 2, 6, 0x42e7871),
    (0x15d, '0f8474030000', 2, 6, 0x42e78a7),
    (0x170, '0f8476030000', 2, 6, 0x42e78bc),
    (0x1bd, '740d', 1, 2, 0x42e759c),
    (0x252, '741c', 1, 2, 0x42e7640),
    (0x27b, '0f8eb0020000', 2, 6, 0x42e7901),
    (0x2ad, '0f8593000000', 2, 6, 0x42e7716),
    (0x2bc, '0f8740010000', 2, 6, 0x42e77d2),
    (0x2c7, '0f835f010000', 2, 6, 0x42e77fc),
    (0x2d9, '0f8323010000', 2, 6, 0x42e77d2),
    (0x2e5, '0f8341010000', 2, 6, 0x42e77fc),
    (0x327, '7518', 1, 2, 0x42e7711),
    (0x32d, '0f85bf000000', 2, 6, 0x42e77c2),
    (0x33c, 'e9b1000000', 1, 5, 0x42e77c2),
    (0x392, '0f846f010000', 2, 6, 0x42e78d7),
    (0x3bb, '750b', 1, 2, 0x42e7798),
    (0x3d8, '7509', 1, 2, 0x42e77b3),
    (0x427, 'e905010000', 1, 5, 0x42e7901),
    (0x445, 'e9e7000000', 1, 5, 0x42e7901),
    (0x4d2, 'e91cfcffff', 1, 5, 0x42e74c3),
    (0x4ea, 'eb13', 1, 2, 0x42e78cf),
    (0x505, 'eb2a', 1, 2, 0x42e7901),
    (0x53f, '755e', 1, 2, 0x42e796f),
    (0x54a, 'eb53', 1, 2, 0x42e796f),
    (0x55f, 'eb3e', 1, 2, 0x42e796f),
    (0x572, '742b', 1, 2, 0x42e796f),
    (0x594, '7509', 1, 2, 0x42e796f),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x42e747b, 0x446da60),
    (0x42e7616, 0x4aee640),
    (0x42e763b, 0x4934300),
    (0x42e774c, 0x4330650),
    (0x42e792a, 0x4346b00),
    (0x42e7954, 0x5660110),
    (0x42e7972, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x42e7485, 0x576e8a0),
    (0x42e7504, 0x576e040),
    (0x42e750f, 0x576e8a0),
    (0x42e7522, 0x576ea48),
    (0x42e7538, 0x576e8b0),
    (0x42e757f, 0x576e040),
    (0x42e7596, 0x576e010),
    (0x42e75ab, 0x576e998),
    (0x42e75dd, 0x576e8a0),
    (0x42e766d, 0x576e8a0),
    (0x42e7706, 0x5773070),
    (0x42e7781, 0x576f4a8),
    (0x42e7792, 0x576f4b0),
    (0x42e77ad, 0x5773020),
    (0x42e77f1, 0x576e048),
    (0x42e780f, 0x576e108),
    (0x42e7839, 0x576e048),
    (0x42e7852, 0x576e108),
    (0x42e786b, 0x576e108),
    (0x42e789c, 0x576e8b8),
    (0x42e78cf, 0x576e468),
    (0x42e78fb, 0x576e048),
    (0x42e7914, 0x5773020),
    (0x42e791c, 0x576e128),
    (0x42e7931, 0x576e128),
    (0x42e794b, 0x576e010),
    (0x42e7969, 0x5773070),
    (0x42e7977, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x42e7803, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x42e7846, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x42e785f, 0x571fe30, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f65786368616e67652e7273'), 601, 17),
    (0x42e78bc, 0x566aa98, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f646174652f6d6f642e7273'), 2061, 38),
]
CALLERS = [0x42e56bb, 0x42e8328]
CALLER_FUNCTIONS = {'0x42e56bb': ('0x42e4600', '0x42e5d3b'), '0x42e8328': ('0x42e8240', '0x42e839a')}
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

