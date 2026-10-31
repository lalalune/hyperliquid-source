#!/usr/bin/env python3
"""Authenticated node94 spot-meta-2a2a9f0 binding (0x2a2a9f0).

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

START, END = 0x2a2a9f0, 0x2a2b09f
FDE_VA = 0x1122278
FDE = bytes.fromhex(
    '500000005046160070879001af0600000457df91ff410e10420e18420e20420e'
    '28420e30410e38470e800283078c068d058e048f0386020345060e38410e3042'
    '0e28420e20420e18420e10410e08410e80020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc80000004d89c2488954244048897c24488b06'
    '8944240c8b460448894424388b46088944240848c74424200000000048c74424'
    '3000000000488b819800000048894c24104c8ba1a800000048894424184885c0'
    '0f95c04d85e40f95c120c180f9010f85ee030000488b442410488b98a0000000'
    '498b82800100004889442450498b8288010000488944245831ed488b442418eb'
    '376666666666662e0f1f840000000000488b4c247048894c3858660f28442460'
    '660f11443848488b1c24b80000000049ffcc0f848a0300004885ed74230fb78d'
    '720200004839cb0f83c30000004989efe9e200000066662e0f1f840000000000'
    '4885db74384889d94889c54883e107743131d2666666662e0f1f840000000000'
    '488bad7802000048ffc24839d175f14889d84829d04883fb087315eb514889c5'
    'eb4c4889d84883fb0872430f1f440000488b8d78020000488b8978020000488b'
    '8978020000488b8978020000488b8978020000488b8978020000488b89780200'
    '00488ba9780200004883c0f875c231db31c00fb78d720200004839cb0f824bff'
    'ffff66666666662e0f1f8400000000004c8bbd100200004d85ff0f84bf040000'
    '48ffc00fb79d700200004c89fd66413b9f7202000073d94885c00f8490000000'
    '498d0cdf4881c1800200004889c24883e2070f845802000031f6660f1f440000'
    '488b29488d8d7802000048ffc64839f275ee4889c24829f24883f80872436690'
    '488b01488b8078020000488b8078020000488b8078020000488b807802000048'
    '8b8078020000488b8078020000488ba878020000488d8d780200004883c2f875'
    'bf48c7042400000000eb100f1f440000488d4301488904244c89fd4d8bacdf18'
    '0200004d89d64c89d74c89eeff151685d4024c3b6c24580f83c4030000488d04'
    '5b48c1e0044901c74969c5e8000000488b4c24500fb6440149f2410f1047180f'
    '1405ca917dfd660f5c05e2817dfd660f28c8660f15c8f20f58c8488d0d379eb5'
    'fdf20f1004c1f20f5ec8f3410f7e5720f3410f7e1f660f6cda660f6fd3660fdb'
    '152be37dfd660feb15e3c97dfd660f73d320660feb1d169f7dfd660f5c1d1e9f'
    '7dfd660f58da660f2815429c7dfd660f14d0660f5eda660f295c2460f20f114c'
    '2470488b4424204885c00f8490000000488b4c24284d89f20fb7b06a0100008d'
    '14f5000000004c8d045248c7c2ffffffff31ff666666662e0f1f840000000000'
    '4939f8743b4c3b6cd010410f97c14180d9004883c71848ffc24180f90174e141'
    '0fb6f185f60f8405fdffff4883e9017318eb2f666666662e0f1f840000000000'
    '4889f24883e9017219488b84d070010000eb85666666662e0f1f840000000000'
    '31c0488d4c242048898c24800000004c89ac2488000000488984249000000048'
    'c78424980000000000000048899424a0000000488dbc24a8000000488db42480'
    '000000488d542460e8539701004d89f2488b1c24b80000000049ffcc0f8596fc'
    'ffffeb1e6666662e0f1f8400000000004889c24883f8080f8204feffffe9befd'
    'ffff660f57c9660f57c04c8b5c24184d85db0f84cc000000488b442410488b80'
    'a000000031c9410fb7bb7202000089fac1e2044c8d045248c7c2ffffffff31f6'
    '4939f0742b493b8cd320020000410f97c14180d9004883c63048ffc24180f901'
    '74de410fb6f985ff7509eb170f1f40004889fa4883e801726b4d8b9cd3780200'
    '00eba3f2410f105433e80f14159f8f7dfd660f5c15b77f7dfd660f28c2f3410f'
    '7e5c33f0f3410f7e4c33d0660f6ccb660f6f1d19e17dfd660fdbd9660feb1dcd'
    'c77dfd660f15c2660f73d120660feb0dfc9c7dfdf20f58c2660f5c0d009d7dfd'
    '660f58cb8b74240c89f2c1fa0d8d42ff31c985d27f22b90100000029d14869c9'
    '1f85eb5148c1e927ffc169d19001000001d069c94fc5fdff4983ba8801000000'
    '0f84ea000000c1ee0481e6ff01000001ce48984869c81f85eb514889ca48c1ea'
    '3f48c1f92501d129ce69c0b5050000c1f80201f0c1f90201c805c506f5ff4898'
    '4869c08051010048034424384869c0e80300008b4c24084869c983de1b4348c1'
    'e9324801c131f64885c9480f4ff1498b8a800100000fb64949488d15189bb5fd'
    'f20f1014caf20f5ec2488b4c2430488b442448488948300f105c24200f115820'
    '660f281d48997dfd660f14da660f5ecb660f1108f20f11401048897018488b4c'
    '24400f10010f1140388b49108948484881c4c80000005b415c415d415e415f5d'
    'c3488d3d9871cc02ff151234d402eb1c488d3d8971cc02ff150334d402eb0d48'
    '8d3d729aca02ff15f433d4020f0beb040f0beb004889c3488d7c2420e86f41fe'
    'ff4889dfe87750c302ff158930d402'
)
BODY_SHA256 = '616f3ce7b0973be3950c2664d5edd31d2ca4b2844092bfaf231e988f4954a531'
BRANCHES = [
    (0x6e, '0f85ee030000', 2, 6, 0x2a2ae52),
    (0x9f, 'eb37', 1, 2, 0x2a2aac8),
    (0xd2, '0f848a030000', 2, 6, 0x2a2ae52),
    (0xdb, '7423', 1, 2, 0x2a2aaf0),
    (0xe7, '0f83c3000000', 2, 6, 0x2a2aba0),
    (0xf0, 'e9e2000000', 1, 5, 0x2a2abc7),
    (0x103, '7438', 1, 2, 0x2a2ab2d),
    (0x10f, '7431', 1, 2, 0x2a2ab32),
    (0x12d, '75f1', 1, 2, 0x2a2ab10),
    (0x139, '7315', 1, 2, 0x2a2ab40),
    (0x13b, 'eb51', 1, 2, 0x2a2ab7e),
    (0x140, 'eb4c', 1, 2, 0x2a2ab7e),
    (0x149, '7243', 1, 2, 0x2a2ab7e),
    (0x18c, '75c2', 1, 2, 0x2a2ab40),
    (0x19c, '0f824bffffff', 2, 6, 0x2a2aadd),
    (0x1ba, '0f84bf040000', 2, 6, 0x2a2b06f),
    (0x1d5, '73d9', 1, 2, 0x2a2aba0),
    (0x1da, '0f8490000000', 2, 6, 0x2a2ac60),
    (0x1f2, '0f8458020000', 2, 6, 0x2a2ae40),
    (0x210, '75ee', 1, 2, 0x2a2abf0),
    (0x21c, '7243', 1, 2, 0x2a2ac51),
    (0x25f, '75bf', 1, 2, 0x2a2ac10),
    (0x269, 'eb10', 1, 2, 0x2a2ac6b),
    (0x297, '0f83c4030000', 2, 6, 0x2a2b051),
    (0x34a, '0f8490000000', 2, 6, 0x2a2add0),
    (0x383, '743b', 1, 2, 0x2a2adb0),
    (0x39d, '74e1', 1, 2, 0x2a2ad70),
    (0x3a5, '0f8405fdffff', 2, 6, 0x2a2aaa0),
    (0x3af, '7318', 1, 2, 0x2a2adb9),
    (0x3b1, 'eb2f', 1, 2, 0x2a2add2),
    (0x3c7, '7219', 1, 2, 0x2a2add2),
    (0x3d1, 'eb85', 1, 2, 0x2a2ad48),
    (0x43c, '0f8596fcffff', 2, 6, 0x2a2aac8),
    (0x442, 'eb1e', 1, 2, 0x2a2ae52),
    (0x457, '0f8204feffff', 2, 6, 0x2a2ac51),
    (0x45d, 'e9befdffff', 1, 5, 0x2a2ac10),
    (0x472, '0f84cc000000', 2, 6, 0x2a2af34),
    (0x4a3, '742b', 1, 2, 0x2a2aec0),
    (0x4c0, '74de', 1, 2, 0x2a2ae90),
    (0x4c8, '7509', 1, 2, 0x2a2aec3),
    (0x4ca, 'eb17', 1, 2, 0x2a2aed3),
    (0x4d7, '726b', 1, 2, 0x2a2af34),
    (0x4e1, 'eba3', 1, 2, 0x2a2ae76),
    (0x554, '7f22', 1, 2, 0x2a2af68),
    (0x580, '0f84ea000000', 2, 6, 0x2a2b060),
    (0x66e, 'eb1c', 1, 2, 0x2a2b07c),
    (0x67d, 'eb0d', 1, 2, 0x2a2b07c),
    (0x68e, 'eb04', 1, 2, 0x2a2b084),
    (0x692, 'eb00', 1, 2, 0x2a2b084),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2a2ae18, 0x2a44570),
    (0x2a2b08c, 0x2a0f200),
    (0x2a2b094, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2a2ac7c, 0x5773198),
    (0x2a2b058, 0x576e470),
    (0x2a2b067, 0x576e470),
    (0x2a2b076, 0x576e470),
    (0x2a2b099, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2a2b051, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2a2b060, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2a2b06f, 0x56d4ae8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5775378']
GOT_SITES = {'0x5775378': ['0x2a2c7d6']}


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

