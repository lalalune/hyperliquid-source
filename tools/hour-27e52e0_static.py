#!/usr/bin/env python3
"""Authenticated node94 hour-27e52e0 binding (0x27e52e0).

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

START, END = 0x27e52e0, 0x27e59c0
FDE_VA = 0x10fb808
FDE = bytes.fromhex(
    '50000000e0db1300d09a6e01e0060000041fe692ff410e10420e18420e20420e'
    '28420e30410e38470ec00283078c068d058e048f0386020308030e38410e3042'
    '0e28420e20420e18420e10410e08410ec0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec080100004889f34989fc0fb64674488d0d9ab8'
    'c0fd486304814801c8ffe048899424c0000000488b431848894320660f104340'
    '660f1143548b4350894364c6437501488b034889442410488b43084889442468'
    '488b431048898424c8000000488d6b684889efff154795f8024c8d6b54488b43'
    '20488b7008488d56100fb686c00500004881c6d80200008904244c8d055ee7c0'
    'fd488d7c241841b9140000004c89e9e82c07ffff488b5424188b7c2420f20f10'
    '4c24248b7424240f1044242d0f298424d00000000f104424380f118424db0000'
    '00f20f10442448f20f58442450440fb674242c660f2e05dd56a2fd76354c8b3d'
    '4495f802418b475085c00f85a6030000410fb6474883f81f7718b900603c800f'
    'a3c1730e8b058e57f90285c00f85f20300004180fe050f85e801000031c04889'
    '4328488b4320418b4d10894c245866410f104500660f11442448c64375004c8b'
    '7c24104c897c2418488b4c246848894c2420488b8c24c800000048894c242848'
    '89442430c644245c00bf48000000ff15648bf8024885c00f84040300004889c6'
    '488b44245848894640660f104424180f104c24280f105424380f105c24480f11'
    '5e300f1156200f114e10660f110648897330488d055febed0248894338488b94'
    '24c0000000eb08488b7330488b4338488d7c2418ff5018440fb67424184180fe'
    '05750c41c6042405b003e9000100008b442429898424b0000000660f10442418'
    '0f104c24190f298c24a0000000660f298424f0000000488b44242548898424fd'
    '0000004c8b6b30488b6b38488b45004885c074054c89efffd0488b75084885f6'
    '7421488b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89efff15ad'
    '8af802488b4320488b70084883c610488d4354488d4b68488d53284889842480'
    '000000488d8424f0000000488984248800000048898c24900000004889942498'
    '000000488d0d49e5c0fd4c8d0dafe3ed02488d7c2418488d94248000000041b8'
    '16000000e89756daffc643750045883424660f288424a000000066410f114424'
    '018b8424b00000004189442411b0018843744881c4080100005b415c415d415e'
    '415f5dc38974240c48895424608b8424e0000000898424b0000000660f288424'
    'd0000000660f298424a0000000897c240889bc2480000000488db42484000000'
    '0f138c2484000000488d7c2418ba7800000031c9ff154e92f802488b44242048'
    'b9000000004057ffff4801c148ba81aefeff7faefeff4839d10f828c02000044'
    '8b7c24188b4c241c894c247048b9572951cea0c8451848f7e94889d648c1ee3f'
    '48c1ea0d01d68b7c2408ff150092f80285c00f84530200008b4d0039c80f9fc0'
    '488b7424608b7c240c0f8584000000443b7b6c0f97c0757b8b4424703b43700f'
    '97c04883fe3d0f93c284d075743b4c24080f8525fdffff8b436c3d00100e000f'
    '83650100003d905f01000f838401000081ff00100e000f839301000081ff905f'
    '01000f83ae01000089c0b9c5b3a291480fafc848c1e92b89f8bac5b3a291480f'
    'afd048c1ea2b31c039d1480f44c6e9cbfcffff4883fe3d0f93c220c280fa0175'
    '8c488b7424104885f60f845afeffff488b7c246831d2ff159488f802e948feff'
    'ffbf08000000be48000000ff158f88f802e98e0100000f294c2470897c240889'
    '74240c48895424604c89bc2480000000488d8424800000004889442418498d7f'
    '50488d0d485ae9024c8d05695ae902488d542418be01000000ff15d990f80248'
    '8b5424608b74240c8b7c24080f284c2470410fb6474883f81f0f86fbfbffffe9'
    '0efcffff0f294c2470897c24088974240c4989d7488d056553f9024889842480'
    '000000488d8424800000004889442418488d3d6153f902488d0d2a47e8024c8d'
    '050b47e802488d542418be01000000ff156390f8024c89fa8b74240c8b7c2408'
    '0f284c2470e9a8fbffff488d3d3945a3fd488d0dc853e8024c8d054952e80248'
    '8d542418be2b000000ff15b987f802e990000000488d3d8e16a3fd488d153615'
    'e802be1c000000ff155b88f802eb75488d3df444a3fd488d0d8353e8024c8d05'
    '0452e802488d542418be2b000000ff157487f802eb4e488d3d4c16a3fd488d15'
    'f414e802be1c000000ff151988f802eb33488d3d50e0ed02ff153a97f802488d'
    '3d43e0ed02ff153597f802488d3d0d47a3fd488d15ff55e802be26000000ff15'
    '448bf8020f0b4989c6488b75084885f6745f488b4510f3480fbcc831d24839f0'
    '0f47d14883f8110f43d14c89efff15bd86f802eb3c4989c6eb37eb1eeb1c4989'
    'c6488b7b30488b7338e872e10400eb21ff15b287f802eb02eb004989c64c8b7c'
    '2410eb0d4989c6488d7c2418e89f7605004d85ff0f95c08443757410488b7c24'
    '684c89fe31d2ff156486f80266c7437402004c89f7e856a7e702ff156887f802'
)
BODY_SHA256 = 'e8f6c5f20467de566ee5509fbc6725bd36e933937aafe19f2e62862298201935'
BRANCHES = [
    (0x29, 'ffe0', 1, 2, 0x27e52eb),
    (0xfb, '7635', 1, 2, 0x27e5412),
    (0x10a, '0f85a6030000', 2, 6, 0x27e5796),
    (0x118, '7718', 1, 2, 0x27e5412),
    (0x122, '730e', 1, 2, 0x27e5412),
    (0x12c, '0f85f2030000', 2, 6, 0x27e5804),
    (0x136, '0f85e8010000', 2, 6, 0x27e5604),
    (0x197, '0f8404030000', 2, 6, 0x27e5781),
    (0x1e5, 'eb08', 1, 2, 0x27e54cf),
    (0x201, '750c', 1, 2, 0x27e54ef),
    (0x20a, 'e900010000', 1, 5, 0x27e55ef),
    (0x252, '7405', 1, 2, 0x27e5539),
    (0x260, '7421', 1, 2, 0x27e5563),
    (0x399, '0f828c020000', 2, 6, 0x27e590b),
    (0x3d2, '0f8453020000', 2, 6, 0x27e590b),
    (0x3e9, '0f8584000000', 2, 6, 0x27e5753),
    (0x3f6, '757b', 1, 2, 0x27e5753),
    (0x40b, '7574', 1, 2, 0x27e5761),
    (0x411, '0f8525fdffff', 2, 6, 0x27e541c),
    (0x41f, '0f8365010000', 2, 6, 0x27e586a),
    (0x42a, '0f8384010000', 2, 6, 0x27e5894),
    (0x436, '0f8393010000', 2, 6, 0x27e58af),
    (0x442, '0f83ae010000', 2, 6, 0x27e58d6),
    (0x46e, 'e9cbfcffff', 1, 5, 0x27e541e),
    (0x47f, '758c', 1, 2, 0x27e56ed),
    (0x489, '0f845afeffff', 2, 6, 0x27e55c9),
    (0x49c, 'e948feffff', 1, 5, 0x27e55c9),
    (0x4b1, 'e98e010000', 1, 5, 0x27e5924),
    (0x519, '0f86fbfbffff', 2, 6, 0x27e53fa),
    (0x51f, 'e90efcffff', 1, 5, 0x27e5412),
    (0x585, 'e9a8fbffff', 1, 5, 0x27e5412),
    (0x5af, 'e990000000', 1, 5, 0x27e5924),
    (0x5cd, 'eb75', 1, 2, 0x27e5924),
    (0x5f4, 'eb4e', 1, 2, 0x27e5924),
    (0x60f, 'eb33', 1, 2, 0x27e5924),
    (0x650, '745f', 1, 2, 0x27e5991),
    (0x673, 'eb3c', 1, 2, 0x27e5991),
    (0x678, 'eb37', 1, 2, 0x27e5991),
    (0x67a, 'eb1e', 1, 2, 0x27e597a),
    (0x67c, 'eb1c', 1, 2, 0x27e597a),
    (0x68e, 'eb21', 1, 2, 0x27e5991),
    (0x696, 'eb02', 1, 2, 0x27e597a),
    (0x698, 'eb00', 1, 2, 0x27e597a),
    (0x6a2, 'eb0d', 1, 2, 0x27e5991),
    (0x6ba, '7410', 1, 2, 0x27e59ac),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x27e538f, 0x27d5ac0),
    (0x27e55c4, 0x258ac60),
    (0x27e5969, 0x2833ae0),
    (0x27e598c, 0x283d030),
    (0x27e59b5, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x27e5353, 0x576e8a0),
    (0x27e546e, 0x576dfd8),
    (0x27e555d, 0x576e010),
    (0x27e5654, 0x576e8a8),
    (0x27e56aa, 0x576e8b0),
    (0x27e5776, 0x576e010),
    (0x27e578b, 0x576e020),
    (0x27e57d9, 0x576e8b8),
    (0x27e584f, 0x576e8b8),
    (0x27e5889, 0x576e048),
    (0x27e58a7, 0x576e108),
    (0x27e58ce, 0x576e048),
    (0x27e58e9, 0x576e108),
    (0x27e58f8, 0x576f038),
    (0x27e5905, 0x576f040),
    (0x27e591e, 0x576e468),
    (0x27e594d, 0x576e010),
    (0x27e5970, 0x576e128),
    (0x27e59a6, 0x576e010),
    (0x27e59ba, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x27e589b, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x27e58dd, 0x5666dd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f686f75722e7273'), 12, 13),
    (0x27e5912, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x27ebfab]
CALLER_FUNCTIONS = {'0x27ebfab': ('0x27e91d0', '0x27ecdc2')}
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

