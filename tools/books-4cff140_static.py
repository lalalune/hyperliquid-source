#!/usr/bin/env python3
"""Authenticated node94 books-4cff140 binding (0x4cff140).

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

START, END = 0x4cff140, 0x4cff8f0
FDE_VA = 0x12e0468
FDE = bytes.fromhex(
    '5000000040283200d0eca103b007000004fb2d8dff410e10420e18420e20420e'
    '28420e30410e38470ef00283078c068d058e048f038602035a050e38410e3042'
    '0e28420e20420e18420e10410e08410ef0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec380100004d89c54889d54889fb83bfa8310000'
    '0149bf4b598638d6c56d3448897424080f851f0100004d89ccf20f1083b03100'
    '00488d7c24104889ceff1529fea6008b4424103b43600f9fc0751a8b4424143b'
    '43640f97c0750e8b436839442418760de9e000000084c00f85d80000004c8964'
    '24784889e849f7e748c1ea0b483b93c80500000f83f00500004989ec4d89fe48'
    '8babc00500004c69faf002000066c74424104101488d7c2410e892a267fe4c89'
    'e049f7e648c1ea0b4869c2102700004d89e04929c44a8b743d704939f40f83d4'
    '0500004d89f14c01fd488b4d684b8d146448c1e2054c89e848f7d8490f48c548'
    'f76411204c8b742408488b7c24780f80c004000048b900000000000000804883'
    'c1fe4839c80f87a904000080bbf20800000248b900e40b540200000048ba00e8'
    '764817000000480f44d14839d073334c89c54d89cf833b010f85db000000488b'
    '4b08488b53280fb6b3f2080000488dbc24100100004531c0e8f389c8fee9cd00'
    '00008b05d0b8a70085c04c89c54d89cf0f854b040000418b461089442420410f'
    '10060f29442410488d742410e8ef2cc4ff0f57c0f2490f2ac5f20f590567b450'
    'fb66480f7ec148b8ffffffffffffff7f4821c1660f57c948baffffffffffffef'
    '7f4839d17f2ef20f10158ab950fb660f2ed07710660f2e05b4b450fb7706660f'
    '28c8eb10f20f5fd0f20f100da0b450fbf20f5dcaf2480f2cc9660f2e0d67af50'
    'fb480f47c84531ed660f2ec94c0f4be9833b010f8425ffffff660f57c0660f29'
    '842420010000660f298424100100004889e849f7e74989d749c1ef0b4c3bbb78'
    '3300000f83c40300004989dc4969c7102700004829c54889eb498bac24703300'
    '004d69f73801000066c74424104101488d7c2410e8b7a067fe48c74424100000'
    '000048c74424180800000048c7442420000000004a3b5c35100f83b70200004c'
    '01f531c94d85ed0f99c14869f3d80000004803750848c7842480000000000000'
    '0048c78424880000000800000048c7842490000000000000004d89e849f7d84d'
    '0f48c54c8dac24800000004c892c24488dbc24c0000000488b5424084d89e1e8'
    '4c5360ff4c89e38b052bb7a70085c00f85530200004c3bbbc80500000f831903'
    '00004d69f7f00200004c03b3c005000066c7442410410140b501488d7c241041'
    'b401e8e99f67fe4c89ee4c8bac24c000000048b800000000000000804939c50f'
    '94c10f848f010000884c24784c896c24084c8bac24c00000004c8ba424c80000'
    '00488b9424d0000000488bac24d8000000488b8424e000000048898424b00000'
    '00488b8424e800000048898424b8000000660f28842410010000660f288c2420'
    '010000660f114c2421660f11442411c64424100148893424488d4c24104c89f7'
    '4c89e641b80100000041b906000600e89c8ffdff4d85ed74124969f538020000'
    '4c89e731d2ff15a5eaa6004885ed744548c74424180000000048896c2420488b'
    '8424b0000000488944242848c74424380000000048896c24404889442448b801'
    '00000040b5014c8b6c2408488b8c24b8000000eb0c31c031c940b5014c8b6c24'
    '084889442410488944243048894c24504531e4488dbc2498000000488d742410'
    'e81b8ec4ff488b8424980000004885c074604c8db424980000004c8d64241048'
    '8b2d0aeaa600662e0f1f840000000000488b8c24a8000000488d0c49488b74c8'
    '084885f67414488d04c84883c008488b780848c1e60331d2ffd54c89f74c89e6'
    'e8bb8dc4ff488b8424980000004885c075be0fb64c2478488b84249000000048'
    '89442420660f10842480000000660f2944241031ed488d7c24104189cc4c89fe'
    '4889dae8e8a162ff48b800000000000000804939c5750d488dbc24c0000000e8'
    '6cf40a004881c4380100005b415c415d415e415f5dc3488d3d7b2ca400ff15ad'
    'eda600e92d010000488d05b1b4a7004889842498000000488d84249800000048'
    '8944241040b501488d3daab4a700488d0d73a896004c8d0554a89600488d5424'
    '1041b401be01000000ff15a9f1a600e961fdffff488d3d654ea400ff154feda6'
    '00488d0558b4a70048898424c0000000488d8424c000000048894424104989fc'
    '488d3d51b4a700488d0d1aa896004c8d05fba79600488d542410be01000000ff'
    '1553f1a6004c89e7e969fbffff66c74424104101488d3dfec888fb488d0d8ea7'
    '9e004c8d059fa39e00488d542410be2b000000ff15afe8a600eb5a66c7442410'
    '4101488d3dd0c888fb488d0d60a79e004c8d0541a39e00488d542410be2b0000'
    '00ff1581e8a600eb2c66c74424104101488d3da2c888fb488d0d32a79e004c8d'
    '05fba29e00488d542410be2b000000ff1553e8a6000f0b488d15c24ca4004c89'
    'e7ff15c1e7a6004889c3488d7c2410e87c9c67fee9c9000000ff1509e9a60048'
    '89c3488dbc24c0000000e891dc0a00e98c0000004889c3488d7c2410e84f9c67'
    'fe40b50141b401eb23ff15d9e8a6004889c3eb6c4889c3488d7c2410e82f9c67'
    'feeb7fff15bfe8a6004889c348b8000000000000008048398424c0000000742e'
    '4584e47436488dbc24c0000000e82edc0a00eb274889c340b50148b800000000'
    '0000008048398424c00000007512488dbc24c0000000e855f20a004084ed7422'
    '488dbc2480000000e8f3df0a00eb13ff1553e8a6004889c3488d7c2410e82ed8'
    '63ff4889dfe826089600ff1538e8a600'
)
BODY_SHA256 = '208a2cd684940325a543a065c99672df77614b0000b61d0351468762b0fe5a14'
BRANCHES = [
    (0x30, '0f851f010000', 2, 6, 0x4cff295),
    (0x59, '751a', 1, 2, 0x4cff1b5),
    (0x65, '750e', 1, 2, 0x4cff1b5),
    (0x6e, '760d', 1, 2, 0x4cff1bd),
    (0x70, 'e9e0000000', 1, 5, 0x4cff295),
    (0x77, '0f85d8000000', 2, 6, 0x4cff295),
    (0x93, '0f83f0050000', 2, 6, 0x4cff7c9),
    (0xdd, '0f83d4050000', 2, 6, 0x4cff7f7),
    (0x10e, '0f80c0040000', 2, 6, 0x4cff714),
    (0x125, '0f87a9040000', 2, 6, 0x4cff714),
    (0x14d, '7333', 1, 2, 0x4cff2c2),
    (0x158, '0f85db000000', 2, 6, 0x4cff379),
    (0x17d, 'e9cd000000', 1, 5, 0x4cff38f),
    (0x190, '0f854b040000', 2, 6, 0x4cff721),
    (0x1e4, '7f2e', 1, 2, 0x4cff354),
    (0x1f2, '7710', 1, 2, 0x4cff344),
    (0x1fc, '7706', 1, 2, 0x4cff344),
    (0x202, 'eb10', 1, 2, 0x4cff354),
    (0x233, '0f8425ffffff', 2, 6, 0x4cff29e),
    (0x263, '0f83c4030000', 2, 6, 0x4cff76d),
    (0x2b9, '0f83b7020000', 2, 6, 0x4cff6b6),
    (0x32f, '0f8553020000', 2, 6, 0x4cff6c8),
    (0x33c, '0f8319030000', 2, 6, 0x4cff79b),
    (0x382, '0f848f010000', 2, 6, 0x4cff657),
    (0x417, '7412', 1, 2, 0x4cff56b),
    (0x42e, '7445', 1, 2, 0x4cff5b5),
    (0x473, 'eb0c', 1, 2, 0x4cff5c1),
    (0x4b0, '7460', 1, 2, 0x4cff652),
    (0x4e4, '7414', 1, 2, 0x4cff63a),
    (0x510, '75be', 1, 2, 0x4cff610),
    (0x555, '750d', 1, 2, 0x4cff6a4),
    (0x583, 'e92d010000', 1, 5, 0x4cff7f5),
    (0x5cf, 'e961fdffff', 1, 5, 0x4cff475),
    (0x628, 'e969fbffff', 1, 5, 0x4cff2d6),
    (0x659, 'eb5a', 1, 2, 0x4cff7f5),
    (0x687, 'eb2c', 1, 2, 0x4cff7f5),
    (0x6d4, 'e9c9000000', 1, 5, 0x4cff8e2),
    (0x6ef, 'e98c000000', 1, 5, 0x4cff8c0),
    (0x707, 'eb23', 1, 2, 0x4cff86c),
    (0x712, 'eb6c', 1, 2, 0x4cff8c0),
    (0x721, 'eb7f', 1, 2, 0x4cff8e2),
    (0x73e, '742e', 1, 2, 0x4cff8ae),
    (0x743, '7436', 1, 2, 0x4cff8bb),
    (0x752, 'eb27', 1, 2, 0x4cff8bb),
    (0x76c, '7512', 1, 2, 0x4cff8c0),
    (0x77e, '7422', 1, 2, 0x4cff8e2),
    (0x78d, 'eb13', 1, 2, 0x4cff8e2),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4cff1f9, 0x3379490),
    (0x4cff2b8, 0x3987cb0),
    (0x4cff2ec, 0x4941fe0),
    (0x4cff3d4, 0x3379490),
    (0x4cff45f, 0x43047b0),
    (0x4cff4a2, 0x3379490),
    (0x4cff54f, 0x4cd84f0),
    (0x4cff5e0, 0x4948400),
    (0x4cff640, 0x4948400),
    (0x4cff683, 0x4329870),
    (0x4cff69f, 0x4daeb10),
    (0x4cff80f, 0x3379490),
    (0x4cff82a, 0x4dad4c0),
    (0x4cff83c, 0x3379490),
    (0x4cff85c, 0x3379490),
    (0x4cff88d, 0x4dad4c0),
    (0x4cff8b6, 0x4daeb10),
    (0x4cff8c8, 0x4dad8c0),
    (0x4cff8dd, 0x433d110),
    (0x4cff8e5, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4cff189, 0x576efb8),
    (0x4cff565, 0x576e010),
    (0x4cff6bd, 0x576e470),
    (0x4cff709, 0x576e8b8),
    (0x4cff71b, 0x576e470),
    (0x4cff75f, 0x576e8b8),
    (0x4cff793, 0x576e048),
    (0x4cff7c1, 0x576e048),
    (0x4cff7ef, 0x576e048),
    (0x4cff801, 0x576dfc8),
    (0x4cff819, 0x576e128),
    (0x4cff849, 0x576e128),
    (0x4cff863, 0x576e128),
    (0x4cff8cf, 0x576e128),
    (0x4cff8ea, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4cff6b6, 0x5742338, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x4cff714, 0x5744580, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f696d706c5f676c6f62616c2e7273'), 626, 100),
    (0x4cff7f7, 0x57444c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x4cfc69e, 0x4cfcfbd]
CALLER_FUNCTIONS = {'0x4cfc69e': ('0x4cf94a0', '0x4cff13d'), '0x4cfcfbd': ('0x4cf94a0', '0x4cff13d')}
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

