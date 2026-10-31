#!/usr/bin/env python3
"""Authenticated node94 books-271bb40 binding (0x271bb40).

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

START, END = 0x271bb40, 0x271c481
FDE_VA = 0x10ee4c4
FDE = bytes.fromhex(
    '500000009c08130074d6620141090000046bff92ff410e10420e18420e20420e'
    '28420e30410e38470ea00583078c068d058e048f038602030d080e38410e3042'
    '0e28420e20420e18420e10410e08410ea0050000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec680200004c89cd4889f34889bc240801000048'
    '8bbc24a00200008b8424b00200008bb424a80200004c89442468897424508944'
    '2454488b424048898424c00100000f1002660f104a100f105220660f105a3066'
    '0f299c24b00100000f299424a0010000660f298c24900100000f298424800100'
    '00488d44246848898424e001000066410f1001660f118424c8010000498b4110'
    '48898424d80100004889bc24e8010000488d44245048898424f001000048894c'
    '243048898c24f8010000bf32000000ff15e32c050384c048895c24187418bf01'
    '000000e8d87b7c0248898424e000000089542424eb08c744242400ca9a3b488b'
    '84248001000048898424e8000000488b84248801000048898424f00000000fb6'
    '9c2499010000488b8424a00100004889442458488b8424a80100004889442440'
    '0fb68424b00100008844240f440fb6b424b10100004c8bbc24c80100004c8ba4'
    '24d0010000bf01000000e8517b7c0248894424608954243c488b7c2418488b87'
    '8808000048ffc048c7c1ffffffff480f45c848898f88080000488b4424684889'
    '842400010000488b45004889442410488b45084889442428488b451048898424'
    'f8000000488b8424a0020000488b004889442448f20f104424500f2984245002'
    '0000488b7424308b461089842480000000660f1006660f29442470e8c0960300'
    '8b6c24244c8b60204981fce80300000f83900000004c8b7424404c89b4240002'
    '0000488b5c2418488bb3e03800004885f67434488b93e8380000488dbc241001'
    '0000488d8c2400020000e881118c0080bc2410010000000f8471010000488b5c'
    '24184c8b742440488bb3000200004939f60f83fb050000488b83f80100004c89'
    'f148c1e10548837c080800488b442410488b4c24280f85470100006641bf6200'
    'e9e00300006641bfc30041f6c6010f851501000080fb020f850c010000488b7c'
    '2430ff1520740503b91027000084c00f85a70300004c89a424d8000000488b4c'
    '2418488b81c80500004885c00f8416030000488ba9c00500004c69e8f0020000'
    '4881c5f80000004531e431db0f1f4000488b4c24308b41108984242001000066'
    '0f1001660f298424100100004889ef488db42410010000e87499fd004c8b7040'
    '488b40484d89f74901df72234989c64d01e672534881c5f00200004d89f44c89'
    'fb4981c510fdffff75a6e98b02000048898424d000000031ff488d35a89fff02'
    'ff15ca7205034901de48c7c0ffffffff4c0f42f04d89f7488b8424d000000049'
    '89c64d01e673ad4989c631ff488d35759fff02ff15977205034d01e648c7c0ff'
    'ffffff4c0f42f0eb8be9b7020000488b5c2418488b442410488b4c24284c8b74'
    '2440488b9424a00200004883c208488b7424484889b424000200000f1002660f'
    '104a100f11842408020000660f118c2418020000488984242802000048898c24'
    '30020000488b8424f80000004889842438020000660f28842450020000660f13'
    '842440020000488b8424000100004889842448020000488dbc2410010000488d'
    'b42480010000488d8c2400020000488b5424304989d8e8954efbff6681bc2410'
    '01000086010f8542020000488b839008000048ffc048c7c1ffffffff480f45c8'
    '48898b900800004883bb883a0000000f845e02000031c9f68424e80000000148'
    '0f458c24f0000000488b44245848f7e10f80530300004989c548b8feffffffff'
    'ffff7f4939c50f873d030000488bb3903300004939f60f8388030000488b8388'
    '3300004969ced8000000488d34084881c680000000488d7c2470e871b3c7ff48'
    '8bbb883a00004885ff0f84e40100000f57c0f2490f2ac5f20f5e0501e1aefd48'
    '8b442470488b4c24784889ca4821c24889ce4831c648d1ee4801d64885c9480f'
    '44f14885c0480f44f031c94885f60f95c166480f6ed6f30f7e1dc27daefd660f'
    '62d3660f2825d66daefd660f5cd4660f28ca660f15caf20f58caf30f7e542458'
    '660f62d3660f5cd4660f28da660f15daf20f58daf20f5ecbf20f580d78e1aefd'
    '488b83903a0000488b7424308b5610899424800000000f10160f295424700fb6'
    '54240f488d7424704c8b442460448b4c243cff5028e91901000049f7d68b6c24'
    '24488b4c2418eb0a49c7c6ffffffff4531ff488db980000000488d742470ff15'
    '0c7005034c8b20488b58084d89e54d01fd0f82010200004c39f30f871e020000'
    '49c1ed0848b9535a9ba02fb844004c89e848f7e148c1ea0b4881faa00f0000b9'
    'a00f0000480f42ca4881c1e80300006641bfc3004c8ba424d80000004939cc0f'
    '8290fbffff488b4424404889842418010000664489bc241001000048837c2448'
    '020f93c0488b5424104885d20f94c108c1488b5c2418751548c1e203488d34d2'
    '488b7c242831d2ff15031e0503488bbb883a00004885ff743a488b83903a0000'
    '488b5424308b4a10898c2480000000660f1002660f29442470488d742470488d'
    '942410010000488b4c2460448b44243cff50300f108424600100000f298424c0'
    '0000000f108424500100000f298424b0000000660f10842410010000660f108c'
    '24200100000f10942430010000660f109c2440010000660f299c24a00000000f'
    '29942490000000660f298c2480000000660f2944247081fd00ca9a3b744dbf01'
    '000000e838757c02488984247001000089942478010000488b8424e000000048'
    '8984240002000089ac2408020000488dbc2410010000488db42470010000488d'
    '942400020000e825747c020f288424c0000000488b8424080100000f1140500f'
    '288424b00000000f1140400f284424700f288c24800000000f28942490000000'
    '0f289c24a00000000f1158300f1150200f1148100f11004881c4680200005b41'
    '5c415d415e415f5dc3488d3d3816fa02ff15fa200503eb5c488d3569f0fc0231'
    'ffff15096e05034d01fc49c7c5ffffffff4d0f43ec4c39f30f86e2fdffff488d'
    '358bf0fc0231ffff15e36d0503e9cefdffff488d151f5cfd024c89f7ff15061c'
    '0503eb10488d1595f0f9024c89f7ff15f41b05030f0b4889c3488d7c2470e8dd'
    '070600e98b000000ff153a1d05034c896424284889c34c897c24104d85ff7541'
    'eb714889c3488b8424c801000048894424104885c0745c488b8424d001000048'
    '89442428eb1beb004889c348837c2448020f93c048837c2410000f94c108c175'
    '32488b44241048c1e003488d34c0488b7c242831d2ff15b51b05034889dfe8ad'
    '3cf4024889c3488dbc2410010000e84d0706004889dfe8953cf402ff15a71c05'
    '03'
)
BODY_SHA256 = 'e5dd5442c1e4b3391d1e99a6a51c073c165d406154e46dec6ae0ccdd9ac0ca35'
BRANCHES = [
    (0xdc, '7418', 1, 2, 0x271bc36),
    (0xf4, 'eb08', 1, 2, 0x271bc3e),
    (0x20f, '0f8390000000', 2, 6, 0x271bde5),
    (0x231, '7434', 1, 2, 0x271bda7),
    (0x257, '0f8471010000', 2, 6, 0x271bf0e),
    (0x271, '0f83fb050000', 2, 6, 0x271c3b2),
    (0x295, '0f8547010000', 2, 6, 0x271bf22),
    (0x2a0, 'e9e0030000', 1, 5, 0x271c1c5),
    (0x2ae, '0f8515010000', 2, 6, 0x271bf09),
    (0x2b7, '0f850c010000', 2, 6, 0x271bf09),
    (0x2cf, '0f85a7030000', 2, 6, 0x271c1bc),
    (0x2ec, '0f8416030000', 2, 6, 0x271c148),
    (0x34a, '7223', 1, 2, 0x271beaf),
    (0x352, '7253', 1, 2, 0x271bee7),
    (0x368, '75a6', 1, 2, 0x271be50),
    (0x36a, 'e98b020000', 1, 5, 0x271c13a),
    (0x3a5, '73ad', 1, 2, 0x271be94),
    (0x3c7, 'eb8b', 1, 2, 0x271be94),
    (0x3c9, 'e9b7020000', 1, 5, 0x271c1c5),
    (0x485, '0f8542020000', 2, 6, 0x271c20d),
    (0x4af, '0f845e020000', 2, 6, 0x271c253),
    (0x4d0, '0f8053030000', 2, 6, 0x271c369),
    (0x4e6, '0f873d030000', 2, 6, 0x271c369),
    (0x4f6, '0f8388030000', 2, 6, 0x271c3c4),
    (0x529, '0f84e4010000', 2, 6, 0x271c253),
    (0x5f5, 'e919010000', 1, 5, 0x271c253),
    (0x606, 'eb0a', 1, 2, 0x271c152),
    (0x631, '0f8201020000', 2, 6, 0x271c378),
    (0x63a, '0f871e020000', 2, 6, 0x271c39e),
    (0x67f, '0f8290fbffff', 2, 6, 0x271bd55),
    (0x6b6, '7515', 1, 2, 0x271c20d),
    (0x6d7, '743a', 1, 2, 0x271c253),
    (0x77c, '744d', 1, 2, 0x271c30b),
    (0x836, 'eb5c', 1, 2, 0x271c3d4),
    (0x858, '0f86e2fdffff', 2, 6, 0x271c180),
    (0x86d, 'e9cefdffff', 1, 5, 0x271c180),
    (0x882, 'eb10', 1, 2, 0x271c3d4),
    (0x8a3, 'e98b000000', 1, 5, 0x271c473),
    (0x8be, '7541', 1, 2, 0x271c441),
    (0x8c0, 'eb71', 1, 2, 0x271c473),
    (0x8d5, '745c', 1, 2, 0x271c473),
    (0x8e4, 'eb1b', 1, 2, 0x271c441),
    (0x8e6, 'eb00', 1, 2, 0x271c428),
    (0x8ff, '7532', 1, 2, 0x271c473),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x271bc23, 0x4ee3800),
    (0x271bcaa, 0x4ee3800),
    (0x271bd3b, 0x2755400),
    (0x271bd8a, 0x2fdcf10),
    (0x271be77, 0x36f57f0),
    (0x271bfb6, 0x26d0e50),
    (0x271c05a, 0x23973d0),
    (0x271c2c3, 0x4ee3800),
    (0x271c306, 0x4ee3730),
    (0x271c3de, 0x277cbc0),
    (0x271c45e, 0x5660110),
    (0x271c46e, 0x277cbc0),
    (0x271c476, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x271bc0f, 0x576e8f8),
    (0x271be02, 0x5773228),
    (0x271bec0, 0x5773190),
    (0x271bef3, 0x5773190),
    (0x271c15e, 0x5773170),
    (0x271c207, 0x576e010),
    (0x271c370, 0x576e470),
    (0x271c381, 0x5773190),
    (0x271c3a7, 0x5773190),
    (0x271c3bc, 0x576dfc8),
    (0x271c3ce, 0x576dfc8),
    (0x271c3e8, 0x576e128),
    (0x271c455, 0x576e010),
    (0x271c47b, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x271c369, 0x56bd9a8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f696d706c5f74726164696e672e7273'), 368, 86),
    (0x271c3b2, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x271c3c4, 0x56bb460, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = [0x24bc050, 0x271f55d, 0x271fdec, 0x27208c0]
CALLER_FUNCTIONS = {'0x24bc050': ('0x24bbee0', '0x24bc716'), '0x271f55d': ('0x271e730', '0x2721113'), '0x271fdec': ('0x271e730', '0x2721113'), '0x27208c0': ('0x271e730', '0x2721113')}
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

