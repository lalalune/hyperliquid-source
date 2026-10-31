#!/usr/bin/env python3
"""Authenticated node94 books-4d1afa0 binding (0x4d1afa0).

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

START, END = 0x4d1afa0, 0x4d1b8b0
FDE_VA = 0x12e13b4
FDE = bytes.fromhex(
    '500000008c373200e49ba3031009000004ef2c8dff410e10420e18420e20420e'
    '28420e30410e38470ec00483078c068d058e048f038602030e080e38410e3042'
    '0e28420e20420e18420e10410e08410ec0040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec080200004d89cd4c8984240001000048894c24'
    '2848897424104889fd0fb642198844240e488b024889442460488b4208488944'
    '2468488b42204889442448488b422848894424380fb642308844240d48899424'
    'f80000000fb642318844240f498b014889442418498b41084889442430bf3200'
    '0000ff15d038a50084c07418bf01000000e8ca871c0048898424e80000008954'
    '2424eb08c744242400ca9a3bbf01000000e8aa871c0048894424588954244448'
    '8b7c2410488b878808000048ffc048c7c1ffffffff480f45c8488b9424400200'
    '0048898f88080000498b451048898424f0000000488b024889442450488b4c24'
    '288b4110898424800000000f10010f294424708b411089842460010000660f10'
    '01660f29842450010000488db42450010000e8097f9dff4c8b70204981fee803'
    '00000f8385000000488b7c24384889bc24b80100004c8b442410498bb0e03800'
    '004885f67434498b90e8380000488dbc2450010000488d8c24b8010000e8ee1d'
    '2cfe80bc2450010000000f84690100004c8b442410488b7c2438498bb0000200'
    '004839f70f83c9060000498b80f80100004889f948c1e10548837c0808000f85'
    '3f01000066bb6200e9b8040000807c240e020f95c00a44240f66bbc300a80174'
    '05e99f040000488b7c2428ff159780a500b91027000084c00f857e0400004c89'
    'b424e0000000488b4c2410488b81c80500004885c00f84e90300004889ac24d8'
    '000000488ba9c00500004c69e8f00200004881c5f80000004531ff31db0f1f00'
    '488b4c24288b411089842460010000660f1001660f298424500100004889ef48'
    '8db42450010000e8e4a59dfe4c8b6040488b40484d89e64901de72234989c44d'
    '01fc72534881c5f00200004d89e74c89f34981c510fdffff75a6e95803000048'
    '898424d000000031ff488d3518ac9f00ff153a7fa5004901dc48c7c0ffffffff'
    '4c0f42e04d89e6488b8424d00000004989c44d01fc73ad4989c431ff488d35e5'
    'ab9f00ff15077fa5004d01fc48c7c0ffffffff4c0f42e0eb8b4c8b442410488b'
    '7c2438488b9424f8000000488d4210488b4c246048898c2408010000488b4c24'
    '6848898c2410010000488b0848898c24180100000fb64008488d4a1a88842420'
    '0100000fb644240e888424210100008b01898424220100000fb7410466898424'
    '26010000488b44244848898424280100004889bc24300100000fb644240d8884'
    '24380100000fb644240f888424390100004883c2320f10020f1184243a010000'
    '488b420e4889842448010000488b44245048898424b8010000488b8424400200'
    '004883c0080f1000660f1048100f118424c0010000660f118c24d0010000488b'
    '44241848898424e0010000488b44243048898424e8010000488b8424f0000000'
    '48898424f00100008b842448020000898424f80100008b842450020000898424'
    'fc010000488b8424000100004889842400020000488b4c24288b411089842480'
    '000000660f1001660f29442470488dbc2450010000488db42408010000488d54'
    '2470488d8c24b8010000e8612e74ff6681bc245001000086010f854802000048'
    '8b542410488b829008000048ffc048c7c1ffffffff480f45c848898a90080000'
    '4883ba883a0000000f846402000031c9f644246001480f454c2468488b442448'
    '48f7e10f80610300004989c648b8feffffffffffff7f4939c60f874b03000048'
    '8b5c2410488bb390330000488b7c24384839f70f8389030000488b8388330000'
    '4869cfd8000000488d34084881c680000000488d7c2470e8c4c1ceff488bbb88'
    '3a00004885ff0f84e60100000f57c0f2490f2ac6f20f5e05a4ec4efb488b4424'
    '70488b4c24784889ca4821c24889ce4831c648d1ee4801d64885c9480f44f148'
    '85c0480f44f031c94885f60f95c166480f6ed6f30f7e1d65894efb660f62d366'
    '0f282579794efb660f5cd4660f28ca660f15caf20f58caf30f7e542448660f62'
    'd3660f5cd4660f28da660f15daf20f58daf20f5ecbf20f580d1bed4efb488b83'
    '903a0000488b7424288b5610899424800000000f10160f295424700fb654240d'
    '488d7424704c8b442458448b4c2444ff5028e91b01000049f7d4488bac24d800'
    '0000eb0a49c7c4ffffffff4531f6488b442410488db880000000488d742470ff'
    '15ab7ba5004c8b38488b58084d89fd4d01f50f82010200004c39e30f871e0200'
    '0049c1ed0848b9535a9ba02fb844004c89e848f7e148c1ea0b4881faa00f0000'
    'b9a00f0000480f42ca4881c1e803000066bbc3004c8bb424e00000004939ce0f'
    '82c3faffff488b442438488984245801000066899c245001000048837c245002'
    '0f93c0488b5424184885d20f94c108c1751548c1e203488d34d2488b7c243031'
    'd2ff15a929a500488b442410488bb8883a00004885ff743a488b80903a000048'
    '8b5424288b4a10898c2480000000660f1002660f29442470488d742470488d94'
    '2450010000488b4c2458448b442444ff50300f108424a00100000f298424c000'
    '00000f108424900100000f298424b0000000660f10842450010000660f108c24'
    '600100000f10942470010000660f109c2480010000660f299c24a00000000f29'
    '942490000000660f298c2480000000660f29442470817c242400ca9a3b7451bf'
    '01000000e8d7801c00488984240801000089942410010000488b8424e8000000'
    '48898424b80100008b442424898424c0010000488dbc2450010000488db42408'
    '010000488d9424b8010000e8c07f1c000f288424c00000000f1145500f288424'
    'b00000000f1145400f284424700f288c24800000000f289424900000000f289c'
    '24a00000000f115d300f1155200f114d100f1145004889e84881c4080200005b'
    '415c415d415e415f5dc3488d3ddf8da200ff15992ca500eb56488d3508fc9c00'
    '31ffff15a879a5004d01f749c7c5ffffffff4d0f43ef4c39e30f86e2fdffff48'
    '8d352afc9c0031ffff158279a500e9cefdffff488d15be679d00ff15a827a500'
    'eb0d488d15f76aa200ff159927a5000f0b4889c3488d7c2470e882310900eb62'
    'ff15e228a500eb004889c348837c241800751deb4deb004889c348837c245002'
    '0f93c048837c2418000f94c108c17532488b44241848c1e003488d34c0488b7c'
    '243031d2ff158627a5004889dfe87e4894004889c3488dbc2450010000e81e31'
    '09004889dfe866489400ff157828a500'
)
BODY_SHA256 = 'd89bc2e6a3e405584a4abe7564b5d4cfad9314cedb3091dbb0d85e273b560ddd'
BRANCHES = [
    (0x8a, '7418', 1, 2, 0x4d1b044),
    (0xa2, 'eb08', 1, 2, 0x4d1b04c),
    (0x142, '0f8385000000', 2, 6, 0x4d1b16d),
    (0x164, '7434', 1, 2, 0x4d1b13a),
    (0x18a, '0f8469010000', 2, 6, 0x4d1b299),
    (0x1a4, '0f83c9060000', 2, 6, 0x4d1b813),
    (0x1be, '0f853f010000', 2, 6, 0x4d1b2a3),
    (0x1c8, 'e9b8040000', 1, 5, 0x4d1b625),
    (0x1df, '7405', 1, 2, 0x4d1b186),
    (0x1e1, 'e99f040000', 1, 5, 0x4d1b625),
    (0x1f8, '0f857e040000', 2, 6, 0x4d1b61c),
    (0x215, '0f84e9030000', 2, 6, 0x4d1b5a4),
    (0x27a, '7223', 1, 2, 0x4d1b23f),
    (0x282, '7253', 1, 2, 0x4d1b277),
    (0x298, '75a6', 1, 2, 0x4d1b1e0),
    (0x29a, 'e958030000', 1, 5, 0x4d1b597),
    (0x2d5, '73ad', 1, 2, 0x4d1b224),
    (0x2f7, 'eb8b', 1, 2, 0x4d1b224),
    (0x479, '0f8548020000', 2, 6, 0x4d1b667),
    (0x4a8, '0f8464020000', 2, 6, 0x4d1b6b2),
    (0x4c3, '0f8061030000', 2, 6, 0x4d1b7ca),
    (0x4d9, '0f874b030000', 2, 6, 0x4d1b7ca),
    (0x4f3, '0f8389030000', 2, 6, 0x4d1b822),
    (0x526, '0f84e6010000', 2, 6, 0x4d1b6b2),
    (0x5f2, 'e91b010000', 1, 5, 0x4d1b6b2),
    (0x602, 'eb0a', 1, 2, 0x4d1b5ae),
    (0x632, '0f8201020000', 2, 6, 0x4d1b7d9),
    (0x63b, '0f871e020000', 2, 6, 0x4d1b7ff),
    (0x67f, '0f82c3faffff', 2, 6, 0x4d1b0e8),
    (0x6b0, '7515', 1, 2, 0x4d1b667),
    (0x6d6, '743a', 1, 2, 0x4d1b6b2),
    (0x77d, '7451', 1, 2, 0x4d1b770),
    (0x837, 'eb56', 1, 2, 0x4d1b82f),
    (0x859, '0f86e2fdffff', 2, 6, 0x4d1b5e1),
    (0x86e, 'e9cefdffff', 1, 5, 0x4d1b5e1),
    (0x880, 'eb0d', 1, 2, 0x4d1b82f),
    (0x89e, 'eb62', 1, 2, 0x4d1b8a2),
    (0x8a6, 'eb00', 1, 2, 0x4d1b848),
    (0x8b1, '751d', 1, 2, 0x4d1b870),
    (0x8b3, 'eb4d', 1, 2, 0x4d1b8a2),
    (0x8b5, 'eb00', 1, 2, 0x4d1b857),
    (0x8ce, '7532', 1, 2, 0x4d1b8a2),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4d1b031, 0x4ee3800),
    (0x4d1b051, 0x4ee3800),
    (0x4d1b0d2, 0x46f2fe0),
    (0x4d1b11d, 0x2fdcf10),
    (0x4d1b207, 0x36f57f0),
    (0x4d1b40a, 0x445e270),
    (0x4d1b4b7, 0x4a07680),
    (0x4d1b724, 0x4ee3800),
    (0x4d1b76b, 0x4ee3730),
    (0x4d1b839, 0x4dae9c0),
    (0x4d1b88d, 0x5660110),
    (0x4d1b89d, 0x4dae9c0),
    (0x4d1b8a5, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4d1b022, 0x576e8f8),
    (0x4d1b18b, 0x5773228),
    (0x4d1b250, 0x5773190),
    (0x4d1b283, 0x5773190),
    (0x4d1b5bf, 0x5773170),
    (0x4d1b661, 0x576e010),
    (0x4d1b7d1, 0x576e470),
    (0x4d1b7e2, 0x5773190),
    (0x4d1b808, 0x5773190),
    (0x4d1b81a, 0x576dfc8),
    (0x4d1b829, 0x576dfc8),
    (0x4d1b840, 0x576e128),
    (0x4d1b884, 0x576e010),
    (0x4d1b8aa, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4d1b7ca, 0x57445b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f696d706c5f74726164696e672e7273'), 368, 86),
    (0x4d1b813, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x4d1b822, 0x5742320, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = [0x444ad60, 0x4d2439b, 0x4d24b6c, 0x4d255d4]
CALLER_FUNCTIONS = {'0x444ad60': ('0x444abf0', '0x444b426'), '0x4d2439b': ('0x4d23580', '0x4d25e38'), '0x4d24b6c': ('0x4d23580', '0x4d25e38'), '0x4d255d4': ('0x4d23580', '0x4d25e38')}
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

