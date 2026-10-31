#!/usr/bin/env python3
"""Authenticated node94 perp-meta-4855be0 binding (0x4855be0).

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

START, END = 0x4855be0, 0x485645e
FDE_VA = 0x129d59c
FDE = bytes.fromhex(
    '6800000074f92d003c865b037e08000004773b8eff410e10420e18420e20420e'
    '28420e30410e38470ec00683078c068d058e048f038602026d0e38410e30420e'
    '28420e20420e18420e10410e08460ec00603a4060e38410e30420e28420e2042'
    '0e18420e10410e08410ec006'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec0803000048894c240880be3002000003740b31'
    'c0483b87d00800007164488b5c2408488b334885f67410488b7b0848c1e60431'
    'd2ff15e983f100488b73184885f67410488b7b2048c1e60431d2ff15d083f100'
    '488b73304885f60f84be060000488b7b3848c1e60431d24881c4080300005b41'
    '5c415d415e415f5dff25a283f1008954242c48897c2468488d87d00800004889'
    '442450488d4660488944247048c78424a80000000000000048c78424b8000000'
    '0000000048c78424c00000000000000048c78424d00000000000000048c78424'
    'd80000000000000048c78424e800000000000000488b442408488d40480f57c0'
    '0f118424c001000048898424f800000048c78424080100000300000066c78424'
    '100100000001c684241201000002488b8424c80100004889842420010000660f'
    '108424bb010000660f11842413010000c684245001000003488b463048898424'
    '88000000488b460848894424604889742478488b4610488984248000000040b6'
    '034531f64531e44080fe0374134839df740e488b4424084c01e0eb4c0f1f4000'
    '4983fe030f84d40100004983fc480f84ca01000049ffc6488b4424084a8b5c20'
    '104983c4184885db74d6488b4c24084a8d04214a8b7c21f048c1e3044801fb42'
    '0fb6b4340f0100004088b424380100004c89b4240001000048898424f0000000'
    '48899c24300100004c8d8424c00000004084f6741b400fb6c683f801750a4c8d'
    '8424a8000000eb084c8d8424d8000000488b0f4889c848ba4b598638d6c56d34'
    '48f7e248c1ea0b483b9424880000000f85e80400004869c2102700004829c148'
    '3b8c24800000000f83d00400004c898424a000000040887424074889bc249000'
    '0000488b470848898424980000004c8d3c4949c1e704488b4424604a8b743808'
    '4e8b6c38104d85ed74274c89ef4989f548897c2458ff153d81f1004885c00f84'
    '970400004889c54c89ee4c8b6c2458eb05bd010000004889ef4c89eaff151e81'
    'f1004c89ac24700200004889ac24780200004c89ac2480020000488b44246042'
    '0fb644382a4883f8070f833d040000b90600000029c1f20f108c24980000000f'
    '140d7adf9afb660f5c0d92cf9afb660f28c1660f15c1f20f58c1c1e103488d05'
    '4c15eafbf20f5e0401488bbc24a0000000488db42470020000e8e2740e00488b'
    'bc24900000004883c7100fb67424074080fe030f8514feffffe922feffff488b'
    '8424b800000048894424400f108424a80000000f29442430488b8424d0000000'
    '48894424200f108424c00000000f29442410488b8424e8000000488984248002'
    '0000660f108424d8000000660f29842470020000488dbc24f0000000488b7424'
    '70488b542478ff155cf5f1008b44242c888424600200000f284424300f298424'
    'd0010000488b44244048898424e00100000f284424100f118424e8010000488b'
    '44242048898424f80100000f288424700200000f29842400020000488b842480'
    '0200004889842410020000660f108424f0000000660f108c24000100000f1094'
    '24100100000f109c2420010000660f11842418020000660f118c24280200000f'
    '119424380200000f119c2448020000488b84243001000048898424580200004c'
    '8b742468410fb6ae780a0000488dbc24ac010000ff150688f100488dbc247002'
    '0000488db424d0010000ba98000000ff152b7ff100498b868009000048ba0000'
    '0000000000804831c24885c0b901000000480f48ca4885c9744f4883f9017568'
    '498b9e900900004839c3750d498dbe80090000ff15a709f2004869fb98000000'
    '4903be88090000488db424d0010000ba98000000ff15c67ef10048ffc349899e'
    '90090000e993010000488db424ac010000488d942470020000488b7c2450e86d'
    'c1eaffe9d9000000418b9e680a000085db0f84ca0000004d8bbe600a00004d8b'
    'a66c0a0000488d7c2430ff153087f1004084ed0f84ba0000008b442438894424'
    '18488b4424304889442410488d742414488dbc24f000000031d2b9005a6202ff'
    '150387f100488b8424f800000048b9000000004057ffff4801c148ba81aefeff'
    '7faefeff4839d1723a448bac24f0000000448bb424f40000008b7c241048b957'
    '2951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6ff15b386f10089c585'
    'c0753e488d3d153e9cfb488d15074de100be26000000ff154c82f100e92a0100'
    '00488dbc24d0010000e88202f9ffe9890000008b6c2430448b6c2434448b7424'
    '38896c241044896c24144489742418488dbc24f8000000488db424d0010000ba'
    '98000000ff15767df10089ac24900100004489ac24940100004489b424980100'
    '00899c249c0100004c89a424a00100004c89bc24f0000000488d742410488d94'
    '24f0000000488b7c2450e801cceaff488dbc24f8000000e8f401f9ff488b5c24'
    '08488b334885f67410488b7b0848c1e60431d2ff15377df100488b73184885f6'
    '7410488b7b2048c1e60431d2ff151e7df100488b73304885f67410488b7b3848'
    'c1e60431d2ff15057df1004881c4080300005b415c415d415e415f5dc3488d3d'
    '9cbee900ff154681f100eb1f488d3d1dd0e900ff15177ef100eb10bf01000000'
    '488b742458ff156d7cf1000f0b4989c6488dbc24d0010000e85301f9ffe9e400'
    '0000ff15c07df1004989c6488dbc24f8000000e83801f9ffe9c90000004989c6'
    '488dbc24d0010000e82301f9ffe9b4000000ff15907df1004989c6488dbc24d0'
    '010000e80801f9ffe999000000ff15757df1004989c6488b7c2408e8c04df9ff'
    '4c89f7e8489de0004989c6488dbc24d0010000e8d800f9ffeb6c4989c6488dbc'
    '2470020000e8d6831500488d7c2410e8cc831500488d7c2430e8c2831500eb46'
    'eb1a4989c64d85ed74154889ef4c89ee31d2ff15f87bf100eb05eb004989c648'
    '8dbc24d8000000e894831500488dbc24c0000000e887831500488dbc24a80000'
    '00e87a831500488b7c2408e8304df9ff4c89f7e8b89ce000ff15ca7cf100'
)
BODY_SHA256 = '94d517549b0af87bf5926e353395bb831356fc224adc2e28ff60f00d9ec6bf1e'
BRANCHES = [
    (0x1d, '740b', 1, 2, 0x4855c0a),
    (0x28, '7164', 1, 2, 0x4855c6e),
    (0x35, '7410', 1, 2, 0x4855c27),
    (0x4e, '7410', 1, 2, 0x4855c40),
    (0x67, '0f84be060000', 2, 6, 0x485630b),
    (0x88, 'ff25a283f100', 1, 2, 0x4855c8f),
    (0x18b, '7413', 1, 2, 0x4855d80),
    (0x190, '740e', 1, 2, 0x4855d80),
    (0x19a, 'eb4c', 1, 2, 0x4855dc8),
    (0x1a4, '0f84d4010000', 2, 6, 0x4855f5e),
    (0x1ae, '0f84ca010000', 2, 6, 0x4855f5e),
    (0x1c8, '74d6', 1, 2, 0x4855d80),
    (0x213, '741b', 1, 2, 0x4855e10),
    (0x21c, '750a', 1, 2, 0x4855e08),
    (0x226, 'eb08', 1, 2, 0x4855e10),
    (0x24f, '0f85e8040000', 2, 6, 0x485631d),
    (0x267, '0f83d0040000', 2, 6, 0x485631d),
    (0x2a8, '7427', 1, 2, 0x4855eb1),
    (0x2be, '0f8497040000', 2, 6, 0x485633b),
    (0x2cf, 'eb05', 1, 2, 0x4855eb6),
    (0x309, '0f833d040000', 2, 6, 0x485632c),
    (0x373, '0f8514feffff', 2, 6, 0x4855d6d),
    (0x379, 'e922feffff', 1, 5, 0x4855d80),
    (0x4f8, '744f', 1, 2, 0x4856129),
    (0x4fe, '7568', 1, 2, 0x4856148),
    (0x50a, '750d', 1, 2, 0x48560f9),
    (0x544, 'e993010000', 1, 5, 0x48562bc),
    (0x563, 'e9d9000000', 1, 5, 0x4856221),
    (0x571, '0f84ca000000', 2, 6, 0x4856221),
    (0x593, '0f84ba000000', 2, 6, 0x4856233),
    (0x5e7, '723a', 1, 2, 0x4856203),
    (0x621, '753e', 1, 2, 0x4856241),
    (0x63c, 'e92a010000', 1, 5, 0x485634b),
    (0x64e, 'e989000000', 1, 5, 0x48562bc),
    (0x6e7, '7410', 1, 2, 0x48562d9),
    (0x700, '7410', 1, 2, 0x48562f2),
    (0x719, '7410', 1, 2, 0x485630b),
    (0x74a, 'eb1f', 1, 2, 0x485634b),
    (0x759, 'eb10', 1, 2, 0x485634b),
    (0x77d, 'e9e4000000', 1, 5, 0x4856446),
    (0x798, 'e9c9000000', 1, 5, 0x4856446),
    (0x7ad, 'e9b4000000', 1, 5, 0x4856446),
    (0x7c8, 'e999000000', 1, 5, 0x4856446),
    (0x7f8, 'eb6c', 1, 2, 0x4856446),
    (0x81e, 'eb46', 1, 2, 0x4856446),
    (0x820, 'eb1a', 1, 2, 0x485641c),
    (0x828, '7415', 1, 2, 0x485641f),
    (0x838, 'eb05', 1, 2, 0x485641f),
    (0x83a, 'eb00', 1, 2, 0x485641c),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4855f39, 0x493d420),
    (0x485613e, 0x47022b0),
    (0x4856229, 0x47e64b0),
    (0x48562aa, 0x4702eb0),
    (0x48562b7, 0x47e64b0),
    (0x4856358, 0x47e64b0),
    (0x4856373, 0x47e64b0),
    (0x4856388, 0x47e64b0),
    (0x48563a3, 0x47e64b0),
    (0x48563bb, 0x47eb180),
    (0x48563c3, 0x5660110),
    (0x48563d3, 0x47e64b0),
    (0x48563e5, 0x49ae7c0),
    (0x48563ef, 0x49ae7c0),
    (0x48563f9, 0x49ae7c0),
    (0x4856427, 0x49ae7c0),
    (0x4856434, 0x49ae7c0),
    (0x4856441, 0x49ae7c0),
    (0x485644b, 0x47eb180),
    (0x4856453, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4855c21, 0x576e010),
    (0x4855c3a, 0x576e010),
    (0x4855e95, 0x576dfd8),
    (0x4855ebc, 0x576dfe0),
    (0x4855fc6, 0x5775528),
    (0x4856094, 0x576e8a0),
    (0x48560af, 0x576dfe0),
    (0x48560f3, 0x5776aa0),
    (0x4856114, 0x576dfe0),
    (0x485616a, 0x576e8a0),
    (0x485619f, 0x576e8a8),
    (0x48561f7, 0x576e8b0),
    (0x4856216, 0x576e468),
    (0x4856264, 0x576dfe0),
    (0x48562d3, 0x576e010),
    (0x48562ec, 0x576e010),
    (0x4856305, 0x576e010),
    (0x4856324, 0x576e470),
    (0x4856333, 0x576e150),
    (0x4856345, 0x576dfb8),
    (0x4856362, 0x576e128),
    (0x4856392, 0x576e128),
    (0x48563ad, 0x576e128),
    (0x4856412, 0x576e010),
    (0x4856458, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x485620a, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
    (0x485631d, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x485632c, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5776b08']
GOT_SITES = {'0x5776b08': ['0x4cf4e86']}


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

