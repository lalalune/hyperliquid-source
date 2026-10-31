#!/usr/bin/env python3
"""Authenticated node94 books-2746b40 binding (0x2746b40).

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

START, END = 0x2746b40, 0x274725b
FDE_VA = 0x10f0208
FDE = bytes.fromhex(
    '50000000e0251300306965011b070000046ffc92ff410e10420e18420e20420e'
    '28420e30410e38470e900683078c068d058e048f03860202f30e38410e30420e'
    '28420e20420e18420e10410e08410e9006000000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecd80200004989fc4d85c974284889cb89d14989'
    'f64983f9017521410fb610b00183fa2b0f84b800000083fa2d0f84af000000eb'
    '0b31c0e9a6000000410fb61031c080fa2b0f94c04c89ca4829c24901c048f7d8'
    '4883fa11733e4885d20f84a00000004901c149f7d931d231c00f1f8000000000'
    '410fb6341083c6d083fe09775f488d048089f6488d044648ffc24c89ce4801d6'
    '75deeb6d4901c149f7d931f6bf0a00000031c0666666662e0f1f840000000000'
    '4c89ca4801f2744948f7e7410fb614300f803405000083c2d083fa0a730e89d2'
    '48ffc64801d073d8b002eb02b0016641c70424b70041884424024c89e04881c4'
    'd80200005b415c415d415e415f5dc331c00fb6bc2410030000498db680000000'
    '498d96f8080000488914240fb6d1440fb6cf488dbc24300100004889d94989c0'
    'ff1572df02030fb78424300100003d860100000f85280300004c8bbc24500100'
    '000f108424380100000f11842426020000488b84244801000048898424360200'
    '0048894424300f29442420498d9690000000488d7c24784889deff15d8d90203'
    '4c897c244048895c24104c89642448488b442420488b4c242831d24889c64885'
    'c00f95c27405488b74243048899424b000000048c78424b80000000000000048'
    '898424c000000048898c24c800000048899424d000000048c78424d800000000'
    '00000048898424e000000048898c24e80000004889b424f0000000498d86f308'
    '00004889442458498d46604889442460498d86400700004889442450488b8424'
    '8000000048894424084c8bac2488000000488dac24300100004869442410e800'
    '00004889442418488d9c24e0010000904889ef488db424b0000000e890251200'
    '488b8424300100004885c00f847c0200004989df488b8c2440010000488d1489'
    '0f104490600f298424900000008b74907089b424a0000000488b5cc8080f1044'
    '90600f298424100100008b449070898424200100004d85ed74264c89efff15b5'
    '7102034885c00f844b0300004989c4eb156666666666662e0f1f840000000000'
    '41bc010000004c89e7488b7424084c89eaff1589710203488b442410493b8618'
    '0200000f83c0020000498b8610020000488b4c24180fb644084966480f6ec366'
    '0f6205f9cfabfd660f5c0511c0abfd660f28c8660f15c8f20f58c8488d0d66dc'
    'e3fdf20f5e0cc14c89ac24280200004c89a424300200004c89ac2438020000f2'
    '0f118c244002000048b810000000000000804889842420020000bf14000000ff'
    '15f37002034885c00f844a0200008b8c24a00000008948100f28842490000000'
    '0f110048c78424f800000001000000488984240001000048c784240801000001'
    '000000488b5424608b4a08894c2470488b0a48894c246841833e0175234989c4'
    '498b4e08498b5628410fb6b6f20800004c89fb4c89ff4531c0e8520d2401eb16'
    '0f57c00f298424f00100000f298424e00100004c89fbbab00000004889ef488d'
    'b42420020000ff1554700203488b7c2458488db424f8000000488d5424684889'
    'd94989e8ff158ed70203488b7c2450488db42410010000e8f4d983ffe9effdff'
    'ff0f10842432010000660f108c2440010000660f118c242e0200000f29842420'
    '020000488b8c2450010000488b94248801000049895424580f10842478010000'
    '410f114424480f10842468010000410f114424380f10842458010000410f1144'
    '24280f1084242e020000410f114424100f28842420020000410f114424026641'
    '89042449894c2420e9edfbffff488d9c24300100004c8dbc24b00000004c8b64'
    '24484c8b6c2410488b6c24400f1f40004889df4c89fee8d52212004883bc2430'
    '0100000075ea4885ed74774d3bae180200000f83c1000000498b8e1002000048'
    '8b542418488b441158488b4c1160488d0cc8498b96f8010000498bb600020000'
    '4839c8743d488b384839f70f83b60000004883c0084989f849c1e0054a837c02'
    '080075dc493bbe90330000737b498b96883300004869f7d800000048896c3278'
    'ebb06641c704248601488b7424784885f60f8423fbffff488b7c240831d2ff15'
    'ec6e0203e911fbffff488d3dc0b0fa02ff153a730203eb5cbf01000000be1400'
    '0000ff15d86e0203eb4a80c2d031c080fa0a1401e9d5faffff488d3d90b0fa02'
    'ff150a730203eb2c488d3d0943f702ff15fb720203eb1dbf010000004c89eeff'
    '15336e0203eb0d488d157a91f402ff15346e02030f0b4889c3488d7c2420e8ad'
    '191600e9a5000000ff157a6f02034889c3be140000004c89e731d2ff154f6e02'
    '03eb19eb0feb06eb04eb02eb074889c3eb2feb004889c3eb5d4889c3488dbc24'
    '20020000e8c77e0300eb164889c34d85ed740e4c89e74c89ee31d2ff150f6e02'
    '034c8db424080200004c8dbc24b00000006666666666662e0f1f840000000000'
    '4c89f74c89fee8252112004883bc24080200000075ea488b7424784885f6740d'
    '488b7c240831d2ff15c36d02034889dfe8bb8ef102ff15cd6e0203'
)
BODY_SHA256 = '0463b6323f79eecfd8b470a44b5438b6a17ca17fc9bc1a09c1136674dfbf918d'
BRANCHES = [
    (0x17, '7428', 1, 2, 0x2746b81),
    (0x25, '7521', 1, 2, 0x2746b88),
    (0x30, '0f84b8000000', 2, 6, 0x2746c2e),
    (0x39, '0f84af000000', 2, 6, 0x2746c2e),
    (0x3f, 'eb0b', 1, 2, 0x2746b8c),
    (0x43, 'e9a6000000', 1, 5, 0x2746c2e),
    (0x64, '733e', 1, 2, 0x2746be4),
    (0x69, '0f84a0000000', 2, 6, 0x2746c4f),
    (0x8b, '775f', 1, 2, 0x2746c2c),
    (0xa0, '75de', 1, 2, 0x2746bc0),
    (0xa2, 'eb6d', 1, 2, 0x2746c51),
    (0xc6, '7449', 1, 2, 0x2746c51),
    (0xd0, '0f8034050000', 2, 6, 0x274714a),
    (0xdc, '730e', 1, 2, 0x2746c2c),
    (0xe6, '73d8', 1, 2, 0x2746c00),
    (0xea, 'eb02', 1, 2, 0x2746c2e),
    (0x153, '0f8528030000', 2, 6, 0x2746fc1),
    (0x1c4, '7405', 1, 2, 0x2746d0b),
    (0x28b, '0f847c020000', 2, 6, 0x274704d),
    (0x2d8, '7426', 1, 2, 0x2746e40),
    (0x2e6, '0f844b030000', 2, 6, 0x2747177),
    (0x2ef, 'eb15', 1, 2, 0x2746e46),
    (0x323, '0f83c0020000', 2, 6, 0x2747129),
    (0x3a8, '0f844a020000', 2, 6, 0x2747138),
    (0x3fb, '7523', 1, 2, 0x2746f60),
    (0x41e, 'eb16', 1, 2, 0x2746f76),
    (0x47c, 'e9effdffff', 1, 5, 0x2746db0),
    (0x508, 'e9edfbffff', 1, 5, 0x2746c3a),
    (0x544, '75ea', 1, 2, 0x2747070),
    (0x549, '7477', 1, 2, 0x2747102),
    (0x552, '0f83c1000000', 2, 6, 0x2747159),
    (0x583, '743d', 1, 2, 0x2747102),
    (0x58b, '0f83b6000000', 2, 6, 0x2747187),
    (0x5a2, '75dc', 1, 2, 0x27470c0),
    (0x5ab, '737b', 1, 2, 0x2747168),
    (0x5c0, 'ebb0', 1, 2, 0x27470b2),
    (0x5d1, '0f8423fbffff', 2, 6, 0x2746c3a),
    (0x5e4, 'e911fbffff', 1, 5, 0x2746c3a),
    (0x5f6, 'eb5c', 1, 2, 0x2747194),
    (0x608, 'eb4a', 1, 2, 0x2747194),
    (0x614, 'e9d5faffff', 1, 5, 0x2746c2e),
    (0x626, 'eb2c', 1, 2, 0x2747194),
    (0x635, 'eb1d', 1, 2, 0x2747194),
    (0x645, 'eb0d', 1, 2, 0x2747194),
    (0x663, 'e9a5000000', 1, 5, 0x274724d),
    (0x681, 'eb19', 1, 2, 0x27471dc),
    (0x683, 'eb0f', 1, 2, 0x27471d4),
    (0x685, 'eb06', 1, 2, 0x27471cd),
    (0x687, 'eb04', 1, 2, 0x27471cd),
    (0x689, 'eb02', 1, 2, 0x27471cd),
    (0x68b, 'eb07', 1, 2, 0x27471d4),
    (0x690, 'eb2f', 1, 2, 0x2747201),
    (0x692, 'eb00', 1, 2, 0x27471d4),
    (0x697, 'eb5d', 1, 2, 0x2747236),
    (0x6a9, 'eb16', 1, 2, 0x2747201),
    (0x6b1, '740e', 1, 2, 0x2747201),
    (0x6f4, '75ea', 1, 2, 0x2747220),
    (0x6fe, '740d', 1, 2, 0x274724d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2746dbb, 0x2869350),
    (0x2746f59, 0x3987cb0),
    (0x2746fb7, 0x1f849b0),
    (0x2747076, 0x2869350),
    (0x274719e, 0x28a8b50),
    (0x27471e4, 0x277f0b0),
    (0x2747226, 0x2869350),
    (0x2747250, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2746c80, 0x5774bf8),
    (0x2746cda, 0x57746b8),
    (0x2746e1d, 0x576dfd8),
    (0x2746e51, 0x576dfe0),
    (0x2746edf, 0x576dfd8),
    (0x2746f86, 0x576dfe0),
    (0x2746fa4, 0x5774738),
    (0x274711e, 0x576e010),
    (0x2747130, 0x576e470),
    (0x2747142, 0x576e020),
    (0x2747160, 0x576e470),
    (0x274716f, 0x576e470),
    (0x274717f, 0x576dfb8),
    (0x274718e, 0x576dfc8),
    (0x27471a8, 0x576e128),
    (0x27471bb, 0x576e010),
    (0x27471fb, 0x576e010),
    (0x2747247, 0x576e010),
    (0x2747255, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2747129, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2747159, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2747168, 0x56bb478, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x2747187, 0x5690308, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x23e801f, 0x274c89e]
CALLER_FUNCTIONS = {'0x23e801f': ('0x23e7d10', '0x23e863d'), '0x274c89e': ('0x274c600', '0x274c9e7')}
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

