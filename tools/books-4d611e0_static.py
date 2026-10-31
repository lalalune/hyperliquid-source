#!/usr/bin/env python3
"""Authenticated node94 books-4d611e0 binding (0x4d611e0).

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

START, END = 0x4d611e0, 0x4d618ee
FDE_VA = 0x12e4388
FDE = bytes.fromhex(
    '500000006067320050cea7030e07000004ef278dff410e10420e18420e20420e'
    '28420e30410e38470ed00483078c068d058e048f03860202f30e38410e30420e'
    '28420e20420e18420e10410e08410ed004000000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec180200004989fc4d85c974284889cb89d14989'
    'f64983f9017521410fb610b00183fa2b0f84b800000083fa2d0f84af000000eb'
    '0b31c0e9a6000000410fb61031c080fa2b0f94c04c89ca4829c24901c048f7d8'
    '4883fa11733e4885d20f84a00000004901c149f7d931d231c00f1f8000000000'
    '410fb6341083c6d083fe09775f488d048089f6488d044648ffc24c89ce4801d6'
    '75deeb6d4901c149f7d931f6bf0a00000031c0666666662e0f1f840000000000'
    '4c89ca4801f2744948f7e7410fb614300f802705000083c2d083fa0a730e89d2'
    '48ffc64801d073d8b002eb02b0016641c70424b70041884424024c89e04881c4'
    '180200005b415c415d415e415f5dc331c00fb6bc2450020000498db680000000'
    '498d9678130000488914240fb6d1440fb6cf488dbc24300100004889d94989c0'
    'ff15d238a1000fb78424300100003d860100000f851b0300004c8bbc24500100'
    '000f108424380100000f11442446488b84244801000048894424564889442430'
    '0f29442420498d9690000000488dbc24c80000004889deff153b33a1004c89bc'
    '249000000048895c24104c89a42498000000488b442420488b4c242831d24889'
    'c64885c00f95c27405488b742430488954244048c74424480000000048894424'
    '5048894c2458488954246048c744246800000000488944247048894c24784889'
    'b42480000000498d86b805000048898424a8000000498d466048898424b00000'
    '00498d86c011000048898424a0000000488b8424d000000048894424084c8bac'
    '24d8000000488dac24300100004869442410e80000004889442418488d9c24e0'
    '010000666666662e0f1f8400000000004889ef488d742440e8b394beff488b84'
    '24300100004885c00f84660200004989df488b8c2440010000488d14890f1044'
    '90600f298424e00000008b74907089b424f0000000488b5cc8080f104490600f'
    '298424100100008b449070898424200100004d85ed74194c89efff1518cba000'
    '4885c00f84410300004989c4eb08669041bc010000004c89e7488b7424084c89'
    'eaff15f9caa000488b442410493b86180200000f83c3020000498b8610020000'
    '488b4c24180fb644084966480f6ec3660f620569294afb660f5c0581194afb66'
    '0f28c8660f15c8f20f58c8488d0dd63582fbf20f5e0cc14c89ac24380100004c'
    '89a424400100004c89ac2448010000f20f118c245001000048b8100000000000'
    '00804889842430010000bf14000000ff1563caa0004885c00f844d0200008b8c'
    '24f00000008948100f288424e00000000f110048c78424f80000000100000048'
    '8984240001000048c784240801000001000000488b9424b00000008b4a08898c'
    '24c0000000488b0a48898c24b800000041833e01752a4989c4498b4e08498b56'
    '28410fb6b6721300004c89fb4c89ff4531c0e8b966c2feeb1d0f1f8000000000'
    '0f57c00f298424f00100000f298424e00100004c89fb488bbc24a8000000488d'
    'b424f8000000488d9424b80000004889d94989e8ff159654a100488bbc24a000'
    '0000488db42410010000e85166a7ffe9fcfdffff0f10842432010000660f108c'
    '2440010000660f114c244e0f29442440488b8c2450010000488b942488010000'
    '49895424580f10842478010000410f114424480f10842468010000410f114424'
    '380f10842458010000410f114424280f1044244e410f114424100f2844244041'
    '0f11442402664189042449894c2420e906fcffff488d9c24300100004c8d7c24'
    '404c8ba424980000004c8b6c2410488bac2490000000662e0f1f840000000000'
    '4889df4c89fee80592beff4883bc24300100000075ea4885ed74774d3bae1802'
    '00000f83c4000000498b8e10020000488b542418488b441158488b4c1160488d'
    '0cc8498b96f8010000498bb6000200004839c8743d488b384839f70f83b90000'
    '004883c0084989f849c1e0054a837c02080075dc493bbe103e0000737e498b96'
    '083e00004869f7d800000048896c3278ebb06641c704248601488bb424c80000'
    '004885f60f8430fbffff488b7c240831d2ff1559c8a000e91efbffff488d3d2d'
    '0a9900ff15a7cca000eb5cbf01000000be14000000ff1545c8a000eb4a80c2d0'
    '31c080fa0a1401e9e2faffff488d3dfd099900ff1577cca000eb2c488d3d360b'
    '9e00ff1568cca000eb1dbf010000004c89eeff15a0c7a000eb0d488d152f0b9e'
    '00ff15a1c7a0000f0b4889c3488d7c2420e84a38c5ffe9a5000000ff15e7c8a0'
    '004889c3be140000004c89e731d2ff15bcc7a000eb19eb0feb06eb04eb02eb07'
    '4889c3eb2feb004889c3eb5a4889c3488dbc2430010000e804e70400eb164889'
    'c34d85ed740e4c89e74c89ee31d2ff157cc7a0004c8db424000200004c8d7c24'
    '406666666666662e0f1f8400000000004c89f74c89fee85590beff4883bc2400'
    '0200000075ea488bb424c80000004885f6740d488b7c240831d2ff1530c7a000'
    '4889dfe828e88f00ff153ac8a000'
)
BODY_SHA256 = '3ed97c1561e88f6e524b2c27a479216e8aa8e0c0c11093693922c750e7a42cc8'
BRANCHES = [
    (0x17, '7428', 1, 2, 0x4d61221),
    (0x25, '7521', 1, 2, 0x4d61228),
    (0x30, '0f84b8000000', 2, 6, 0x4d612ce),
    (0x39, '0f84af000000', 2, 6, 0x4d612ce),
    (0x3f, 'eb0b', 1, 2, 0x4d6122c),
    (0x43, 'e9a6000000', 1, 5, 0x4d612ce),
    (0x64, '733e', 1, 2, 0x4d61284),
    (0x69, '0f84a0000000', 2, 6, 0x4d612ef),
    (0x8b, '775f', 1, 2, 0x4d612cc),
    (0xa0, '75de', 1, 2, 0x4d61260),
    (0xa2, 'eb6d', 1, 2, 0x4d612f1),
    (0xc6, '7449', 1, 2, 0x4d612f1),
    (0xd0, '0f8027050000', 2, 6, 0x4d617dd),
    (0xdc, '730e', 1, 2, 0x4d612cc),
    (0xe6, '73d8', 1, 2, 0x4d612a0),
    (0xea, 'eb02', 1, 2, 0x4d612ce),
    (0x153, '0f851b030000', 2, 6, 0x4d61654),
    (0x1c7, '7405', 1, 2, 0x4d613ae),
    (0x288, '0f8466020000', 2, 6, 0x4d616d4),
    (0x2d5, '7419', 1, 2, 0x4d614d0),
    (0x2e3, '0f8441030000', 2, 6, 0x4d6180a),
    (0x2ec, 'eb08', 1, 2, 0x4d614d6),
    (0x313, '0f83c3020000', 2, 6, 0x4d617bc),
    (0x398, '0f844d020000', 2, 6, 0x4d617cb),
    (0x3f4, '752a', 1, 2, 0x4d61600),
    (0x417, 'eb1d', 1, 2, 0x4d61616),
    (0x46f, 'e9fcfdffff', 1, 5, 0x4d61450),
    (0x4ef, 'e906fcffff', 1, 5, 0x4d612da),
    (0x534, '75ea', 1, 2, 0x4d61700),
    (0x539, '7477', 1, 2, 0x4d61792),
    (0x542, '0f83c4000000', 2, 6, 0x4d617ec),
    (0x573, '743d', 1, 2, 0x4d61792),
    (0x57b, '0f83b9000000', 2, 6, 0x4d6181a),
    (0x592, '75dc', 1, 2, 0x4d61750),
    (0x59b, '737e', 1, 2, 0x4d617fb),
    (0x5b0, 'ebb0', 1, 2, 0x4d61742),
    (0x5c4, '0f8430fbffff', 2, 6, 0x4d612da),
    (0x5d7, 'e91efbffff', 1, 5, 0x4d612da),
    (0x5e9, 'eb5c', 1, 2, 0x4d61827),
    (0x5fb, 'eb4a', 1, 2, 0x4d61827),
    (0x607, 'e9e2faffff', 1, 5, 0x4d612ce),
    (0x619, 'eb2c', 1, 2, 0x4d61827),
    (0x628, 'eb1d', 1, 2, 0x4d61827),
    (0x638, 'eb0d', 1, 2, 0x4d61827),
    (0x656, 'e9a5000000', 1, 5, 0x4d618e0),
    (0x674, 'eb19', 1, 2, 0x4d6186f),
    (0x676, 'eb0f', 1, 2, 0x4d61867),
    (0x678, 'eb06', 1, 2, 0x4d61860),
    (0x67a, 'eb04', 1, 2, 0x4d61860),
    (0x67c, 'eb02', 1, 2, 0x4d61860),
    (0x67e, 'eb07', 1, 2, 0x4d61867),
    (0x683, 'eb2f', 1, 2, 0x4d61894),
    (0x685, 'eb00', 1, 2, 0x4d61867),
    (0x68a, 'eb5a', 1, 2, 0x4d618c6),
    (0x69c, 'eb16', 1, 2, 0x4d61894),
    (0x6a4, '740e', 1, 2, 0x4d61894),
    (0x6e4, '75ea', 1, 2, 0x4d618b0),
    (0x6f1, '740d', 1, 2, 0x4d618e0),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4d61458, 0x494a910),
    (0x4d615f2, 0x3987cb0),
    (0x4d6164a, 0x47d7ca0),
    (0x4d61706, 0x494a910),
    (0x4d61831, 0x49b5080),
    (0x4d61877, 0x4daff80),
    (0x4d618b6, 0x494a910),
    (0x4d618e3, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4d61320, 0x5774bf8),
    (0x4d61377, 0x57746b8),
    (0x4d614ba, 0x576dfd8),
    (0x4d614e1, 0x576dfe0),
    (0x4d6156f, 0x576dfd8),
    (0x4d61634, 0x5776ad0),
    (0x4d617b1, 0x576e010),
    (0x4d617c3, 0x576e470),
    (0x4d617d5, 0x576e020),
    (0x4d617f3, 0x576e470),
    (0x4d61802, 0x576e470),
    (0x4d61812, 0x576dfb8),
    (0x4d61821, 0x576dfc8),
    (0x4d6183b, 0x576e128),
    (0x4d6184e, 0x576e010),
    (0x4d6188e, 0x576e010),
    (0x4d618da, 0x576e010),
    (0x4d618e8, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4d617bc, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d617ec, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d617fb, 0x5742338, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x4d6181a, 0x5742350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x4ad84ef, 0x4d6c21e]
CALLER_FUNCTIONS = {'0x4ad84ef': ('0x4ad81e0', '0x4ad8b0d'), '0x4d6c21e': ('0x4d6bf80', '0x4d6c367')}
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

