#!/usr/bin/env python3
"""Authenticated node94 clearinghouses-24bda40 binding (0x24bda40).

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

START, END = 0x24bda40, 0x24be316
FDE_VA = 0x10be314
FDE = bytes.fromhex(
    'ac000000ec06100024f73f01d608000004c70e94ff410e10420e18420e20420e'
    '28420e30410e38470ec00583078c068d058e048f038602031e012e20440ec805'
    '650ed005410ed805460ee005490ec00502f52e00026a2e00542e0002432e0002'
    'dc2e00025c2e0002ce2e0002ef2e0002c52e000310012e004f0e38410e30420e'
    '28420e20420e18420e10410e08410ec0052e004f2e004f2e00562e006c2e004c'
    '2e004b2e005b2e00702e00482e000000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec88020000488b5f0848897c2478488b6f184839'
    'eb488934240f84960700004c8b6618488b462048898424f8000000488b462848'
    '898424f0000000488b463048898424e80000004c8b76384c8b6e08488b461048'
    '898424e00000004c8b46404889ac24800000004c896424080f1f840000000000'
    '488b4340488d942440020000488942400f10030f104b100f1053200f105b300f'
    '115a300f1152200f114a100f11024c898424380200004c8bbc2468020000488b'
    '8c24f80000008b4110898424800100000f10010f2984247001000048c7842400'
    '0100000000000048c78424080100000800000048c78424100100000000000048'
    '8b8c24f0000000488b412048894424300f10010f1049100f294c24200f294424'
    '10488b8c24e80000008b01448b51044883ec08488dbc24b00100004c89e6488d'
    '8c24780100004c898424a00000004c8d8c2408010000415250488d44242850e8'
    '7cd625004883c4200fb78424a80100003d860100000f851502000048899c24d8'
    '0000004c89ac2488000000488b8424b001000048898424c0000000488b8424b8'
    '0100004889842490000000488b8424c0010000488b8c24c801000048898c24c8'
    '000000488b8c24d001000048898c24b8000000488b8c24d801000048898c24d0'
    '0000004885c00f84a40000004c69e038020000488b842490000000488da83402'
    '000066666666662e0f1f8400000000000fb64500c1e00883bc0514feffff0175'
    '2f488b9c051cfeffff4d8b2e4c89e84801d872294989064881c5380200004981'
    'c4c8fdffff75c9eb470f1f800000000031db4d8b2e4c89e84801d873d731ff48'
    '8d35d2202203ff15e4542b034901dd48c7c0ffffffff4c0f42e84c89e8498906'
    '4881c5380200004981c4c8fdffff75804c89f848b94b598638d6c56d3448f7e1'
    '4989d749c1ef0b488b4424084c3bb8c80500000f83760500004c8ba0c0050000'
    '66c74424104101488d7c2410e87fb7eb004969c7f00200004901c4488dbc2408'
    '020000488db424b00100004c89e2e81d62e7ff488b8c24c00000004885c9488b'
    '9c24d8000000488bac2480000000488b05bb022b0374134869f138020000488b'
    'bc249000000031d2ffd0488b8424c80000004885c04c8bac24880000004c8b64'
    '2408488b8c24d00000000f849700000048c7442418000000004889442420488b'
    '9424b8000000488954242848c74424380000000048894424404889542448b801'
    '000000eb6666662e0f1f840000000000488d9424aa010000488b4a2e48898c24'
    '5e0100000f10020f104a100f1052200f299424500100000f298c24400100000f'
    '298424300100000f1042360f104a460f294424100f294c2420488b4a5648894c'
    '2430e93803000031c031c94889442410488944243048894c2450488dbc24a000'
    '0000488d742410e854cf3a00488b8424a00000004885c04c8d7c24180f84ce02'
    '000066666666662e0f1f840000000000488b8c24b0000000488d0c49488b74c8'
    '084885f67418488d04c84883c008488b780848c1e60331d2ff1572012b03488b'
    '4424504885c00f845e01000048ffc84889442450837c2410010f859203000048'
    '837c2418000f8599000000488b442420488b4c24284885c974744889ca4883e2'
    '070f841101000031f60f1f8000000000488b80f001000048ffc64839f275f148'
    '89ca4829f24883f90872430f1f440000488b80f0010000488b80f0010000488b'
    '80f0010000488b80f0010000488b80f0010000488b80f0010000488b80f00100'
    '00488b80f00100004883c2f875c248c74424100100000048894424180f57c041'
    '0f114708488dbc24000100004c89fee84c8466ff4883bc2400010000000f84bf'
    '0200000f108424000100000f108c24100100000f109424200100000f29942490'
    '0100000f298c24800100000f29842470010000488b8424800100004989471041'
    '0f1107488d8424880100000f10000f298424a0000000488b401048898424b000'
    '0000488b8424a00000004885c00f857dfeffffe9380100004889ca4883f9080f'
    '830bffffffe944fffffff6442410010f841b010000488b7c2418488b44242048'
    '85ff41b8f001000074464889c1488b074885c00f84c6000000488b2dd0ff2a03'
    '4989c74c8d61014885c9be50020000490f44f031d2ffd541b8f0010000498b07'
    '4c89ff4c89e14885c075d5e99c000000488b4c24284885c974744889ca4883e2'
    '070f846801000031f60f1f8000000000488b80f001000048ffc64839f275f148'
    '89ca4829f24883f90872430f1f440000488b80f0010000488b80f0010000488b'
    '80f0010000488b80f0010000488b80f0010000488b80f0010000488b80f00100'
    '00488b80f00100004883c2f875c231c94889c7488b074885c00f853affffff49'
    '89cc4989ff488b2d04ff2a034d85e4be50020000490f44f04c89ff31d2ffd54c'
    '8b642408488bac24800000000f1f40000f108424080200000f108c2418020000'
    '0f10942428020000488d8424360100000f1150200f1148100f110066b886014c'
    '8b8424980000004a8d0c6d000000004c01e948c1e105488b9424e00000006689'
    '040a0f288424300100000f288c24400100000f289424500100000f11440a020f'
    '114c0a120f11540a22488b84245e0100004889440a300f284424100f284c2420'
    '0f11440a380f114c0a48488b4424304889440a5849ffc549ffc00f8480000000'
    '4883c3484839eb0f85d3f8ffffeb164889ca4883f9080f83b4feffffe9edfeff'
    'ff4c8b6e08488b0424488b004c8928488b4c2478488b41104885c07413488b39'
    '48c1e003488d34c031d2ff15e0fd2a034881c4880200005b415c415d415e415f'
    '5dc3488d3ddf722003ff1521022b03eb4a488d3d18732003ff1512022b03eb3b'
    '488d3d199f1f03ff15abfe2a03eb2c66c74424104101488d3dfcdd0cfe488d0d'
    '8cbc22034c8d0555b82203488d542410be2b000000ff15adfd2a030f0beb1748'
    '89c3488d7c2410e8e4b1eb00eb0bff1574fe2a03eb284889c3488dbc24b00100'
    '00e8fa2e0400488b04244c8bac2488000000eb11ff154efe2a03eb020f0b4889'
    'c3488b0424488b004c8928488b4c2478488b41104885c07413488b3948c1e003'
    '488d34c031d2ff1504fd2a034889dfe8fc1d1a030f0b'
)
BODY_SHA256 = '388f1b921be64f4574652a725a3c20095cfceacb753d54ac244e176e884a0a82'
BRANCHES = [
    (0x25, '0f8496070000', 2, 6, 0x24be201),
    (0x175, '0f8515020000', 2, 6, 0x24bddd0),
    (0x1e6, '0f84a4000000', 2, 6, 0x24bdcd0),
    (0x21f, '752f', 1, 2, 0x24bdc90),
    (0x232, '7229', 1, 2, 0x24bdc9d),
    (0x245, '75c9', 1, 2, 0x24bdc50),
    (0x247, 'eb47', 1, 2, 0x24bdcd0),
    (0x25b, '73d7', 1, 2, 0x24bdc74),
    (0x28e, '7580', 1, 2, 0x24bdc50),
    (0x2b3, '0f8376050000', 2, 6, 0x24be26f),
    (0x315, '7413', 1, 2, 0x24bdd6a),
    (0x34a, '0f8497000000', 2, 6, 0x24bde27),
    (0x383, 'eb66', 1, 2, 0x24bde2b),
    (0x3e2, 'e938030000', 1, 5, 0x24be15f),
    (0x41c, '0f84ce020000', 2, 6, 0x24be130),
    (0x444, '7418', 1, 2, 0x24bde9e),
    (0x466, '0f845e010000', 2, 6, 0x24be00a),
    (0x479, '0f8592030000', 2, 6, 0x24be251),
    (0x485, '0f8599000000', 2, 6, 0x24bdf64),
    (0x498, '7474', 1, 2, 0x24bdf4e),
    (0x4a1, '0f8411010000', 2, 6, 0x24bdff8),
    (0x4bd, '75f1', 1, 2, 0x24bdef0),
    (0x4c9, '7243', 1, 2, 0x24bdf4e),
    (0x50c, '75c2', 1, 2, 0x24bdf10),
    (0x53d, '0f84bf020000', 2, 6, 0x24be242),
    (0x5ad, '0f857dfeffff', 2, 6, 0x24bde70),
    (0x5b3, 'e938010000', 1, 5, 0x24be130),
    (0x5bf, '0f830bffffff', 2, 6, 0x24bdf10),
    (0x5c5, 'e944ffffff', 1, 5, 0x24bdf4e),
    (0x5cf, '0f841b010000', 2, 6, 0x24be130),
    (0x5e8, '7446', 1, 2, 0x24be070),
    (0x5f3, '0f84c6000000', 2, 6, 0x24be0ff),
    (0x629, '75d5', 1, 2, 0x24be040),
    (0x62b, 'e99c000000', 1, 5, 0x24be10c),
    (0x638, '7474', 1, 2, 0x24be0ee),
    (0x641, '0f8468010000', 2, 6, 0x24be1ef),
    (0x65d, '75f1', 1, 2, 0x24be090),
    (0x669, '7243', 1, 2, 0x24be0ee),
    (0x6ac, '75c2', 1, 2, 0x24be0b0),
    (0x6b9, '0f853affffff', 2, 6, 0x24be039),
    (0x79a, '0f8480000000', 2, 6, 0x24be260),
    (0x7a7, '0f85d3f8ffff', 2, 6, 0x24bdac0),
    (0x7ad, 'eb16', 1, 2, 0x24be205),
    (0x7b6, '0f83b4feffff', 2, 6, 0x24be0b0),
    (0x7bc, 'e9edfeffff', 1, 5, 0x24be0ee),
    (0x7db, '7413', 1, 2, 0x24be230),
    (0x80f, 'eb4a', 1, 2, 0x24be29b),
    (0x81e, 'eb3b', 1, 2, 0x24be29b),
    (0x82d, 'eb2c', 1, 2, 0x24be29b),
    (0x85d, 'eb17', 1, 2, 0x24be2b6),
    (0x86c, 'eb0b', 1, 2, 0x24be2b9),
    (0x874, 'eb28', 1, 2, 0x24be2de),
    (0x892, 'eb11', 1, 2, 0x24be2e5),
    (0x89a, 'eb02', 1, 2, 0x24be2de),
    (0x8b7, '7413', 1, 2, 0x24be30c),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x24bdb9f, 0x271b220),
    (0x24bdd0c, 0x3379490),
    (0x24bdd2e, 0x2333f50),
    (0x24bde47, 0x286ada0),
    (0x24bdf6f, 0x1b263c0),
    (0x24be2a7, 0x3379490),
    (0x24be2c1, 0x25011c0),
    (0x24be30f, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x24bdca6, 0x5773190),
    (0x24bde98, 0x576e010),
    (0x24be22a, 0x576e010),
    (0x24be249, 0x576e470),
    (0x24be258, 0x576e470),
    (0x24be267, 0x576e118),
    (0x24be295, 0x576e048),
    (0x24be2ae, 0x576e128),
    (0x24be2d4, 0x576e128),
    (0x24be306, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x24be242, 0x56c5528, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 600, 48),
    (0x24be251, 0x56c5570, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 198, 39),
    (0x24be260, 0x56b8180, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f636f72652f7372632f697465722f61646170746572732f656e756d65726174652e7273'), 141, 17),
]
CALLERS = [0x251965d]
CALLER_FUNCTIONS = {'0x251965d': ('0x2519590', '0x25196d1')}
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

