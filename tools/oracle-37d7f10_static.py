#!/usr/bin/env python3
"""Authenticated node94 oracle-37d7f10 binding (0x37d7f10).

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

START, END = 0x37d7f10, 0x37d8364
FDE_VA = 0x11aac0c
FDE = bytes.fromhex(
    '50000000e4cf1e00fcd262025404000004f35e90ff410e10420e18420e20420e'
    '28420e30410e38470ed00183078c068d058e048f03860203fb030e38410e3042'
    '0e28420e20420e18420e10410e08410ed0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec980000004889542418488b1f488b47084885c0'
    '0f95c1488b6f184885ed0f95c220ca80fa010f85bb030000488b560848895424'
    '10488b561048895424084c8b7f104531e4eb4d49c1fe3f48b900000000000000'
    '804931ce4801c34c0f41f331ff488d350cbbf101ff1506b2f9014c89f34c29eb'
    '0f8087020000662e0f1f840000000000b101b80000000048ffcd0f8453030000'
    'f6c1010f847d0300004d85e47422410fb78c24220300004939cf0f83c0000000'
    '4c89e14c89fae9de0000000f1f4400004d85ff74394c89f94989c44883e10774'
    '3231d2666666662e0f1f8400000000004d8ba4242803000048ffc24839d175f0'
    '4c89f84829d04983ff087314eb514989c4eb4c4c89f84983ff0872430f1f4000'
    '498b8c2428030000488b8928030000488b8928030000488b8928030000488b89'
    '28030000488b8928030000488b89280300004c8ba1280300004883c0f875c131'
    'c04531ff410fb78c24220300004939cf0f824affffff662e0f1f840000000000'
    '498b8c24c00200004885c90f848602000048ffc0410fb79424200300004989cc'
    '663b912203000073d74885c00f848e000000488d34d14881c6300300004889c7'
    '4883e7070f84c60100004531c00f1f004c8b26498db4242803000049ffc04c39'
    'c775ed4889c74c29c74883f808724390488b06488b8028030000488b80280300'
    '00488b8028030000488b8028030000488b8028030000488b80280300004c8ba0'
    '28030000498db424280300004883c7f875be4531ffeb10660f1f840000000000'
    '4c8d7a014989cc488bbcd1c802000048c1e2060f1004110f104c11100f105411'
    '200f105c11300f295c24500f295424400f294c24300f294424204889f848b94b'
    '598638d6c56d3448f7e148c1ea0b4869c2102700004829c7483b7c24080f8390'
    '010000488d047f48c1e005488b4c2410488b540120488d7c2468488d742420b9'
    '010000004c8b4c2418ff15f9c4f901488b442470807c24680074654c8bac2490'
    '0000004d85ed0f88e20000004c39e80f8d9bfdffff4989de4901c60f8052fdff'
    'ff4c89f34c29eb0f8183fdffff0f99c00fb6c048b9ffffffffffffff7f4801c8'
    '4d29ee4c0f40f031ff488d3538b8f101ff154aaff9014c89f3e952fdffff6690'
    '4c8b7424784989dd4901c570554d85f6787c4c89eb4c29f30f8132fdffff0f99'
    'c00fb6c048b9ffffffffffffff7f4801c84d29f54c0f40e831ff488d35e7b7f1'
    '01ff15f9aef9014c89ebe901fdffff904889c74883f8080f8295feffffe94efe'
    'ffff49c1fd3f48b900000000000000804931cd4801c34c0f41eb31ff488d35bd'
    'b7f101ff15b7aef9014d85f67984488d3d0d3fdcfc488d0d1cbaf1014c8d056d'
    'b7f101488d542420be2b000000ff15455df9014889d848f7d8704a48c1fb3f48'
    '21c34889d84881c4980000005b415c415d415e415f5dc3488d3dba1cf101ff15'
    '3c61f9010f0b488d3de307f101ff152d61f901488d15e6b6f101488b742408ff'
    '15735cf901488d3d04b7f101ff15d667f9010f0b'
)
BODY_SHA256 = 'ca546ab49ed6f58d4eb7dd827a348506a7e374d1402d01b512c73e2da0198379'
BRANCHES = [
    (0x32, '0f85bb030000', 2, 6, 0x37d8303),
    (0x51, 'eb4d', 1, 2, 0x37d7fb0),
    (0x80, '0f8087020000', 2, 6, 0x37d821d),
    (0x9a, '0f8453030000', 2, 6, 0x37d8303),
    (0xa3, '0f847d030000', 2, 6, 0x37d8336),
    (0xac, '7422', 1, 2, 0x37d7fe0),
    (0xba, '0f83c0000000', 2, 6, 0x37d8090),
    (0xc6, 'e9de000000', 1, 5, 0x37d80b9),
    (0xd3, '7439', 1, 2, 0x37d801e),
    (0xdf, '7432', 1, 2, 0x37d8023),
    (0xfe, '75f0', 1, 2, 0x37d8000),
    (0x10a, '7314', 1, 2, 0x37d8030),
    (0x10c, 'eb51', 1, 2, 0x37d806f),
    (0x111, 'eb4c', 1, 2, 0x37d806f),
    (0x11a, '7243', 1, 2, 0x37d806f),
    (0x15d, '75c1', 1, 2, 0x37d8030),
    (0x170, '0f824affffff', 2, 6, 0x37d7fd0),
    (0x18b, '0f8486020000', 2, 6, 0x37d8327),
    (0x1a7, '73d7', 1, 2, 0x37d8090),
    (0x1ac, '0f848e000000', 2, 6, 0x37d8150),
    (0x1c4, '0f84c6010000', 2, 6, 0x37d82a0),
    (0x1e1, '75ed', 1, 2, 0x37d80e0),
    (0x1ed, '7243', 1, 2, 0x37d8142),
    (0x230, '75be', 1, 2, 0x37d8100),
    (0x235, 'eb10', 1, 2, 0x37d8157),
    (0x29d, '0f8390010000', 2, 6, 0x37d8343),
    (0x2d9, '7465', 1, 2, 0x37d8250),
    (0x2e6, '0f88e2000000', 2, 6, 0x37d82de),
    (0x2ef, '0f8d9bfdffff', 2, 6, 0x37d7fa0),
    (0x2fb, '0f8052fdffff', 2, 6, 0x37d7f63),
    (0x307, '0f8183fdffff', 2, 6, 0x37d7fa0),
    (0x339, 'e952fdffff', 1, 5, 0x37d7fa0),
    (0x34b, '7055', 1, 2, 0x37d82b2),
    (0x350, '787c', 1, 2, 0x37d82de),
    (0x358, '0f8132fdffff', 2, 6, 0x37d7fa0),
    (0x38a, 'e901fdffff', 1, 5, 0x37d7fa0),
    (0x397, '0f8295feffff', 2, 6, 0x37d8142),
    (0x39d, 'e94efeffff', 1, 5, 0x37d8100),
    (0x3cc, '7984', 1, 2, 0x37d8262),
    (0x3f9, '704a', 1, 2, 0x37d8355),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x37d7f84, 0x5773190),
    (0x37d81d9, 0x57746d8),
    (0x37d8240, 0x5773190),
    (0x37d8291, 0x5773190),
    (0x37d82d3, 0x5773190),
    (0x37d82fd, 0x576e048),
    (0x37d832e, 0x576e470),
    (0x37d833d, 0x576e470),
    (0x37d834f, 0x576dfc8),
    (0x37d835c, 0x576eb38),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37d8327, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x37d8336, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x37d8343, 0x56f3a30, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774af0']
GOT_SITES = {'0x5774af0': ['0x272a89f', '0x4d34332', '0x4d35fc2']}


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

