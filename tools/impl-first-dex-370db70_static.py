#!/usr/bin/env python3
"""Authenticated node94 impl-first-dex-370db70 binding (0x370db70).

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

START, END = 0x370db70, 0x370e296
FDE_VA = 0x11a52cc
FDE = bytes.fromhex(
    '50000000a4761e009c88560226070000042f7d90ff410e10420e18420e20420e'
    '28420e30410e38470ee00283078c068d058e048f0386020343060e38410e3042'
    '0e28420e20420e18420e10410e08410ee0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec2801000048894c246048897c24284885f60f88'
    '770600004989f6488b5a304885db0f849e050000488b4248488b4a380fb7b31a'
    '0200008d14f500000000488d3c9248c7c2ffffffff4531ff0f1f840000000000'
    '4c39ff742b483b44d310410f97c04180d8004983c72848ffc24180f80174e141'
    '0fb6f085f6750ceb1e0f1f80000000004889f24883e9010f8235050000488b9c'
    'd320020000eb954c8934244a8d343b4883c638488d7c2468e8a372c5ff488b44'
    '246831c94889c24885c0400f95c54088e97405488b542478488b7424704531d2'
    '4989d04989c34989f131ffeb240f1f004d8d61014d89f240b50141bb00000000'
    '4b03bcce680100004d89e10f827b0500004983e8010f82b001000040f6c5010f'
    '84580500004d85d27426450fb7b2c20100004d39f10f83c50000004d89d6e9e5'
    '000000666666662e0f1f8400000000004d85c974384d89ce4d89da4983e60774'
    '314531e46666662e0f1f8400000000004d8b92c801000049ffc44d39e675f14d'
    '89cb4d29e34983f9087315eb514d89daeb4c4d89cb4983f90872430f1f440000'
    '4d8b8ac80100004d8b89c80100004d8b89c80100004d8b89c80100004d8b89c8'
    '0100004d8b89c80100004d8b89c80100004d8b91c80100004983c3f875c24531'
    'db4531c9450fb7b2c20100004d39f10f8246ffffff66662e0f1f840000000000'
    '4d8bb2600100004d85f60f844f04000049ffc3450fb78ac00100004d89f26645'
    '3b8ec201000073d84d85db0f84bffeffff4f8d24ce4981c4d00100004d89dd49'
    '83e507747b31ed660f1f8400000000004d8b14244d8da2c801000048ffc54939'
    'ed75ed4d89dd4929ed4983fb087243904d8b14244d8b92c80100004d8b92c801'
    '00004d8b92c80100004d8b92c80100004d8b92c80100004d8b92c80100004d8b'
    '92c80100004d8da2c80100004983c5f875be4531e4e93dfeffff660f1f440000'
    '4d89dd4983fb0873a7ebe748898c248000000048c78424880000000000000048'
    '898424900000004889b4249800000048898c24a000000048c78424a800000000'
    '00000048898424b00000004889b424b800000048899424c00000004885ff0f84'
    'c702000048895c241866480f6ec7660f6205da5faffc660f5c05f24faffc660f'
    '28c8660f15c8f20f58c8660f298c24000100004c8b34240f57c0f2490f2ac6f2'
    '0f11442450488d5c24304c8da4248000000049bdffffffffffffff7f0f1f4000'
    '4889df4c89e6e8e50acaff488b4c24304885c90f847a020000488b542440488b'
    '84d16801000048c1e205660f100411660f104c1110660f294c2440660f294424'
    '304885c074ba66480f6ec8660f620d3d5faffc660f5c0d554faffc660f28c166'
    '0f15c1f20f58c1f20f5e842400010000f20f5944245066480f7ec04c21e8660f'
    '57c948b9ffffffffffffef7f4839c87f36f20f100d2fcdaffc660f2ec8771066'
    '0f2e0559c8affc7706660f28c8eb18f20f101511cdaffcf20f5fd0f20f100d3d'
    'c8affcf20f5dcaf2480f2cc9660f2e0d04c3affc490f47cd660f2ec9b8000000'
    '00480f4ac84c89f048894c24104829c80f80140100004989c6488b4424184a8b'
    '4c38384885c90f84defeffff4c893424488b4424184a8b443840488944242048'
    '8da9c002000048894c2408440fb7a12a0400004c8964245841c1e40549c7c5ff'
    'ffffff4531f6662e0f1f8400000000004d39f4743b498d342eba200000004889'
    'dfff153104060248984885c00f98c10f9fc028c84983c62049ffc53c0174d10f'
    'b6c085c0750feb380f1f8400000000004c8b6c24584c8b3424488b4c2408488b'
    '4424204883e8010f823dfeffff48894424204a8b8ce930040000e960ffffff90'
    '488b4c2408428b4471e8898424f000000066420f104471d8660f298424e00000'
    '00488b5424104885d24c8b34240f88fb000000488b7c2428488db424e0000000'
    'e8fb13ffffe9e0fdffff31ff488d355d3efe01ff158750060231c0488b542410'
    '4939d60f99c048b9ffffffffffffff7f4801c84929d64c0f40f0488b4424184a'
    '8b4c38384885c90f85bffeffffe998fdffff66c78424800000009700488dbc24'
    '80000000e8b7430500eb484c8d6424304c8dac24800000004c8b34240f1f4000'
    '4c89e74c89eee86508caff48837c24300075ed4c8d6424304c8dac2480000000'
    '4c89e74c89eee84508caff48837c24300075ed4d85f67415488b7c242831f64c'
    '89f2488b4c2460ff155b6706024881c4280100005b415c415d415e415f5dc348'
    '8d3d12befd01ff1594020602eb2b488d3d933dfe01ff1585020602eb1c488d3d'
    '2ca9fd01ff1576020602eb0d488d3d6d41fe01ff150fff05020f0b488d3d41b8'
    'e8fc488d0d1741fe014c8d05c03afe01488d942480000000be2b000000ff1515'
    'fe0502eb1beb19eb17eb004889c3488d7c2468e8184bceffeb3cff15d8fe0502'
    '4889c34c8db424100100004c8dbc2480000000666666662e0f1f840000000000'
    '4c89f74c89fee86507caff4883bc24100100000075ea4889dfe8821ef501ff15'
    '94fe05020f0b'
)
BODY_SHA256 = '33f6a376b2686832da1c606618541912bc4bf134dc6cec86bd1fa334ab55d370'
BRANCHES = [
    (0x1e, '0f8877060000', 2, 6, 0x370e20b),
    (0x2e, '0f849e050000', 2, 6, 0x370e142),
    (0x63, '742b', 1, 2, 0x370dc00),
    (0x7d, '74e1', 1, 2, 0x370dbd0),
    (0x85, '750c', 1, 2, 0x370dc03),
    (0x87, 'eb1e', 1, 2, 0x370dc17),
    (0x97, '0f8235050000', 2, 6, 0x370e142),
    (0xa5, 'eb95', 1, 2, 0x370dbac),
    (0xd1, '7405', 1, 2, 0x370dc48),
    (0xeb, 'eb24', 1, 2, 0x370dc81),
    (0x10b, '0f827b050000', 2, 6, 0x370e1fc),
    (0x115, '0f82b0010000', 2, 6, 0x370de3b),
    (0x11f, '0f8458050000', 2, 6, 0x370e1ed),
    (0x128, '7426', 1, 2, 0x370dcc0),
    (0x135, '0f83c5000000', 2, 6, 0x370dd70),
    (0x13e, 'e9e5000000', 1, 5, 0x370dd98),
    (0x153, '7438', 1, 2, 0x370dcfd),
    (0x15f, '7431', 1, 2, 0x370dd02),
    (0x17d, '75f1', 1, 2, 0x370dce0),
    (0x189, '7315', 1, 2, 0x370dd10),
    (0x18b, 'eb51', 1, 2, 0x370dd4e),
    (0x190, 'eb4c', 1, 2, 0x370dd4e),
    (0x199, '7243', 1, 2, 0x370dd4e),
    (0x1dc, '75c2', 1, 2, 0x370dd10),
    (0x1ef, '0f8246ffffff', 2, 6, 0x370dcab),
    (0x20a, '0f844f040000', 2, 6, 0x370e1cf),
    (0x226, '73d8', 1, 2, 0x370dd70),
    (0x22b, '0f84bffeffff', 2, 6, 0x370dc60),
    (0x243, '747b', 1, 2, 0x370de30),
    (0x261, '75ed', 1, 2, 0x370ddc0),
    (0x26d, '7243', 1, 2, 0x370de22),
    (0x2b0, '75be', 1, 2, 0x370dde0),
    (0x2b5, 'e93dfeffff', 1, 5, 0x370dc67),
    (0x2c7, '73a7', 1, 2, 0x370dde0),
    (0x2c9, 'ebe7', 1, 2, 0x370de22),
    (0x31e, '0f84c7020000', 2, 6, 0x370e15b),
    (0x393, '0f847a020000', 2, 6, 0x370e183),
    (0x3c4, '74ba', 1, 2, 0x370def0),
    (0x40f, '7f36', 1, 2, 0x370dfb7),
    (0x41d, '7710', 1, 2, 0x370df9f),
    (0x427, '7706', 1, 2, 0x370df9f),
    (0x42d, 'eb18', 1, 2, 0x370dfb7),
    (0x470, '0f8014010000', 2, 6, 0x370e0fa),
    (0x486, '0f84defeffff', 2, 6, 0x370deda),
    (0x4d3, '743b', 1, 2, 0x370e080),
    (0x4fd, '74d1', 1, 2, 0x370e040),
    (0x504, '750f', 1, 2, 0x370e085),
    (0x506, 'eb38', 1, 2, 0x370e0b0),
    (0x527, '0f823dfeffff', 2, 6, 0x370deda),
    (0x53a, 'e960ffffff', 1, 5, 0x370e00f),
    (0x56d, '0f88fb000000', 2, 6, 0x370e1de),
    (0x585, 'e9e0fdffff', 1, 5, 0x370deda),
    (0x5c7, '0f85bffeffff', 2, 6, 0x370dffc),
    (0x5cd, 'e998fdffff', 1, 5, 0x370deda),
    (0x5e9, 'eb48', 1, 2, 0x370e1a3),
    (0x611, '75ed', 1, 2, 0x370e170),
    (0x631, '75ed', 1, 2, 0x370e190),
    (0x636, '7415', 1, 2, 0x370e1bd),
    (0x66c, 'eb2b', 1, 2, 0x370e209),
    (0x67b, 'eb1c', 1, 2, 0x370e209),
    (0x68a, 'eb0d', 1, 2, 0x370e209),
    (0x6c3, 'eb1b', 1, 2, 0x370e250),
    (0x6c5, 'eb19', 1, 2, 0x370e250),
    (0x6c7, 'eb17', 1, 2, 0x370e250),
    (0x6c9, 'eb00', 1, 2, 0x370e23b),
    (0x6d8, 'eb3c', 1, 2, 0x370e286),
    (0x714, '75ea', 1, 2, 0x370e270),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x370dc28, 0x3364ed0),
    (0x370def6, 0x33ae9e0),
    (0x370e0f0, 0x36ff4f0),
    (0x370e154, 0x3762510),
    (0x370e176, 0x33ae9e0),
    (0x370e196, 0x33ae9e0),
    (0x370e243, 0x33f2d60),
    (0x370e276, 0x33ae9e0),
    (0x370e289, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x370e051, 0x576e488),
    (0x370e103, 0x5773190),
    (0x370e1b7, 0x5774918),
    (0x370e1d6, 0x576e470),
    (0x370e1e5, 0x576e470),
    (0x370e1f4, 0x576e470),
    (0x370e203, 0x576e118),
    (0x370e22d, 0x576e048),
    (0x370e24a, 0x576e128),
    (0x370e28e, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x370e1cf, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x370e1de, 0x56f1f78, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f696d706c5f66697273745f6465782e7273'), 69, 88),
    (0x370e1ed, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x370e1fc, 0x56f2370, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f636f72652f7372632f697465722f7472616974732f616363756d2e7273'), 204, 1),
]
CALLERS = [0x370da11, 0x370dad8]
CALLER_FUNCTIONS = {'0x370da11': ('0x370d980', '0x370da51'), '0x370dad8': ('0x370da60', '0x370db63')}
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

