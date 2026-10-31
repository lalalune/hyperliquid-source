#!/usr/bin/env python3
"""Authenticated node94 duration-13d1b00 binding (0x13d1b00).

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

START, END = 0x13d1b00, 0x13d2134
FDE_VA = 0xfc6568
FDE = bytes.fromhex(
    '500000004089000090b5400034060000048b9195ff410e10420e18420e20420e'
    '28420e30410e38470ed00183078c068d058e048f03860203a5040e38410e3042'
    '0e28420e20420e18420e10410e08410ed0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec98000000833f010f85b0000000488b5f104c8b'
    '7718488d0d6f532904488dbc24800000004889de4c89f2ff159bcf39044c8ba4'
    '2480000000488bac24880000004d85e40f94c04c8bbc24900000004d85ff0f94'
    'c108c10f848a000000488d7c24184889de4c89f2ff1566cf3904837c2418010f'
    '84bf040000f20f105424204d85e4660f295424600f848d03000048c744242000'
    '0000004c8964242848896c243048c7442440000000004c8964244848896c2450'
    'b801000000e962030000488b7710488b5718488d7c2418ff1503cf3904837c24'
    '18010f842e040000f20f10442420e9bc0300004d89e64885ed74734889e84883'
    'e0070f84c700000031c94d89e60f1f004d8bb61801000048ffc14839c875f148'
    '89e84829c84883fd0872430f1f440000498b8e18010000488b8918010000488b'
    '8918010000488b8918010000488b8918010000488b8918010000488b89180100'
    '004c8bb1180100004883c0f875c2664183be1201000000740e31c94c89f04c8d'
    '6901e9da00000040b60131d20f1f4000498b064885c00f84130400004189f048'
    'ffc2410fb78e10010000418d70014989c6663b881201000073d64889d74883ef'
    '01731e4989c64c8d6901e9920000004d89e64889e84883fd080f8351ffffffeb'
    '8d488d34c84881c620010000f6c2070f84cc020000450fb6c04183e0074531c9'
    '4c8b36498db61801000049ffc14d39c875ee4c29ca4531ed4883ff0772436690'
    '488b36488bb618010000488bb618010000488bb618010000488bb61801000048'
    '8bb618010000488bb6180100004c8bb618010000498db6180100004883c2f875'
    'bf488d0c49488b74c810488b54c818488d7c2418ff1566cd3904837c2418010f'
    '84ed02000048896c2470f20f10542420488d5c2418488b2d44cd39044c897c24'
    '786666666666662e0f1f84000000000049ffcf0f8455010000410fb786120100'
    '004939c5660f2954246073144c89e94c89f049ffc5e9da000000660f1f440000'
    '40b60131d266662e0f1f840000000000498b064885c00f84a40200004189f048'
    'ffc2410fb78e10010000418d70014989c6663b881201000073d64889d74883ef'
    '01730d4989c64c8d6901e98500000090488d34c84881c620010000f6c2070f84'
    'be000000450fb6c04183e0074531c9904c8b36498db61801000049ffc14d39c8'
    '75ee4c29ca4883ff0772460f1f440000488b36488bb618010000488bb6180100'
    '00488bb618010000488bb618010000488bb618010000488bb6180100004c8bb6'
    '18010000498db6180100004883c2f875bf4531ed488d0c49488b74c810488b54'
    'c8184889dfffd5837c241801660f285424600f84fb000000f20f10442420660f'
    '2ed0660f28caf20fc2c802660f54d1660f55c8660f56d10f8bb3feffffe90201'
    '00004883ff070f8364ffffffeba34c8b7c2478488b6c24704d85e4660f295424'
    '600f8573fcffff31c04531ff488944241848894424384c897c24584889e7488d'
    '742418e838b30f00488b04244885c074594889e34c8d7424184c8b3db0c03904'
    'eb2266666666662e0f1f8400000000004889df4c89f6e805b30f00488b042448'
    '85c07426488b4c2410488d0c49488b74c8084885f674d9488d04c84883c00848'
    '8b780831d241ffd7ebc60f284424604881c4980000005b415c415d415e415f5d'
    'c34531ed4883ff070f8352fdffffe98efdffff488b44242048890424488d3dba'
    '4fe4fe488d0d6e4f29044c8d05d74e29044889e2be2b000000ff1549c03904e9'
    'b8000000488d3d258d2904ff155fc43904e9a6000000488b4424204889042448'
    '8d3d774fe4fe488d0d2b4f29044c8d054c4e29044889e2be2b000000ff1506c0'
    '3904eb78488b44242048890424488d3d494fe4fe488d0dfd4e29044c8d054e4e'
    '29044889e2be2b000000ff15d8bf3904eb4a488b44242048890424488d3d1b4f'
    'e4fe488d0dcf4e29044c8d05384e29044889e2be2b000000ff15aabf3904eb1c'
    '488d3d31cd2904ff15c3c33904eb0d488d3d22cd2904ff15b4c339040f0beb42'
    '0f0beb3e0f0b4889c3488b3c24488b07ff10eb3fff154ec039044889c3488b3c'
    '24488b07ff10eb2bff153ac039044889c3488b3c24488b07ff10eb24ff1526c0'
    '39044889c3eb0c4889c3488b3c24488b07ff10488dbc2480000000e8608a1000'
    '4889dfe8e8df2804ff15fabf3904ff15f4bf3904'
)
BODY_SHA256 = 'a55a97006d67253f946e76591466f5237c15b0268c2d34941f25165a087bacb1'
BRANCHES = [
    (0x14, '0f85b0000000', 2, 6, 0x13d1bca),
    (0x63, '0f848a000000', 2, 6, 0x13d1bf3),
    (0x7f, '0f84bf040000', 2, 6, 0x13d2044),
    (0x94, '0f848d030000', 2, 6, 0x13d1f27),
    (0xc5, 'e962030000', 1, 5, 0x13d1f2c),
    (0xe2, '0f842e040000', 2, 6, 0x13d2016),
    (0xee, 'e9bc030000', 1, 5, 0x13d1faf),
    (0xf9, '7473', 1, 2, 0x13d1c6e),
    (0x102, '0f84c7000000', 2, 6, 0x13d1ccf),
    (0x11d, '75f1', 1, 2, 0x13d1c10),
    (0x129, '7243', 1, 2, 0x13d1c6e),
    (0x16c, '75c2', 1, 2, 0x13d1c30),
    (0x177, '740e', 1, 2, 0x13d1c87),
    (0x182, 'e9da000000', 1, 5, 0x13d1d61),
    (0x196, '0f8413040000', 2, 6, 0x13d20af),
    (0x1b8, '73d6', 1, 2, 0x13d1c90),
    (0x1c1, '731e', 1, 2, 0x13d1ce1),
    (0x1ca, 'e992000000', 1, 5, 0x13d1d61),
    (0x1d9, '0f8351ffffff', 2, 6, 0x13d1c30),
    (0x1df, 'eb8d', 1, 2, 0x13d1c6e),
    (0x1ef, '0f84cc020000', 2, 6, 0x13d1fc1),
    (0x210, '75ee', 1, 2, 0x13d1d00),
    (0x21c, '7243', 1, 2, 0x13d1d61),
    (0x25f, '75bf', 1, 2, 0x13d1d20),
    (0x27f, '0f84ed020000', 2, 6, 0x13d2072),
    (0x2b3, '0f8455010000', 2, 6, 0x13d1f0e),
    (0x2ca, '7314', 1, 2, 0x13d1de0),
    (0x2d5, 'e9da000000', 1, 5, 0x13d1eb4),
    (0x2f6, '0f84a4020000', 2, 6, 0x13d20a0),
    (0x318, '73d6', 1, 2, 0x13d1df0),
    (0x321, '730d', 1, 2, 0x13d1e30),
    (0x32a, 'e985000000', 1, 5, 0x13d1eb4),
    (0x33e, '0f84be000000', 2, 6, 0x13d1f02),
    (0x360, '75ee', 1, 2, 0x13d1e50),
    (0x369, '7246', 1, 2, 0x13d1eb1),
    (0x3af, '75bf', 1, 2, 0x13d1e70),
    (0x3d2, '0f84fb000000', 2, 6, 0x13d1fd3),
    (0x3f7, '0f8bb3feffff', 2, 6, 0x13d1db0),
    (0x3fd, 'e902010000', 1, 5, 0x13d2004),
    (0x406, '0f8364ffffff', 2, 6, 0x13d1e70),
    (0x40c, 'eba3', 1, 2, 0x13d1eb1),
    (0x421, '0f8573fcffff', 2, 6, 0x13d1b9a),
    (0x44f, '7459', 1, 2, 0x13d1faa),
    (0x460, 'eb22', 1, 2, 0x13d1f84),
    (0x482, '7426', 1, 2, 0x13d1faa),
    (0x495, '74d9', 1, 2, 0x13d1f70),
    (0x4a8, 'ebc6', 1, 2, 0x13d1f70),
    (0x4c8, '0f8352fdffff', 2, 6, 0x13d1d20),
    (0x4ce, 'e98efdffff', 1, 5, 0x13d1d61),
    (0x4ff, 'e9b8000000', 1, 5, 0x13d20bc),
    (0x511, 'e9a6000000', 1, 5, 0x13d20bc),
    (0x542, 'eb78', 1, 2, 0x13d20bc),
    (0x570, 'eb4a', 1, 2, 0x13d20bc),
    (0x59e, 'eb1c', 1, 2, 0x13d20bc),
    (0x5ad, 'eb0d', 1, 2, 0x13d20bc),
    (0x5be, 'eb42', 1, 2, 0x13d2102),
    (0x5c2, 'eb3e', 1, 2, 0x13d2102),
    (0x5d2, 'eb3f', 1, 2, 0x13d2113),
    (0x5e6, 'eb2b', 1, 2, 0x13d2113),
    (0x5fa, 'eb24', 1, 2, 0x13d2120),
    (0x605, 'eb0c', 1, 2, 0x13d2113),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x13d1f43, 0x14cd280),
    (0x13d1f76, 0x14cd280),
    (0x13d211b, 0x14dab80),
    (0x13d2123, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x13d1b37, 0x576ead8),
    (0x13d1b74, 0x576eae0),
    (0x13d1bd7, 0x576eae0),
    (0x13d1d74, 0x576eae0),
    (0x13d1ff9, 0x576e048),
    (0x13d200b, 0x576e470),
    (0x13d203c, 0x576e048),
    (0x13d206a, 0x576e048),
    (0x13d2098, 0x576e048),
    (0x13d20a7, 0x576e470),
    (0x13d20b6, 0x576e470),
    (0x13d20d4, 0x576e128),
    (0x13d20e8, 0x576e128),
    (0x13d20fc, 0x576e128),
    (0x13d2128, 0x576e128),
    (0x13d212e, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x13d2004, 0x566ad30, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 58, 33),
    (0x13d20a0, 0x566edd8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x13d20af, 0x566edd8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x576ea98']
GOT_SITES = {'0x576ea98': ['0x13cfc33']}


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

