#!/usr/bin/env python3
"""Authenticated node94 duration-3978840 binding (0x3978840).

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

START, END = 0x3978840, 0x3978f3d
FDE_VA = 0x11c8ff8
FDE = bytes.fromhex(
    '50000000d0b3200040f87a02fd06000004e70190ff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f038602031c060e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004989d64889fb488b1285f60f849d02'
    '000048898c24980000004531c04885d2410f95c0498b7e084d8b4e104c894c24'
    '484c0f44ca4531db4889d04d89ca4989fc4589c76666662e0f1f840000000000'
    '4983ea010f82c103000041f6c7010f84030600004d85db7427410fb78b120100'
    '004939cc0f83c60000004d89dd4c89e5e9df00000066662e0f1f840000000000'
    '4d85e474384d89e74989c34983e707743131c0666666662e0f1f840000000000'
    '4d8b9b1801000048ffc04939c775f14d89e74929c74983fc087315eb514989c3'
    'eb4c4d89e74983fc0872430f1f440000498b8318010000488b8018010000488b'
    '8018010000488b8018010000488b8018010000488b8018010000488b80180100'
    '004c8b98180100004983c7f875c231c04531e4410fb78b120100004939cc0f82'
    '46ffffff6666662e0f1f8400000000004d8b2b4d85ed0f84dc04000048ffc041'
    '0fb7ab100100004d89eb66413bad1201000073dc4885c00f84930000004c8d24'
    'ed200100004d01ec4989c74983e7070f84db00000031c9660f1f840000000000'
    '4d8b1c244d8da31801000048ffc14939cf75ed4989c74929cf4883f808724390'
    '498b0424488b8018010000488b8018010000488b8018010000488b8018010000'
    '488b8018010000488b80180100004c8b98180100004d8da3180100004983c7f8'
    '75be4531e4eb10660f1f8400000000004c8d65014d89eb488d046d0000000048'
    '01e8418b4cc50866bdb50081f9ffe0f505774b81c1f0d8ffff81f9a086010072'
    '3d488d04c5080000004c01e88078110266bdb300752841b70180780801b80000'
    '00000f84f8fdffffeb14660f1f4400004989c74883f8087289e942ffffff6689'
    '2b4885d20f84e802000048c744240800000000488954241048897c241848c744'
    '242800000000488954243048897c2438b801000000488b4c2448e9b702000049'
    '8b46084889d74885d27404498b7e10f20f104108f20f1144244848c784248000'
    '00000000000048c78424900000000000000048c78424a00000000000000048c7'
    '8424b000000000000000400f95c6400fb6f64889342448c74424080000000048'
    '895424104889442418488974242048c744242800000000488954243048894424'
    '3848897c24404c8d7424504989e74c8da424a00000004c8dac2480000000eb0f'
    '81fe00e1f505490f43fce811fca1ff4c89f74c89fee8e6dca3ff488b44245048'
    '85c0743c488b4c2460488d0c490fb654c81980fa0374298b74c80880fa027507'
    '807cc8100074c88d86f0d8ffff4c89e73da086010072a94c89efeba40f1f4000'
    '488d7c24684889e6e893dca3ff48837c24680075eb4883bc249000000000660f'
    '57c07406f20f10442448488b8424b0000000488943200f108c24a00000000f11'
    '4b10488b84249000000048894338660f108c2480000000660f114b28f20f1143'
    '0866c7038601e9f80100004c89042448c744240800000000488954241048897c'
    '24184c8944242048c744242800000000488954243048897c24384c894c244048'
    '8d7c24504889e089f54889c6e88fa62300488b84249800000089e9f2480f2ac1'
    'f20f5e05d82189fcf20f5e4010f20f58055b1a89fc66480f7ec14885c90f98c2'
    '48beffffffffffffff7f4821ce48b9000000000000f0ff4801f148c1e93581f9'
    'ff0300000f92c120d1488d7eff49b8ffffffffffff0f004c39c7400f92c74020'
    'd748ba000000000000f07f4839d60f9fc2400f94c64008d64008fe4008ce0f85'
    'a1000000660f2e05e41989fc0f8793000000f20f1008f20f105008660f2ed10f'
    '8222010000f20f5cd1660f57db660f2ed30f8225010000f20f59c2f20f58c848'
    '8b44246048894338660f10442450660f114328f20f114b0848c7431000000000'
    '48c743200000000066c7038601e9b100000031c031c948890424488944242048'
    '894c24404c8d7424684989e70f1f40004c89f74c89fee8c5daa3ff48837c2468'
    '0075edeb7e66c703b200488b4c24504885c97437488b542458488b44246048c7'
    '4424080000000048894c2410488954241848c74424280000000048894c243048'
    '89542438b901000000eb0431c931c048890c2448894c242048894424404c8d74'
    '24684989e766662e0f1f8400000000004c89f74c89fee815d3a3ff48837c2468'
    '0075ed4889d84881c4b80000005b415c415d415e415f5dc3488d3d6911d701ff'
    '15eb55df01eb3d488d159a1fcf01be23000000488d3dfb108afceb13488d15b5'
    '1fcf01be1e000000488d3daa108afcff155352df01eb0d488d3d62fcd601ff15'
    'ac55df010f0b4889c34c89f7e8ef4ca8ffeb5c4889c34c8d7424684989e76690'
    '4c89f74c89fee8b5d9a3ff48837c24680075edeb09ff152d52df014889c3488d'
    'bc24a0000000e8a5a7a7ff488dbc2480000000e898a7a7ffeb15ff150852df01'
    '0f0b4889c3488d7c2450e881a7a7ff4889dfe8d971ce01ff15eb51df01'
)
BODY_SHA256 = 'e9603e06b7ab90bb29309f514b4e96be09e69bc199adb2589ce4b4436aa65743'
BRANCHES = [
    (0x1c, '0f849d020000', 2, 6, 0x3978aff),
    (0x64, '0f82c1030000', 2, 6, 0x3978c6b),
    (0x6e, '0f8403060000', 2, 6, 0x3978eb7),
    (0x77, '7427', 1, 2, 0x39788e0),
    (0x84, '0f83c6000000', 2, 6, 0x3978990),
    (0x90, 'e9df000000', 1, 5, 0x39789b4),
    (0xa3, '7438', 1, 2, 0x397891d),
    (0xaf, '7431', 1, 2, 0x3978922),
    (0xcd, '75f1', 1, 2, 0x3978900),
    (0xd9, '7315', 1, 2, 0x3978930),
    (0xdb, 'eb51', 1, 2, 0x397896e),
    (0xe0, 'eb4c', 1, 2, 0x397896e),
    (0xe9, '7243', 1, 2, 0x397896e),
    (0x12c, '75c2', 1, 2, 0x3978930),
    (0x13e, '0f8246ffffff', 2, 6, 0x39788ca),
    (0x156, '0f84dc040000', 2, 6, 0x3978e78),
    (0x172, '73dc', 1, 2, 0x3978990),
    (0x177, '0f8493000000', 2, 6, 0x3978a50),
    (0x18f, '0f84db000000', 2, 6, 0x3978ab0),
    (0x1b1, '75ed', 1, 2, 0x39789e0),
    (0x1bd, '7243', 1, 2, 0x3978a42),
    (0x200, '75be', 1, 2, 0x3978a00),
    (0x205, 'eb10', 1, 2, 0x3978a57),
    (0x231, '774b', 1, 2, 0x3978abe),
    (0x23f, '723d', 1, 2, 0x3978abe),
    (0x254, '7528', 1, 2, 0x3978abe),
    (0x262, '0f84f8fdffff', 2, 6, 0x39788a0),
    (0x268, 'eb14', 1, 2, 0x3978abe),
    (0x277, '7289', 1, 2, 0x3978a42),
    (0x279, 'e942ffffff', 1, 5, 0x3978a00),
    (0x284, '0f84e8020000', 2, 6, 0x3978db2),
    (0x2ba, 'e9b7020000', 1, 5, 0x3978db6),
    (0x2c9, '7404', 1, 2, 0x3978b0f),
    (0x35e, 'eb0f', 1, 2, 0x3978baf),
    (0x382, '743c', 1, 2, 0x3978c00),
    (0x395, '7429', 1, 2, 0x3978c00),
    (0x39e, '7507', 1, 2, 0x3978be7),
    (0x3a5, '74c8', 1, 2, 0x3978baf),
    (0x3b5, '72a9', 1, 2, 0x3978ba0),
    (0x3ba, 'eba4', 1, 2, 0x3978ba0),
    (0x3d3, '75eb', 1, 2, 0x3978c00),
    (0x3e2, '7406', 1, 2, 0x3978c2a),
    (0x426, 'e9f8010000', 1, 5, 0x3978e63),
    (0x4fe, '0f85a1000000', 2, 6, 0x3978de5),
    (0x50c, '0f8793000000', 2, 6, 0x3978de5),
    (0x51f, '0f8222010000', 2, 6, 0x3978e87),
    (0x531, '0f8225010000', 2, 6, 0x3978e9c),
    (0x56d, 'e9b1000000', 1, 5, 0x3978e63),
    (0x5a1, '75ed', 1, 2, 0x3978dd0),
    (0x5a3, 'eb7e', 1, 2, 0x3978e63),
    (0x5b2, '7437', 1, 2, 0x3978e2b),
    (0x5e9, 'eb04', 1, 2, 0x3978e2f),
    (0x621, '75ed', 1, 2, 0x3978e50),
    (0x645, 'eb3d', 1, 2, 0x3978ec4),
    (0x65a, 'eb13', 1, 2, 0x3978eaf),
    (0x675, 'eb0d', 1, 2, 0x3978ec4),
    (0x691, 'eb5c', 1, 2, 0x3978f2f),
    (0x6b1, '75ed', 1, 2, 0x3978ee0),
    (0x6b3, 'eb09', 1, 2, 0x3978efe),
    (0x6d8, 'eb15', 1, 2, 0x3978f2f),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3978baa, 0x33987c0),
    (0x3978bb5, 0x33b68a0),
    (0x3978c08, 0x33b68a0),
    (0x3978cac, 0x3bb3340),
    (0x3978dd6, 0x33b68a0),
    (0x3978e56, 0x33b6170),
    (0x3978ecc, 0x33fdbc0),
    (0x3978ee6, 0x33b68a0),
    (0x3978f06, 0x33f36b0),
    (0x3978f13, 0x33f36b0),
    (0x3978f2a, 0x33f36b0),
    (0x3978f32, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3978e7f, 0x576e470),
    (0x3978eaf, 0x576e108),
    (0x3978ebe, 0x576e470),
    (0x3978ef5, 0x576e128),
    (0x3978f1a, 0x576e128),
    (0x3978f37, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3978e78, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3978e9c, 0x566ae58, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 124, 13),
    (0x3978eb7, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = [0x1ea31d6, 0x1ea3fef, 0x33df1e0, 0x33e0259, 0x3576fea, 0x3bde15d, 0x4322d39, 0x4323bcf, 0x432491f, 0x4325679]
CALLER_FUNCTIONS = {'0x1ea31d6': ('0x1ea3140', '0x1ea3f55'), '0x1ea3fef': ('0x1ea3f60', '0x1ea4caf'), '0x33df1e0': ('0x33df1a0', '0x33df1f3'), '0x33e0259': ('0x33e0200', '0x33e0284'), '0x3576fea': ('0x3576f90', '0x3577015'), '0x3bde15d': ('0x3bde110', '0x3bde16f'), '0x4322d39': ('0x4322ca0', '0x4323b3e'), '0x4323bcf': ('0x4323b40', '0x432488f'), '0x432491f': ('0x4324890', '0x43255df'), '0x4325679': ('0x43255e0', '0x432647e')}
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

