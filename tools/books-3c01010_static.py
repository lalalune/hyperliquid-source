#!/usr/bin/env python3
"""Authenticated node94 books-3c01010 binding (0x3c01010).

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

START, END = 0x3c01010, 0x3c014aa
FDE_VA = 0x11ea4b4
FDE = bytes.fromhex(
    '4c0000008cc82200546ba1029a04000004b3d08fff410e10420e18420e20420e'
    '28420e30410e38440e6083078c068d058e048f03860203f0020e38410e30420e'
    '28420e20420e18420e10410e08410e60'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec284c8b3e488b41204d8baf880100004c39e80f'
    '83330400004d8ba7800100004869c0e800000049837c0460010f85de0000004c'
    '01e04883c050488b40084c8b18488b4e08488b41104939c30f83250400004c8b'
    '41084d69cbd80000004b8d04084b8b8c088000000031ed4885c90f84eb000000'
    '4b83bc0890000000000f84dc0000004c8b80880000004d85c074734d89c14983'
    'e1070f849f0200004531d20f1f440000488b89c801000049ffc24d39d175f14d'
    '89c14d29d14983f80872430f1f440000488b89c8010000488b89c8010000488b'
    '89c8010000488b89c8010000488b89c8010000488b89c8010000488b89c80100'
    '00488b89c80100004983c1f875c26683b9c20100000074104531c0eb38c64701'
    '00b001e9d00100004989c90f1f440000498b89600100004885c90f8425030000'
    '450fb781c00100004989c966443b81c201000073db450fb7c04a8b8cc1680100'
    '004889cd48f7dd480f48e9488b88980000004531f64885c90f84db0000004883'
    'b8a8000000000f84cd000000488b80a00000004885c074764989c04983e0070f'
    '84b40100004531c90f1f840000000000488b89c801000049ffc14d39c875f149'
    '89c04d29c84883f80872430f1f440000488b81c8010000488b80c8010000488b'
    '80c8010000488b80c8010000488b80c8010000488b80c8010000488b80c80100'
    '00488b88c80100004983c0f875c26683b9c201000000740431c0eb284989c890'
    '498b88600100004885c90f8444020000410fb780c00100004989c8663b81c201'
    '000073dc0fb7c0488b84c1680100004989c649f7de4c0f48f0488b461031c94c'
    '3958080f95c18038000fb6c20f45c13c017551488b76184885ed48897c240874'
    '48498b8f680100004d8b8770010000488d7c241048897424204c89db4c89dae8'
    '0c60b2ff807c241001755e0fb6442411488904244531ed488b7424204989dbe9'
    'b20000004d89f5eb254531ed488904244531e44d85f60f85aa00000031ed31c9'
    '488b7c24084408e10f851901000048896f084c896f1031c088074883c4285b41'
    '5c415d415e415f5dc3488b4c2418488b41204c39e80f833d0100004869c0e800'
    '000049837c046001488b7424204989db75394c8b69184929ed0f83dd000000b0'
    '0848890424eb2c4d89c14983f8080f837cfdffffe9b5fdffff4989c04883f808'
    '0f836afeffffe9a3feffff48c70424000000004531ed4d85ed410f94c44d85f6'
    '0f8456ffffff498b8f680100004d8b8770010000488d7c24104c89dae80f5fb2'
    'ff807c241001750e0fb644241131ed488b7c2408eb42488b442418488b502049'
    '3b97880100000f838c000000498b8f800100004869d2e800000048837c116001'
    '488b7c2408750d488b68184c29f57351b008eb0231c031ed4885ed0f94c14408'
    'e10f84e7feffff0fb60c240fb6c04584e40f45c1884701e905fdffffb9090000'
    '0048890c240f844bffffff4c01e04883c050488b40088b0048890424e935ffff'
    'ffb80900000074b0488d04114883c050488b40088b00eba0488d3d810daf01ff'
    '15fbcfb601488d3d6c8bae01ff15eecfb601eb0d488d3d5d8bae01ff15dfcfb6'
    '010f0b488d150ee9ad014c89df4889c6ff1522cbb6010f0b0f0b'
)
BODY_SHA256 = '1bd669ffda057d2c425c4a22274f6d3395c1b6add0a07ae4db8aca3db1d44d8d'
BRANCHES = [
    (0x1f, '0f8333040000', 2, 6, 0x3c01468),
    (0x39, '0f85de000000', 2, 6, 0x3c0112d),
    (0x58, '0f8325040000', 2, 6, 0x3c01493),
    (0x7a, '0f84eb000000', 2, 6, 0x3c0117b),
    (0x89, '0f84dc000000', 2, 6, 0x3c0117b),
    (0x99, '7473', 1, 2, 0x3c0111e),
    (0xa2, '0f849f020000', 2, 6, 0x3c01357),
    (0xbd, '75f1', 1, 2, 0x3c010c0),
    (0xc9, '7243', 1, 2, 0x3c0111e),
    (0x10c, '75c2', 1, 2, 0x3c010e0),
    (0x116, '7410', 1, 2, 0x3c01138),
    (0x11b, 'eb38', 1, 2, 0x3c01165),
    (0x123, 'e9d0010000', 1, 5, 0x3c01308),
    (0x13a, '0f8425030000', 2, 6, 0x3c01475),
    (0x153, '73db', 1, 2, 0x3c01140),
    (0x178, '0f84db000000', 2, 6, 0x3c01269),
    (0x186, '0f84cd000000', 2, 6, 0x3c01269),
    (0x196, '7476', 1, 2, 0x3c0121e),
    (0x19f, '0f84b4010000', 2, 6, 0x3c01369),
    (0x1bd, '75f1', 1, 2, 0x3c011c0),
    (0x1c9, '7243', 1, 2, 0x3c0121e),
    (0x20c, '75c2', 1, 2, 0x3c011e0),
    (0x216, '7404', 1, 2, 0x3c0122c),
    (0x21a, 'eb28', 1, 2, 0x3c01254),
    (0x22a, '0f8444020000', 2, 6, 0x3c01484),
    (0x242, '73dc', 1, 2, 0x3c01230),
    (0x271, '7551', 1, 2, 0x3c012d4),
    (0x27f, '7448', 1, 2, 0x3c012d9),
    (0x2a9, '755e', 1, 2, 0x3c01319),
    (0x2bf, 'e9b2000000', 1, 5, 0x3c01386),
    (0x2c7, 'eb25', 1, 2, 0x3c012fe),
    (0x2d6, '0f85aa000000', 2, 6, 0x3c01396),
    (0x2e8, '0f8519010000', 2, 6, 0x3c01417),
    (0x315, '0f833d010000', 2, 6, 0x3c01468),
    (0x330, '7539', 1, 2, 0x3c0137b),
    (0x339, '0f83dd000000', 2, 6, 0x3c0142c),
    (0x345, 'eb2c', 1, 2, 0x3c01383),
    (0x34e, '0f837cfdffff', 2, 6, 0x3c010e0),
    (0x354, 'e9b5fdffff', 1, 5, 0x3c0111e),
    (0x360, '0f836afeffff', 2, 6, 0x3c011e0),
    (0x366, 'e9a3feffff', 1, 5, 0x3c0121e),
    (0x380, '0f8456ffffff', 2, 6, 0x3c012ec),
    (0x3a6, '750e', 1, 2, 0x3c013c6),
    (0x3b4, 'eb42', 1, 2, 0x3c01408),
    (0x3c6, '0f838c000000', 2, 6, 0x3c01468),
    (0x3e5, '750d', 1, 2, 0x3c01404),
    (0x3ee, '7351', 1, 2, 0x3c01451),
    (0x3f2, 'eb02', 1, 2, 0x3c01406),
    (0x401, '0f84e7feffff', 2, 6, 0x3c012fe),
    (0x417, 'e905fdffff', 1, 5, 0x3c01131),
    (0x425, '0f844bffffff', 2, 6, 0x3c01386),
    (0x43c, 'e935ffffff', 1, 5, 0x3c01386),
    (0x446, '74b0', 1, 2, 0x3c01408),
    (0x456, 'eba0', 1, 2, 0x3c01408),
    (0x472, 'eb0d', 1, 2, 0x3c01491),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3c012af, 0x37272c0),
    (0x3c013ac, 0x37272c0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3c0146f, 0x576e470),
    (0x3c0147c, 0x576e470),
    (0x3c0148b, 0x576e470),
    (0x3c014a0, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3c01468, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x3c01475, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3c01484, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3c01493, 0x56dfda8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = [0x3727207, 0x3727224]
CALLER_FUNCTIONS = {'0x3727207': ('0x37270e0', '0x37272b2'), '0x3727224': ('0x37270e0', '0x37272b2')}
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

