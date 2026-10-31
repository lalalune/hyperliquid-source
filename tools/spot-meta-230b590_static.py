#!/usr/bin/env python3
"""Authenticated node94 spot-meta-230b590 binding (0x230b590).

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

START, END = 0x230b590, 0x230b841
FDE_VA = 0xd47238
FDE = bytes.fromhex(
    '38000000245d060050435c01b102000000420e10420e18410e2083048e038f02'
    '03e9010e18420e10420e08410e20028f0e18420e10420e08410e2000'
)
BODY = bytes.fromhex(
    '41574156534989d74989f64889fb4889faff15898746034889c1b8e8030000f6'
    'c1010f85c5010000b8010000004981ffa08601000f8244010000b80a00000049'
    '81ff40420f000f8232010000b8640000004981ff809698000f8220010000b8e8'
    '0300004981ff00e1f5050f820e010000b8102700004981ff00ca9a3b0f82fc00'
    '00004c89f948c1e90ab8a08601004881f9f90295000f82e30000004c89f948c1'
    'e90bb840420f004881f9dd0ee9020f82ca0000004c89f948c1e90cb880969800'
    '4881f9514a8d0e0f82b10000004c89f948c1e90db800e1f5054881f99573c248'
    '0f829800000048b9ff3f7a10f35a0000b800ca9a3b4939cf0f868000000048b8'
    'ff7fc6a47e8d03004939c7764048baffffc06ff28623004939d7763d48ba0000'
    '8a5d784563014939d7723a48ba000064a7b3b6e00d4939d7723748ba0000e889'
    '0423c78a4939d7480f42c1eb2e48b8ffe30b5402000000eb2248b8ffe7764817'
    '000000eb1648b8ff0fa5d4e8000000eb0a48b8ff9f724e1809000048ffc0488b'
    'b3700100004939f60f830601000049c1e605488bb368010000488b9388010000'
    '4a8b4c36084839d10f83d90000004a8b34364839d60f83cc000000488bbb8001'
    '00004869c9e80000000fb6540f494869cee80000002a540f480f82c5000000b9'
    '01000000750d4839c1480f42c15b415e415fc30fb6f240f6c601740ab90a0000'
    '0083fe0174e0f6c202740e486bc96489f783e7fe83ff0274cdf6c20474114869'
    'c91027000089f783e7fc83ff0474b7f6c20874114869c900e1f50589f783e7f8'
    '83ff0874a1f6c21074a34889c748baffffc06ff286230048ffc24889c848f7e2'
    '0f90c283e6f083fe1075134889c184d24889f80f846dffffffe96fffffff4889'
    'f85b415e415fc3488d3dd2693e03ff154c2c4603488d15ad673e034c89f7ff15'
    '94274603488d3d1d6a3e03ff150f294603'
)
BODY_SHA256 = 'aabc0d01de2b505391d3d4fa87edd3e6229e9f2644e34ef4d80c711d7b1a56fa'
BRANCHES = [
    (0x22, '0f85c5010000', 2, 6, 0x230b77d),
    (0x34, '0f8244010000', 2, 6, 0x230b70e),
    (0x46, '0f8232010000', 2, 6, 0x230b70e),
    (0x58, '0f8220010000', 2, 6, 0x230b70e),
    (0x6a, '0f820e010000', 2, 6, 0x230b70e),
    (0x7c, '0f82fc000000', 2, 6, 0x230b70e),
    (0x95, '0f82e3000000', 2, 6, 0x230b70e),
    (0xae, '0f82ca000000', 2, 6, 0x230b70e),
    (0xc7, '0f82b1000000', 2, 6, 0x230b70e),
    (0xe0, '0f8298000000', 2, 6, 0x230b70e),
    (0xf8, '0f8680000000', 2, 6, 0x230b70e),
    (0x10b, '7640', 1, 2, 0x230b6dd),
    (0x11a, '763d', 1, 2, 0x230b6e9),
    (0x129, '723a', 1, 2, 0x230b6f5),
    (0x138, '7237', 1, 2, 0x230b701),
    (0x14b, 'eb2e', 1, 2, 0x230b70b),
    (0x157, 'eb22', 1, 2, 0x230b70b),
    (0x163, 'eb16', 1, 2, 0x230b70b),
    (0x16f, 'eb0a', 1, 2, 0x230b70b),
    (0x188, '0f8306010000', 2, 6, 0x230b824),
    (0x1a8, '0f83d9000000', 2, 6, 0x230b817),
    (0x1b5, '0f83cc000000', 2, 6, 0x230b817),
    (0x1d9, '0f82c5000000', 2, 6, 0x230b834),
    (0x1e4, '750d', 1, 2, 0x230b783),
    (0x1fa, '740a', 1, 2, 0x230b796),
    (0x204, '74e0', 1, 2, 0x230b776),
    (0x209, '740e', 1, 2, 0x230b7a9),
    (0x217, '74cd', 1, 2, 0x230b776),
    (0x21c, '7411', 1, 2, 0x230b7bf),
    (0x22d, '74b7', 1, 2, 0x230b776),
    (0x232, '7411', 1, 2, 0x230b7d5),
    (0x243, '74a1', 1, 2, 0x230b776),
    (0x248, '74a3', 1, 2, 0x230b77d),
    (0x269, '7513', 1, 2, 0x230b80e),
    (0x273, '0f846dffffff', 2, 6, 0x230b776),
    (0x279, 'e96fffffff', 1, 5, 0x230b77d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x230b5a1, 0x5773d30),
    (0x230b81e, 0x576e470),
    (0x230b82e, 0x576dfc8),
    (0x230b83b, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x230b817, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x230b824, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x230b834, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x1e839b6, 0x21f8900, 0x21f8b0b, 0x26e591e, 0x26e880c, 0x27009b9, 0x2774192]
CALLER_FUNCTIONS = {'0x1e839b6': ('0x1e83350', '0x1e83e1f'), '0x21f8900': ('0x21f8520', '0x21f8cb1'), '0x21f8b0b': ('0x21f8520', '0x21f8cb1'), '0x26e591e': ('0x26e5760', '0x26e6a29'), '0x26e880c': ('0x26e81c0', '0x26ebdc0'), '0x27009b9': ('0x2700390', '0x2701d93'), '0x2774192': ('0x2773d60', '0x27747d9')}
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

