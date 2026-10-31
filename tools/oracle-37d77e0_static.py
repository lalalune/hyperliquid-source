#!/usr/bin/env python3
"""Authenticated node94 oracle-37d77e0 binding (0x37d77e0).

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

START, END = 0x37d77e0, 0x37d79e0
FDE_VA = 0xe61844
FDE = bytes.fromhex(
    '3c00000030031800945f97020002000000410e10420e18420e20410e28470eb0'
    '0183058e048f03860202c70e28410e20420e18420e10410e08410eb001000000'
)
BODY = bytes.fromhex(
    '5541574156534881ec880000004889f84c8b9424b000000040f6c6017475488b'
    '70084885f60f8477010000488b781031c00fb79e220300004189df41c1e70649'
    'c7c3ffffffff4531f60f1f80000000004d39f7742b4a3b94ded0020000400f97'
    'c54080dd004983c64049ffc34080fd0174de400fb6dd85db7461eb070f1f4000'
    '4989db4883ef0172444a8bb4de28030000eb9e4c8914240fb6c9450fb6c0488d'
    '7c24104889c631d2ff15eab8f901488b5c2410488b4c24184885c90f88bc0000'
    '004889d84829c80f80dc0000004881c4880000005b415e415f5dc3420f104436'
    'c0420f104c36d0420f105436e0420f105c36f00f295c24400f295424300f294c'
    '24200f2944241048be4b598638d6c56d344889d04889d748f7e648c1ea0b4869'
    'c2102700004829c7498b71104839f70f83be000000498b4108488d147f48c1e2'
    '05488b5410200fb6c9450fb6c0488d7c2458488d7424104d89d1ff1598cdf901'
    '807c2458007473488b5c2460488b8c24800000004885c90f8944ffffff488d3d'
    '8e48dcfc488d0d9dc3f1014c8d05eec0f101488d542410be2b000000ff15c666'
    'f90131c0e924ffffff0f99c00fb6c048baffffffffffffff7f4801c24829cb48'
    '8d35d2c0f101480f40da31ffff15deb7f9014889d8e9f3feffff488d3d693bdc'
    'fc488d1580c0f101be28000000ff153567f901488d1556c0f101ff15e865f901'
)
BODY_SHA256 = '06773ad410d87661980d9af32e9b05c3e94a0ea3cf9eaf89c04577bd8b3c22e2'
BRANCHES = [
    (0x1c, '7475', 1, 2, 0x37d7873),
    (0x25, '0f8477010000', 2, 6, 0x37d7982),
    (0x53, '742b', 1, 2, 0x37d7860),
    (0x70, '74de', 1, 2, 0x37d7830),
    (0x78, '7461', 1, 2, 0x37d78bb),
    (0x7a, 'eb07', 1, 2, 0x37d7863),
    (0x87, '7244', 1, 2, 0x37d78ad),
    (0x91, 'eb9e', 1, 2, 0x37d7811),
    (0xbb, '0f88bc000000', 2, 6, 0x37d795d),
    (0xc7, '0f80dc000000', 2, 6, 0x37d7989),
    (0x12f, '0f83be000000', 2, 6, 0x37d79d3),
    (0x165, '7473', 1, 2, 0x37d79ba),
    (0x177, '0f8944ffffff', 2, 6, 0x37d78a1),
    (0x1a4, 'e924ffffff', 1, 5, 0x37d78ad),
    (0x1d5, 'e9f3feffff', 1, 5, 0x37d78ad),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x37d7888, 0x5773178),
    (0x37d793a, 0x57746d8),
    (0x37d797c, 0x576e048),
    (0x37d79ac, 0x5773190),
    (0x37d79cd, 0x576e108),
    (0x37d79da, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37d79c1, 0x56f3a48, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f757365725f73746174652e7273'), 87, 60),
    (0x37d79d3, 0x56f3a30, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x57746f0']
GOT_SITES = {'0x57746f0': ['0x26b65b9', '0x36f82db', '0x36fc88e', '0x36ff0b6', '0x36ff113', '0x3700814', '0x370756f', '0x370a249', '0x370a27a', '0x370bb09', '0x370bbb7', '0x370bc42', '0x3714529', '0x37d76b9']}


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

