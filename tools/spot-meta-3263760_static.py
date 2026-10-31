#!/usr/bin/env python3
"""Authenticated node94 spot-meta-3263760 binding (0x3263760).

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

START, END = 0x3263760, 0x32639b9
FDE_VA = 0xde4060
FDE = bytes.fromhex(
    '380000004c2b1000f8f647025902000000420e10420e18420e20410e28440e40'
    '83058c048e038f020333020e28410e20420e18420e10420e08410e40'
)
BODY = bytes.fromhex(
    '415741564154534883ec184989f6488bb1800100004839f20f83280200004989'
    'cf4889fb488b817801000048c1e2054c8b2410660f76c0660f7f0424c7442410'
    'ffffffff4889e64889cfff15c0f95002488b50104885d20f8467010000488b40'
    '1831c90fb7ba6a0100008d34fd000000004c8d0c7648c7c6ffffffff4531c090'
    '4d39c1742b4c3b64f210410f97c24180da004983c01848ffc64180fa0174e141'
    '0fb6fa85ff741ceb0a0f1f80000000004889fe4883e801720f488b94f2700100'
    '00eba04a8b4c02484d3ba7980100000f83fe000000498b97900100004969f4e8'
    '0000000fb64432492a4432480f82c5000000498b7e18be01000000753b4885ff'
    '0f84da0000004889c84809f048c1e8200f84d20000004889c831d248f7f64889'
    'c14809f948c1e9200f84d000000031d248f7f7e9ca000000440fb6c041f6c001'
    '740bbe0a0000004183f80174b0a802740f486bf6644489c283e2fe83fa02749d'
    'a80474124869f6102700004489c283e2fc83fa047487a80874164869f600e1f5'
    '054489c283e2f883fa080f846dffffffa810742348ba0000c16ff28623004889'
    'f048f7e270114889c64183e0f04183f8100f8446ffffff488d3d52e94802ff15'
    '4cab500231c94d3ba7980100000f8202ffffff488d3db6e84802ff1530ab5002'
    '498b4e1031f6eb4489c831d2f7f64889c14809f948c1e9200f8530ffffff31d2'
    'f7f7498b7e1031f64889f94829c1480f42ce4885d2741348ffc931f64839c748'
    '0f46cebe01000000eb0231d248890b48897308488953104889d84883c4185b41'
    '5c415e415fc3488d057bbe47024889d74889c2ff150fa65002'
)
BODY_SHA256 = 'c941aff228579ea80e0ed094001d92485325d350ff420b552bd80af7d8642c23'
BRANCHES = [
    (0x18, '0f8328020000', 2, 6, 0x32639a6),
    (0x57, '0f8467010000', 2, 6, 0x3263924),
    (0x83, '742b', 1, 2, 0x3263810),
    (0x9d, '74e1', 1, 2, 0x32637e0),
    (0xa5, '741c', 1, 2, 0x3263823),
    (0xa7, 'eb0a', 1, 2, 0x3263813),
    (0xb7, '720f', 1, 2, 0x3263828),
    (0xc1, 'eba0', 1, 2, 0x32637c3),
    (0xcf, '0f83fe000000', 2, 6, 0x3263933),
    (0xec, '0f82c5000000', 2, 6, 0x3263917),
    (0xfb, '753b', 1, 2, 0x3263898),
    (0x100, '0f84da000000', 2, 6, 0x3263940),
    (0x110, '0f84d2000000', 2, 6, 0x3263948),
    (0x128, '0f84d0000000', 2, 6, 0x326395e),
    (0x133, 'e9ca000000', 1, 5, 0x3263962),
    (0x140, '740b', 1, 2, 0x32638ad),
    (0x14b, '74b0', 1, 2, 0x326385d),
    (0x14f, '740f', 1, 2, 0x32638c0),
    (0x15e, '749d', 1, 2, 0x326385d),
    (0x162, '7412', 1, 2, 0x32638d6),
    (0x174, '7487', 1, 2, 0x326385d),
    (0x178, '7416', 1, 2, 0x32638f0),
    (0x18a, '0f846dffffff', 2, 6, 0x326385d),
    (0x192, '7423', 1, 2, 0x3263917),
    (0x1a4, '7011', 1, 2, 0x3263917),
    (0x1b1, '0f8446ffffff', 2, 6, 0x326385d),
    (0x1cd, '0f8202ffffff', 2, 6, 0x3263835),
    (0x1e6, 'eb44', 1, 2, 0x326398c),
    (0x1f8, '0f8530ffffff', 2, 6, 0x326388e),
    (0x215, '7413', 1, 2, 0x326398a),
    (0x228, 'eb02', 1, 2, 0x326398c),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x32637aa, 0x5773170),
    (0x326391e, 0x576e470),
    (0x326393a, 0x576e470),
    (0x32639b3, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3263917, 0x56f2270, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 1199, 57),
    (0x3263933, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774750']
GOT_SITES = {'0x5774750': ['0x26cb645', '0x42d2b3b', '0x42d40fb']}


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

