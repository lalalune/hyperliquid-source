#!/usr/bin/env python3
"""Authenticated node94 pdi-3bb7280 binding (0x3bb7280).

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

START, END = 0x3bb7280, 0x3bb7671
FDE_VA = 0x11e136c
FDE = bytes.fromhex(
    '50000000443722000c5f9d02f103000004d70990ff410e10420e18420e20420e'
    '28420e30410e38470ee00283078c068d058e048f038602037c030e38410e3042'
    '0e28420e20420e18420e10410e08410ee0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec2801000048897c2418488b4630488944242048'
    'c704240000000048c744241000000000488b7a104885ff0f848f0200004889d1'
    'ba102700004c8b4424204c89c048f7e20f806f0300004c8b61084c69efd80000'
    '00488b5608488b4e1048894c24404c8db424040100004969c800530700488d1c'
    '114883c32a48894424484989c70f1f004c89f848b94b598638d6c56d3448f7e1'
    '4c3b7c24480f82fc0200004889d54c89e7e88a0e6cff4889c14c89f848ba4b59'
    '8638d6c56d3448f7e248c1ea0b483b5424200f85c002000048c1ed0b4869c510'
    '2700004c89fa4829c2483b5424400f83a40200004869c500adf8ff0fb6040348'
    '83f8070f83ad020000ba0600000029c266480f6ec1660f6205e3ca64fc660f5c'
    '05fbba64fc660f28c8660f15c8f20f58c8c1e203488d054dd79cfcf20f5e0c02'
    '66480f7ec84889c148baffffffffffffff7f4821d148ba000000000000f07f48'
    '39d10f8d8e0100004889c248c1ea344889c148beffffffffffff0f004821f181'
    'e2ff070000742948c1e92089442450c74424580000000081c900001000894c24'
    '5481c2cdfbffffeb290f1f80000000004885c90f84e300000048c1e920894424'
    '50894c2454c744245800000000bacefbffff31c94885c00f99c1488d7c242848'
    '8d74245041b80100000041b901000000e8cb522f018b44242866c7442450ac00'
    '83f8010f85ed000000488d4c242c8b01418906488b4104498946048b410c4189'
    '460c488d7c2450e864b0baff410f1006488d8424f20000000f11000f1000488d'
    '8424e00000000f11000f1000488d8424ce0000000f1100660f1000660f298424'
    'b0000000488dbc24140100004889e64c89fa488d8c24b0000000e851e07dff49'
    '81c4d800000049ffc74883c3304981c528ffffff0f85f6fdffffeb3048c1e83f'
    'c1e01f8944242c8b057f0865fc488d4c242c89410c488b05680865fc48894104'
    '66c7442450ac00e93dffffff488b4424104c8b7c241849894718488b04244989'
    '4708488b442408498947106641c7078601e98d0000004c8b7c24186641c707ac'
    '00488b0c244885c9743d488b542408488b44241048c74424580000000048894c'
    '2460488954246848c74424780000000048898c24800000004889942488000000'
    'b901000000eb0431c931c048894c245048894c24704889842490000000488d5c'
    '24284c8d742450660f1f8400000000004889df4c89f6e8752e80ff48837c2428'
    '0075ed4c89f84881c4280100005b415c415d415e415f5dc3488d3da1abb301ff'
    '154b6ebb01eb2b488d3ddad0b501ff15e46abb01eb1c488d3d13bdb301ff150d'
    '6bbb01eb0d488d3dbcd0b501ff155e6bbb010f0beb02eb004889c34889e7e81d'
    '8584ff4889dfe8a58aaa01ff15b76abb01'
)
BODY_SHA256 = 'b9efe3e754dc2ff222b2654a8f3104a97c19050198d7dd17b9e0a4fadece4515'
BRANCHES = [
    (0x37, '0f848f020000', 2, 6, 0x3bb754c),
    (0x50, '0f806f030000', 2, 6, 0x3bb7645),
    (0xa5, '0f82fc020000', 2, 6, 0x3bb7627),
    (0xd2, '0f85c0020000', 2, 6, 0x3bb7618),
    (0xee, '0f83a4020000', 2, 6, 0x3bb7618),
    (0x103, '0f83ad020000', 2, 6, 0x3bb7636),
    (0x162, '0f8d8e010000', 2, 6, 0x3bb7576),
    (0x185, '7429', 1, 2, 0x3bb7430),
    (0x1a7, 'eb29', 1, 2, 0x3bb7452),
    (0x1b3, '0f84e3000000', 2, 6, 0x3bb751c),
    (0x203, '0f85ed000000', 2, 6, 0x3bb7576),
    (0x294, '0f85f6fdffff', 2, 6, 0x3bb7310),
    (0x29a, 'eb30', 1, 2, 0x3bb754c),
    (0x2c7, 'e93dffffff', 1, 5, 0x3bb7489),
    (0x2f1, 'e98d000000', 1, 5, 0x3bb7603),
    (0x308, '743d', 1, 2, 0x3bb75c7),
    (0x345, 'eb04', 1, 2, 0x3bb75cb),
    (0x381, '75ed', 1, 2, 0x3bb75f0),
    (0x3a5, 'eb2b', 1, 2, 0x3bb7652),
    (0x3b4, 'eb1c', 1, 2, 0x3bb7652),
    (0x3c3, 'eb0d', 1, 2, 0x3bb7652),
    (0x3d4, 'eb02', 1, 2, 0x3bb7658),
    (0x3d6, 'eb00', 1, 2, 0x3bb7658),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3bb7331, 0x32781c0),
    (0x3bb7470, 0x4eac740),
    (0x3bb74a7, 0x3762510),
    (0x3bb74fa, 0x3395550),
    (0x3bb75f6, 0x33ba470),
    (0x3bb765e, 0x33ffb80),
    (0x3bb7666, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3bb761f, 0x576e470),
    (0x3bb762e, 0x576e118),
    (0x3bb763d, 0x576e150),
    (0x3bb764c, 0x576e1b0),
    (0x3bb766b, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3bb7618, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x3bb7627, 0x5714708, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f61737365742f7064692e7273'), 30, 14),
    (0x3bb7636, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774be0']
GOT_SITES = {'0x5774be0': ['0x27449aa', '0x4d5d41c', '0x4d5dcdc']}


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

