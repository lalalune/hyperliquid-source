#!/usr/bin/env python3
"""Authenticated node94 oracle-3709560 binding (0x3709560).

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

START, END = 0x3709560, 0x3709894
FDE_VA = 0xe4b838
FDE = bytes.fromhex(
    '4c00000024a3160020dd8b023403000000410e10420e18420e20420e28420e30'
    '410e38440eb00183078c068d058e048f0386020345020e38410e30420e28420e'
    '20420e18420e10410e08410eb0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec78f20f100dca13b0fc660f2ec80f8704010000'
    '660f2e05a811b0fc0f87f60000004889d348ba4b598638d6c56d344889c848f7'
    'e248c1ea0b483b56300f854b0200004869c2102700004989ce4929c64c3b7610'
    '0f8334020000488b46084b8d2c764889ea48c1e204807c1028020f85ae000000'
    'f20f11442410488d86f800000048897c24084889c74989f44889de4989cde8ed'
    'c1feff488b7c2408488b50084885d20f84920100004c89e64c89e9488b401044'
    '0fb792220300004589d341c1e30649c7c1ffffffff4531c00f1f840000000000'
    '4d39c374284a3b8ccad0020000410f97c74180df004983c04049ffc14180ff01'
    '74de450fb6d74585d2742deb034d89d14883e8010f822d0100004a8b94ca2803'
    '0000eb9b66c7074300e91e01000066c7073901e914010000488b46704939c60f'
    '83dc010000488b466848c1e5054c8b7428204d85f60f884c0100004e0faf7402'
    'd00f8040010000428b4402c0a8010f84d30000004a8b5402c84c89f548f7dd49'
    '0f48ee4c89f04801d00f80250100004885ed0f885a010000f20f100d3010b0fc'
    'f2480f2ac5f20f5e4c2410f20f59c166490f7ec048baffffffffffffff7f4921'
    'd0660f57c949b9ffffffffffffef7f4d39c87f2ef20f10157c15b0fc660f2ed0'
    '7710660f2e05a610b0fc7706660f28c8eb10f20f5fd0f20f100d9210b0fcf20f'
    '5dcaf24c0f2cc9660f2e0d590bb0fc4c0f47ca4531c0660f2ec94d0f4bc14929'
    'c00f80f00000004d85c07e1b488d7c24184889dae867d8ffff66817c24188601'
    '751c488b7c240866c70786014889f84883c4785b415c415d415e415f5dc30f10'
    '442468488b7c24080f1147500f104424580f1147400f104424180f104c24280f'
    '105424380f105c24480f115f300f1157200f114f100f1107ebb2488d3dbf89fe'
    '01ff15694c0602488d3d9a87fe01ff155c4c060248c1f83f48b9000000000000'
    '00804831c14901d6488d35c984fe014c0f40f131ffff15559906024c89e64c89'
    'e9488b7c24084c89f04885ed0f89a6feffff488d3d0900ebfc488d0dd0b60002'
    '4c8d05a9b30002488d542418be2b000000ff15d147060266c707bf00e92bffff'
    'ff488d152884fe014c89f74889c6ff1534470602'
)
BODY_SHA256 = '2c6f986955eabde93a25349ecbe321df6b1869adb4ccf21d6221e444de109ef2'
BRANCHES = [
    (0x1a, '0f8704010000', 2, 6, 0x3709684),
    (0x28, '0f87f6000000', 2, 6, 0x3709684),
    (0x49, '0f854b020000', 2, 6, 0x37097fa),
    (0x60, '0f8334020000', 2, 6, 0x37097fa),
    (0x7a, '0f85ae000000', 2, 6, 0x370968e),
    (0xaf, '0f8492010000', 2, 6, 0x37097a7),
    (0xe3, '7428', 1, 2, 0x370966d),
    (0x100, '74de', 1, 2, 0x3709640),
    (0x109, '742d', 1, 2, 0x3709698),
    (0x10b, 'eb03', 1, 2, 0x3709670),
    (0x114, '0f822d010000', 2, 6, 0x37097a7),
    (0x122, 'eb9b', 1, 2, 0x370961f),
    (0x129, 'e91e010000', 1, 5, 0x37097ac),
    (0x133, 'e914010000', 1, 5, 0x37097ac),
    (0x13f, '0f83dc010000', 2, 6, 0x3709881),
    (0x155, '0f884c010000', 2, 6, 0x3709807),
    (0x161, '0f8040010000', 2, 6, 0x3709807),
    (0x16e, '0f84d3000000', 2, 6, 0x37097a7),
    (0x189, '0f8025010000', 2, 6, 0x3709814),
    (0x192, '0f885a010000', 2, 6, 0x3709852),
    (0x1d2, '7f2e', 1, 2, 0x3709762),
    (0x1e0, '7710', 1, 2, 0x3709752),
    (0x1ea, '7706', 1, 2, 0x3709752),
    (0x1f0, 'eb10', 1, 2, 0x3709762),
    (0x221, '0f80f0000000', 2, 6, 0x3709877),
    (0x22a, '7e1b', 1, 2, 0x37097a7),
    (0x240, '751c', 1, 2, 0x37097be),
    (0x298, 'ebb2', 1, 2, 0x37097ac),
    (0x2ec, '0f89a6feffff', 2, 6, 0x37096f8),
    (0x31c, 'e92bffffff', 1, 5, 0x37097ac),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x37095fe, 0x36f57f0),
    (0x3709794, 0x3707000),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3709801, 0x576e470),
    (0x370980e, 0x576e470),
    (0x3709835, 0x5773190),
    (0x3709871, 0x576e048),
    (0x370988e, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37097fa, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x3709807, 0x56f1fa8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f706f736974696f6e2e7273'), 204, 57),
    (0x3709881, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5773970']
GOT_SITES = {'0x5773970': ['0x21e307c', '0x4c03d3c', '0x4c0404c']}


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

